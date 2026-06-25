"""
sniffer.py — Zero-Trust Packet Sniffer with Active Firewall Blocking

Monitors all non-SSH traffic.  Untrusted source IPs are banned via iptables
using subprocess (injection-safe).  DNS payloads are inspected inline.
Run as root: sudo python3 sniffer.py
"""

import logging
import shlex
import subprocess
import signal
import sys
from ipaddress import ip_address, ip_network

from scapy.all import DNSQR, IP, sniff

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
import os
# IPs that are always allowed (gateway, Pi, router, Google DNS)
_PI_IP = os.environ.get("PI_LOCAL_IP", os.environ.get("GATEWAY_IP", "10.238.130.161"))
TRUSTED_IPS = {
    _PI_IP,
    os.environ.get("MOBILE_IP", "10.238.130.38"),   # Mobile hotspot gateway/router
    "8.8.8.8",
    "8.8.4.4",
    "127.0.0.1",
}

# RFC-1918 private subnets — treat as semi-trusted (log but don't auto-ban)
PRIVATE_SUBNETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
]

BLOCKED_IPS: set[str] = set()   # in-memory block list (dedup firewall calls)

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# ---------------------------------------------------------------------------
# ANSI COLOURS
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"


def _is_private(ip: str) -> bool:
    try:
        addr = ip_address(ip)
        return any(addr in net for net in PRIVATE_SUBNETS)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# FIREWALL
# ---------------------------------------------------------------------------
def _run_iptables(rule_args: list[str]) -> int:
    """Run an iptables command safely using a list (no shell injection)."""
    try:
        result = subprocess.run(
            ["iptables"] + rule_args,
            capture_output=True,
            text=True,
        )
        return result.returncode
    except FileNotFoundError:
        logging.error("[FIREWALL] iptables not found — is this running as root?")
        return 1


def block_ip(src_ip: str) -> None:
    """Add an iptables INPUT DROP rule for src_ip, idempotently."""
    if src_ip in TRUSTED_IPS or src_ip in BLOCKED_IPS:
        return

    # Check if the rule already exists
    check_rc = _run_iptables(["-C", "INPUT", "-s", src_ip, "-j", "DROP"])
    if check_rc == 0:
        BLOCKED_IPS.add(src_ip)
        return

    add_rc = _run_iptables(["-I", "INPUT", "-s", src_ip, "-j", "DROP"])
    if add_rc == 0:
        BLOCKED_IPS.add(src_ip)
        print(f"{YELLOW}[ACTION]{RESET} Banned IP at firewall: {src_ip}")
        logging.warning("[FIREWALL BAN] %s", src_ip)
    else:
        logging.error("[FIREWALL] Failed to ban %s", src_ip)


# ---------------------------------------------------------------------------
# PACKET HANDLER
# ---------------------------------------------------------------------------
def process_packet(packet) -> None:
    if not packet.haslayer(IP):
        return

    src_ip: str = packet[IP].src
    dst_ip: str = packet[IP].dst

    # --- DPI: inspect DNS questions ---
    dpi_info = ""
    if packet.haslayer(DNSQR):
        try:
            domain = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            dpi_info = f"  [DPI→ {domain}]"
        except Exception:
            pass

    # --- Zero-Trust decision ---
    if src_ip in TRUSTED_IPS:
        print(f"{GREEN}[TRUSTED  ]{RESET} {src_ip} → {dst_ip}{dpi_info}")
    else:
        label = "PRIVATE  " if _is_private(src_ip) else "UNTRUSTED"
        colour = YELLOW if _is_private(src_ip) else RED
        print(f"{colour}[{label}]{RESET} {src_ip} → {dst_ip}{dpi_info}")
        logging.warning("[%s] %s → %s%s", label.strip(), src_ip, dst_ip, dpi_info)

        # Only hard-ban fully external (non-RFC1918) untrusted IPs
        if not _is_private(src_ip):
            block_ip(src_ip)


# ---------------------------------------------------------------------------
# GRACEFUL SHUTDOWN
# ---------------------------------------------------------------------------
def _handle_sigint(sig, frame):  # noqa: ANN001
    print(f"\n{YELLOW}[SNIFFER] Shutting down.{RESET}")
    sys.exit(0)


signal.signal(signal.SIGINT, _handle_sigint)

# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"{GREEN}--- Zero-Trust Gateway Sniffer Active ---{RESET}")
    print("1. Deep Packet Inspection (DNS) : ON")
    print("2. Active Firewall Blocking     : ON  (external IPs only)")
    print(f"3. Trusted IPs                  : {', '.join(sorted(TRUSTED_IPS))}")
    print("Press Ctrl+C to stop.\n")

    sniff(
        filter="not port 22",      # exclude SSH to prevent feedback loops
        prn=process_packet,
        store=False,
    )
