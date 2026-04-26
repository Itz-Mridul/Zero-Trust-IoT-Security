"""
dpi.py — Deep Packet Inspection (DNS Monitor)

Listens on wlan0 for DNS queries and logs every device→domain pair.
Suspicious TLDs and known-bad domains are highlighted in red.
Run as root: sudo python3 dpi.py
"""

import logging
import os
import signal
import sys
from collections import defaultdict

from scapy.all import DNSQR, IP, sniff

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
INTERFACE = os.environ.get("GATEWAY_IFACE", "wlan0")   # override: export GATEWAY_IFACE=eth0

# Domains / TLDs to flag as suspicious
SUSPICIOUS_TLDS = {".ru", ".cn", ".tk", ".top", ".xyz", ".ml"}
SUSPICIOUS_KEYWORDS = {"malware", "phishing", "c2", "botnet", "tracker", "telemetry"}

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s - [DPI] %(message)s",
)

# ---------------------------------------------------------------------------
# STATE  (per-device seen-domain cache to avoid log spam)
# ---------------------------------------------------------------------------
# device_ip -> set of domains already logged this session
_seen: defaultdict = defaultdict(set)

# ---------------------------------------------------------------------------
# ANSI COLOUR HELPERS
# ---------------------------------------------------------------------------
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
RESET  = "\033[0m"


def _is_suspicious(domain: str) -> bool:
    """Return True if the domain matches any known-bad pattern."""
    lower = domain.lower()
    for tld in SUSPICIOUS_TLDS:
        if lower.endswith(tld):
            return True
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower:
            return True
    return False


# ---------------------------------------------------------------------------
# PACKET HANDLER
# ---------------------------------------------------------------------------
def process_dns(packet) -> None:
    if not (packet.haslayer(DNSQR) and packet.haslayer(IP)):
        return

    try:
        domain = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
    except Exception:
        return

    device_ip = packet[IP].src

    # Suppress duplicate (device, domain) pairs within a session
    if domain in _seen[device_ip]:
        return
    _seen[device_ip].add(domain)

    suspicious = _is_suspicious(domain)

    if suspicious:
        colour = RED
        label = "SUSPICIOUS"
        logging.warning("SUSPICIOUS DNS — device=%s domain=%s", device_ip, domain)
    else:
        colour = GREEN
        label = "LOOKUP    "

    print(f"{colour}[DPI {label}]{RESET}  {YELLOW}{device_ip}{RESET}  →  {domain}")


# ---------------------------------------------------------------------------
# GRACEFUL SHUTDOWN
# ---------------------------------------------------------------------------
def _handle_sigint(sig, frame):  # noqa: ANN001
    print(f"\n{YELLOW}[DPI] Shutting down — goodbye.{RESET}")
    sys.exit(0)


signal.signal(signal.SIGINT, _handle_sigint)

# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"{GREEN}--- Deep Packet Inspection Active ---{RESET}")
    print(f"Interface : {INTERFACE}")
    print(f"Filter    : UDP port 53 (DNS)")
    print(f"Suspicious TLDs: {', '.join(sorted(SUSPICIOUS_TLDS))}")
    print("Press Ctrl+C to stop.\n")

    sniff(
        iface=INTERFACE,
        filter="udp port 53",
        prn=process_dns,
        store=False,
    )
