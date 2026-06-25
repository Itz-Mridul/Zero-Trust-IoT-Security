"""
ultimate_gateway.py — Zero-Trust Gateway (main entry point)

Combines:
  1. Packet sniffing + DPI (Scapy, thread-safe)
  2. Firewall blocking (iptables, subprocess — injection-safe)
  3. Blockchain evidence logging (async, so it never stalls packet capture)
  4. Flask command-center dashboard

Run as root: sudo python3 ultimate_gateway.py
"""

import html
import logging
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

from flask import Flask
from scapy.all import DNSQR, IP, sniff

# ---------------------------------------------------------------------------
# PROJECT ROOT ON PYTHON PATH
# blockchain_bridge.py lives one level up: iot_gateway/blockchain_bridge.py
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))   # = iot_gateway/gateway_logic/
IOT_ROOT     = os.path.dirname(PROJECT_ROOT)                 # = iot_gateway/
if IOT_ROOT not in sys.path:
    sys.path.append(IOT_ROOT)

try:
    from blockchain_bridge import hash_event, register_event_on_chain  # noqa: E402
except Exception as _imp_err:
    print(f"⚠️  blockchain_bridge unavailable: {_imp_err}. Running in local-only mode.")
    import hashlib as _hl
    def hash_event(event_data: str) -> str:
        return _hl.sha256(event_data.encode("utf-8")).hexdigest()
    def register_event_on_chain(*_a, **_kw):
        return None

# ---------------------------------------------------------------------------
# 1. CONFIGURATION
# ---------------------------------------------------------------------------
# Use env vars to override without editing this file
INTERFACE           = os.environ.get("GATEWAY_IFACE", "wlan0")     # set to eth0 if wired
GATEWAY_IP          = os.environ.get("PI_LOCAL_IP", os.environ.get("GATEWAY_IP", "10.238.130.161"))  # Pi LAN IP (wlan0)
COMMAND_CENTER_IP   = os.environ.get("PI_LOCAL_IP", os.environ.get("GATEWAY_IP", "10.238.130.161"))  # Pi LAN IP (wlan0)
COMMAND_CENTER_PORT = int(os.environ.get("DASHBOARD_PORT", "5000"))

BANNED_DOMAINS = {"spacejam.com", "tiktok.com", "facebook.com"}

TRUSTED_IPS: set[str] = {
    GATEWAY_IP,
    os.environ.get("MOBILE_IP", "10.238.130.38"),   # Mobile hotspot router/gateway
    "8.8.8.8",         # Google DNS
    "8.8.4.4",
    "127.0.0.1",
}

BLOCKED_IPS: set[str] = set()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "gateway.log")

# Thread pool for async blockchain calls (so sniff() is never blocked)
_chain_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="chain")

# ---------------------------------------------------------------------------
# 2. LOGGING
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# ---------------------------------------------------------------------------
# 3. FLASK COMMAND-CENTER DASHBOARD
# ---------------------------------------------------------------------------
app = Flask(__name__)

_SEVERITY_KEYWORDS = ("BLOCKED", "BAN", "ALERT", "CRITICAL", "SUSPICIOUS")


@app.route("/")
def index():
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8") as lf:
                logs = lf.readlines()
        else:
            logs = ["No gateway events logged yet.\n"]

        logs.reverse()
        rows = []
        for raw in logs[:100]:
            safe = html.escape(raw.strip())
            upper = raw.upper()
            if any(kw in upper for kw in _SEVERITY_KEYWORDS):
                rows.append(
                    f"<li style='color:#f85149;font-weight:600;margin-bottom:4px;"
                    f"padding:4px 8px;border-left:3px solid #f85149;'>{safe}</li>"
                )
            else:
                rows.append(
                    f"<li style='margin-bottom:4px;padding:4px 8px;"
                    f"border-left:3px solid #30363d;'>{safe}</li>"
                )

        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta http-equiv="refresh" content="5">
          <title>Zero-Trust Command Center</title>
          <style>
            @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap');
            body {{
              background:#0d1117; color:#e6edf3;
              font-family:'JetBrains Mono', monospace;
              padding:28px; margin:0;
            }}
            h1 {{ color:#f85149; margin-bottom:4px; font-size:1.5rem; }}
            h3 {{ color:#8b949e; font-size:.9rem; margin-bottom:20px; font-weight:400; }}
            ul {{ list-style:none; padding:0; }}
            .pill {{
              display:inline-block;
              background:rgba(46,160,67,.15); color:#2ea043;
              border:1px solid #2ea043; border-radius:999px;
              padding:3px 12px; font-size:.75rem; margin-left:12px;
            }}
          </style>
        </head>
        <body>
          <h1>🛡 Zero-Trust Command Center <span class="pill">● LIVE</span></h1>
          <h3>Live Gateway Log — last 100 entries (newest first) · auto-refreshes every 5 s</h3>
          <ul>{''.join(rows)}</ul>
        </body>
        </html>
        """
    except Exception as exc:
        return f"Dashboard Error: {html.escape(str(exc))}", 500


def run_dashboard():
    app.run(
        host="0.0.0.0",
        port=COMMAND_CENTER_PORT,
        debug=False,
        use_reloader=False,
    )


# ---------------------------------------------------------------------------
# 4. FIREWALL (injection-safe)
# ---------------------------------------------------------------------------
def _iptables(args: list[str]) -> int:
    try:
        r = subprocess.run(["iptables"] + args, capture_output=True, text=True)
        return r.returncode
    except FileNotFoundError:
        logging.error("[FIREWALL] iptables not found.")
        return 1


def add_firewall_rule(direction: str, ip_address: str) -> bool:
    check = _iptables(["-C", "FORWARD", direction, ip_address, "-j", "DROP"])
    if check == 0:
        return True   # rule already present
    add = _iptables(["-A", "FORWARD", direction, ip_address, "-j", "DROP"])
    if add != 0:
        logging.error("[FIREWALL ERROR] Could not add rule for %s %s", direction, ip_address)
        return False
    return True


def ban_ip(ip_addr: str) -> None:
    if ip_addr in TRUSTED_IPS or ip_addr in BLOCKED_IPS:
        return

    print(f"[FIREWALL] Banning untrusted IP: {ip_addr}")
    logging.warning("[FIREWALL BAN] %s", ip_addr)

    src_ok  = add_firewall_rule("-s", ip_addr)
    dst_ok  = add_firewall_rule("-d", ip_addr)

    if src_ok and dst_ok:
        BLOCKED_IPS.add(ip_addr)
        # Fire-and-forget blockchain call — never blocks the sniffer thread
        _chain_pool.submit(record_on_chain, f"Firewall ban: {ip_addr}")


# ---------------------------------------------------------------------------
# 5. BLOCKCHAIN (called from thread pool — never blocks sniffing)
# ---------------------------------------------------------------------------
def record_on_chain(event_text: str) -> None:
    try:
        fingerprint_hex = hash_event(event_text)
        fingerprint_int = int(fingerprint_hex[:8], 16)
        receipt = register_event_on_chain(
            f"GW_01: {event_text[:40]}", fingerprint_int
        )
        if receipt is None:
            logging.warning("[BLOCKCHAIN] Failed to record: %s", event_text)
        else:
            logging.info("[BLOCKCHAIN] Recorded at block %s: %s",
                         receipt.blockNumber, event_text)
    except Exception as exc:
        logging.warning("[BLOCKCHAIN] Exception: %s", exc)


# ---------------------------------------------------------------------------
# 6. DPI HELPERS
# ---------------------------------------------------------------------------
def is_banned_domain(website: str) -> bool:
    site = website.lower().rstrip(".")
    return any(
        site == banned or site.endswith(f".{banned}")
        for banned in BANNED_DOMAINS
    )


# ---------------------------------------------------------------------------
# 7. PACKET HANDLER
# ---------------------------------------------------------------------------
def process_packet(packet) -> None:
    if not packet.haslayer(IP):
        return

    src_ip: str = packet[IP].src
    dst_ip: str = packet[IP].dst

    # --- DNS / DPI ---
    if packet.haslayer(DNSQR):
        try:
            website = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        except Exception:
            return

        if is_banned_domain(website):
            print(f"[DPI] BLOCKED domain: {website}")
            logging.critical("[SECURITY ALERT] Banned domain lookup: %s from %s", website, src_ip)
            _chain_pool.submit(record_on_chain, f"Banned domain: {website}")
        else:
            logging.info("[DNS] %s → %s", src_ip, website)
        return

    # --- IP-level Zero-Trust ---
    if src_ip == GATEWAY_IP and dst_ip not in TRUSTED_IPS:
        ban_ip(dst_ip)
    elif dst_ip == GATEWAY_IP and src_ip not in TRUSTED_IPS:
        ban_ip(src_ip)


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("--- ZERO-TRUST ULTIMATE GATEWAY ACTIVE ---")
    print(f"Watching interface : {INTERFACE}")
    print(f"Command Center     : http://{COMMAND_CENTER_IP}:{COMMAND_CENTER_PORT}")
    print(f"Log file           : {LOG_FILE}")
    print("Press Ctrl+C to stop.\n")

    threading.Thread(target=run_dashboard, daemon=True).start()

    sniff(
        iface=INTERFACE,
        filter="not port 22",   # exclude SSH so the sniffer doesn't loop on itself
        prn=process_packet,
        store=False,
    )
