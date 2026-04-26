"""
brain.py — mitmproxy addon: HTTP threat keyword interception + dashboard logging.

Usage:
    mitmproxy --listen-port 8080 -s brain.py
    # or
    mitmdump --listen-port 8080 -s brain.py
"""

import datetime
import json
import logging
import os
from pathlib import Path

from mitmproxy import http

# ---------------------------------------------------------------------------
# PATHS  (relative to this script so it works on any machine)
# ---------------------------------------------------------------------------
BASE_DIR   = Path(__file__).resolve().parent
ALERTS_FILE = BASE_DIR / "alerts.json"
LOG_FILE    = BASE_DIR / "security.log"

# ---------------------------------------------------------------------------
# FILE LOGGING (complement the JSON store with a plain-text log)
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.WARNING,
    format="%(asctime)s - [BRAIN] %(message)s",
)

# ---------------------------------------------------------------------------
# THREAT CONFIGURATION
# ---------------------------------------------------------------------------
THREAT_KEYWORDS = [
    "password", "passwd", "secret", "token",
    "api_key", "apikey", "access_token", "private_key",
]

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def _load_alerts() -> list:
    """Load existing alerts from disk; return empty list on any error."""
    if not ALERTS_FILE.exists():
        return []
    try:
        with ALERTS_FILE.open("r") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []


def _save_alerts(alerts: list) -> None:
    """Persist alert list to disk atomically."""
    try:
        tmp = ALERTS_FILE.with_suffix(".tmp")
        with tmp.open("w") as fh:
            json.dump(alerts, fh, indent=4)
        tmp.replace(ALERTS_FILE)
    except OSError as exc:
        logging.error("Could not save alerts.json: %s", exc)


def _log_alert(alert: dict) -> None:
    """Append alert to JSON store and write to security.log."""
    alerts = _load_alerts()
    alerts.append(alert)
    _save_alerts(alerts)
    logging.warning(
        "BLOCKED  source=%-18s  keyword='%s'  url=%s",
        alert["source"],
        alert.get("keyword", "?"),
        alert["target"],
    )


# ---------------------------------------------------------------------------
# MITMPROXY ADDON
# ---------------------------------------------------------------------------
class DashboardBrain:
    def request(self, flow: http.HTTPFlow) -> None:  # noqa: D401
        url   = flow.request.pretty_url
        lower = url.lower()

        for word in THREAT_KEYWORDS:
            if word not in lower:
                continue

            # Safely get source IP
            try:
                source_ip = flow.client_conn.peername[0]
            except Exception:
                source_ip = "unknown"

            alert = {
                "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
                "source"   : source_ip,
                "target"   : url,
                "keyword"  : word,
                "reason"   : f"Sensitive keyword '{word}' in URL",
                "action"   : "BLOCKED",
            }

            _log_alert(alert)

            print(f"🚨 [BRAIN] BLOCKED — keyword='{word}'  src={source_ip}")

            flow.response = http.Response.make(
                403,
                b"GATEWAY BLOCK: Threat detected and logged to Dashboard.",
                {"Content-Type": "text/plain"},
            )
            return   # first match is enough


addons = [DashboardBrain()]
