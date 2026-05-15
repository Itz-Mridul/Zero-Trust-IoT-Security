
#!/usr/bin/env python3
"""
IoT Telemetry Server - Raspberry Pi

Receives heartbeats from the ESP32 gateway and keeps a separate MQTT status
listener so the server can distinguish:
- hard disconnects (broker LWT -> freeze trust)
- reconnects/boots (short grace period)
- genuine spoofing (too-fast packet cadence)

Also handles card-payload validation (mailbox/access):
- HMAC-SHA256 signature verification
- UID lookup in authorized_users.json
- Name / gender / secret-code match
- GRANT or DENY reply to ESP32 on mailbox/decision
- Access log (access_log.json) + photo save + Telegram deny alert
"""

import datetime
import hashlib
import hmac as hmac_lib
import json
import os
import sqlite3
import sys
import threading
import time

# Add project root to path so we can import from pi_backend directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    import requests as _requests
except ImportError:
    _requests = None

try:
    from flask import Flask, jsonify, request
except ImportError:  # pragma: no cover - keeps the trust logic importable in lean environments
    class _FallbackResponse:
        def __init__(self, payload):
            self._payload = payload

        def get_json(self):
            return self._payload

    class _FallbackRequest:
        def get_json(self, silent=False):
            return {}

    class _FallbackContext:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class Flask:  # type: ignore
        def __init__(self, name):
            self.name = name

        def route(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

        def app_context(self):
            return _FallbackContext()

        def run(self, *args, **kwargs):
            raise RuntimeError("Flask is not installed in this environment")

    def jsonify(payload):
        return _FallbackResponse(payload)

    request = _FallbackRequest()

try:
    import paho.mqtt.client as mqtt
except ImportError:  # pragma: no cover - keeps the HTTP server usable without MQTT
    mqtt = None

try:
    from pathlib import Path
except ImportError:  # pragma: no cover
    Path = None  # type: ignore


app = Flask(__name__)

# ── Paths & core config ──────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "security.db")

# Resolve project root (one level up from pi_backend/)
_PROJECT_ROOT = os.path.dirname(BASE_DIR)

from dotenv import load_dotenv
load_dotenv(os.path.join(_PROJECT_ROOT, ".env"))

MQTT_BROKER = os.environ.get("MQTT_BROKER", "localhost")
MQTT_PORT   = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_STATUS_TOPIC       = os.environ.get("MQTT_STATUS_TOPIC",       "mailbox/status")
MQTT_HEARTBEAT_TOPIC    = os.environ.get("MQTT_HEARTBEAT_TOPIC",    "mailbox/heartbeat")
MQTT_ENVIRONMENT_TOPIC  = os.environ.get("MQTT_ENVIRONMENT_TOPIC",  "mailbox/environment")
MQTT_PHOTO_PREFIX       = os.environ.get("MQTT_PHOTO_PREFIX",       "mailbox/photo/")
MQTT_ACCESS_TOPIC       = "mailbox/access"
MQTT_DECISION_TOPIC     = "mailbox/decision"
MQTT_NONCE_RESP_TOPIC   = "perimeter/nonce_response"
MQTT_RETRY_DELAY_SECONDS = int(os.environ.get("MQTT_RETRY_DELAY_SECONDS", "5"))

GRACE_PERIOD_SECONDS = int(os.environ.get("GRACE_PERIOD_SECONDS", "10"))
BLOCK_THRESHOLD  = float(os.environ.get("BLOCK_THRESHOLD",  "50"))
MAX_TRUST_SCORE  = float(os.environ.get("MAX_TRUST_SCORE",  "100"))
MIN_TRUST_SCORE  = float(os.environ.get("MIN_TRUST_SCORE",  "0"))
EXPECTED_IPD_MS  = int(os.environ.get("EXPECTED_IPD_MS",   "5000"))

# ── Access-control config ─────────────────────────────────────────────────────
HMAC_SECRET_KEY   = os.environ.get("HMAC_SECRET_KEY",   "b3962f909a1507407466c4c962711d6d6f8ed9c98064e56592f31a13d6b035b9").encode()
TELEGRAM_TOKEN    = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID  = os.environ.get("TELEGRAM_CHAT_ID",  "")
NONCE_EXPIRY_SEC  = 60
FPGA_THRESHOLD_US = int(os.environ.get("FPGA_THRESHOLD_US", "10"))

USERS_FILE = os.path.join(_PROJECT_ROOT, "authorized_users.json")
LOG_FILE   = os.path.join(_PROJECT_ROOT, "access_log.json")
PHOTO_DIR  = os.path.join(_PROJECT_ROOT, "photos")
os.makedirs(PHOTO_DIR, exist_ok=True)

# ── Access-control runtime state ──────────────────────────────────────────────
_used_nonces    = {}   # {nonce_int: timestamp_float}
_pending_photos = {}   # {uid_str: bytes}  — buffered until payload arrives
_pending_deny   = {}   # {uid_str: dict}   — awaiting photo before final log+alert


def clamp(value, lower=MIN_TRUST_SCORE, upper=MAX_TRUST_SCORE):
    return max(lower, min(upper, float(value)))


# ═════════════════════════════════════════════════════════════════════════════
# 🔐 ACCESS CONTROL — card-payload validation
# ═════════════════════════════════════════════════════════════════════════════

def _load_users() -> dict:
    """Load authorized_users.json, returning empty dict on any error."""
    if not os.path.exists(USERS_FILE):
        print(f"[⚠️  DB  ] {USERS_FILE} not found — no users authorised.")
        return {}
    try:
        with open(USERS_FILE) as f:
            return json.load(f)
    except Exception as exc:
        print(f"[⚠️  DB  ] Failed to load users file: {exc}")
        return {}


def _purge_nonces():
    """Remove nonces older than NONCE_EXPIRY_SEC to prevent unbounded growth."""
    cutoff = time.time() - NONCE_EXPIRY_SEC
    expired = [n for n, t in _used_nonces.items() if t < cutoff]
    for n in expired:
        del _used_nonces[n]


def _verify_hmac(payload_str: str, received_sig: str, nonce: int):
    """
    Returns (is_valid: bool, reason: str).

    IMPORTANT — key ordering note:
    The ESP32 (ArduinoJson) serialises keys in insertion order, NOT sorted.
    We therefore verify against the *raw received JSON string* with the "sig"
    field stripped, not a re-serialised copy.  The Pi side must NOT re-encode
    the dict (which would sort keys) before computing the expected HMAC.
    """
    _purge_nonces()
    if nonce in _used_nonces:
        return False, "REPLAY_ATTACK"
    expected = hmac_lib.new(HMAC_SECRET_KEY,
                            payload_str.encode(),
                            hashlib.sha256).hexdigest()[:32]
    if hmac_lib.compare_digest(expected, received_sig.lower()):
        _used_nonces[nonce] = time.time()
        return True, "OK"
    return False, "HMAC_MISMATCH"


def _log_access(uid: str, name: str, gender: str,
                decision: str, reason: str, photo_path: str = ""):
    """Append one entry to access_log.json (create file if absent)."""
    entry = {
        "timestamp":  datetime.datetime.now().isoformat(),
        "uid":        uid,
        "name":       name,
        "gender":     gender,
        "decision":   decision,
        "reason":     reason,
        "photo_path": photo_path,
    }
    log = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE) as f:
                log = json.load(f)
        except Exception:
            log = []
    log.append(entry)
    try:
        with open(LOG_FILE, "w") as f:
            json.dump(log, f, indent=2)
    except Exception as exc:
        print(f"[⚠️  LOG ] Write failed: {exc}")
    print(f" [ 📋 LOG ] {decision} | {name} ({uid}) | {reason}")


def _save_photo(uid: str, photo_bytes: bytes) -> str:
    """Write buffered JPEG to photos/ and return the saved path."""
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(PHOTO_DIR, f"{uid}_{ts}.jpg")
    try:
        with open(filename, "wb") as f:
            f.write(photo_bytes)
        print(f" [ 📸 CAM ] Photo saved: {filename}")
    except Exception as exc:
        print(f"[⚠️  CAM ] Photo save failed: {exc}")
        return ""
    return filename


def _send_telegram_deny(name: str, uid: str, gender: str,
                        secret_code: str, reason: str, photo_path: str = ""):
    """Fire-and-forget Telegram deny alert (runs in daemon thread)."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print(" [ ⚠️  TG  ] No Telegram credentials — alert skipped.")
        return
    if _requests is None:
        print(" [ ⚠️  TG  ] requests library not installed — alert skipped.")
        return

    ts      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    caption = (
        f"🚨 *ACCESS DENIED*\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"🕐 Time:   `{ts}`\n"
        f"🆔 UID:    `{uid}`\n"
        f"👤 Name:   `{name}`\n"
        f"⚧ Gender: `{gender}`\n"
        f"🔑 Code:   `{secret_code}`\n"
        f"❌ Reason: `{reason}`\n"
        f"━━━━━━━━━━━━━━━━"
    )

    def _send():
        base = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}"
        try:
            if photo_path and os.path.exists(photo_path):
                with open(photo_path, "rb") as img:
                    resp = _requests.post(
                        f"{base}/sendPhoto",
                        data={"chat_id": TELEGRAM_CHAT_ID,
                              "caption": caption, "parse_mode": "Markdown"},
                        files={"photo": img}, timeout=10)
            else:
                resp = _requests.post(
                    f"{base}/sendMessage",
                    json={"chat_id": TELEGRAM_CHAT_ID,
                          "text": caption, "parse_mode": "Markdown"},
                    timeout=10)
            if resp.status_code == 200:
                print(" [ ✅  TG  ] Telegram deny alert sent.")
            else:
                print(f" [ ❌  TG  ] Telegram error: {resp.text[:200]}")
        except Exception as exc:
            print(f" [ ❌  TG  ] Exception: {exc}")

    threading.Thread(target=_send, daemon=True).start()


def _grant(mqtt_client, uid: str, name: str, gender: str):
    ts         = datetime.datetime.now().isoformat()
    photo_path = ""
    if uid in _pending_photos:
        photo_path = _save_photo(uid, _pending_photos.pop(uid))
    decision_payload = json.dumps(
        {"decision": "GRANT", "uid": uid, "name": name, "timestamp": ts})
    mqtt_client.publish(MQTT_DECISION_TOPIC, decision_payload)
    _log_access(uid, name, gender, "GRANT", "ALL_OK", photo_path)
    print(f"\n ✅ GRANTED → {name} ({uid}) at {ts}\n")


def _deny(mqtt_client, uid: str, name: str,
          gender: str, secret_code: str, reason: str):
    ts = datetime.datetime.now().isoformat()

    # 1. Send DENY decision to ESP32 immediately (fast response)
    decision_payload = json.dumps(
        {"decision": "DENY", "uid": uid, "reason": reason, "timestamp": ts})
    mqtt_client.publish(MQTT_DECISION_TOPIC, decision_payload)

    # 2. Trigger ESP32-CAM to capture intruder photo (non-blocking)
    photo_request = json.dumps({"uid": uid, "reason": reason, "timestamp": ts})
    mqtt_client.publish("mailbox/photo_request", photo_request)
    print(f" [ \U0001f4f8 CAM ] Photo request sent for UID: {uid}")

    # 3. Store deny context so photo handler can complete logging + Telegram
    _pending_deny[uid] = {
        "name": name, "gender": gender,
        "secret_code": secret_code, "reason": reason, "ts": ts
    }

    # 4. Fallback thread: if no photo arrives in 5s, log and alert without it
    def _fallback():
        import time as _t
        _t.sleep(5)
        if uid not in _pending_deny:
            return   # photo already handled
        deny_info = _pending_deny.pop(uid)
        photo_path = ""
        if uid in _pending_photos:
            photo_path = _save_photo(uid, _pending_photos.pop(uid))
        _log_access(uid, deny_info["name"], deny_info["gender"],
                    "DENY", deny_info["reason"], photo_path)
        _send_telegram_deny(deny_info["name"], uid, deny_info["gender"],
                            deny_info["secret_code"], deny_info["reason"], photo_path)
        print(f" [ \u23f0 ] Deny fallback complete for {uid} (no camera photo)")

    threading.Thread(target=_fallback, daemon=True).start()
    print(f"\n \u274c DENIED  \u2192 {name} ({uid}) | {reason}\n")


def process_access_payload(data: dict, mqtt_client):
    """
    Validate a card-tap payload from the ESP32 and publish GRANT or DENY.

    Pipeline:
      1. Extract fields from payload dict.
      2. Reconstruct the raw JSON string (without "sig") that the ESP32 signed.
         We use the raw_payload_str if provided (preserves key order), else fall
         back to re-serialising without sig (works only if order matches).
      3. HMAC-SHA256 verify.
      4. Replay-nonce check.
      5. UID lookup in authorized_users.json.
      6. Name / gender / secret_code comparison.
      7. GRANT or DENY.
    """
    uid          = str(data.get("uid",         ""))
    name         = str(data.get("name",        ""))
    gender       = str(data.get("gender",      ""))
    secret_code  = str(data.get("secret_code", ""))
    nonce        = int(data.get("nonce",       0))
    received_sig = str(data.get("sig",         ""))
    # raw_json_no_sig is set by the caller if it preserved the original bytes
    raw_payload_str = data.pop("_raw_no_sig", None)

    if raw_payload_str is None:
        # Fallback: re-serialise without sig (key order may differ on older firmware)
        payload_copy    = {k: v for k, v in data.items() if k != "sig"}
        raw_payload_str = json.dumps(payload_copy, separators=(',', ':'))

    # 1. HMAC check
    hmac_ok, hmac_reason = _verify_hmac(raw_payload_str, received_sig, nonce)
    if not hmac_ok:
        print(f" [ 🚨 SEC ] HMAC fail: {hmac_reason} | UID: {uid}")
        _deny(mqtt_client, uid, name, gender, secret_code, hmac_reason)
        return

    # 2. User DB lookup
    users = _load_users()
    # Skip _README meta-key
    if uid not in users or uid == "_README":
        _deny(mqtt_client, uid, name, gender, secret_code, "UID_NOT_REGISTERED")
        return

    expected = users[uid]

    # 3. Field validation (case-insensitive for name and gender)
    errors = []
    if name.strip().lower() != expected.get("name", "").strip().lower():
        errors.append("NAME_MISMATCH")
    if gender.upper() != expected.get("gender", "").upper():
        errors.append("GENDER_MISMATCH")
    if secret_code != expected.get("secret_code", ""):
        errors.append("CODE_MISMATCH")

    if errors:
        _deny(mqtt_client, uid, name, gender, secret_code, "+".join(errors))
        return

    _grant(mqtt_client, uid, name, gender)


def init_db():
    """Initialize database with required tables."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Heartbeat table (for ML training)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS heartbeats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                temperature REAL,
                humidity REAL,
                rssi INTEGER,
                free_heap INTEGER,
                inter_packet_delay INTEGER,
                packet_size INTEGER,
                received_at REAL NOT NULL,
                is_legitimate INTEGER DEFAULT 1
            )
            """
        )

        # Evidence table (for blockchain reference)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                filename TEXT,
                image_hash TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                blockchain_tx TEXT,
                verified BOOLEAN DEFAULT 0
            )
            """
        )

        # Alerts table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                details TEXT
            )
            """
        )

        # Device Status table (for LWT/reconnect tracking)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS device_status (
                device_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                last_seen REAL NOT NULL,
                grace_period_until REAL DEFAULT 0,
                trust_score REAL NOT NULL DEFAULT 100,
                last_rssi INTEGER,
                last_ipd INTEGER,
                last_transition REAL DEFAULT 0,
                status_source TEXT DEFAULT 'bootstrap',
                connection_state TEXT DEFAULT 'UNKNOWN',
                last_event TEXT DEFAULT ''
            )
            """
        )

        # Lightweight migrations for older databases.
        ensure_column(cursor, "device_status", "trust_score", "REAL NOT NULL DEFAULT 100")
        ensure_column(cursor, "device_status", "last_rssi", "INTEGER")
        ensure_column(cursor, "device_status", "last_ipd", "INTEGER")
        ensure_column(cursor, "device_status", "last_transition", "REAL DEFAULT 0")
        ensure_column(cursor, "device_status", "status_source", "TEXT DEFAULT 'bootstrap'")
        ensure_column(cursor, "device_status", "connection_state", "TEXT DEFAULT 'UNKNOWN'")
        ensure_column(cursor, "device_status", "last_event", "TEXT DEFAULT ''")

    print("Database initialized:", DB_PATH)


def ensure_column(cursor, table_name, column_name, column_definition):
    """Add a missing column without forcing a destructive schema reset."""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = {row[1] for row in cursor.fetchall()}

    if column_name not in columns:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")


def get_device_status(device_id):
    """Return the latest device status row, or a default in-memory shape."""
    default_state = {
        "device_id": device_id,
        "status": "UNKNOWN",
        "last_seen": 0.0,
        "grace_period_until": 0.0,
        "trust_score": MAX_TRUST_SCORE,
        "last_rssi": None,
        "last_ipd": None,
        "last_transition": 0.0,
        "status_source": "bootstrap",
        "connection_state": "UNKNOWN",
        "last_event": "",
    }

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT device_id, status, last_seen, grace_period_until, trust_score,
                   last_rssi, last_ipd, last_transition, status_source,
                   connection_state, last_event
            FROM device_status
            WHERE device_id = ?
            """,
            (device_id,),
        ).fetchone()

    if row is None:
        return default_state

    state = dict(row)
    for key, value in default_state.items():
        state.setdefault(key, value)
    return state


def save_device_status(
    device_id,
    *,
    status,
    last_seen,
    grace_period_until,
    trust_score,
    last_rssi,
    last_ipd,
    last_transition,
    status_source,
    connection_state,
    last_event,
):
    """Persist the device status row."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO device_status (
                device_id, status, last_seen, grace_period_until, trust_score,
                last_rssi, last_ipd, last_transition, status_source,
                connection_state, last_event
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                status = excluded.status,
                last_seen = excluded.last_seen,
                grace_period_until = excluded.grace_period_until,
                trust_score = excluded.trust_score,
                last_rssi = excluded.last_rssi,
                last_ipd = excluded.last_ipd,
                last_transition = excluded.last_transition,
                status_source = excluded.status_source,
                connection_state = excluded.connection_state,
                last_event = excluded.last_event
            """,
            (
                device_id,
                status,
                last_seen,
                grace_period_until,
                trust_score,
                last_rssi,
                last_ipd,
                last_transition,
                status_source,
                connection_state,
                last_event,
            ),
        )
        conn.commit()


def parse_json_or_text(payload):
    """Accept plain strings ('ONLINE') or JSON status packets."""
    if payload is None:
        return {}

    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")

    if isinstance(payload, dict):
        return payload

    text = str(payload).strip()
    if not text:
        return {}

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"status": text.upper()}

    if isinstance(data, dict):
        return data

    if isinstance(data, str):
        return {"status": data.upper()}

    return {}


def normalize_status(value):
    if value is None:
        return ""
    return str(value).strip().upper()


def score_heartbeat(inter_packet_delay, rssi):
    """
    Higher scores mean more trust.

    This intentionally penalizes too-fast IPDs much more aggressively than long
    delays, because spoofing usually looks like overlapping traffic, not lag.
    """
    if inter_packet_delay is None:
        return 0.0, "WARNING", "Missing inter-packet delay"

    try:
        ipd = float(inter_packet_delay)
    except (TypeError, ValueError):
        return 0.0, "WARNING", "Invalid inter-packet delay"

    try:
        signal = int(rssi)
    except (TypeError, ValueError):
        signal = -100

    perfect_window_low = EXPECTED_IPD_MS - 500
    perfect_window_high = EXPECTED_IPD_MS + 500

    if ipd < 1000:
        penalty = -40.0 if signal >= -60 else -30.0
        return penalty, "REJECTED", "Timing far too fast for a normal heartbeat"

    if ipd < 4000:
        if signal <= -75:
            return -5.0, "WARNING", "Early packet softened by weak RSSI"
        return -25.0, "WARNING", "Early packet is spoofing-like"

    if perfect_window_low <= ipd <= perfect_window_high:
        return 5.0, "AUTHENTICATED", "Heartbeat matches the expected cadence"

    if ipd <= 9000:
        if signal <= -75:
            return 0.0, "AUTHENTICATED", "Delayed packet forgiven because RSSI is weak"
        return -10.0, "WARNING", "Delayed packet on a strong link"

    if signal <= -75:
        return 0.0, "AUTHENTICATED", "Long delay but weak RSSI suggests network jitter"

    return -15.0, "WARNING", "Unexpected long delay on a strong link"


def evaluate_heartbeat(data):
    """
    Convert raw heartbeat data into a trust decision and a persisted status row.
    """
    current_time = time.time()
    device_id = data.get("device_id")

    if not device_id:
        return {
            "status": "REJECTED",
            "confidence": 0.0,
            "message": "Missing device_id",
            "trust_score": 0.0,
            "grace_period_until": 0.0,
        }, 400, None

    try:
        rssi = int(data.get("rssi", -100))
    except (TypeError, ValueError):
        rssi = -100

    try:
        inter_packet_delay = int(data.get("inter_packet_delay", 0))
    except (TypeError, ValueError):
        inter_packet_delay = 0

    try:
        packet_timestamp = int(data.get("timestamp", 0))
    except (TypeError, ValueError):
        packet_timestamp = 0

    try:
        temperature = data.get("temperature")
        humidity = data.get("humidity")
        free_heap = data.get("free_heap")
        packet_size = data.get("packet_size")
    except Exception:  # pragma: no cover - defensive guard for malformed payloads
        temperature = None
        humidity = None
        free_heap = None
        packet_size = None

    connection_state = normalize_status(
        data.get("connection_state")
        or data.get("boot_state")
        or data.get("reconnect_state")
    )

    current_state = get_device_status(device_id)
    trust_score = float(current_state["trust_score"])
    grace_period_until = float(current_state["grace_period_until"] or 0.0)
    status = normalize_status(current_state["status"]) or "UNKNOWN"

    if connection_state in {"BOOT", "RECONNECTED", "RECONNECT", "FRESH_CONNECTION"}:
        grace_period_until = current_time + GRACE_PERIOD_SECONDS
        status = "ONLINE"
        current_state["status"] = "ONLINE"
        current_state["grace_period_until"] = grace_period_until

    if current_state["status"] == "OFFLINE":
        # Trust is frozen while the device is offline. Do not decay it on stale
        # or missing packets. A reconnect status will re-open the grace period.
        if current_time < grace_period_until or connection_state in {
            "BOOT",
            "RECONNECTED",
            "RECONNECT",
            "FRESH_CONNECTION",
        }:
            status = "ONLINE"
        else:
            return persist_heartbeat_result(
                device_id=device_id,
                current_time=current_time,
                rssi=rssi,
                inter_packet_delay=inter_packet_delay,
                packet_timestamp=packet_timestamp,
                temperature=temperature,
                humidity=humidity,
                free_heap=free_heap,
                packet_size=packet_size,
                trust_score=trust_score,
                status="OFFLINE",
                confidence=100.0,
                message="Device is offline; trust is frozen until reconnect",
                grace_period_until=grace_period_until,
                connection_state=connection_state or current_state["connection_state"],
                status_source="heartbeat",
                last_event="offline_frozen",
            ), 200, current_state

    if current_time < grace_period_until:
        trust_score = clamp(trust_score)
        return persist_heartbeat_result(
            device_id=device_id,
            current_time=current_time,
            rssi=rssi,
            inter_packet_delay=inter_packet_delay,
            packet_timestamp=packet_timestamp,
            temperature=temperature,
            humidity=humidity,
            free_heap=free_heap,
            packet_size=packet_size,
            trust_score=trust_score,
            status="AUTHENTICATED",
            confidence=100.0,
            message="Reconnect grace period active",
            grace_period_until=grace_period_until,
            connection_state=connection_state or current_state["connection_state"],
            status_source="heartbeat",
            last_event="grace_period",
        ), 200, current_state

    delta, classification, reason = score_heartbeat(inter_packet_delay, rssi)
    trust_score = clamp(trust_score + delta)

    if trust_score < BLOCK_THRESHOLD:
        final_status = "REJECTED"
        confidence = trust_score
        message = "Trust score fell below the block threshold"
    elif classification == "WARNING":
        final_status = "WARNING"
        confidence = trust_score
        message = reason
    else:
        final_status = "AUTHENTICATED"
        confidence = trust_score
        message = reason

    return persist_heartbeat_result(
        device_id=device_id,
        current_time=current_time,
        rssi=rssi,
        inter_packet_delay=inter_packet_delay,
        packet_timestamp=packet_timestamp,
        temperature=temperature,
        humidity=humidity,
        free_heap=free_heap,
        packet_size=packet_size,
        trust_score=trust_score,
        status=final_status,
        confidence=confidence,
        message=message,
        grace_period_until=grace_period_until,
        connection_state=connection_state or current_state["connection_state"],
        status_source="heartbeat",
        last_event=f"ipd_delta={delta}",
    ), 403 if final_status == "REJECTED" else 200, current_state


def persist_heartbeat_result(
    *,
    device_id,
    current_time,
    rssi,
    inter_packet_delay,
    packet_timestamp,
    temperature,
    humidity,
    free_heap,
    packet_size,
    trust_score,
    status,
    confidence,
    message,
    grace_period_until,
    connection_state,
    status_source,
    last_event,
):
    """Store both the heartbeat row and the device status snapshot."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO heartbeats
            (device_id, timestamp, temperature, humidity, rssi, free_heap,
             inter_packet_delay, packet_size, received_at, is_legitimate)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                packet_timestamp if packet_timestamp else int(current_time * 1000),
                temperature,
                humidity,
                rssi,
                free_heap,
                inter_packet_delay,
                packet_size,
                current_time,
                1 if status != "REJECTED" else 0,
            ),
        )

        cursor.execute(
            """
            INSERT INTO device_status (
                device_id, status, last_seen, grace_period_until, trust_score,
                last_rssi, last_ipd, last_transition, status_source,
                connection_state, last_event
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                status = excluded.status,
                last_seen = excluded.last_seen,
                grace_period_until = excluded.grace_period_until,
                trust_score = excluded.trust_score,
                last_rssi = excluded.last_rssi,
                last_ipd = excluded.last_ipd,
                last_transition = excluded.last_transition,
                status_source = excluded.status_source,
                connection_state = excluded.connection_state,
                last_event = excluded.last_event
            """,
            (
                device_id,
                status,
                current_time,
                grace_period_until,
                trust_score,
                rssi,
                inter_packet_delay,
                current_time,
                status_source,
                connection_state,
                last_event,
            ),
        )

        conn.commit()

    try:
        from pi_backend.forensic_logger import log_access_attempt
        log_access_attempt(
            device_id=device_id,
            result=status,
            reason=message,
            trust_score=trust_score,
            db_path=DB_PATH,
        )
    except Exception as exc:  # pragma: no cover - logging must not block auth
        print(f"[VERIFY] Forensic log skipped: {exc}")

    print(
        f"[VERIFY] {status} | {device_id} | IPD: {inter_packet_delay}ms | "
        f"RSSI: {rssi}dBm | Trust: {trust_score:.1f}"
    )

    return jsonify(
        {
            "status": status,
            "confidence": confidence,
            "message": message,
            "trust_score": trust_score,
            "grace_period_until": grace_period_until,
            "block_threshold": BLOCK_THRESHOLD,
        }
    )


def handle_status_message(topic, payload, retained=False):
    """Process retained MQTT status updates and broker LWT events."""
    data = parse_json_or_text(payload)
    current_time = time.time()

    device_id = data.get("device_id") or os.environ.get("DEFAULT_DEVICE_ID", "")
    if not device_id:
        print(f"[STATUS] Ignored {topic}: missing device_id")
        return

    status_value = normalize_status(
        data.get("status") or data.get("state") or data.get("message")
    )
    connection_state = normalize_status(
        data.get("connection_state")
        or data.get("boot_state")
        or data.get("reconnect_state")
        or data.get("reason")
    )

    current_state = get_device_status(device_id)
    trust_score = float(current_state["trust_score"])
    grace_period_until = float(current_state["grace_period_until"] or 0.0)
    last_event = f"mqtt:{status_value or 'UNKNOWN'}"

    if status_value == "OFFLINE":
        grace_period_until = 0.0
    elif status_value == "ONLINE":
        transitioned = normalize_status(current_state["status"]) != "ONLINE"
        bootlike = connection_state in {
            "BOOT",
            "RECONNECTED",
            "RECONNECT",
            "REBOOT",
            "FRESH_CONNECTION",
            "BROKER_WILL",
        }
        if transitioned or bootlike or retained:
            grace_period_until = current_time + GRACE_PERIOD_SECONDS
            last_event = "mqtt_online_grace"

    save_device_status(
        device_id,
        status=status_value or "UNKNOWN",
        last_seen=current_time,
        grace_period_until=grace_period_until,
        trust_score=trust_score,
        last_rssi=current_state["last_rssi"],
        last_ipd=current_state["last_ipd"],
        last_transition=current_time,
        status_source="mqtt",
        connection_state=connection_state or current_state["connection_state"],
        last_event=last_event,
    )

    print(
        f"[STATUS] {device_id} -> {status_value or 'UNKNOWN'} "
        f"(grace until {grace_period_until:.1f})"
    )


def handle_heartbeat_message(topic, payload):
    """Score an MQTT heartbeat payload through the same engine as /verify."""
    data = parse_json_or_text(payload)
    if not data.get("device_id"):
        print(f"[HEARTBEAT] Ignored {topic}: missing device_id")
        return None, 400

    with app.app_context():
        response, http_code, _ = evaluate_heartbeat(data)

    body = response.get_json()
    print(
        f"[HEARTBEAT] MQTT scored {data.get('device_id')} -> "
        f"{body.get('status')} ({http_code})"
    )
    return body, http_code


def handle_environment_message(topic, payload):
    """Persist MQTT environment readings for dashboard consumption."""
    data = parse_json_or_text(payload)
    device_id = data.get("device_id") or "PI_DHT22"
    temperature = data.get("temperature")
    humidity = data.get("humidity")

    if temperature is None and humidity is None:
        print(f"[ENV] Ignored {topic}: missing temperature/humidity")
        return

    now = time.time()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO heartbeats (
                device_id, timestamp, temperature, humidity, rssi, free_heap,
                inter_packet_delay, packet_size, received_at, is_legitimate
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                int(now),
                temperature,
                humidity,
                data.get("rssi"),
                data.get("free_heap"),
                data.get("inter_packet_delay"),
                data.get("packet_size"),
                now,
                1,
            ),
        )
        conn.commit()

    print(f"[ENV] Stored reading from {device_id}: T={temperature} H={humidity}")


def handle_photo_message(topic, payload):
    """Persist the latest ESP32-CAM JPEG from mailbox/photo/<device_id>."""
    if not topic.startswith(MQTT_PHOTO_PREFIX):
        return

    device_id = topic[len(MQTT_PHOTO_PREFIX):] or "unknown"
    try:
        from pi_backend.photo_store import store_device_photo
        path = store_device_photo(device_id, bytes(payload))
        print(f"[PHOTO] Stored latest image for {device_id}: {path}")
    except Exception as exc:
        print(f"[PHOTO] Store failed for {device_id}: {exc}")


def on_mqtt_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        subscriptions = (
            (MQTT_STATUS_TOPIC,       1),
            (MQTT_HEARTBEAT_TOPIC,    1),
            (MQTT_ENVIRONMENT_TOPIC,  0),
            (f"{MQTT_PHOTO_PREFIX}+/+", 0),  # burst: mailbox/photo/<uid>/<index>
            (MQTT_ACCESS_TOPIC,       1),   # card-tap payloads from ESP32
            (MQTT_NONCE_RESP_TOPIC,   0),   # anti-FPGA puzzle responses
        )
        print("Connected to MQTT broker. Subscribing to telemetry topics.")
        for topic, qos in subscriptions:
            client.subscribe(topic, qos=qos)
            print(f"  subscribed: {topic}")
    else:
        print(f"Failed to connect to MQTT broker. Code: {reason_code}")


def handle_access_message(topic, payload, mqtt_client):
    """Validate a card-tap payload and publish GRANT/DENY to the ESP32."""
    try:
        raw_str = payload.decode() if isinstance(payload, bytes) else payload
        data    = json.loads(raw_str)
        if not isinstance(data, dict):
            raise ValueError("payload is not a JSON object")
        # Preserve the raw JSON string (without "sig") so HMAC uses original
        # key order (ArduinoJson inserts in code order, NOT alphabetically).
        sig = data.get("sig", "")
        # Strip sig from raw string rather than re-serialising the dict
        raw_no_sig = raw_str
        for suffix in (f',"sig":"{sig}"', f',"sig": "{sig}"',
                       f'"sig":"{sig}",',  f'"sig": "{sig}",'):
            if suffix in raw_no_sig:
                raw_no_sig = raw_no_sig.replace(suffix, "", 1)
                break
        data["_raw_no_sig"] = raw_no_sig.strip()
        process_access_payload(data, mqtt_client)
    except Exception as exc:
        print(f" [ ❌ ACC ] Parse/process error: {exc}")


def handle_nonce_response_message(topic, payload):
    """Log FPGA puzzle solve times; flag suspiciously fast responses."""
    try:
        data     = json.loads(payload.decode() if isinstance(payload, bytes) else payload)
        solve_us = int(data.get("solve_time_us", 9999))
        dev_id   = data.get("device_id", "?")
        if solve_us < FPGA_THRESHOLD_US:
            print(f" [ 🚨 FPGA] {dev_id} solved in {solve_us}µs "
                  f"< threshold {FPGA_THRESHOLD_US}µs — possible FPGA clone!")
        else:
            print(f" [ ✅ CPU ] {dev_id} nonce solved in {solve_us}µs — hardware OK.")
    except Exception:
        pass


def on_mqtt_message(client, userdata, msg):
    if msg.topic == MQTT_STATUS_TOPIC:
        handle_status_message(msg.topic, msg.payload,
                              retained=getattr(msg, "retain", False))
    elif msg.topic == MQTT_HEARTBEAT_TOPIC:
        handle_heartbeat_message(msg.topic, msg.payload)
    elif msg.topic == MQTT_ENVIRONMENT_TOPIC:
        handle_environment_message(msg.topic, msg.payload)
    elif msg.topic.startswith(MQTT_PHOTO_PREFIX):
        # Topic format: mailbox/photo/<uid>/<shot_index>
        remainder  = msg.topic[len(MQTT_PHOTO_PREFIX):]   # "<uid>/<index>"
        parts      = remainder.rsplit("/", 1)
        uid        = parts[0] if parts else "unknown"
        shot_index = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else 0
        photo_bytes = bytes(msg.payload)

        if photo_bytes == b"NOCAMERA":
            print(f" [ \u26a0\ufe0f CAM ] No camera for UID: {uid}")
        else:
            print(f" [ \U0001f4f7 CAM ] Shot {shot_index} received for UID: {uid} ({len(photo_bytes)} bytes)")

        if uid in _pending_deny:
            deny_info  = _pending_deny[uid]
            photo_path = _save_photo(uid + f"_shot{shot_index}", photo_bytes)

            if shot_index == 0:
                # First photo: complete the deny log + send Telegram
                _pending_deny.pop(uid)
                _log_access(uid, deny_info["name"], deny_info["gender"],
                            "DENY", deny_info["reason"], photo_path)
                _send_telegram_deny(deny_info["name"], uid, deny_info["gender"],
                                    deny_info["secret_code"], deny_info["reason"], photo_path)
                print(f" [ \U0001f4f8 ] Shot 0 saved + Telegram sent: {photo_path}")
                # Re-register in recent_denies so shots 1-4 are also saved
                _pending_deny[f"{uid}_burst"] = deny_info
            else:
                # Subsequent shots: just save to disk (appear in dashboard gallery)
                _log_access(uid, deny_info.get("name", uid), deny_info.get("gender", ""),
                            "DENY", f"BURST_SHOT_{shot_index}", photo_path)
                print(f" [ \U0001f4f8 ] Shot {shot_index} saved: {photo_path}")
        else:
            # Buffer as heartbeat/device photo
            _pending_photos[uid] = photo_bytes
    elif msg.topic == MQTT_ACCESS_TOPIC:
        handle_access_message(msg.topic, msg.payload, client)
    elif msg.topic == MQTT_NONCE_RESP_TOPIC:
        handle_nonce_response_message(msg.topic, msg.payload)


def mqtt_status_listener():
    """Background MQTT loop that keeps the device status table up to date."""
    if mqtt is None:
        print("paho-mqtt is not installed; MQTT status listener disabled.")
        return

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_mqtt_connect
    client.on_message = on_mqtt_message

    while True:
        try:
            client.connect(MQTT_BROKER, MQTT_PORT, 60)
            client.loop_forever()
        except OSError as exc:
            print(f"MQTT status listener error: {exc}. Retrying in {MQTT_RETRY_DELAY_SECONDS}s")
            time.sleep(MQTT_RETRY_DELAY_SECONDS)


@app.route("/verify", methods=["POST"])
def verify_device():
    """
    Receives heartbeats from the ESP32 gateway.
    Uses status-aware forgiveness so WiFi outages do not look like spoofing.
    """
    data = request.get_json(silent=True) or {}
    result, http_code, _ = evaluate_heartbeat(data)
    return result, http_code


@app.route("/stats", methods=["GET"])
def get_stats():
    """Get system statistics."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM heartbeats")
        heartbeat_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM evidence")
        evidence_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT device_id) FROM heartbeats")
        device_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM device_status WHERE status = 'OFFLINE'")
        offline_count = cursor.fetchone()[0]

    return jsonify(
        {
            "heartbeats": heartbeat_count,
            "evidence": evidence_count,
            "devices": device_count,
            "offline_devices": offline_count,
        }
    )


def start_background_services():
    """Start the MQTT listener if available."""
    if mqtt is None:
        return

    thread = threading.Thread(target=mqtt_status_listener, daemon=True)
    thread.start()


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("IoT Telemetry Server - Zero-Trust Gateway")
    print("=" * 60)

    init_db()
    start_background_services()

    print("\nStarting Flask server on 0.0.0.0:5005")
    print("Endpoints:")
    print("   POST /verify - Receive heartbeats")
    print("   GET  /stats  - System statistics")
    print("\nServer ready. Waiting for ESP32 connections...\n")

    app.run(host="0.0.0.0", port=5005, debug=False)
