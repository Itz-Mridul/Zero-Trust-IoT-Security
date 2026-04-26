"""
telegram_alert.py — Zero-Trust Telegram Notifier

Listens on MQTT for tamper alerts and forwards them to a Telegram chat.
Credentials are read from environment variables — NEVER hard-coded.

Set these before running:
    export TELEGRAM_BOT_TOKEN="your_bot_token_here"
    export TELEGRAM_CHAT_ID="your_chat_id_here"

Run: python3 telegram_alert.py
"""

import html
import json
import os
import time
import sys
from pathlib import Path

import requests
import paho.mqtt.client as mqtt

# ---------------------------------------------------------------------------
# PROJECT ROOT & CONFIG
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent  # Master_IoT_Project
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

import config
from blockchain_bridge import register_event_on_chain
from concurrent.futures import ThreadPoolExecutor

# Thread pool for async blockchain logging
_chain_pool = ThreadPoolExecutor(max_workers=2)

# ---------------------------------------------------------------------------
# CONFIGURATION (from config.py)
# ---------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = config.TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID   = config.TELEGRAM_CHAT_ID
MQTT_BROKER        = config.MQTT_BROKER
MQTT_PORT          = config.MQTT_PORT

TAMPER_TOPIC   = "mailbox/tamper"
EVIDENCE_TOPIC = "mailbox/evidence"

# ---------------------------------------------------------------------------
# TELEGRAM SENDER  (with retry / back-off)
# ---------------------------------------------------------------------------
_TELEGRAM_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"


def send_telegram_alert(message: str, retries: int = 3) -> None:
    """POST a Telegram message, retrying up to `retries` times on failure."""
    payload = {
        "chat_id"   : TELEGRAM_CHAT_ID,
        "text"      : message,
        "parse_mode": "HTML",
    }

    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(_TELEGRAM_URL, json=payload, timeout=10)
            if resp.status_code == 200:
                print("✅ Telegram alert sent.")
                return
            else:
                print(f"⚠️  Telegram rejected (attempt {attempt}): {resp.status_code} — {resp.text}")
        except requests.RequestException as exc:
            print(f"⚠️  Network error (attempt {attempt}): {exc}")

        if attempt < retries:
            time.sleep(2 ** attempt)   # exponential back-off: 2s, 4s

    print("❌ Telegram alert failed after all retries.")


# ---------------------------------------------------------------------------
# MQTT CALLBACKS
# ---------------------------------------------------------------------------
def on_connect(client, userdata, flags, reason_code, properties=None) -> None:
    if reason_code == 0:
        print(f"✅ Connected to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}")
        client.subscribe(TAMPER_TOPIC)
        client.subscribe(EVIDENCE_TOPIC)
        print(f"📡 Subscribed to: {TAMPER_TOPIC} and {EVIDENCE_TOPIC}")
    else:
        print(f"❌ MQTT connection failed. Code: {reason_code}")


def on_message(client, userdata, msg) -> None:
    raw = msg.payload.decode("utf-8", errors="replace")
    print(f"\n[ALERT] Topic: {msg.topic}")
    print(f"        Payload: {raw}")

    try:
        data = json.loads(raw)

        # --- Handle Tamper Alert ---
        if msg.topic == TAMPER_TOPIC:
            device = html.escape(str(data.get("device_id", "Unknown Device")))
            sensor = html.escape(str(data.get("sensor",    "Unknown Sensor")))
            rssi   = data.get("rssi", "N/A")

            alert_text = (
                "🚨 <b>ZERO-TRUST SECURITY ALERT</b> 🚨\n\n"
                f"<b>Device:</b> <code>{device}</code>\n"
                f"<b>Trigger:</b> Physical Tampering Detected\n"
                f"<b>Sensor:</b> <code>{sensor}</code>\n"
                f"<b>RSSI:</b> {rssi} dBm\n"
                "<b>Action:</b> Sentry Camera activated. Flash burst deployed.\n\n"
                "⚠️ <b>Check the Sentry Web GUI immediately!</b>"
            )
            send_telegram_alert(alert_text)

        # --- Handle Evidence Hash (Blockchain Logging) ---
        elif msg.topic == EVIDENCE_TOPIC:
            device = data.get("device_id", "Unknown")
            frame  = data.get("frame", "?")
            h_val  = data.get("hash", "")
            
            print(f"📸 Received Evidence: Frame {frame} | Hash {h_val[:10]}...")
            
            if h_val:
                # Convert first 8 hex chars of hash to an int for the blockchain score field
                try:
                    score = int(h_val[:8], 16)
                    event_name = f"EVIDENCE_F{frame}_{device}"
                    # Fire and forget to avoid blocking MQTT loop
                    _chain_pool.submit(register_event_on_chain, event_name, score)
                except ValueError:
                    print("⚠️  Invalid hash format.")

    except json.JSONDecodeError:
        print("⚠️  Non-JSON payload — sending raw alert.")
        if msg.topic == TAMPER_TOPIC:
            send_telegram_alert(
                f"🚨 <b>TAMPER ALERT</b>\nRaw payload: <code>{html.escape(raw)}</code>"
            )


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main() -> None:
    print("🚀 Booting Zero-Trust Telegram Notifier...")
    print(f"   Broker : {MQTT_BROKER}:{MQTT_PORT}")
    print(f"   Topics : {TAMPER_TOPIC}, {EVIDENCE_TOPIC}")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n🛑 Notifier stopped.")
        client.disconnect()


if __name__ == "__main__":
    main()
