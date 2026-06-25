#!/usr/bin/env python3
"""
Telegram Alert Service
Listens to MQTT tamper events and sends formatted alerts to smartphone.
Integrates blockchain evidence logging and robust retry logic.
"""

import html
import json
import os
import socket
import sys
import time
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import paho.mqtt.client as mqtt

# ---------------------------------------------------------------------------
# PROJECT ROOT & CONFIG
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent  # Master_IoT_Project
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

try:
    from blockchain_bridge import register_event_on_chain
except ImportError as e:
    print(f"⚠️  blockchain_bridge not found: {e}. Blockchain logging disabled.")
    register_event_on_chain = None

# Thread pool for async blockchain logging
_chain_pool = ThreadPoolExecutor(max_workers=2)

# ---------------------------------------------------------------------------
# CONFIGURATION (use environment variables or update these defaults)
# ---------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID",   "")
MQTT_BROKER        = os.environ.get("MQTT_BROKER",         "127.0.0.1")
MQTT_PORT          = int(os.environ.get("MQTT_PORT",        "1883"))

TAMPER_TOPIC   = "gateway/tamper"
EVIDENCE_TOPIC = "mailbox/evidence" # Preserved from old system

# Dynamic IP for the dashboard link
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    DASHBOARD_IP = s.getsockname()[0]
    s.close()
except Exception:
    DASHBOARD_IP = os.environ.get("PI_LOCAL_IP", "10.238.130.161")

# ---------------------------------------------------------------------------
# TELEGRAM SENDER
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
                print("✅ Telegram alert sent successfully.")
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
    
    try:
        data = json.loads(raw)

        # --- Handle Tamper Alert ---
        if msg.topic == TAMPER_TOPIC:
            print(f"\n🚨 TAMPER ALERT RECEIVED!")
            print(f"Topic: {msg.topic}")
            print(f"Payload: {raw}")
            
            device = html.escape(str(data.get("device_id", "Unknown Device")))
            sensor = html.escape(str(data.get("sensor", "Unknown Sensor")))
            timestamp = data.get("timestamp", 0)
            
            alert_text = (
                "🚨 <b>ZERO-TRUST SECURITY ALERT</b> 🚨\n\n"
                f"<b>Device:</b> <code>{device}</code>\n"
                f"<b>Sensor:</b> <code>{sensor}</code>\n"
                "<b>Event:</b> Physical Tampering Detected\n"
                f"<b>Time:</b> {timestamp}ms since boot\n\n"
                "📸 <b>ESP32-CAM Sentry activated</b>\n"
                "⛓️ Evidence being logged to blockchain\n\n"
                "⚠️ <b>Check dashboard immediately!</b>\n"
                f"http://{DASHBOARD_IP}:5005"
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
                    if register_event_on_chain:
                        _chain_pool.submit(register_event_on_chain, event_name, score)
                    else:
                        print("⚠️  Blockchain logging skipped (module not available).")
                except ValueError:
                    print("⚠️  Invalid hash format.")

    except json.JSONDecodeError:
        print("⚠️  Invalid JSON format in MQTT message")
        if msg.topic == TAMPER_TOPIC:
            send_telegram_alert(
                f"🚨 <b>TAMPER ALERT</b>\nRaw payload: <code>{html.escape(raw)}</code>"
            )

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main() -> None:
    print("\n" + "="*60)
    print("📱 Telegram Alert Service - Zero-Trust Notifier")
    print("="*60)
    print(f"   Broker : {MQTT_BROKER}:{MQTT_PORT}")
    print(f"   Topics : {TAMPER_TOPIC}, {EVIDENCE_TOPIC}")
    print(f"   Dash IP: {DASHBOARD_IP}\n")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    print("🔌 Connecting to MQTT broker...")
    client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)

    print("✅ Service running. Waiting for tamper events...\n")
    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n🛑 Notifier stopped.")
        client.disconnect()

if __name__ == "__main__":
    main()
