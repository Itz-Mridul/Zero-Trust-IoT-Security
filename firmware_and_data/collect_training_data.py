"""
collect_training_data.py — ML Training Data Collector (MQTT listener)

Listens for heartbeat packets from ESP32 devices on the MQTT broker,
calculates Inter-Packet Delay (IPD), and stores everything in SQLite.

Run: python3 collect_training_data.py
Stop when you have 200+ samples (Ctrl+C).
"""

import json
import os
import sqlite3
import time
import paho.mqtt.client as mqtt

# ---------------------------------------------------------------------------
# PATHS  — resolved relative to THIS script
# ---------------------------------------------------------------------------
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))   # firmware_and_data/
IOT_ROOT     = os.path.dirname(BASE_DIR)                     # Master_IoT_Project/
DB_PATH = os.environ.get(
    "TRAINING_DB_PATH",
    os.path.join(IOT_ROOT, "training_data.db"),
)

# ---------------------------------------------------------------------------
# MQTT CONFIGURATION  (override via environment variables on the Pi)
# ---------------------------------------------------------------------------
MQTT_BROKER = os.environ.get("MQTT_BROKER", "127.0.0.1")
MQTT_PORT   = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_TOPIC  = os.environ.get("MQTT_TOPIC",  "gateway/heartbeat")


# ---------------------------------------------------------------------------
# DATABASE
# ---------------------------------------------------------------------------
def init_db() -> None:
    """Create the heartbeats table if it does not already exist."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS heartbeats (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id          TEXT,
                timestamp          INTEGER,
                temperature        REAL,
                humidity           REAL,
                rssi               INTEGER,
                free_heap          INTEGER,
                inter_packet_delay REAL,
                packet_size        INTEGER,
                received_at        REAL,
                is_legitimate      INTEGER
            )
            """
        )
        conn.commit()


# ---------------------------------------------------------------------------
# MQTT CALLBACKS
# ---------------------------------------------------------------------------
def on_connect(client, userdata, flags, reason_code, properties=None) -> None:
    if reason_code == 0:
        print("✅ Connected to MQTT broker. Ready for ML data collection...")
        client.subscribe(MQTT_TOPIC)
        print(f"📡 Subscribed to topic: {MQTT_TOPIC}")
    else:
        print(f"❌ Failed to connect to MQTT broker. Code: {reason_code}")


def on_message(client, userdata, msg) -> None:
    try:
        current_time = time.time()
        payload = msg.payload.decode("utf-8", errors="ignore")
        data = json.loads(payload)
        device_id = data.get("device_id", "unknown")

        with sqlite3.connect(DB_PATH, timeout=20) as conn:
            # Find the timestamp of the last packet from THIS device
            row = conn.execute(
                "SELECT received_at FROM heartbeats WHERE device_id = ? ORDER BY id DESC LIMIT 1",
                (device_id,),
            ).fetchone()

            # IPD in milliseconds (0.0 for the very first packet)
            actual_ipd = (current_time - row[0]) * 1000.0 if row else 0.0

            conn.execute(
                """
                INSERT INTO heartbeats (
                    device_id, timestamp, temperature, humidity, rssi,
                    free_heap, inter_packet_delay, packet_size, received_at, is_legitimate
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    data.get("timestamp"),
                    data.get("temperature"),
                    data.get("humidity"),
                    data.get("rssi"),
                    data.get("free_heap"),
                    actual_ipd,
                    len(msg.payload),   # raw network payload size
                    current_time,
                    1,                  # labelled as legitimate traffic
                ),
            )
            conn.commit()

        rssi_val = data.get("rssi", "N/A")
        print(f"📊 [COLLECTED] {device_id} | IPD: {actual_ipd:.1f} ms | RSSI: {rssi_val}")

    except json.JSONDecodeError:
        print("⚠️  Invalid JSON payload received.")
    except Exception as exc:
        print(f"⚠️  Error processing heartbeat: {exc}")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main() -> None:
    print(f"💾 Database : {DB_PATH}")
    print(f"📡 Broker   : {MQTT_BROKER}:{MQTT_PORT}")
    print(f"📬 Topic    : {MQTT_TOPIC}")
    print("⏳ Collecting data... Press Ctrl+C when you have 200+ samples.\n")

    init_db()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n🛑 Data collection stopped.")
        client.disconnect()


if __name__ == "__main__":
    main()
