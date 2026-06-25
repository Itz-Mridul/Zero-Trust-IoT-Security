#!/usr/bin/env python3
"""
collect_training_data.py — AI Model Training Data Collector
=============================================================
Subscribes to the MQTT heartbeat topic and records samples into
ml_models/training_data.db with is_legitimate labels.

Usage:
  # Collect LEGITIMATE samples (real ESP32 on the bench):
  python3 pi_backend/collect_training_data.py --label 1 --samples 200

  # Collect ATTACK/SPOOF samples (run spoofer.py on another terminal):
  python3 pi_backend/collect_training_data.py --label 0 --samples 200

Labels:
  1 = Legitimate real ESP32 hardware
  0 = Software spoof / attacker simulation

After collecting both classes, run:
  python3 ml_models/train_model.py
"""

import argparse
import json
import os
import sqlite3
import sys
import time

import paho.mqtt.client as mqtt

# ── Paths ────────────────────────────────────────────────────────────────────
_BASE  = os.path.dirname(os.path.abspath(__file__))
_ROOT  = os.path.dirname(_BASE)
DB_PATH = os.path.join(_ROOT, "ml_models", "training_data.db")

MQTT_BROKER = os.environ.get("MQTT_BROKER", "localhost")
MQTT_PORT   = int(os.environ.get("MQTT_PORT", "1883"))
HB_TOPIC    = "perimeter/heartbeat"

FEATS = ["rssi", "packet_size", "free_heap", "inter_packet_delay", "temperature", "humidity"]

# ── DB setup ──────────────────────────────────────────────────────────────────

def _ensure_db(db_path: str) -> None:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS heartbeats (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id        TEXT    NOT NULL,
                rssi             REAL,
                packet_size      REAL,
                free_heap        REAL,
                inter_packet_delay REAL,
                temperature      REAL,
                humidity         REAL,
                is_legitimate    INTEGER NOT NULL,
                received_at      INTEGER NOT NULL
            )
        """)


def _save_sample(conn: sqlite3.Connection, data: dict, label: int) -> None:
    conn.execute(
        "INSERT INTO heartbeats "
        "(device_id, rssi, packet_size, free_heap, inter_packet_delay, "
        " temperature, humidity, is_legitimate, received_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (
            data.get("device_id", "unknown"),
            float(data.get("rssi") or -100),
            float(data.get("packet_size") or 0),
            float(data.get("free_heap") or 0),
            float(data.get("inter_packet_delay") or 0),
            float(data.get("temperature") or 25.0),
            float(data.get("humidity") or 50.0),
            label,
            int(time.time()),
        )
    )
    conn.commit()


# ── Collector ─────────────────────────────────────────────────────────────────

class DataCollector:
    def __init__(self, label: int, target: int, db_path: str) -> None:
        self.label    = label
        self.target   = target
        self.db_path  = db_path
        self.count    = 0
        self._conn    = sqlite3.connect(db_path)
        self._done    = False

    def on_connect(self, client, userdata, flags, rc, properties=None):
        lname = "LEGITIMATE" if self.label == 1 else "SPOOF/ATTACK"
        print(f"✅ Connected — collecting {self.target} {lname} samples from {HB_TOPIC}")
        client.subscribe(HB_TOPIC)

    def on_message(self, client, userdata, msg):
        if self._done:
            return
        try:
            data = json.loads(msg.payload.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        _save_sample(self._conn, data, self.label)
        self.count += 1
        pct = (self.count / self.target) * 100
        print(f"  [{self.count:4d}/{self.target}] ({pct:5.1f}%)  "
              f"device={data.get('device_id','?')}  rssi={data.get('rssi','?')}  "
              f"ipd={data.get('inter_packet_delay','?')}")

        if self.count >= self.target:
            self._done = True
            print(f"\n✅ Collected {self.count} samples → {self.db_path}")
            client.disconnect()

    def run(self) -> None:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.on_connect = self.on_connect
        client.on_message = self.on_message
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        client.loop_forever()
        self._conn.close()


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect MQTT heartbeat samples for AI model training"
    )
    parser.add_argument("--label", type=int, required=True, choices=[0, 1],
                        help="1=legitimate, 0=spoof/attack")
    parser.add_argument("--samples", type=int, default=200,
                        help="Number of samples to collect (default: 200)")
    parser.add_argument("--db", default=DB_PATH,
                        help=f"Output DB path (default: {DB_PATH})")
    args = parser.parse_args()

    _ensure_db(args.db)
    lname = "LEGITIMATE (real ESP32)" if args.label == 1 else "ATTACK/SPOOF (simulated)"
    print(f"\n🎯 Collecting {args.samples} {lname} samples")
    print(f"   DB: {args.db}")
    print(f"   Broker: {MQTT_BROKER}:{MQTT_PORT}  Topic: {HB_TOPIC}\n")
    print("   Tip: If collecting spoof data, run gateway_logic/spoofer.py in another terminal\n")

    collector = DataCollector(label=args.label, target=args.samples, db_path=args.db)
    collector.run()

    print(f"\n📊 Next steps:")
    if args.label == 1:
        print(f"  1. Collect attack data:  python3 pi_backend/collect_training_data.py --label 0 --samples {args.samples}")
    else:
        print(f"  1. Train the model:  python3 ml_models/train_model.py")


if __name__ == "__main__":
    main()
