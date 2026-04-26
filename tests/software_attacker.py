#!/usr/bin/env python3
"""
Software Attacker — Generates synthetic attack data for CNN-LSTM training.

Simulates a software-based attacker sending spoofed heartbeats from a PC/laptop.
The key difference from a real ESP32:
  - OS scheduler jitter: IPD varies 50–300ms (vs. real ESP32's ~500ms ±3ms)
  - Free heap: ~8MB (process memory) vs. ~240KB on ESP32
  - RSSI: typically -35 (laptop close to AP) vs. -60 (wall-mounted ESP32)

Run this on your Mac, then transfer attack_data.db to the Pi.
"""
import sqlite3
import numpy as np
import os
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACK_DB    = os.path.join(PROJECT_ROOT, "attack_data.db")
LEGIT_DB     = os.path.join(PROJECT_ROOT, "security.db")

NUM_ATTACK_SAMPLES = 200
FAKE_DEVICE_ID     = "SOFTWARE_ATTACKER_001"

print("\n" + "=" * 60)
print("💀 SOFTWARE ATTACKER — Attack Data Generator")
print("=" * 60)
print(f"   Output    : {ATTACK_DB}")
print(f"   Samples   : {NUM_ATTACK_SAMPLES}")
print()

# ── Get baseline IPD from legit data if available ──────────────────────
base_ipd = 500  # default: real ESP32 fires ~every 500ms
if os.path.exists(LEGIT_DB):
    try:
        conn = sqlite3.connect(LEGIT_DB)
        row  = conn.execute(
            "SELECT AVG(inter_packet_delay) FROM heartbeats WHERE inter_packet_delay > 0"
        ).fetchone()
        conn.close()
        if row and row[0]:
            base_ipd = float(row[0])
            print(f"   Baseline IPD from legit DB: {base_ipd:.1f} ms")
    except Exception:
        pass

# ── Set up attack database ─────────────────────────────────────────────
conn = sqlite3.connect(ATTACK_DB)
conn.execute("""
    CREATE TABLE IF NOT EXISTS heartbeats (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id          TEXT,
        timestamp          INTEGER,
        temperature        REAL,
        humidity           REAL,
        rssi               INTEGER,
        free_heap          INTEGER,
        inter_packet_delay INTEGER,
        packet_size        INTEGER,
        received_at        REAL,
        is_legitimate      INTEGER
    )
""")
conn.execute("DELETE FROM heartbeats")  # clear stale data

rng = np.random.default_rng(seed=42)
now = time.time()
samples = []

print(f"Generating {NUM_ATTACK_SAMPLES} attack samples...")
print(f"  IPD range : 50–300 ms  (vs real ESP32 ~{base_ipd:.0f} ms)")
print(f"  Free heap : ~8 MB      (vs real ESP32 ~240 KB)")
print(f"  RSSI      : ~-35 dBm   (laptop near AP)")

for i in range(NUM_ATTACK_SAMPLES):
    # OS scheduler jitter: much faster and more erratic than ESP32
    ipd         = max(10, int(rng.uniform(50, 300)))

    # Software stack fingerprint: large heap, good signal
    free_heap   = int(8_000_000 + rng.normal(0, 200_000))
    rssi        = int(-35 + rng.normal(0, 5))

    # Temperature/humidity: not available on attacker device, use neutral values
    temperature = float(25.0 + rng.normal(0, 1))
    humidity    = float(50.0 + rng.normal(0, 2))
    packet_size = int(245 + rng.integers(-5, 5))

    received_at = now + i * (ipd / 1000.0)
    timestamp   = int(received_at * 1000)

    samples.append((
        FAKE_DEVICE_ID, timestamp, temperature, humidity,
        rssi, free_heap, ipd, packet_size, received_at, 0  # 0 = not legitimate
    ))

conn.executemany("""
    INSERT INTO heartbeats
        (device_id, timestamp, temperature, humidity, rssi, free_heap,
         inter_packet_delay, packet_size, received_at, is_legitimate)
    VALUES (?,?,?,?,?,?,?,?,?,?)
""", samples)
conn.commit()

# ── Summary stats ──────────────────────────────────────────────────────
stats = conn.execute("""
    SELECT
        COUNT(*)                          AS total,
        ROUND(AVG(inter_packet_delay), 1) AS avg_ipd,
        MIN(inter_packet_delay)           AS min_ipd,
        MAX(inter_packet_delay)           AS max_ipd,
        ROUND(AVG(rssi), 1)               AS avg_rssi,
        ROUND(AVG(free_heap)/1e6, 2)      AS avg_heap_mb
    FROM heartbeats
""").fetchone()
conn.close()

print()
print(f"✅ Attack database saved: {ATTACK_DB}")
print(f"   Total samples : {stats[0]}")
print(f"   Avg IPD       : {stats[1]} ms  (min={stats[2]}, max={stats[3]})")
print(f"   Avg RSSI      : {stats[4]} dBm")
print(f"   Avg heap      : {stats[5]} MB")
print()
print("Next steps:")
print("  1. scp attack_data.db mridul@<PI_IP>:~/Master_IoT_Project/")
print("  2. On Pi: python3 ml_models/train_model.py")
