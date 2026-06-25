#!/usr/bin/env python3
"""
merge_datasets.py — Merge Training Databases
=============================================
Merges collected heartbeat samples from multiple SQLite DBs into
ml_models/training_data.db ready for train_model.py.

Usage:
  python3 pi_backend/merge_datasets.py

Sources (auto-discovered if they exist):
  pi_backend/training_data.db   (raw collected data)
  pi_backend/security.db        (live server logs with is_legitimate labels)
  ml_models/training_data.db    (existing merged DB — extended, not overwritten)
"""

import os
import sqlite3
import sys
import time

_BASE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_BASE)

SOURCES = [
    os.path.join(_BASE, "training_data.db"),
    os.path.join(_BASE, "security.db"),
]
OUTPUT_DB = os.path.join(_ROOT, "ml_models", "training_data.db")

FEATS = ["rssi", "packet_size", "free_heap", "inter_packet_delay", "temperature", "humidity"]

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS heartbeats (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id          TEXT    NOT NULL,
    rssi               REAL,
    packet_size        REAL,
    free_heap          REAL,
    inter_packet_delay REAL,
    temperature        REAL,
    humidity           REAL,
    is_legitimate      INTEGER NOT NULL,
    received_at        INTEGER NOT NULL
)
"""

INSERT_SQL = (
    "INSERT INTO heartbeats "
    "(device_id, rssi, packet_size, free_heap, inter_packet_delay, "
    " temperature, humidity, is_legitimate, received_at) "
    "VALUES (?,?,?,?,?,?,?,?,?)"
)


def _ensure_output(db_path: str) -> None:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(CREATE_SQL)


def _copy_table(src_path: str, dst_conn: sqlite3.Connection) -> int:
    """Copy all rows from src heartbeats table into dst. Returns row count copied."""
    try:
        src = sqlite3.connect(src_path)
        rows = src.execute(
            "SELECT device_id, rssi, packet_size, free_heap, inter_packet_delay, "
            "       temperature, humidity, is_legitimate, received_at "
            "FROM heartbeats WHERE inter_packet_delay > 0"
        ).fetchall()
        src.close()
    except sqlite3.OperationalError as e:
        print(f"  ⚠️  Skipping {src_path}: {e}")
        return 0

    if not rows:
        return 0

    dst_conn.executemany(INSERT_SQL, rows)
    dst_conn.commit()
    return len(rows)


def main() -> None:
    print("\n" + "=" * 60)
    print("🔀 DATASET MERGE — Combining training data sources")
    print("=" * 60)

    _ensure_output(OUTPUT_DB)

    total = 0
    with sqlite3.connect(OUTPUT_DB) as dst:
        for src_path in SOURCES:
            if not os.path.exists(src_path):
                print(f"  ⏭  Not found (skip): {src_path}")
                continue
            n = _copy_table(src_path, dst)
            print(f"  ✅ {n:5d} rows  ← {src_path}")
            total += n

        # Show class distribution
        rows = dst.execute(
            "SELECT is_legitimate, COUNT(*) FROM heartbeats GROUP BY is_legitimate"
        ).fetchall()

    print(f"\n📊 Total rows merged: {total}")
    for label, count in rows:
        lname = "Legitimate" if label == 1 else "Attack/Spoof"
        print(f"   {lname:15s}: {count}")

    print(f"\n✅ Merged DB: {OUTPUT_DB}")
    print("\n📋 Next step: python3 ml_models/train_model.py\n")


if __name__ == "__main__":
    main()
