"""
iot_server.py — Lightweight Flask IoT heartbeat receiver

Receives heartbeat POST requests from ESP32 devices and stores them in SQLite.
Also exposes a /health endpoint for monitoring.

Run: python3 iot_server.py
"""

import os
import sqlite3
import time
from pathlib import Path

from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# DATABASE PATH  — single source of truth, resolved relative to this file
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DB_PATH  = str(BASE_DIR / "iot_data.db")   # always next to iot_server.py

app = Flask(__name__)


# ---------------------------------------------------------------------------
# DATABASE HELPERS
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    """Open and return a connection to the shared SQLite database."""
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    """Create the heartbeats table if it does not already exist."""
    conn = get_db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS heartbeats (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT    NOT NULL,
                rssi      REAL    NOT NULL,
                timestamp REAL    NOT NULL
            )
            """
        )
        conn.commit()
        print(f"[DB] Initialised → {DB_PATH}")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------
@app.post("/verify")
def verify():
    """
    Record a heartbeat from an ESP32 device.

    Expected JSON body:
        { "device_id": "ESP32_001", "rssi": -65 }
    """
    payload   = request.get_json(silent=True) or {}
    device_id = payload.get("device_id")
    rssi      = payload.get("rssi")

    if device_id is None or rssi is None:
        return jsonify({
            "success": False,
            "error"  : "Both 'device_id' and 'rssi' are required.",
        }), 400

    try:
        rssi = float(rssi)
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "error"  : "'rssi' must be a number.",
        }), 400

    timestamp = time.time()

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO heartbeats (device_id, rssi, timestamp) VALUES (?, ?, ?)",
            (str(device_id), rssi, timestamp),
        )
        conn.commit()
    finally:
        conn.close()

    print(f"[HB] {device_id} | RSSI: {rssi} dBm")
    return jsonify({
        "success"  : True,
        "message"  : "Heartbeat recorded.",
        "timestamp": timestamp,
    })


@app.get("/health")
def health():
    """Quick health-check endpoint for monitoring / uptime checks."""
    try:
        conn = get_db()
        count = conn.execute("SELECT COUNT(*) FROM heartbeats").fetchone()[0]
        conn.close()
        db_ok = True
    except Exception as exc:
        count = 0
        db_ok = False

    return jsonify({
        "status"         : "ok" if db_ok else "degraded",
        "db_path"        : DB_PATH,
        "heartbeat_count": count,
        "uptime_s"       : round(time.time()),
    })


@app.get("/devices")
def devices():
    """Return a list of unique device IDs seen so far."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT DISTINCT device_id, COUNT(*) as packets, MAX(timestamp) as last_seen "
            "FROM heartbeats GROUP BY device_id ORDER BY last_seen DESC"
        ).fetchall()
    finally:
        conn.close()

    return jsonify([
        {"device_id": r[0], "packets": r[1], "last_seen": r[2]}
        for r in rows
    ])


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    print(f"[Server] Listening on http://0.0.0.0:5005")
    print(f"[Server] Endpoints: POST /verify  |  GET /health  |  GET /devices")
    app.run(host="0.0.0.0", port=5005, debug=False)
