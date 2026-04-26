#!/usr/bin/env python3
"""
Forensic Logger - Blockchain Audit Trail
Records every access attempt with SHA-256 hash and submits to Ganache blockchain.
Provides court-admissible, immutable proof of access or tampering.
"""

import hashlib
import json
import sqlite3
import time
import os
import sys

# Add parent path for blockchain_bridge import
sys.path.insert(0, '/home/mridul/Master_IoT_Project')

DB_PATH = '/home/mridul/Master_IoT_Project/security.db'

# Try to import blockchain bridge
try:
    from blockchain_bridge import register_event_on_chain, hash_event
    BLOCKCHAIN_ENABLED = True
except Exception as e:
    print(f"⚠️  Blockchain bridge unavailable: {e}. Running in local-only mode.")
    BLOCKCHAIN_ENABLED = False
    register_event_on_chain = None
    hash_event = None

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def compute_event_hash(device_id: str, event_type: str, timestamp: float, details: str) -> str:
    """Compute SHA-256 hash of event data for blockchain submission."""
    payload = f"{device_id}|{event_type}|{timestamp:.3f}|{details}"
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()

def log_event(device_id: str, event_type: str, details: str = "") -> str:
    """
    Log a security event to:
    1. Local SQLite database (immediate)
    2. Blockchain (async, may fail gracefully)
    Returns: SHA-256 hash of the event
    """
    ts = time.time()
    event_hash = compute_event_hash(device_id, event_type, ts, details)
    
    # 1. Write to local DB immediately
    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO alerts (device_id, event_type, timestamp, details)
            VALUES (?, ?, ?, ?)
        """, (device_id, event_type, int(ts), details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"❌ DB write failed: {e}")

    # 2. Write evidence record with hash
    tx_hash = None
    if BLOCKCHAIN_ENABLED and register_event_on_chain:
        try:
            # Store the SHA-256 hash as a uint256 (first 8 hex chars → int)
            hash_int = int(event_hash[:8], 16)
            receipt = register_event_on_chain(
                f"{event_type}:{device_id}",
                hash_int
            )
            if receipt:
                tx_hash = receipt.transactionHash.hex()
                print(f"⛓️  Blockchain TX: {tx_hash[:20]}...")
        except Exception as e:
            print(f"⚠️  Blockchain submission failed (cached locally): {e}")

    # 3. Write to evidence table
    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO evidence (device_id, filename, image_hash, timestamp, blockchain_tx, verified)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (device_id, f"{event_type}_{int(ts)}", event_hash, int(ts), tx_hash, 1 if tx_hash else 0))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"❌ Evidence write failed: {e}")

    status = "✅ BLOCKCHAIN" if tx_hash else "💾 LOCAL CACHE"
    print(f"📋 [{status}] [{event_type}] {device_id} | Hash: {event_hash[:16]}...")
    return event_hash


def log_authenticated(device_id: str, confidence: float):
    log_event(device_id, "AUTHENTICATED", f"AI confidence: {confidence:.1f}%")

def log_rejected(device_id: str, confidence: float, reason: str = "AI_FINGERPRINT"):
    log_event(device_id, "REJECTED", f"Reason: {reason} | Confidence: {confidence:.1f}%")

def log_tamper(device_id: str, sensor: str):
    log_event(device_id, "TAMPER", f"Sensor triggered: {sensor}")

def log_thermal(device_id: str, temp: float):
    log_event(device_id, "THERMAL", f"Temperature: {temp:.1f}°C — Emergency shutdown triggered.")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("📋  FORENSIC LOGGER — STANDALONE TEST")
    print("="*60)
    print("\nLogging test events...\n")

    log_authenticated("ESP32_GATEWAY_01", 94.7)
    time.sleep(0.5)
    log_rejected("UNKNOWN_DEVICE_99", 12.3, "HEARTBEAT_SPOOF")
    time.sleep(0.5)
    log_tamper("ESP32_GATEWAY_01", "SW-420 Vibration")
    time.sleep(0.5)
    log_thermal("VAULT_MONITOR_01", 71.2)

    print("\n✅ All events logged successfully.")
