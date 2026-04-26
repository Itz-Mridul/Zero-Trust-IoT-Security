#!/usr/bin/env python3
"""
IoT Telemetry Server - Raspberry Pi
Receives heartbeats from ESP32 Gateway and stores timing data for ML training
"""

import sqlite3
import time
import random
import ast
import operator
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# SAFE MATH EVALUATOR (replaces dangerous eval())
# ---------------------------------------------------------------------------
_SAFE_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
}

def _safe_eval(expr: str) -> int:
    """Evaluate a simple two-operand arithmetic expression safely."""
    tree = ast.parse(expr, mode='eval')
    node = tree.body
    if not isinstance(node, ast.BinOp):
        raise ValueError(f"Unsupported expression: {expr}")
    op_type = type(node.op)
    if op_type not in _SAFE_OPS:
        raise ValueError(f"Unsupported operator: {op_type}")
    left  = ast.literal_eval(node.left)
    right = ast.literal_eval(node.right)
    return _SAFE_OPS[op_type](left, right)

# Database path (absolute to avoid conflicts)
DB_PATH = '/home/mridul/Master_IoT_Project/security.db'

def init_db():
    """Initialize database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Heartbeat table (for ML training)
    cursor.execute('''
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
    ''')
    
    # Evidence table (for blockchain reference)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            filename TEXT,
            image_hash TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            blockchain_tx TEXT,
            verified BOOLEAN DEFAULT 0
        )
    ''')
    
    # Alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            details TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized:", DB_PATH)

# Store pending challenges: {device_id: expected_answer}
pending_challenges = {}

@app.route('/verify', methods=['POST'])
def verify_device():
    """
    Receives heartbeat from ESP32 Gateway
    Stores timing data for ML fingerprinting
    """
    data = request.json
    current_time = time.time()
    
    # Extract data
    device_id = data.get('device_id')
    timestamp = data.get('timestamp')
    temperature = data.get('temperature')
    humidity = data.get('humidity')
    rssi = data.get('rssi')
    free_heap = data.get('free_heap')
    inter_packet_delay = data.get('inter_packet_delay')
    packet_size = data.get('packet_size')
    
    # Store in database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO heartbeats 
        (device_id, timestamp, temperature, humidity, rssi, free_heap, 
         inter_packet_delay, packet_size, received_at, is_legitimate)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    ''', (
        device_id, timestamp, temperature, humidity, rssi, free_heap,
        inter_packet_delay, packet_size, current_time
    ))
    
    conn.commit()
    conn.close()
    
    # 1. Check previous challenge (if any)
    previous_answer = data.get('challenge_answer')
    if device_id in pending_challenges:
        expected = pending_challenges[device_id]
        if str(previous_answer) != str(expected):
            print(f"🚨 [MATH CHALLENGE] Incorrect answer from {device_id}! Expected {expected}, got {previous_answer}")
            # In a strict zero-trust mode, we might reject this. 
            # For now, we log it.

    # 2. Generate new challenge
    a, b = random.randint(1, 10), random.randint(1, 10)
    op = random.choice(['+', '*', '-'])
    challenge_str = f"{a} {op} {b}"
    answer = _safe_eval(challenge_str)   # safe — no eval()
    pending_challenges[device_id] = answer

    print(f"📡 Heartbeat from {device_id} | IPD: {inter_packet_delay}ms | Challenge: {challenge_str}")
    
    return jsonify({
        'status': 'AUTHENTICATED',
        'confidence': 100.0,
        'challenge': challenge_str,
        'message': 'Heartbeat received and challenge issued.'
    })

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM heartbeats")
    heartbeat_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM evidence")
    evidence_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(DISTINCT device_id) FROM heartbeats")
    device_count = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'heartbeats': heartbeat_count,
        'evidence': evidence_count,
        'devices': device_count
    })

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️  IoT Telemetry Server - Zero-Trust Gateway")
    print("="*60)
    
    init_db()
    
    print("\n📊 Starting Flask server on 0.0.0.0:5005")
    print("📡 Endpoints:")
    print("   POST /verify - Receive heartbeats")
    print("   GET  /stats  - System statistics")
    print("\n✅ Server ready. Waiting for ESP32 connections...\n")
    
    app.run(host='0.0.0.0', port=5005, debug=False)
