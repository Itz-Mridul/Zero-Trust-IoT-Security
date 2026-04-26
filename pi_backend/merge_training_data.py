#!/usr/bin/env python3
"""
Merge legitimate and attack data into single training database
"""

import sqlite3
import shutil
import os
from datetime import datetime

# Paths (Corrected for your environment)
LEGITIMATE_DB = '/home/mridul/Master_IoT_Project/security.db'
ATTACK_DB = '/home/mridul/Master_IoT_Project/attack_data.db'
TRAINING_DB = '/home/mridul/Master_IoT_Project/pi_backend/training_data.db'

# Ensure the pi_backend directory exists
os.makedirs(os.path.dirname(TRAINING_DB), exist_ok=True)

# Backup existing training DB
backup_path = f'{TRAINING_DB}.backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
try:
    shutil.copy(TRAINING_DB, backup_path)
    print(f"✅ Backup created: {backup_path}")
except FileNotFoundError:
    print("ℹ️  No existing training DB to backup")

# Create fresh training database
conn_train = sqlite3.connect(TRAINING_DB)
cursor_train = conn_train.cursor()

cursor_train.execute('''
    CREATE TABLE IF NOT EXISTS heartbeats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        timestamp INTEGER,
        temperature REAL,
        humidity REAL,
        rssi INTEGER,
        free_heap INTEGER,
        inter_packet_delay INTEGER,
        packet_size INTEGER,
        received_at REAL,
        is_legitimate INTEGER
    )
''')

print("\n" + "="*60)
print("📊 MERGING TRAINING DATA")
print("="*60)

# Copy legitimate samples
try:
    conn_legit = sqlite3.connect(LEGITIMATE_DB)
    cursor_legit = conn_legit.cursor()

    cursor_legit.execute('''
        SELECT device_id, timestamp, temperature, humidity, rssi, free_heap,
               inter_packet_delay, packet_size, received_at, 1
        FROM heartbeats 
        WHERE device_id LIKE 'ESP32_%' 
        AND inter_packet_delay > 0
    ''')

    legit_samples = cursor_legit.fetchall()
    cursor_train.executemany('''
        INSERT INTO heartbeats 
        (device_id, timestamp, temperature, humidity, rssi, free_heap,
         inter_packet_delay, packet_size, received_at, is_legitimate)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', legit_samples)

    print(f"✅ Copied {len(legit_samples)} legitimate samples")
    conn_legit.close()
except sqlite3.Error as e:
    print(f"❌ Error reading legitimate database: {e}")
    legit_samples = []

# Copy attack samples
attack_samples_count = 0
try:
    if os.path.exists(ATTACK_DB):
        conn_attack = sqlite3.connect(ATTACK_DB)
        cursor_attack = conn_attack.cursor()
        
        cursor_attack.execute('''
            SELECT device_id, timestamp, temperature, humidity, rssi, free_heap,
                   inter_packet_delay, packet_size, received_at, 0
            FROM heartbeats
            WHERE inter_packet_delay > 0
        ''')
        
        attack_samples = cursor_attack.fetchall()
        attack_samples_count = len(attack_samples)
        cursor_train.executemany('''
            INSERT INTO heartbeats 
            (device_id, timestamp, temperature, humidity, rssi, free_heap,
             inter_packet_delay, packet_size, received_at, is_legitimate)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', attack_samples)
        
        print(f"✅ Copied {len(attack_samples)} attack samples")
        conn_attack.close()
    else:
        print(f"ℹ️  Attack database not found at {ATTACK_DB}")
        print(f"   Continuing with legitimate data only...")
        
except sqlite3.Error as e:
    print(f"⚠️  Error reading attack database: {e}")
    print(f"   Continuing with legitimate data only...")

conn_train.commit()
conn_train.close()

print(f"\n✅ Training database ready: {TRAINING_DB}")
print(f"\nTotal samples: {len(legit_samples) + attack_samples_count}")
