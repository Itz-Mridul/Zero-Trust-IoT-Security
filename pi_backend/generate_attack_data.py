import sqlite3
import numpy as np

print("Generating synthetic software spoofing data...")

LEGIT_DB = '/home/mridul/Master_IoT_Project/security.db'
ATTACK_DB = '/home/mridul/Master_IoT_Project/attack_data.db'

# Connect to legit db to get baseline
conn_legit = sqlite3.connect(LEGIT_DB)
cursor_legit = conn_legit.cursor()

cursor_legit.execute("SELECT device_id, timestamp, temperature, humidity, rssi, free_heap, inter_packet_delay, packet_size, received_at FROM heartbeats WHERE inter_packet_delay > 0 LIMIT 1000")
samples = cursor_legit.fetchall()
conn_legit.close()

if not samples:
    print("No legitimate samples to base attack on.")
    exit(1)

# Connect to attack db
conn_attack = sqlite3.connect(ATTACK_DB)
cursor_attack = conn_attack.cursor()

cursor_attack.execute('''
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

# Clear old attack data
cursor_attack.execute("DELETE FROM heartbeats")

attack_samples = []
for row in samples:
    device_id = "SPOOFER_001"
    timestamp = row[1]
    
    # Software attacker usually has different thermal/memory profiles
    temperature = row[2] + np.random.normal(5, 2) if row[2] else 45.0
    humidity = row[3] if row[3] else 50.0
    rssi = -35 # Better signal usually for laptop
    free_heap = 8000000 # Much larger heap for a PC
    
    # OS Scheduler jitter (CRITICAL for ML detection)
    # A real ESP32 running an RTOS has very tight timing (e.g., exactly 200ms)
    # A Python script on a PC has high jitter from the OS scheduler (+/- 15ms)
    ipd = max(10, int(row[6] + np.random.normal(0, 15))) 
    
    packet_size = row[7]
    received_at = row[8]
    
    attack_samples.append((device_id, timestamp, temperature, humidity, rssi, free_heap, ipd, packet_size, received_at, 0))

cursor_attack.executemany('''
    INSERT INTO heartbeats 
    (device_id, timestamp, temperature, humidity, rssi, free_heap,
     inter_packet_delay, packet_size, received_at, is_legitimate)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
''', attack_samples)

conn_attack.commit()
conn_attack.close()

print(f"✅ Generated {len(attack_samples)} synthetic software attack samples in {ATTACK_DB}")
