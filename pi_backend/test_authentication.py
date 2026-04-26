import os
import sqlite3
import numpy as np
from tensorflow import keras
import pickle

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'device_authenticator.h5')
SCALER_PATH = os.path.join(BASE_DIR, 'scaler.pkl')
DB_PATH = '/home/mridul/Master_IoT_Project/security.db'
SEQ_LENGTH = 10

FEATURES = [
    'rssi', 'packet_size', 'free_heap', 
    'inter_packet_delay', 'temperature', 'humidity'
]

print("Loading Model and Scaler...")
try:
    model = keras.models.load_model(MODEL_PATH)
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
except Exception as e:
    print(f"Error loading model: {e}")
    exit(1)

print("Fetching latest packets from live database...")
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute(f"""
    SELECT device_id, rssi, packet_size, free_heap, inter_packet_delay, temperature, humidity
    FROM heartbeats 
    WHERE inter_packet_delay > 0
    ORDER BY received_at DESC 
    LIMIT {SEQ_LENGTH}
""")
rows = cursor.fetchall()
conn.close()

if len(rows) < SEQ_LENGTH:
    print(f"Not enough data in live DB. Need {SEQ_LENGTH} consecutive packets.")
    exit(1)

# Reverse so it's in chronological order
rows.reverse()

# Extract features
features = []
for row in rows:
    temp = row[5] if row[5] else 45.0
    hum = row[6] if row[6] else 50.0
    features.append([row[1], row[2], row[3], row[4], temp, hum])

feature_array = np.array([features]) # Shape (1, 10, 6)

# Normalize
flat = feature_array.reshape(-1, len(FEATURES))
scaled_flat = scaler.transform(flat)
X_test = scaled_flat.reshape(1, SEQ_LENGTH, len(FEATURES))

print("Running Authentication Check...")
prediction = model.predict(X_test, verbose=0)[0][0]
confidence = prediction * 100 if prediction > 0.5 else (1 - prediction) * 100

print("\n" + "="*50)
if prediction > 0.5:
    print(f"✅ AUTHENTICATED: Real physical device detected.")
else:
    print(f"🚨 ALERT: Software Spoofing / Network Attacker detected!")
print(f"Classification Score: {prediction:.4f}")
print(f"Confidence: {confidence:.2f}%")
print("="*50)
