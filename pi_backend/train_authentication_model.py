#!/usr/bin/env python3
"""
ML Model Trainer - CNN-LSTM for Hardware Fingerprinting
Trains on inter-packet delay patterns to distinguish real ESP32 from software spoofing
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import pickle
import sqlite3

print("\n" + "="*60)
print("🧠 ML Authentication Model Trainer")
print("="*60)

# Configuration
DB_PATH = '/home/mridul/Master_IoT_Project/security.db'
SEQ_LENGTH = 10  # Analyze last 10 packets
MIN_SAMPLES = 100  # Minimum samples needed

print(f"\n📊 Loading training data from: {DB_PATH}")

# Load data
conn = sqlite3.connect(DB_PATH)
df = pd.read_sql_query("""
    SELECT * FROM heartbeats 
    WHERE inter_packet_delay > 0 
    ORDER BY device_id, received_at
""", conn)
conn.close()

print(f"✅ Loaded {len(df)} total samples")

# Check if we have enough data
if len(df) < MIN_SAMPLES:
    print(f"\n❌ ERROR: Need at least {MIN_SAMPLES} samples to train")
    print(f"   Current: {len(df)} samples")
    print(f"\nSolution:")
    print(f"   1. Run ESP32 Gateway for longer (collect 500+ samples)")
    print(f"   2. Run attack simulation: python3 software_attacker.py")
    exit(1)

# Feature columns
features = [
    'rssi',
    'packet_size',
    'free_heap',
    'inter_packet_delay',
    'temperature',
    'humidity'
]

print(f"\n🔧 Features used for ML:")
for f in features:
    print(f"   • {f}")

# Create sequences
def create_sequences(data, seq_length=SEQ_LENGTH):
    """Create sequences of packets for LSTM"""
    sequences = []
    labels = []
    
    for device in data['device_id'].unique():
        device_data = data[data['device_id'] == device].sort_values('received_at')
        
        if len(device_data) < seq_length:
            continue
        
        feature_data = device_data[features].values
        label_data = device_data['is_legitimate'].values
        
        for i in range(len(feature_data) - seq_length):
            seq = feature_data[i:i+seq_length]
            label = label_data[i+seq_length]
            
            sequences.append(seq)
            labels.append(label)
    
    return np.array(sequences), np.array(labels)

print(f"\n🔄 Creating sequences (window size: {SEQ_LENGTH} packets)...")
X, y = create_sequences(df)

print(f"✅ Created {len(X)} sequences")
print(f"   Legitimate: {sum(y)} samples")
print(f"   Attack: {len(y) - sum(y)} samples")

if len(X) < 50:
    print(f"\n⚠️  WARNING: Only {len(X)} sequences created")
    print(f"   Model accuracy may be limited with small dataset")
    print(f"   Recommended: 200+ sequences for good accuracy")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"\n📊 Train/Test Split:")
print(f"   Training: {len(X_train)} sequences")
print(f"   Testing: {len(X_test)} sequences")

# Normalize features
print(f"\n🔧 Normalizing features...")
scaler = StandardScaler()
X_train_flat = X_train.reshape(-1, X_train.shape[-1])
X_test_flat = X_test.reshape(-1, X_test.shape[-1])

scaler.fit(X_train_flat)

X_train_scaled = scaler.transform(X_train_flat).reshape(X_train.shape)
X_test_scaled = scaler.transform(X_test_flat).reshape(X_test.shape)

# Build CNN-LSTM model
print(f"\n🏗️  Building CNN-LSTM model...")
print(f"   Architecture:")
print(f"   • Input: ({SEQ_LENGTH}, {len(features)})")
print(f"   • Conv1D layer (filters=32)")
print(f"   • LSTM layer (units=32)")
print(f"   • Dense layers (16 → 1)")
print(f"   • Activation: sigmoid (binary classification)")

model = keras.Sequential([
    # Convolutional layer to extract spatial features
    layers.Conv1D(32, 3, activation='relu', input_shape=(SEQ_LENGTH, len(features))),
    layers.MaxPooling1D(2),
    
    # LSTM layer to capture temporal patterns
    layers.LSTM(32, return_sequences=True),
    layers.Dropout(0.3),
    layers.LSTM(16),
    layers.Dropout(0.3),
    
    # Dense layers for classification
    layers.Dense(16, activation='relu'),
    layers.Dense(1, activation='sigmoid')
])

model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy', 
             keras.metrics.Precision(name='precision'),
             keras.metrics.Recall(name='recall')]
)

print(f"\n📝 Model Summary:")
model.summary()

# Train model
print(f"\n🚀 Training model...")
print(f"   Epochs: 50")
print(f"   Batch size: 16")
print(f"   Validation split: 20%\n")

history = model.fit(
    X_train_scaled, y_train,
    epochs=50,
    batch_size=16,
    validation_split=0.2,
    verbose=1
)

# Evaluate
print(f"\n📊 Evaluating on test set...")
results = model.evaluate(X_test_scaled, y_test, verbose=0)

print(f"\n" + "="*60)
print(f"🎯 FINAL RESULTS")
print(f"="*60)
print(f"   Accuracy:  {results[1]*100:.2f}%")
print(f"   Precision: {results[2]*100:.2f}%")
print(f"   Recall:    {results[3]*100:.2f}%")
print(f"="*60)

# Save model
MODEL_PATH = 'device_authenticator.h5'
SCALER_PATH = 'scaler.pkl'

model.save(MODEL_PATH)
print(f"\n✅ Model saved: {MODEL_PATH}")

with open(SCALER_PATH, 'wb') as f:
    pickle.dump(scaler, f)
print(f"✅ Scaler saved: {SCALER_PATH}")

print(f"\n🎉 Training complete!")
print(f"\nNext steps:")
print(f"   1. Use model in enhanced_mqtt_handler.py")
print(f"   2. Test with: python3 enhanced_mqtt_handler.py")
print(f"   3. Verify real-time authentication works")
