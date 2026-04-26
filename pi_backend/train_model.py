#!/usr/bin/env python3
"""
CNN-LSTM Model Trainer for Hardware Device Authentication
Analyzes inter-packet delay patterns to fingerprint physical ESP32
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import pickle
import sqlite3
import matplotlib.pyplot as plt
import os

print("\n" + "="*70)
print("🧠 ML DEVICE AUTHENTICATION MODEL - TRAINING PIPELINE")
print("="*70)

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'training_data.db')
MODEL_PATH = os.path.join(BASE_DIR, 'device_authenticator.h5')
SCALER_PATH = os.path.join(BASE_DIR, 'scaler.pkl')
SEQ_LENGTH = 10  # Analyze sequences of 10 packets
MIN_SAMPLES_PER_CLASS = 50

# Feature columns (CRITICAL FOR PATENT - Hardware timing fingerprints)
FEATURES = [
    'rssi',                    # WiFi signal strength
    'packet_size',             # Payload size
    'free_heap',              # Available memory
    'inter_packet_delay',     # ⭐ PATENT-CRITICAL: Hardware timing signature
    'temperature',            # Environmental context
    'humidity'                # Environmental context
]

print(f"\n📊 Loading data from: {DB_PATH}")

# Load data
try:
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("""
        SELECT * FROM heartbeats 
        WHERE inter_packet_delay > 0 
        ORDER BY device_id, received_at
    """, conn)
    conn.close()
except sqlite3.Error as e:
    print(f"❌ Database error: {e}")
    exit(1)

print(f"✅ Loaded {len(df)} total samples")

# Check data distribution
print(f"\n📊 Class Distribution:")
print(df['is_legitimate'].value_counts())

legitimate_count = len(df[df['is_legitimate'] == 1])
attack_count = len(df[df['is_legitimate'] == 0])

print(f"\n   Legitimate: {legitimate_count}")
print(f"   Attack:     {attack_count}")

if legitimate_count < MIN_SAMPLES_PER_CLASS or attack_count < MIN_SAMPLES_PER_CLASS:
    print(f"\n❌ ERROR: Insufficient data")
    print(f"   Need at least {MIN_SAMPLES_PER_CLASS} samples per class")
    print(f"\n📝 Solution:")
    print(f"   1. Run ESP32 Gateway longer (collect more legitimate data)")
    print(f"   2. Run software_attacker.py (generate attack data)")
    exit(1)

def create_sequences(data, seq_length=SEQ_LENGTH):
    """
    Create sequences of packets for LSTM
    Each sequence = last N packets from same device
    """
    sequences = []
    labels = []
    
    for device in data['device_id'].unique():
        device_data = data[data['device_id'] == device].sort_values('received_at')
        
        if len(device_data) < seq_length:
            continue
        
        feature_data = device_data[FEATURES].values
        label_data = device_data['is_legitimate'].values
        
        # Sliding window
        for i in range(len(feature_data) - seq_length):
            seq = feature_data[i:i+seq_length]
            label = label_data[i+seq_length]  # Predict next packet's legitimacy
            
            sequences.append(seq)
            labels.append(label)
    
    return np.array(sequences), np.array(labels)

print(f"\n🔄 Creating sequences (window size: {SEQ_LENGTH} packets)...")
X, y = create_sequences(df)

print(f"✅ Created {len(X)} sequences")
print(f"   Shape: {X.shape}")
print(f"   Legitimate sequences: {sum(y)}")
print(f"   Attack sequences: {len(y) - sum(y)}")

if len(X) < 100:
    print(f"\n⚠️  WARNING: Only {len(X)} sequences")
    print(f"   Model accuracy may be limited")
    print(f"   Recommended: 200+ sequences for production")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, 
    test_size=0.2, 
    random_state=42, 
    stratify=y
)

print(f"\n📊 Train/Test Split:")
print(f"   Training:   {len(X_train)} sequences")
print(f"   Testing:    {len(X_test)} sequences")

# Normalize features (CRITICAL for neural network convergence)
print(f"\n🔧 Normalizing features...")
scaler = StandardScaler()

# Fit scaler on training data only
X_train_flat = X_train.reshape(-1, X_train.shape[-1])
scaler.fit(X_train_flat)

# Transform both train and test
X_train_scaled = scaler.transform(X_train_flat).reshape(X_train.shape)
X_test_flat = X_test.reshape(-1, X_test.shape[-1])
X_test_scaled = scaler.transform(X_test_flat).reshape(X_test.shape)

# Build CNN-LSTM architecture
print(f"\n🏗️  Building CNN-LSTM Model...")
print(f"   Input shape: ({SEQ_LENGTH}, {len(FEATURES)})")

model = keras.Sequential([
    # Conv1D layer: Extract spatial features from packet sequences
    layers.Conv1D(
        filters=32, 
        kernel_size=3, 
        activation='relu', 
        input_shape=(SEQ_LENGTH, len(FEATURES)),
        name='conv1d_feature_extraction'
    ),
    layers.MaxPooling1D(pool_size=2),
    layers.Dropout(0.2),
    
    # LSTM layers: Capture temporal patterns in timing
    layers.LSTM(
        units=32, 
        return_sequences=True,
        name='lstm_temporal_1'
    ),
    layers.Dropout(0.3),
    
    layers.LSTM(
        units=16,
        name='lstm_temporal_2'
    ),
    layers.Dropout(0.3),
    
    # Dense layers: Classification
    layers.Dense(16, activation='relu', name='dense_features'),
    layers.Dropout(0.2),
    layers.Dense(1, activation='sigmoid', name='output_authentication')
])

# Compile model
model.compile(
    optimizer=keras.optimizers.Adam(learning_rate=0.001),
    loss='binary_crossentropy',
    metrics=[
        'accuracy',
        keras.metrics.Precision(name='precision'),
        keras.metrics.Recall(name='recall'),
        keras.metrics.AUC(name='auc')
    ]
)

print(f"\n📝 Model Architecture:")
model.summary()

# Training callbacks
early_stopping = keras.callbacks.EarlyStopping(
    monitor='val_loss',
    patience=10,
    restore_best_weights=True
)

reduce_lr = keras.callbacks.ReduceLROnPlateau(
    monitor='val_loss',
    factor=0.5,
    patience=5,
    min_lr=0.00001
)

# Train model
print(f"\n🚀 Training model...")
print(f"   Epochs: 100 (with early stopping)")
print(f"   Batch size: 16")
print(f"   Validation split: 20%\n")

history = model.fit(
    X_train_scaled, y_train,
    epochs=100,
    batch_size=16,
    validation_split=0.2,
    callbacks=[early_stopping, reduce_lr],
    verbose=1
)

# Evaluate on test set
print(f"\n📊 Evaluating on test set...")
results = model.evaluate(X_test_scaled, y_test, verbose=0)

# Predictions for detailed analysis
y_pred_proba = model.predict(X_test_scaled, verbose=0)
y_pred = (y_pred_proba > 0.5).astype(int).flatten()

print(f"\n" + "="*70)
print(f"🎯 FINAL RESULTS")
print(f"="*70)
print(f"   Test Loss:      {results[0]:.4f}")
print(f"   Test Accuracy:  {results[1]*100:.2f}%")
print(f"   Precision:      {results[2]*100:.2f}%")
print(f"   Recall:         {results[3]*100:.2f}%")
print(f"   AUC:            {results[4]:.4f}")
print(f"="*70)

# Detailed classification report
print(f"\n📊 Classification Report:")
print(classification_report(
    y_test, 
    y_pred, 
    target_names=['Attack', 'Legitimate']
))

# Confusion matrix
print(f"\n📊 Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(f"                  Predicted")
print(f"                Attack  Legitimate")
print(f"Actual Attack    {cm[0][0]:6d}  {cm[0][1]:10d}")
print(f"       Legit     {cm[1][0]:6d}  {cm[1][1]:10d}")

# Save model
model.save(MODEL_PATH)
print(f"\n✅ Model saved: {MODEL_PATH}")

# Save scaler
with open(SCALER_PATH, 'wb') as f:
    pickle.dump(scaler, f)
print(f"✅ Scaler saved: {SCALER_PATH}")

# Plot training history (if matplotlib available)
try:
    plt.figure(figsize=(12, 4))
    
    # Accuracy
    plt.subplot(1, 2, 1)
    plt.plot(history.history['accuracy'], label='Train')
    plt.plot(history.history['val_accuracy'], label='Validation')
    plt.title('Model Accuracy')
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy')
    plt.legend()
    plt.grid(True)
    
    # Loss
    plt.subplot(1, 2, 2)
    plt.plot(history.history['loss'], label='Train')
    plt.plot(history.history['val_loss'], label='Validation')
    plt.title('Model Loss')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.legend()
    plt.grid(True)
    
    plt.tight_layout()
    PLOT_PATH = os.path.join(BASE_DIR, 'training_history.png')
    plt.savefig(PLOT_PATH, dpi=150)
    print(f"✅ Training plot saved: {PLOT_PATH}")
except Exception as e:
    print(f"ℹ️  Matplotlib not available or failed: {e}")

print(f"\n🎉 Training complete!")
print(f"\n📋 Next steps:")
print(f"   1. Test model: python3 test_authentication.py")
print(f"   2. Deploy in production: enhanced_mqtt_handler.py")
print(f"   3. Monitor real-time authentication performance")
