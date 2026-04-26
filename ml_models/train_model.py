#!/usr/bin/env python3
"""
CNN-LSTM Hardware Fingerprint Trainer
Trains the device authentication model on merged legitimate + attack data.

Expected DB: ml_models/training_data.db
Output:
  ml_models/device_authenticator.h5   (Keras model)
  ml_models/scaler.pkl                 (StandardScaler)
"""
import os
import sys
import pickle
import sqlite3

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

print("\n" + "=" * 70)
print("🧠  ML DEVICE AUTHENTICATION MODEL — TRAINING PIPELINE")
print("=" * 70)

# ── Paths ─────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(BASE_DIR, "training_data.db")
MODEL_PATH  = os.path.join(BASE_DIR, "device_authenticator.h5")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")

SEQ_LENGTH          = 10
MIN_PER_CLASS       = 50
FEATS = ["rssi", "packet_size", "free_heap",
         "inter_packet_delay", "temperature", "humidity"]

# ── Load ──────────────────────────────────────────────────────────────
if not os.path.exists(DB_PATH):
    print(f"\n❌ Training DB not found: {DB_PATH}")
    print("   Run the merge step first (see FINAL_COMPLETION_GUIDE.md Part 2 Step 3)")
    sys.exit(1)

print(f"\n📊 Loading data from: {DB_PATH}")
conn = sqlite3.connect(DB_PATH)
df   = pd.read_sql(
    "SELECT * FROM heartbeats WHERE inter_packet_delay > 0 ORDER BY device_id, received_at",
    conn,
)
conn.close()

print(f"✅ Loaded {len(df)} total samples")
print("\n📊 Class distribution:")
print(df["is_legitimate"].value_counts().to_string())

legit_count  = int((df["is_legitimate"] == 1).sum())
attack_count = int((df["is_legitimate"] == 0).sum())

if legit_count < MIN_PER_CLASS or attack_count < MIN_PER_CLASS:
    print(f"\n❌ Insufficient data — need ≥{MIN_PER_CLASS} per class")
    print(f"   Legitimate: {legit_count}  |  Attack: {attack_count}")
    print("\nSolutions:")
    print("  1. Let ESP32-CAM run longer (collect more legit data)")
    print("  2. Run: python3 tests/software_attacker.py")
    sys.exit(1)

# ── Build sliding-window sequences ────────────────────────────────────
print(f"\n🔄 Creating sequences (window={SEQ_LENGTH} packets)…")
Xs, ys = [], []
for dev in df["device_id"].unique():
    d = df[df["device_id"] == dev].sort_values("received_at")
    feat_data  = d[FEATS].values
    label_data = d["is_legitimate"].values
    for i in range(len(feat_data) - SEQ_LENGTH):
        Xs.append(feat_data[i : i + SEQ_LENGTH])
        ys.append(label_data[i + SEQ_LENGTH])

X, y = np.array(Xs), np.array(ys)
print(f"✅ {len(X)} sequences  |  shape: {X.shape}")
print(f"   Legit={int(y.sum())}  Attack={int(len(y) - y.sum())}")

if len(X) < 100:
    print(f"⚠️  Only {len(X)} sequences — recommended 200+ for production accuracy")

# ── Split & scale ─────────────────────────────────────────────────────
X_tr, X_te, y_tr, y_te = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)
print(f"\n📊 Train/Test: {len(X_tr)} / {len(X_te)} sequences")

scaler = StandardScaler()
X_tr_s = scaler.fit_transform(X_tr.reshape(-1, len(FEATS))).reshape(X_tr.shape)
X_te_s = scaler.transform(X_te.reshape(-1, len(FEATS))).reshape(X_te.shape)

# ── Build CNN-LSTM ────────────────────────────────────────────────────
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
except ImportError:
    print("❌ TensorFlow not installed — run: pip install tensorflow>=2.15.0")
    sys.exit(1)

print(f"\n🏗️  Building CNN-LSTM (input shape: {SEQ_LENGTH} × {len(FEATS)})…")
model = keras.Sequential([
    layers.Conv1D(32, 3, activation="relu",
                  input_shape=(SEQ_LENGTH, len(FEATS)),
                  name="conv1d_feature_extraction"),
    layers.MaxPooling1D(2),
    layers.Dropout(0.2),
    layers.LSTM(32, return_sequences=True, name="lstm_temporal_1"),
    layers.Dropout(0.3),
    layers.LSTM(16, name="lstm_temporal_2"),
    layers.Dropout(0.3),
    layers.Dense(16, activation="relu", name="dense_features"),
    layers.Dropout(0.2),
    layers.Dense(1, activation="sigmoid", name="output_authentication"),
])

model.compile(
    optimizer=keras.optimizers.Adam(learning_rate=0.001),
    loss="binary_crossentropy",
    metrics=[
        "accuracy",
        keras.metrics.Precision(name="precision"),
        keras.metrics.Recall(name="recall"),
    ],
)
model.summary()

# ── Train ─────────────────────────────────────────────────────────────
print(f"\n🚀 Training (max 100 epochs, early stopping at patience=10)…\n")
callbacks = [
    keras.callbacks.EarlyStopping(
        monitor="val_loss", patience=10, restore_best_weights=True
    ),
    keras.callbacks.ReduceLROnPlateau(
        monitor="val_loss", patience=5, factor=0.5, min_lr=1e-5
    ),
]

history = model.fit(
    X_tr_s, y_tr,
    epochs=100, batch_size=16,
    validation_split=0.2,
    callbacks=callbacks,
    verbose=1,
)

# ── Evaluate ──────────────────────────────────────────────────────────
results = model.evaluate(X_te_s, y_te, verbose=0)
print("\n" + "=" * 50)
print(f"ACCURACY  : {results[1] * 100:.2f}%")
print(f"PRECISION : {results[2] * 100:.2f}%")
print(f"RECALL    : {results[3] * 100:.2f}%")
print("=" * 50)

if results[1] < 0.90:
    print("\n⚠️  Accuracy < 90%. Possible causes:")
    print("   • Not enough data separation between classes")
    print("   • Run: sqlite3 security.db")
    print("     SELECT is_legitimate, ROUND(AVG(inter_packet_delay)) FROM heartbeats GROUP BY 1;")
    print("   • Legit avg should be ~500ms; attack avg should be ~100–300ms")
    print("   Collect more data and retrain.\n")

# ── Save ──────────────────────────────────────────────────────────────
model.save(MODEL_PATH)
with open(SCALER_PATH, "wb") as f:
    pickle.dump(scaler, f)

print(f"\n✅ Model saved  : {MODEL_PATH}")
print(f"✅ Scaler saved : {SCALER_PATH}")

# Optionally save training plot
try:
    import matplotlib.pyplot as plt
    plt.figure(figsize=(12, 4))
    plt.subplot(1, 2, 1)
    plt.plot(history.history["accuracy"],     label="Train")
    plt.plot(history.history["val_accuracy"], label="Val")
    plt.title("Accuracy"); plt.xlabel("Epoch"); plt.legend(); plt.grid(True)
    plt.subplot(1, 2, 2)
    plt.plot(history.history["loss"],     label="Train")
    plt.plot(history.history["val_loss"], label="Val")
    plt.title("Loss"); plt.xlabel("Epoch"); plt.legend(); plt.grid(True)
    plt.tight_layout()
    plot_path = os.path.join(BASE_DIR, "training_history.png")
    plt.savefig(plot_path, dpi=150)
    print(f"✅ Plot saved   : {plot_path}")
except Exception as e:
    print(f"ℹ️  Plot skipped: {e}")

print("\n📋 Next steps:")
print("  1. Restart: python3 pi_backend/mqtt_ai_engine.py")
print("  2. Tap RFID card → expect AUTHENTICATED (≥75%)")
print("  3. Press attacker button → expect DENIED (<75%)")
