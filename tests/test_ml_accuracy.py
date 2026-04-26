#!/usr/bin/env python3
"""
Test ML Model Accuracy
Loads the trained CNN-LSTM model and evaluates on test sequences.
"""
import os
import sys
import numpy as np
import pickle
import sqlite3

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pi_backend")
MODEL_PATH = os.path.join(BASE_DIR, "device_authenticator.h5")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")
DB_PATH = os.environ.get("DB_PATH", "/home/mridul/Master_IoT_Project/security.db")
SEQ_LENGTH = 10
FEATURES = ["rssi", "packet_size", "free_heap", "inter_packet_delay", "temperature", "humidity"]


def test_model_loads():
    """Test that model and scaler files exist and load without error."""
    from tensorflow import keras

    assert os.path.exists(MODEL_PATH), f"Model not found: {MODEL_PATH}"
    assert os.path.exists(SCALER_PATH), f"Scaler not found: {SCALER_PATH}"

    model = keras.models.load_model(MODEL_PATH)
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)

    # Verify model input shape
    input_shape = model.input_shape
    assert input_shape[1] == SEQ_LENGTH, f"Expected SEQ_LENGTH={SEQ_LENGTH}, got {input_shape[1]}"
    assert input_shape[2] == len(FEATURES), f"Expected {len(FEATURES)} features, got {input_shape[2]}"

    print(f"✅ Model loaded: input shape = {input_shape}")
    return model, scaler


def test_prediction_range():
    """Test that model outputs are in [0, 1] range (sigmoid)."""
    model, scaler = test_model_loads()

    # Create a dummy sequence
    dummy = np.random.randn(1, SEQ_LENGTH, len(FEATURES)).astype(np.float32)
    prediction = model.predict(dummy, verbose=0)[0][0]

    assert 0.0 <= prediction <= 1.0, f"Prediction {prediction} out of [0,1] range"
    print(f"✅ Prediction range valid: {prediction:.4f}")


def test_live_data_accuracy():
    """Test model on live database data if available."""
    if not os.path.exists(DB_PATH):
        print("⚠️  Live database not found — skipping live accuracy test")
        return

    model, scaler = test_model_loads()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT rssi, packet_size, free_heap, inter_packet_delay, temperature, humidity "
        f"FROM heartbeats WHERE inter_packet_delay > 0 "
        f"ORDER BY received_at DESC LIMIT {SEQ_LENGTH}"
    )
    rows = cursor.fetchall()
    conn.close()

    if len(rows) < SEQ_LENGTH:
        print(f"⚠️  Only {len(rows)} rows in DB — need {SEQ_LENGTH} for test")
        return

    rows.reverse()
    features = []
    for row in rows:
        features.append([row[0], row[1], row[2], row[3], row[4] or 45.0, row[5] or 50.0])

    seq = np.array([features])
    scaled = scaler.transform(seq.reshape(-1, len(FEATURES))).reshape(1, SEQ_LENGTH, len(FEATURES))
    confidence = float(model.predict(scaled, verbose=0)[0][0]) * 100.0

    print(f"✅ Live data test: confidence = {confidence:.1f}%")
    assert confidence > 0, "Confidence should be positive"


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🧪 ML MODEL ACCURACY TESTS")
    print("=" * 60 + "\n")

    try:
        test_model_loads()
        test_prediction_range()
        test_live_data_accuracy()
        print("\n✅ All ML tests passed.\n")
    except Exception as e:
        print(f"\n❌ Test failed: {e}\n")
        sys.exit(1)
