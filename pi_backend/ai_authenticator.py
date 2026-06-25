#!/usr/bin/env python3
"""
AI Authenticator — Dual-Backend Hardware Fingerprint Engine
=============================================================
Research Paper Reference: Phase 4, Section 4.2 — Patent Claim 3

Dual-backend model support (as specified in research.md):
  Primary  : TensorFlow/Keras CNN-LSTM  (device_authenticator.h5)
  Fallback : scikit-learn RandomForest  (device_authenticator.pkl)

The fallback activates automatically on Python environments where
TensorFlow is unavailable (e.g. Python 3.14+). Both backends produce
a legitimacy probability in the same 0–1 range with the same threshold.

How it works:
  1. Keeps a per-device rolling buffer of the last SEQ=10 heartbeats.
  2. Once the buffer is full, runs inference.
  3. Returns (is_legitimate, confidence, buffer_size) for iot_server.
"""

import collections
import os
import pickle
import threading
from typing import Optional, Tuple

import numpy as np

# ── Config ────────────────────────────────────────────────────────────────────
_BASE    = os.path.dirname(os.path.abspath(__file__))
_ROOT    = os.path.dirname(_BASE)

MODEL_H5  = os.environ.get("MODEL_PATH",
            os.path.join(_ROOT, "ml_models", "device_authenticator.h5"))
MODEL_PKL = os.environ.get("MODEL_PKL_PATH",
            os.path.join(_ROOT, "ml_models", "device_authenticator.pkl"))
SCALER_PKL = os.environ.get("SCALER_PATH",
             os.path.join(_ROOT, "ml_models", "scaler.pkl"))

SEQ   = 10
FEATS = ["rssi", "packet_size", "free_heap",
         "inter_packet_delay", "temperature", "humidity"]

SPOOF_THRESHOLD = float(os.environ.get("AI_SPOOF_THRESHOLD", "0.45"))

# ── Module-level singletons ───────────────────────────────────────────────────
_lock      = threading.Lock()
_model     = None
_scaler    = None
_ready     = False
_backend   = None   # "keras" | "sklearn" | None

_buffers: dict = {}


def _load_model() -> bool:
    """Attempt to load model (Keras primary, sklearn fallback). Thread-safe."""
    global _model, _scaler, _ready, _backend

    if _ready:
        return True

    with _lock:
        if _ready:
            return True

        if not os.path.exists(SCALER_PKL):
            print(f"[AI_AUTH] ⚠️  Scaler not found at {SCALER_PKL}")
            return False

        with open(SCALER_PKL, "rb") as f:
            _scaler = pickle.load(f)

        # ── Try Keras / TensorFlow first ─────────────────────────────────
        if os.path.exists(MODEL_H5):
            try:
                os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
                from tensorflow.keras.models import load_model  # type: ignore
                _model   = load_model(MODEL_H5, compile=False)
                _backend = "keras"
                _ready   = True
                print(f"[AI_AUTH] ✅ CNN-LSTM (Keras) loaded — "
                      f"real-time hardware fingerprinting ACTIVE")
                return True
            except Exception as exc:
                print(f"[AI_AUTH] ℹ️  Keras unavailable ({exc}) — trying sklearn fallback…")

        # ── sklearn RandomForest fallback ─────────────────────────────────
        if os.path.exists(MODEL_PKL):
            try:
                with open(MODEL_PKL, "rb") as f:
                    _model = pickle.load(f)
                _backend = "sklearn"
                _ready   = True
                print(f"[AI_AUTH] ✅ RandomForest (sklearn) loaded — "
                      f"hardware fingerprinting ACTIVE (fallback backend)")
                return True
            except Exception as exc:
                print(f"[AI_AUTH] ❌ sklearn fallback failed: {exc}")
                return False

        print(f"[AI_AUTH] ⚠️  No model found — checked:\n"
              f"  Keras : {MODEL_H5}\n"
              f"  sklearn: {MODEL_PKL}\n"
              "  Falling back to rule-based scoring only.")
        return False


def _extract_features(data: dict) -> Optional[list]:
    """Extract the 6 feature values from a heartbeat payload."""
    try:
        return [
            float(data.get("rssi")               or -100),
            float(data.get("packet_size")        or 0),
            float(data.get("free_heap")          or 0),
            float(data.get("inter_packet_delay") or 0),
            float(data.get("temperature")        or 25.0),
            float(data.get("humidity")           or 50.0),
        ]
    except (TypeError, ValueError):
        return None


def predict_legitimacy(
    device_id: str,
    data: dict,
) -> Optional[Tuple[bool, float, int]]:
    """
    Buffer a heartbeat sample and run inference when buffer is full.

    Returns:
        None                               — buffer warming up (< SEQ samples).
        (is_legitimate, confidence, size)  — when prediction is ready.
    """
    if not _load_model():
        return None

    feats = _extract_features(data)
    if feats is None:
        return None

    if device_id not in _buffers:
        _buffers[device_id] = collections.deque(maxlen=SEQ)
    buf = _buffers[device_id]
    buf.append(feats)

    if len(buf) < SEQ:
        return None

    try:
        X = np.array(list(buf), dtype=np.float32)   # (SEQ, 6)
        X_flat = _scaler.transform(X)               # normalise all rows

        if _backend == "keras":
            X_seq = X_flat.reshape(1, SEQ, len(FEATS))
            prob = float(_model.predict(X_seq, verbose=0)[0][0])
        else:
            # sklearn: flatten to (1, SEQ*6) and use predict_proba[:,1]
            X_in = X_flat.reshape(1, -1)
            prob = float(_model.predict_proba(X_in)[0][1])   # P(legitimate)

        is_legit = prob >= SPOOF_THRESHOLD

        if not is_legit:
            print(f"[AI_AUTH] 🚨 SPOOF DETECTED | {device_id} | "
                  f"confidence={prob:.3f} (threshold={SPOOF_THRESHOLD}) "
                  f"[backend={_backend}]")
        else:
            print(f"[AI_AUTH] ✅ LEGITIMATE   | {device_id} | "
                  f"confidence={prob:.3f} [backend={_backend}]")

        return is_legit, prob, len(buf)

    except Exception as exc:
        print(f"[AI_AUTH] Prediction error: {exc}")
        return None


def reset_device_buffer(device_id: str) -> None:
    """Clear a device's rolling buffer (call on reconnect/boot)."""
    if device_id in _buffers:
        _buffers[device_id].clear()


def get_buffer_status() -> dict:
    """Return buffer fill levels for all devices."""
    return {dev: len(buf) for dev, buf in _buffers.items()}


def get_backend() -> Optional[str]:
    """Return the active backend: 'keras', 'sklearn', or None."""
    return _backend


# Pre-load on import so the first heartbeat doesn't pay the load cost
_load_model()
