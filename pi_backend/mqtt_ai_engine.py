#!/usr/bin/env python3
"""
mqtt_ai_engine.py — MQTT + CNN-LSTM AI Engine
Core brain: authenticates devices via hardware timing fingerprints.

This is the canonical entry point referenced in FINAL_COMPLETION_GUIDE.md.
It delegates to enhanced_mqtt_handler.py which contains the full implementation.
"""
import os
import sys
import subprocess

# Resolve paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HANDLER  = os.path.join(BASE_DIR, "enhanced_mqtt_handler.py")

if not os.path.exists(HANDLER):
    print(f"❌ enhanced_mqtt_handler.py not found at {HANDLER}")
    sys.exit(1)

print("🚀 Starting MQTT + AI Engine (via enhanced_mqtt_handler.py)…")

# Replace current process with the handler — keeps PID, logs, signals identical
os.execv(sys.executable, [sys.executable, HANDLER] + sys.argv[1:])
