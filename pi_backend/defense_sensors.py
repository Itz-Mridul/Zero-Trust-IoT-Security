#!/usr/bin/env python3
"""
defense_sensors.py — Physical Defense Sensors (SW-420 + DHT22)
This is the canonical service name referenced in FINAL_COMPLETION_GUIDE.md.
Delegates to environment_monitor.py which contains the full implementation.
"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MONITOR  = os.path.join(BASE_DIR, "environment_monitor.py")

if not os.path.exists(MONITOR):
    print(f"❌ environment_monitor.py not found at {MONITOR}")
    sys.exit(1)

print("🛡️  Starting Defense Sensors (via environment_monitor.py)…")
os.execv(sys.executable, [sys.executable, MONITOR] + sys.argv[1:])
