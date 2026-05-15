#!/usr/bin/env python3
"""
Zero-Trust RFID Simulation Script
This script simulates an ESP32-CAM scanning an RFID card.
Use it to test the full backend pipeline (Server -> Bridge -> Blockchain -> Dashboard).

Requirements:
  pip install paho-mqtt requests
"""

import json
import time
import hashlib
import paho.mqtt.client as mqtt
import requests

# --- Configuration ---
MQTT_BROKER = "localhost"
DEVICE_ID   = "SIMULATED_ESP32_001"
# Test UID from authorized_users.json
TEST_UID    = "AABBCCDD"
TEST_CODE   = "1234"  # Use 9999 to test Duress

class RFIDSimulator:
    def __init__(self):
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.challenge_received = None
        self.access_decision = None

    def on_connect(self, client, userdata, flags, rc, properties=None):
        print(f"✅ Simulator connected to MQTT broker (Code: {rc})")
        client.subscribe("perimeter/challenge")
        client.subscribe("perimeter/door_command")

    def on_message(self, client, userdata, msg):
        payload = json.loads(msg.payload.decode())
        
        if msg.topic == "perimeter/challenge":
            print(f"🎨 CHALLENGE RECEIVED: {payload.get('color')}")
            self.challenge_received = payload.get('color')
            
        elif msg.topic == "perimeter/door_command":
            print(f"🔓 DOOR COMMAND: {payload.get('action')}")
            self.access_decision = payload.get('action')

    def run_test(self):
        print("\n🚀 Starting Zero-Trust RFID Simulation...")
        self.client.connect(MQTT_BROKER, 1883, 60)
        self.client.loop_start()
        
        time.sleep(1) # Wait for connection

        # 1. SEND RFID SCAN
        print(f"🔑 [1/3] Scanning RFID UID: {TEST_UID}...")
        scan_payload = {
            "device_id": DEVICE_ID,
            "rfid_uid": TEST_UID
        }
        self.client.publish("perimeter/rfid_scan", json.dumps(scan_payload))

        # 2. WAIT FOR CHALLENGE
        timeout = 5
        start = time.time()
        while not self.challenge_received and (time.time() - start < timeout):
            time.sleep(0.1)

        if not self.challenge_received:
            print("❌ TIMEOUT: No RGB challenge received from Pi. Is enhanced_mqtt_handler.py running?")
            self.client.loop_stop()
            return

        # 3. SEND ACCESS ATTEMPT (with Secret Code and Image Hash)
        print(f"📸 [2/3] Sending Access Attempt (Code: {TEST_CODE})...")
        dummy_image = b"fake_camera_capture_data_12345"
        img_hash = hashlib.sha256(dummy_image).hexdigest()
        
        attempt_payload = {
            "device_id": DEVICE_ID,
            "rfid_uid": TEST_UID,
            "secret_code": TEST_CODE,
            "image_hash": img_hash,
            "rgb_challenge": self.challenge_received,
            "timestamp": int(time.time() * 1000)
        }
        self.client.publish("perimeter/access_attempt", json.dumps(attempt_payload))

        # 4. WAIT FOR DOOR COMMAND
        start = time.time()
        while not self.access_decision and (time.time() - start < timeout):
            time.sleep(0.1)

        if self.access_decision == "UNLOCK":
            print("\n✅ SUCCESS: Access Granted! Door unlocked.")
        else:
            print("\n⛔ DENIED: Access refused. Check Pi logs for details.")

        self.client.loop_stop()

if __name__ == "__main__":
    sim = RFIDSimulator()
    sim.run_test()
