#!/usr/bin/env python3
"""
Software Attacker - LIVE MQTT SPOOFING
Simulates a Rogue Skimmer ESP32 by publishing fake heartbeats
with erratic timing to trigger the AI Spoofing Detection.
"""

import os
import json
import time
import random
import paho.mqtt.client as mqtt

# ---------------- CONFIGURATION ----------------
PI_IP = "127.0.0.1"  # Run locally on Pi
MQTT_PORT = 1883
MQTT_HEARTBEAT_TOPIC = "mailbox/heartbeat"

# Attacker pretends to be the real Gateway
DEVICE_ID = "ESP32_RFID_NODE"

print("\n" + "="*60)
print("⚠️  SOFTWARE ATTACK SIMULATOR (ROGUE SKIMMER)")
print("="*60)
print(f"Targeting IP: {PI_IP}")
print(f"Spoofing ID:  {DEVICE_ID}\n")

# Connect to MQTT
client = mqtt.Client(client_id="Rogue_Skimmer_Simulator")
try:
    client.connect(PI_IP, MQTT_PORT, 60)
    client.loop_start()
    print("✅ Connected to MQTT broker. Commencing attack...\n")
except Exception as e:
    print(f"❌ Failed to connect to MQTT broker: {e}")
    exit(1)

# Initialize timing
last_timestamp = int(time.time() * 1000)
sent_count = 0

try:
    while True:
        # Software attacker has erratic inter-packet delay (100ms - 900ms)
        # instead of the exact 500ms heartbeat of real hardware
        delay_ms = random.randint(100, 900)
        time.sleep(delay_ms / 1000.0)
        
        current_time = int(time.time() * 1000)
        inter_packet_delay = current_time - last_timestamp
        last_timestamp = current_time
        
        # Create spoofed payload
        payload = {
            "device_id": DEVICE_ID,
            "timestamp": current_time,
            "temperature": round(random.uniform(22, 26), 2),
            "humidity": round(random.uniform(45, 55), 2),
            "rssi": random.randint(-65, -55),
            "free_heap": random.randint(220000, 240000),
            "inter_packet_delay": inter_packet_delay,
            "packet_size": random.randint(400, 450)
        }
        
        # Publish to live system
        client.publish(MQTT_HEARTBEAT_TOPIC, json.dumps(payload))
        
        sent_count += 1
        print(f"🎯 [ATTACK] Spoofed heartbeat sent | IPD: {inter_packet_delay}ms")
        
        # Attack for 20 packets then stop
        if sent_count >= 20:
            break

except KeyboardInterrupt:
    print("\nAttack stopped manually.")

client.loop_stop()
client.disconnect()

print(f"\n✅ Attack simulation complete! Sent {sent_count} spoofed packets.")
print("Check your dashboard Threat Radar — AI Spoofing should be RED!")

