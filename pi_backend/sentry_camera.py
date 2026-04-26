#!/usr/bin/env python3
import paho.mqtt.client as mqtt
import json
import base64
import os
import time

# Configuration
MQTT_BROKER = "localhost"
MQTT_PORT = 1883
IMAGE_DIR = "/home/mridul/Master_IoT_Project/static/evidence"

# Ensure directory exists
os.makedirs(IMAGE_DIR, exist_ok=True)

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("📸 Sentry Camera Service connected to MQTT")
        client.subscribe("sentry/camera_feed")
    else:
        print(f"❌ Connection failed: {rc}")

def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        device_id = data.get("device_id", "unknown")
        image_b64 = data.get("image")
        
        if image_b64:
            # Decode and save image
            image_data = base64.b64decode(image_b64)
            filename = f"capture_{device_id}_{int(time.time())}.jpg"
            filepath = os.path.join(IMAGE_DIR, filename)
            
            with open(filepath, "wb") as f:
                f.write(image_data)
            
            print(f"✅ Image captured and saved: {filename}")
            
            # Update latest symlink for dashboard
            latest_path = os.path.join(IMAGE_DIR, f"latest_{device_id}.jpg")
            if os.path.exists(latest_path):
                os.remove(latest_path)
            os.symlink(filepath, latest_path)
            
    except Exception as e:
        print(f"❌ Error processing image: {e}")

if __name__ == "__main__":
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    
    print("🚀 Starting Sentry Camera Integration Service...")
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_forever()
