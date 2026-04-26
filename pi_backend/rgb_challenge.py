#!/usr/bin/env python3
import paho.mqtt.client as mqtt
import json
import random
import base64
import io
import time
from PIL import Image, ImageStat

# Configuration
MQTT_BROKER = "localhost"
MQTT_PORT = 1883

COLORS = {
    "RED":     (255,   0,   0),
    "GREEN":   (  0, 255,   0),
    "BLUE":    (  0,   0, 255),
    "CYAN":    (  0, 255, 255),
    "YELLOW": (255, 255,   0),
    "MAGENTA":(255,   0, 255),   # explicitly referenced in the spec
}

current_challenge = None

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("💡 RGB Challenge Service active")
        client.subscribe("sentry/camera_feed")
    else:
        print(f"❌ Connection failed: {rc}")

def issue_challenge(client):
    global current_challenge
    color_name = random.choice(list(COLORS.keys()))
    current_challenge = color_name
    print(f"🎲 ISSUING CHALLENGE: Flash {color_name}")
    client.publish("gateway/rgb_command", json.dumps({"color": color_name, "action": "FLASH"}))

def analyze_color(image_bytes, target_color_name):
    img = Image.open(io.BytesIO(image_bytes))
    stat = ImageStat.Stat(img)
    avg_color = stat.mean[:3]  # R, G, B
    
    print(f"📊 Image Average Color: {avg_color}")
    
    # Simple heuristic: is the target channel significantly higher?
    r, g, b = avg_color
    
    if target_color_name == "RED"     and r > g + 20 and r > b + 20: return True
    if target_color_name == "GREEN"   and g > r + 20 and g > b + 20: return True
    if target_color_name == "BLUE"    and b > r + 20 and b > g + 20: return True
    if target_color_name == "CYAN"    and g > r + 10 and b > r + 10: return True
    if target_color_name == "YELLOW"  and r > b + 10 and g > b + 10: return True
    if target_color_name == "MAGENTA" and r > g + 20 and b > g + 20: return True  # high R+B, low G
    return False  # no pattern matched → challenge failed

def on_message(client, userdata, msg):
    global current_challenge
    if current_challenge:
        try:
            data = json.loads(msg.payload.decode())
            image_b64 = data.get("image")
            
            if image_b64:
                image_data = base64.b64decode(image_b64)
                passed = analyze_color(image_data, current_challenge)
                
                if passed:
                    print(f"✅ CHALLENGE PASSED: Real environment verified ({current_challenge})")
                else:
                    print(f"🚨 CHALLENGE FAILED: Potential Video Injection detected!")
                
                current_challenge = None # Reset
                
        except Exception as e:
            print(f"❌ Error during challenge verification: {e}")

if __name__ == "__main__":
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    
    # Run in a loop, issuing a challenge every 10 seconds for testing
    # In production, this would be triggered by an RFID scan event
    try:
        while True:
            client.loop(timeout=1.0)
            if not current_challenge:
                time.sleep(5)
                issue_challenge(client)
    except KeyboardInterrupt:
        print("Stopping...")
