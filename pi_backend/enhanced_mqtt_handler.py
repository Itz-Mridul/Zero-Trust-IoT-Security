#!/usr/bin/env python3
"""
Enhanced MQTT Handler - Integration Layer
Connects: MQTT ← ML Authentication ← Blockchain Storage → Telegram Alerts
"""

import paho.mqtt.client as mqtt
import json
import sqlite3
import numpy as np
import pickle
from tensorflow import keras
from web3 import Web3
from collections import deque
import time
import os
import threading

# ============================================
# CONFIGURATION
# ============================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# MQTT
MQTT_BROKER = "localhost"
MQTT_PORT = 1883

# Heartbeat Monitoring
HEARTBEAT_TIMEOUT = 0.5  # Seconds (500ms)
last_heartbeat = {}
lockdown_active = False

# Database
DB_PATH = '/home/mridul/Master_IoT_Project/security.db'

# ML Model
MODEL_PATH = os.path.join(BASE_DIR, 'device_authenticator.h5')
SCALER_PATH = os.path.join(BASE_DIR, 'scaler.pkl')

# Blockchain — configured via env var (no hardcoded IPs)
BLOCKCHAIN_PROVIDER = os.environ.get("BLOCKCHAIN_URL", "http://127.0.0.1:7545")
CONTRACT_ADDRESS    = os.environ.get("CONTRACT_ADDRESS", "0xed299E909dfB6804093E5F71034aE33b3E3e64f5")

# ABI for the DeviceRegistry contract (from your deployment)
CONTRACT_ABI = [{"inputs": [{"internalType": "address","name": "_deviceAddr","type": "address"},{"internalType": "string","name": "_name","type": "string"},{"internalType": "uint256","name": "_fingerprint","type": "uint256"}],"name": "registerDevice","outputs": [],"stateMutability": "nonpayable","type": "function"},{"inputs": [],"stateMutability": "nonpayable","type": "constructor"},{"inputs": [{"internalType": "address","name": "","type": "address"}],"name": "devices","outputs": [{"internalType": "string","name": "name","type": "string"},{"internalType": "bool","name": "isAuthorized","type": "bool"},{"internalType": "uint256","name": "lastFingerprint","type": "uint256"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "address","name": "_deviceAddr","type": "address"}],"name": "isAllowed","outputs": [{"internalType": "bool","name": "","type": "bool"}],"stateMutability": "view","type": "function"},{"inputs": [],"name": "owner","outputs": [{"internalType": "address","name": "","type": "address"}],"stateMutability": "view","type": "function"}]

# Authentication threshold
CONFIDENCE_THRESHOLD = 75.0  # % confidence required to authenticate

# ============================================
# LOAD ML MODEL
# ============================================

print(f"\n🧠 Loading ML model...")
try:
    model = keras.models.load_model(MODEL_PATH)
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
    print(f"✅ Model loaded successfully")
except Exception as e:
    print(f"❌ Model loading failed: {e}")
    print(f"\n📝 Solution: Train model first")
    print(f"   python3 pi_backend/train_model.py")
    exit(1)

# ============================================
# CONNECT TO BLOCKCHAIN
# ============================================

print(f"\n⛓️  Connecting to blockchain...")
w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_PROVIDER))

if not w3.is_connected():
    print(f"❌ Blockchain connection failed")
    print(f"   Check that Ganache is running on your Mac at {BLOCKCHAIN_PROVIDER}")
    # exit(1) # Don't exit, allow ML-only mode if blockchain is down
else:
    print(f"✅ Blockchain connected")

# Load contract
try:
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS),
        abi=CONTRACT_ABI
    )
    print(f"✅ Smart contract loaded at {CONTRACT_ADDRESS}")
except Exception as e:
    print(f"⚠️  Contract loading failed: {e}")

# ============================================
# DEVICE HISTORY (for sequence classification)
# ============================================

# Store last 10 packets per device
device_history = {}
SEQ_LENGTH = 10

# Feature extraction order (MUST match training)
FEATURES = ['rssi', 'packet_size', 'free_heap', 'inter_packet_delay', 'temperature', 'humidity']

def authenticate_device(device_id, data):
    """
    Use ML model to verify device identity
    Returns: (confidence, status)
    """
    
    # Extract features
    features = [
        data.get('rssi', 0),
        data.get('packet_size', 0),
        data.get('free_heap', 0),
        data.get('inter_packet_delay', 0),
        data.get('temperature', 0) or 45.0,
        data.get('humidity', 0) or 50.0
    ]
    
    # Initialize history for new device
    if device_id not in device_history:
        device_history[device_id] = deque(maxlen=SEQ_LENGTH)
    
    # Add current features
    device_history[device_id].append(features)
    
    # Need minimum sequence length
    if len(device_history[device_id]) < SEQ_LENGTH:
        return 0, "COLLECTING_DATA"
    
    # Prepare sequence for model
    sequence = np.array([list(device_history[device_id])])
    
    # Scale sequence
    flat = sequence.reshape(-1, len(FEATURES))
    scaled_flat = scaler.transform(flat)
    sequence_scaled = scaled_flat.reshape(1, SEQ_LENGTH, len(FEATURES))
    
    # Predict
    prediction = model.predict(sequence_scaled, verbose=0)[0][0]
    confidence = float(prediction * 100)
    
    # Determine status
    if confidence >= CONFIDENCE_THRESHOLD:
        status = "AUTHENTICATED"
    else:
        status = "DENIED"
    
    return confidence, status

def monitor_heartbeats():
    """Background thread to detect missing heartbeats"""
    global lockdown_active
    while True:
        current_time = time.time()
        for device_id, last_time in list(last_heartbeat.items()):
            if current_time - last_time > HEARTBEAT_TIMEOUT:
                if not lockdown_active:
                    print(f"\n🚨 [DEAD-MAN'S SWITCH] Heartbeat lost for {device_id}!")
                    print(f"⚠️  TRIGGERING SECURITY LOCKDOWN - ALL RELAYS DISCONNECTED")
                    # Send lockdown command via MQTT
                    mqtt_client.publish("gateway/lockdown", json.dumps({"reason": "HEARTBEAT_LOST", "device_id": device_id}))
                    lockdown_active = True
            else:
                # If heartbeat returns, we could potentially reset lockdown (optional)
                pass
        time.sleep(0.1)

# ============================================
# MQTT CALLBACKS
# ============================================

def on_connect(client, userdata, flags, rc, properties=None):
    """MQTT connection callback"""
    if rc == 0:
        print(f"\n✅ Connected to MQTT broker")
        client.subscribe("gateway/heartbeat")
        client.subscribe("sentry/evidence")
        print(f"📡 Monitoring topics: gateway/heartbeat, sentry/evidence")
    else:
        print(f"❌ MQTT connection failed (code: {rc})")

def on_message(client, userdata, msg):
    """MQTT message callback"""
    try:
        data = json.loads(msg.payload.decode())
        
        if msg.topic == "gateway/heartbeat":
            device_id = data.get('device_id')
            
            # 1. AI Authentication
            confidence, status = authenticate_device(device_id, data)
            
            # 2. Blockchain Verification (if connected)
            blockchain_status = "N/A"
            if w3.is_connected():
                try:
                    # Note: You might need to map device_id to a wallet address here
                    # For now, we'll use the default account for testing
                    is_allowed = contract.functions.isAllowed(w3.eth.accounts[0]).call()
                    blockchain_status = "VERIFIED" if is_allowed else "UNAUTHORIZED"
                except Exception as bc_err:
                    blockchain_status = f"ERROR: {bc_err}"

            # 3. Update Dead-Man's Switch
            last_heartbeat[device_id] = time.time()
            if lockdown_active:
                print(f"🔄 Heartbeat restored for {device_id}. System resuming...")
                lockdown_active = False

            # Log result
            if status == "AUTHENTICATED":
                print(f"🔐 {device_id}: ✅ {status} ({confidence:.1f}%) | Blockchain: {blockchain_status}")
            else:
                print(f"🔐 {device_id}: ⛔ {status} ({confidence:.1f}%) | Blockchain: {blockchain_status} - ALERT!")
        
    except Exception as e:
        print(f"❌ Message error: {e}")

# ============================================
# START SERVICE
# ============================================

print(f"\n🚀 Starting Heartbeat Monitor thread...")
monitor_thread = threading.Thread(target=monitor_heartbeats, daemon=True)
monitor_thread.start()

print(f"\n🚀 Starting enhanced MQTT handler...")
mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message

mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)

print(f"\n" + "="*70)
print(f"✅ SYSTEM OPERATIONAL")
print(f"="*70)
mqtt_client.loop_forever()
