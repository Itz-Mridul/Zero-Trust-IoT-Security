#!/usr/bin/env python3
"""
Blockchain Bridge — logs every security event to Ganache
"""
import os
import json
import time
import logging
import threading
from flask import Flask, request, jsonify
from web3 import Web3
import paho.mqtt.client as mqtt
from dotenv import load_dotenv

load_dotenv(override=True)
log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

BLOCKCHAIN_URL   = os.getenv("BLOCKCHAIN_URL",   "http://127.0.0.1:7545")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "")
MQTT_BROKER      = os.getenv("MQTT_BROKER",      "localhost")

w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))
if not w3.is_connected():
    log.warning(f"⚠️  Cannot connect to blockchain at {BLOCKCHAIN_URL}. Running without blockchain.")


# Minimal ABI for SecurityRegistry
ABI = [
    {"inputs":[
        {"name":"deviceId","type":"string"},
        {"name":"eventType","type":"string"},
        {"name":"dataHash","type":"string"},
        {"name":"timestamp","type":"uint256"}
     ],"name":"logEvent","outputs":[{"type":"uint256"}],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"name":"uid","type":"string"}],"name":"isRfidRegistered",
     "outputs":[{"type":"bool"}],"stateMutability":"view","type":"function"},
    {"inputs":[{"name":"uid","type":"string"},{"name":"owner","type":"string"}],
     "name":"registerRfid","outputs":[],"stateMutability":"nonpayable","type":"function"},
]

try:
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS) if CONTRACT_ADDRESS else Web3.to_checksum_address("0x0000000000000000000000000000000000000000"),
        abi=ABI
    )
    deployer = w3.eth.accounts[0] if w3.eth.accounts else None
except Exception as e:
    log.error(f"Blockchain setup failed: {e}")
    deployer = None
    contract = None

app = Flask(__name__)

def log_to_chain(device_id: str, event_type: str, data_hash: str) -> str:
    if not contract or not deployer:
        return ""
    try:
        tx = contract.functions.logEvent(
            device_id, event_type, data_hash, int(time.time())
        ).transact({"from": deployer, "gas": 200000})
        receipt = w3.eth.wait_for_transaction_receipt(tx)
        tx_hash = receipt.transactionHash.hex()
        log.info(f"⛓️ Logged to blockchain: {tx_hash[:16]}...")
        return tx_hash
    except Exception as e:
        log.error(f"Blockchain log failed: {e}")
        return ""

@app.route("/check_rfid", methods=["POST"])
def check_rfid():
    uid = request.json.get("uid", "")
    secret_code = request.json.get("secret_code", "")
    
    # Duress Check
    if secret_code == "9999" or uid == "9999":
        log.warning(f"🚨 DURESS CODE DETECTED for UID {uid}")
        log_to_chain("SYSTEM", "DURESS_ALERT", f"uid={uid}")
        # In a real system, you might trigger a silent alarm here
        return jsonify({"registered": False, "duress": True})

    try:
        registered = contract.functions.isRfidRegistered(uid).call()
        return jsonify({"registered": registered, "duress": False})
    except Exception as e:
        log.error(f"Check RFID failed: {e}")
        return jsonify({"registered": False, "error": str(e), "duress": False})

@app.route("/register_rfid", methods=["POST"])
def register_rfid():
    uid   = request.json.get("uid", "")
    owner = request.json.get("owner", "ADMIN")
    if not contract or not deployer:
        return jsonify({"success": False, "error": "Blockchain not connected"})
    try:
        contract.functions.registerRfid(uid, owner).transact({"from": deployer})
        return jsonify({"success": True})
    except Exception as e:
        log.error(f"Register RFID failed: {e}")
        return jsonify({"success": False, "error": str(e)})

# MQTT listener for blockchain/log topic
def mqtt_logger():
    def on_msg(client, userdata, msg):
        try:
            d  = json.loads(msg.payload.decode())
            tx = log_to_chain(
                d.get("device","UNKNOWN"),
                d.get("event","EVENT"),
                d.get("hash","")
            )
            if tx:
                mqtt_pub.publish("blockchain/tx", json.dumps({"tx_hash": tx}))
        except Exception as e: 
            log.error(f"MQTT Error: {e}")

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    c.on_message = on_msg
    
    while True:
        try:
            c.connect(MQTT_BROKER, 1883, 60)
            c.subscribe("blockchain/log")
            log.info("⛓️ Connected to MQTT for blockchain logging")
            c.loop_forever()
        except Exception as e:
            log.error(f"MQTT connection failed: {e}. Retrying in 5s...")
            time.sleep(5)

mqtt_pub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
try:
    mqtt_pub.connect(MQTT_BROKER, 1883, 60)
except:
    pass

if __name__ == "__main__":
    threading.Thread(target=mqtt_logger, daemon=True).start()
    print("⛓️  Blockchain bridge: http://0.0.0.0:5010")
    app.run(host="0.0.0.0", port=5010, debug=False)
