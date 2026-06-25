#!/usr/bin/env python3
"""
Blockchain Bridge — REST API + MQTT Bridge for Ganache
=======================================================
Provides:
  - POST /check_rfid   → Verify RFID UID against blockchain registry
  - POST /register_rfid → Register new RFID UID on blockchain
  - MQTT listener on 'blockchain/log' → Logs events to chain
  - Publishes TX hashes to 'blockchain/tx' for dashboard display

Runs on port 5010.

Usage:
    python3 pi_backend/blockchain_bridge.py
"""

import json
import logging
import os
import sys
import threading
import time

# Add project root to path so we can import from pi_backend directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BLOCKCHAIN] %(levelname)s: %(message)s",
)
log = logging.getLogger(__name__)

BLOCKCHAIN_URL = os.environ.get("BLOCKCHAIN_URL", "http://127.0.0.1:7545")
CONTRACT_ADDRESS = os.environ.get("CONTRACT_ADDRESS", "")
MQTT_BROKER = os.environ.get("MQTT_BROKER", "localhost")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
BRIDGE_PORT = int(os.environ.get("BLOCKCHAIN_BRIDGE_PORT", "5010"))

# ── Web3 setup ─────────────────────────────────────────────────────────────────

_w3 = None
_contract = None
_deployer = None
_mqtt_pub = None


def _init_web3():
    """Initialize Web3 connection and contract. Fails gracefully."""
    global _w3, _contract, _deployer

    try:
        from web3 import Web3
    except ImportError:
        log.error("web3 not installed: pip install web3")
        return False

    _w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))

    if not _w3.is_connected():
        log.error(f"Cannot connect to blockchain at {BLOCKCHAIN_URL}")
        return False

    if not CONTRACT_ADDRESS:
        log.warning(
            "CONTRACT_ADDRESS not set — blockchain logging disabled. "
            "Deploy contract first and set CONTRACT_ADDRESS in .env"
        )
        return False

    # ABI for SecurityRegistry (logEvent, registerRfid, isRfidRegistered)
    abi = [
        {
            "inputs": [
                {"name": "deviceId", "type": "string"},
                {"name": "eventType", "type": "string"},
                {"name": "dataHash", "type": "string"},
                {"name": "timestamp", "type": "uint256"},
            ],
            "name": "logEvent",
            "outputs": [{"type": "uint256"}],
            "stateMutability": "nonpayable",
            "type": "function",
        },
        {
            "inputs": [{"name": "uid", "type": "string"}],
            "name": "isRfidRegistered",
            "outputs": [{"type": "bool"}],
            "stateMutability": "view",
            "type": "function",
        },
        {
            "inputs": [
                {"name": "uid", "type": "string"},
                {"name": "owner", "type": "string"},
            ],
            "name": "registerRfid",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function",
        },
        {
            "inputs": [{"name": "uid", "type": "string"}],
            "name": "emergencyRevoke",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function",
        },
    ]

    try:
        from web3 import Web3 as W3
        _contract = _w3.eth.contract(
            address=W3.to_checksum_address(CONTRACT_ADDRESS),
            abi=abi,
        )
        _deployer = _w3.eth.accounts[0]
        log.info(
            f"✅ Blockchain connected: {BLOCKCHAIN_URL} | "
            f"Contract: {CONTRACT_ADDRESS[:16]}..."
        )
        return True
    except Exception as exc:
        log.error(f"Contract load failed: {exc}")
        return False


# ── Public helpers (imported by forensic_logger, gateway_logic, tests) ─────────

import hashlib as _hashlib


def hash_event(event_data: str) -> str:
    """Return SHA-256 hex digest of an event string."""
    return _hashlib.sha256(event_data.encode("utf-8")).hexdigest()


def register_event_on_chain(device_name: str, fingerprint_score: int):
    """
    Compatibility wrapper used by forensic_logger.py and gateway_logic.
    Maps old registerDevice() interface to new logEvent() interface.
    Returns receipt-like object with .transactionHash, or None on failure.
    """
    data_hash = hash_event(f"{device_name}:{fingerprint_score}")
    tx = log_to_chain(device_name, "SECURITY_EVENT", data_hash)
    if tx:
        # Return a minimal receipt-like object so callers can do receipt.transactionHash.hex()
        class _Receipt:
            class transactionHash:
                @staticmethod
                def hex():
                    return tx
        return _Receipt()
    return None


# ── Blockchain functions ───────────────────────────────────────────────────────


def log_to_chain(device_id: str, event_type: str, data_hash: str) -> str:
    """Log a security event to the blockchain. Returns TX hash or empty string."""
    if _contract is None or _deployer is None:
        return ""

    try:
        tx = _contract.functions.logEvent(
            device_id, event_type, data_hash, int(time.time())
        ).transact({"from": _deployer, "gas": 200000})
        receipt = _w3.eth.wait_for_transaction_receipt(tx, timeout=10)
        tx_hash = receipt.transactionHash.hex()
        log.info(f"⛓️ Logged to blockchain: {tx_hash[:16]}...")
        return tx_hash
    except Exception as exc:
        log.error(f"Blockchain log failed: {exc}")
        return ""


def check_rfid_on_chain(uid: str) -> bool:
    """Check if an RFID UID is registered on the blockchain."""
    if _contract is None:
        return False
    try:
        return _contract.functions.isRfidRegistered(uid).call()
    except Exception:
        return False


def register_rfid_on_chain(uid: str, owner: str) -> bool:
    """Register an RFID UID on the blockchain."""
    if _contract is None or _deployer is None:
        return False
    try:
        _contract.functions.registerRfid(uid, owner).transact(
            {"from": _deployer}
        )
        log.info(f"✅ RFID registered: {uid} → {owner}")
        return True
    except Exception as exc:
        log.error(f"RFID registration failed: {exc}")
        return False


def revoke_rfid_on_chain(uid: str) -> bool:
    """Emergency revoke an RFID UID on the blockchain."""
    if _contract is None or _deployer is None:
        return False
    try:
        _contract.functions.emergencyRevoke(uid).transact(
            {"from": _deployer}
        )
        log.info(f"🚨 RFID revoked: {uid}")
        return True
    except Exception as exc:
        log.error(f"RFID revoke failed: {exc}")
        return False


# ── MQTT listener ──────────────────────────────────────────────────────────────


def _mqtt_logger_loop():
    """Background MQTT listener that logs events to blockchain."""
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        log.warning("paho-mqtt not installed — MQTT→blockchain disabled")
        return

    def on_msg(client, userdata, msg):
        try:
            d = json.loads(msg.payload.decode())
            tx = log_to_chain(
                d.get("device", d.get("device_id", "UNKNOWN")),
                d.get("event", d.get("event_type", "EVENT")),
                d.get("hash", d.get("data_hash", "")),
            )
            if tx and _mqtt_pub:
                _mqtt_pub.publish(
                    "blockchain/tx",
                    json.dumps({"tx_hash": tx}),
                )
        except Exception as exc:
            log.error(f"MQTT→blockchain error: {exc}")

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="BC_LOGGER")
    c.on_message = on_msg
    try:
        c.connect(MQTT_BROKER, MQTT_PORT, 60)
        c.subscribe("blockchain/log")
        c.loop_forever()
    except Exception as exc:
        log.error(f"MQTT logger connection failed: {exc}")


# ── Flask REST API ─────────────────────────────────────────────────────────────


def create_app():
    """Create the Flask app with blockchain endpoints."""
    from flask import Flask, request, jsonify

    app = Flask(__name__)

    @app.route("/check_rfid", methods=["POST"])
    def check_rfid():
        """Check if an RFID UID is registered on the blockchain."""
        data = request.get_json(silent=True) or {}
        uid = data.get("uid", "")
        if not uid:
            return jsonify({"registered": False, "error": "Missing uid"}), 400
        registered = check_rfid_on_chain(uid)
        return jsonify({"registered": registered, "uid": uid})

    @app.route("/register_rfid", methods=["POST"])
    def register_rfid():
        """Register a new RFID UID on the blockchain."""
        data = request.get_json(silent=True) or {}
        uid = data.get("uid", "")
        owner = data.get("owner", "ADMIN")
        if not uid:
            return jsonify({"success": False, "error": "Missing uid"}), 400
        success = register_rfid_on_chain(uid, owner)
        return jsonify({"success": success, "uid": uid, "owner": owner})

    @app.route("/revoke_rfid", methods=["POST"])
    def revoke_rfid():
        """Emergency revoke an RFID UID."""
        data = request.get_json(silent=True) or {}
        uid = data.get("uid", "")
        if not uid:
            return jsonify({"success": False, "error": "Missing uid"}), 400
        success = revoke_rfid_on_chain(uid)
        return jsonify({"success": success, "uid": uid})

    @app.route("/log_event", methods=["POST"])
    def log_event():
        """Manually log an event to the blockchain."""
        data = request.get_json(silent=True) or {}
        device = data.get("device_id", "MANUAL")
        event_type = data.get("event_type", "MANUAL_LOG")
        data_hash = data.get("data_hash", "")
        tx = log_to_chain(device, event_type, data_hash)
        return jsonify({"tx_hash": tx, "success": bool(tx)})

    @app.route("/health", methods=["GET"])
    def health():
        """Health check for the blockchain bridge."""
        connected = _w3 is not None and _w3.is_connected()
        return jsonify({
            "blockchain_connected": connected,
            "blockchain_url": BLOCKCHAIN_URL,
            "contract_address": CONTRACT_ADDRESS or "NOT_SET",
            "mqtt_broker": MQTT_BROKER,
        })

    return app


# ── Entry point ────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    import paho.mqtt.client as mqtt

    _init_web3()

    # Start MQTT publisher client
    _mqtt_pub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="BC_PUB")
    try:
        _mqtt_pub.connect(MQTT_BROKER, MQTT_PORT, 60)
        _mqtt_pub.loop_start()
    except Exception as exc:
        log.warning(f"MQTT publisher failed: {exc}")
        _mqtt_pub = None

    # Start MQTT→blockchain logger in background
    threading.Thread(target=_mqtt_logger_loop, daemon=True).start()

    # Start Flask REST API
    app = create_app()
    print(f"\n⛓️  Blockchain Bridge: http://0.0.0.0:{BRIDGE_PORT}")
    print(f"   Endpoints: /check_rfid, /register_rfid, /revoke_rfid, /log_event")
    print(f"   Health:    /health\n")
    app.run(host="0.0.0.0", port=BRIDGE_PORT, debug=False)
