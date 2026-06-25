import hashlib
import json
import os
import time
from web3 import Web3


# ---------------- CONFIGURATION ----------------

BLOCKCHAIN_URL = os.environ.get("BLOCKCHAIN_URL", "http://10.238.130.167:7545")  # Mac Ganache fallback
CONTRACT_ADDRESS = os.environ.get("CONTRACT_ADDRESS", "")

# ABI for SecurityRegistry (matching blockchain_bridge.py and SecurityRegistry.sol)
ABI_JSON = '''
[
    {
        "inputs": [
            {"name": "deviceId", "type": "string"},
            {"name": "eventType", "type": "string"},
            {"name": "dataHash", "type": "string"},
            {"name": "timestamp", "type": "uint256"}
        ],
        "name": "logEvent",
        "outputs": [{"type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getTotalEvents",
        "outputs": [{"type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]
'''

# ---------------- SETUP ----------------

w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))

def connect_to_blockchain():
    if not w3.is_connected():
        raise ConnectionError(f"Connection failed to {BLOCKCHAIN_URL}")

def load_contract():
    if not CONTRACT_ADDRESS:
        raise ValueError("CONTRACT_ADDRESS not set in environment.")
    abi = json.loads(ABI_JSON)
    return w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=abi)

# ---------------- BLOCKCHAIN FUNCTION ----------------

def register_event_on_chain(device_name, event_hash, event_type="SECURITY_EVENT"):
    """
    Logs a security event to the SecurityRegistry contract.
    """
    try:
        connect_to_blockchain()
        contract = load_contract()
        accounts = w3.eth.accounts
        if not accounts:
            raise RuntimeError("No accounts found.")
        
        sender = accounts[0]
        
        # logEvent(deviceId, eventType, dataHash, timestamp)
        tx_hash = contract.functions.logEvent(
            device_name,
            event_type,
            str(event_hash),
            int(time.time())
        ).transact({"from": sender})
        
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"[BLOCKCHAIN] Event secured: {tx_hash.hex()}")
        return receipt
    except Exception as e:
        print(f"[BLOCKCHAIN] Error: {e}")
        return None

def send_to_blockchain(device_id, fingerprint_score):
    """Compatibility wrapper for forensic_logger."""
    return register_event_on_chain(device_id, fingerprint_score, "ACCESS_ATTEMPT")
