import os
import sqlite3
import numpy as np
import pickle
import warnings
from tensorflow import keras
from web3 import Web3
from web3.exceptions import ContractLogicError

# Ignore minor warnings
warnings.filterwarnings("ignore", category=UserWarning)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

print("\n" + "="*60)
print("🛡️  IoT Zero-Trust Gatekeeper 🛡️")
print("="*60)

# ==========================================
# Phase 1: AI Hardware Fingerprinting
# ==========================================
print("\n[1] AI Phase: Authenticating Hardware Fingerprint...")

MODEL_PATH = os.path.join(BASE_DIR, 'device_authenticator.h5')
SCALER_PATH = os.path.join(BASE_DIR, 'scaler.pkl')
DB_PATH = '/home/mridul/Master_IoT_Project/security.db'
SEQ_LENGTH = 10
FEATURES = ['rssi', 'packet_size', 'free_heap', 'inter_packet_delay', 'temperature', 'humidity']

try:
    model = keras.models.load_model(MODEL_PATH)
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
except Exception as e:
    print(f"❌ Error loading AI model: {e}")
    exit(1)

# Fetch latest packets
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute(f"SELECT device_id, rssi, packet_size, free_heap, inter_packet_delay, temperature, humidity FROM heartbeats WHERE inter_packet_delay > 0 ORDER BY received_at DESC LIMIT {SEQ_LENGTH}")
rows = cursor.fetchall()
conn.close()

if len(rows) < SEQ_LENGTH:
    print(f"❌ Not enough data in live DB. Need {SEQ_LENGTH} consecutive packets.")
    exit(1)

rows.reverse()
features = []
for row in rows:
    features.append([row[1], row[2], row[3], row[4], row[5] or 45.0, row[6] or 50.0])

feature_array = np.array([features])
scaled_flat = scaler.transform(feature_array.reshape(-1, len(FEATURES)))
X_test = scaled_flat.reshape(1, SEQ_LENGTH, len(FEATURES))

prediction = model.predict(X_test, verbose=0)[0][0]
is_ai_authentic = prediction > 0.5

if is_ai_authentic:
    print(f"✅ AI AUTHENTICATED: Physical device timing matches ESP32 profile (Confidence: {prediction*100:.2f}%)")
else:
    print(f"🚨 AI ALERT: Software Spoofing Detected! (Confidence: {(1-prediction)*100:.2f}%)")


# ==========================================
# Phase 2: Blockchain Decentralized Registry
# ==========================================
print("\n[2] Blockchain Phase: Verifying Immutable Registry...")

BLOCKCHAIN_URL = os.environ.get("BLOCKCHAIN_URL", "http://127.0.0.1:7545")
w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))
contract_address = "0xed299E909dfB6804093E5F71034aE33b3E3e64f5"
device_wallet_address = Web3.to_checksum_address("0x5Fc5E9432BA7C493a7a9d66447eBD74d7171356E")

contract_abi = [{"inputs": [{"internalType": "address","name": "_deviceAddr","type": "address"},{"internalType": "string","name": "_name","type": "string"},{"internalType": "uint256","name": "_fingerprint","type": "uint256"}],"name": "registerDevice","outputs": [],"stateMutability": "nonpayable","type": "function"},{"inputs": [],"stateMutability": "nonpayable","type": "constructor"},{"inputs": [{"internalType": "address","name": "","type": "address"}],"name": "devices","outputs": [{"internalType": "string","name": "name","type": "string"},{"internalType": "bool","name": "isAuthorized","type": "bool"},{"internalType": "uint256","name": "lastFingerprint","type": "uint256"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "address","name": "_deviceAddr","type": "address"}],"name": "isAllowed","outputs": [{"internalType": "bool","name": "","type": "bool"}],"stateMutability": "view","type": "function"},{"inputs": [],"name": "owner","outputs": [{"internalType": "address","name": "","type": "address"}],"stateMutability": "view","type": "function"}]

is_blockchain_authentic = False

if not w3.is_connected():
    print("⚠️  Blockchain connection skipped (Ganache not reachable).")
else:
    try:
        contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=contract_abi)
        is_blockchain_authentic = contract.functions.isAllowed(device_wallet_address).call()
        if is_blockchain_authentic:
            print(f"✅ BLOCKCHAIN VERIFIED: Device is registered on the ledger.")
        else:
            print(f"❌ BLOCKCHAIN ALERT: Device is NOT registered.")
    except Exception as exc:
        print(f"⚠️  Blockchain verification failed: {exc}")


# ==========================================
# Final Access Decision
# ==========================================
print("\n[3] Final Zero-Trust Decision...")
if is_ai_authentic and is_blockchain_authentic:
    print("\n🟢 ACCESS GRANTED 🟢")
    print("Device is physically authentic (AI) AND registered on the ledger (Blockchain).")
else:
    print("\n🔴 ACCESS DENIED 🔴")
    if not is_ai_authentic:
        print("- Failed AI Physical Fingerprint Check")
    if not is_blockchain_authentic:
        print("- Failed Blockchain Registry Check")
print("="*60 + "\n")
