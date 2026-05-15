import os
from dotenv import load_dotenv
from web3 import Web3

load_dotenv()
BLOCKCHAIN_URL   = os.getenv("BLOCKCHAIN_URL",   "http://127.0.0.1:7545")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "")

# Minimal ABI for SecurityRegistry (including RFID methods)
ABI = [
    {"inputs":[{"name":"uid","type":"string"}],"name":"isRfidRegistered",
     "outputs":[{"type":"bool"}],"stateMutability":"view","type":"function"},
]

w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))
if not w3.is_connected():
    print("Cannot connect to blockchain")
    exit(1)

contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=ABI)

uids = ["AABBCCDD", "11223344", "99999999"]
print(f"{'UID':<12} | {'Registered':<10}")
print("-" * 25)
for uid in uids:
    try:
        is_reg = contract.functions.isRfidRegistered(uid).call()
        print(f"{uid:<12} | {str(is_reg):<10}")
    except Exception as e:
        print(f"{uid:<12} | Error: {e}")
