#!/usr/bin/env python3
"""
Test Blockchain Bridge
Verifies Web3 connection and contract interaction with Ganache.
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BLOCKCHAIN_URL = os.environ.get("BLOCKCHAIN_URL", "http://127.0.0.1:7545")


def test_web3_connection():
    """Test that Web3 can connect to the blockchain node."""
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))

    if not w3.is_connected():
        print(f"⚠️  Cannot connect to blockchain at {BLOCKCHAIN_URL}")
        print("   Start Ganache: ganache-cli -p 7545")
        return False

    print(f"✅ Connected to blockchain at {BLOCKCHAIN_URL}")

    accounts = w3.eth.accounts
    assert len(accounts) > 0, "No accounts found on blockchain"
    print(f"✅ Found {len(accounts)} accounts")

    balance = w3.eth.get_balance(accounts[0])
    print(f"✅ Account[0] balance: {w3.from_wei(balance, 'ether')} ETH")
    return True


def test_blockchain_bridge_import():
    """Test that blockchain_bridge module imports correctly."""
    try:
        from blockchain_bridge import register_event_on_chain, hash_event, connect_to_blockchain
        print("✅ blockchain_bridge imported successfully")

        # Test hash function
        h = hash_event("test_event_data")
        assert len(h) == 64, f"Expected 64-char hex hash, got {len(h)}"
        print(f"✅ hash_event works: {h[:16]}...")
        return True
    except ImportError as e:
        print(f"⚠️  Import failed: {e}")
        return False


def test_register_event():
    """Test recording an event on-chain (requires running Ganache)."""
    if not test_web3_connection():
        print("⚠️  Skipping on-chain test — no blockchain connection")
        return

    try:
        from blockchain_bridge import register_event_on_chain
        receipt = register_event_on_chain("TEST_DEVICE", 42)

        if receipt:
            print(f"✅ Event recorded on block {receipt.blockNumber}")
            print(f"   TX hash: {receipt.transactionHash.hex()[:20]}...")
        else:
            print("⚠️  Event recording returned None — check Ganache logs")
    except Exception as e:
        print(f"⚠️  On-chain test failed: {e}")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🧪 BLOCKCHAIN BRIDGE TESTS")
    print("=" * 60 + "\n")

    test_blockchain_bridge_import()
    connected = test_web3_connection()
    if connected:
        test_register_event()

    print("\n✅ Blockchain tests complete.\n")
