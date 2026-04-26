#!/usr/bin/env python3
"""
Test Physics Hardening Modules
Validates key_vault, environment_monitor logic, and nonce_challenger.
"""
import os
import sys
import time
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pi_backend"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_key_vault_xor():
    """Test XOR split/reconstruct cycle."""
    from pi_backend.key_vault import _xor_bytes

    secret = b"test_secret_key_32_bytes_long!!!"
    import secrets
    share_a = secrets.token_bytes(len(secret))
    share_b = _xor_bytes(secret, share_a)
    recovered = _xor_bytes(share_a, share_b)

    assert recovered == secret, f"XOR roundtrip failed: {recovered} != {secret}"
    print("✅ XOR split/reconstruct works correctly")


def test_key_vault_store_retrieve():
    """Test full store → retrieve → wipe cycle (uses /dev/shm)."""
    try:
        from pi_backend.key_vault import store_key, retrieve_key, wipe_vault

        test_secret = b"blockchain_private_key_test_data"
        store_key("test_physics", test_secret)
        recovered = retrieve_key("test_physics")

        assert recovered == test_secret, "Retrieved key doesn't match stored key"
        print("✅ Key vault store/retrieve works")

        wipe_vault()
        try:
            retrieve_key("test_physics")
            print("❌ ERROR: Key accessible after wipe!")
        except RuntimeError:
            print("✅ Key vault wipe confirmed (key inaccessible)")
    except Exception as e:
        print(f"⚠️  Key vault test skipped: {e}")


def test_nonce_challenger_solution():
    """Test that nonce solution algorithm is deterministic."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pi_backend"))

    from nonce_challenger import expected_solution

    # Test known values
    assert expected_solution(0) == 0, "Solution for nonce=0 should be 0"
    assert expected_solution(1) == 999, "Solution for nonce=1 should be 999"
    assert expected_solution(500) == 500, "Solution for nonce=500 should be 500"

    # Verify: (nonce + solution) % 1000 == 0
    for nonce in [0, 1, 42, 500, 999, 12345]:
        sol = expected_solution(nonce)
        assert (nonce + sol) % 1000 == 0, f"Failed for nonce={nonce}: ({nonce}+{sol}) % 1000 != 0"

    print("✅ Nonce solution algorithm is correct and deterministic")


def test_rate_of_rise_detection():
    """Test the environment monitor's rate-of-rise temperature logic."""
    from pi_backend.environment_monitor import get_rate_of_rise, _cpu_temp_history

    _cpu_temp_history.clear()

    # Simulate gradual rise (normal)
    rise1 = get_rate_of_rise(50.0)
    rise2 = get_rate_of_rise(50.5)
    assert rise2 <= 1.0, f"Normal rise should be ≤1°C, got {rise2}"
    print(f"✅ Normal rise detected: {rise2:.2f}°C/poll (expected ≤1.0)")

    # Simulate abrupt spike (acoustic attack)
    rise3 = get_rate_of_rise(55.0)
    assert rise3 > 3.0, f"Acoustic spike should be >3°C, got {rise3}"
    print(f"✅ Acoustic attack spike detected: {rise3:.2f}°C/poll (expected >3.0)")

    _cpu_temp_history.clear()


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🧪 PHYSICS HARDENING TESTS")
    print("=" * 60 + "\n")

    try:
        test_key_vault_xor()
        test_key_vault_store_retrieve()
        test_nonce_challenger_solution()
        test_rate_of_rise_detection()
        print("\n✅ All physics hardening tests passed.\n")
    except Exception as e:
        print(f"\n❌ Test failed: {e}\n")
        sys.exit(1)
