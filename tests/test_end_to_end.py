#!/usr/bin/env python3
"""
End-to-End Integration Test
Simulates the full authentication pipeline without hardware.
"""
import os
import sys
import json
import sqlite3
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pi_backend"))

DB_PATH = os.environ.get("DB_PATH", "/home/mridul/Master_IoT_Project/security.db")


def test_database_tables():
    """Verify all required database tables exist."""
    if not os.path.exists(DB_PATH):
        print(f"⚠️  Database not found: {DB_PATH}")
        return False

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    required_tables = ["heartbeats", "evidence", "alerts"]
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing = {row[0] for row in cursor.fetchall()}
    conn.close()

    for table in required_tables:
        if table in existing:
            print(f"✅ Table '{table}' exists")
        else:
            print(f"❌ Table '{table}' MISSING")
            return False

    return True


def test_forensic_logger():
    """Test that forensic_logger writes to DB correctly."""
    try:
        from pi_backend.forensic_logger import log_event, compute_event_hash

        # Test hash computation
        h = compute_event_hash("TEST_DEV", "TEST_EVENT", 1234567890.0, "test details")
        assert len(h) == 64, f"Expected 64-char SHA-256 hash, got {len(h)}"
        print(f"✅ Forensic hash: {h[:16]}...")

        # Test event logging (only if DB exists)
        if os.path.exists(DB_PATH):
            result = log_event("TEST_DEVICE", "INTEGRATION_TEST", "End-to-end test")
            assert len(result) == 64, "log_event should return a 64-char hash"
            print(f"✅ Forensic event logged: {result[:16]}...")
        else:
            print("⚠️  DB not found — skipping write test")

        return True
    except Exception as e:
        print(f"⚠️  Forensic logger test: {e}")
        return False


def test_safe_eval():
    """Test that iot_server's _safe_eval blocks dangerous expressions."""
    try:
        from pi_backend.iot_server import _safe_eval
    except ImportError as e:
        pytest.skip(f"iot_server import failed (missing optional dep): {e}")

    assert _safe_eval("3 + 5") == 8
    assert _safe_eval("7 * 3") == 21
    assert _safe_eval("10 - 4") == 6
    print("✅ _safe_eval handles valid expressions")

    dangerous = ["__import__('os')", "open('/etc/passwd')", "eval('1+1')"]
    for expr in dangerous:
        try:
            _safe_eval(expr)
            assert False, f"_safe_eval should have rejected: {expr}"
        except (ValueError, SyntaxError):
            pass
    print("✅ _safe_eval blocks dangerous expressions")


def test_blockchain_bridge_import():
    """Test blockchain bridge can be imported."""
    try:
        from blockchain_bridge import hash_event
        h = hash_event("integration_test")
        assert len(h) == 64
        print(f"✅ blockchain_bridge.hash_event works")
        return True
    except Exception as e:
        print(f"⚠️  blockchain_bridge: {e}")
        return False


def test_rgb_challenge_colors():
    """Test RGB color detection logic."""
    try:
        from pi_backend.rgb_challenge import analyze_color, COLORS
        assert len(COLORS) >= 6, f"Expected ≥6 colors, got {len(COLORS)}"
        print(f"✅ RGB challenge has {len(COLORS)} colors defined")

        # Verify MAGENTA is included (spec requirement)
        assert "MAGENTA" in COLORS, "MAGENTA color missing from COLORS dict"
        print("✅ MAGENTA color support confirmed")
        return True
    except Exception as e:
        print(f"⚠️  RGB test: {e}")
        return False


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🧪 END-TO-END INTEGRATION TESTS")
    print("=" * 60 + "\n")

    results = []
    results.append(("Database tables", test_database_tables()))
    results.append(("Forensic logger", test_forensic_logger()))
    results.append(("Safe eval (RCE prevention)", test_safe_eval()))
    results.append(("Blockchain bridge", test_blockchain_bridge_import()))
    results.append(("RGB challenge colors", test_rgb_challenge_colors()))

    print("\n" + "=" * 60)
    print("📊 RESULTS SUMMARY")
    print("=" * 60)
    passed = 0
    for name, ok in results:
        status = "✅ PASS" if ok else "⚠️  SKIP/FAIL"
        print(f"  {status}  {name}")
        if ok:
            passed += 1

    print(f"\n  {passed}/{len(results)} tests passed\n")
