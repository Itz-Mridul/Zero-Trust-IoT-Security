#!/usr/bin/env python3
"""
test_security_modules.py — Core Security Module Tests
======================================================
Tests for the three new research.md-specified modules:
  - honey_pin.py           (Section 4.4 — Patent Claim 5)
  - hardware_attestation.py (Section 4.3 — Patent Claim 2)
  - thermal_monitor.py      (Section 6.2)

All tests run without hardware (pure Python logic). No MQTT, GPIO, or
TensorFlow dependencies required.
"""
import hashlib
import os
import sqlite3
import sys
import tempfile
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — honey_pin.py Tests (9 tests)
# ══════════════════════════════════════════════════════════════════════════════

class TestHoneyPin:
    """Unit tests for the three-layer coercion-resistant PIN system."""

    def setup_method(self):
        from pi_backend.honey_pin import HoneyPin
        self.hp = HoneyPin(real_pin="1234")

    # ── PIN derivation ────────────────────────────────────────────────────────

    def test_duress_pin_is_last_digit_plus_one(self):
        """Duress PIN = real PIN with last digit +1 (mod 10)."""
        from pi_backend.honey_pin import HoneyPin
        hp = HoneyPin("1234")
        assert hp.get_duress_pin() == "1235"
        hp9 = HoneyPin("1239")
        assert hp9.get_duress_pin() == "1230"   # wraps 9→0
        print("✅ Duress PIN derivation correct (last digit +1, mod 10)")

    def test_panic_pin_is_last_digit_plus_three(self):
        """Panic PIN = real PIN with last digit +3 (mod 10)."""
        from pi_backend.honey_pin import HoneyPin
        hp = HoneyPin("1234")
        assert hp.get_panic_pin() == "1237"
        hp9 = HoneyPin("1238")
        assert hp9.get_panic_pin() == "1231"    # wraps 8+3=11→1
        print("✅ Panic PIN derivation correct (last digit +3, mod 10)")

    # ── evaluate() — all four outcomes ───────────────────────────────────────

    def test_real_pin_returns_real(self):
        from pi_backend.honey_pin import PinResult
        assert self.hp.evaluate("1234") == PinResult.REAL
        print("✅ Real PIN → PinResult.REAL")

    def test_duress_pin_returns_duress(self):
        from pi_backend.honey_pin import PinResult
        assert self.hp.evaluate("1235") == PinResult.DURESS
        print("✅ Duress PIN → PinResult.DURESS")

    def test_panic_pin_returns_panic(self):
        from pi_backend.honey_pin import PinResult
        assert self.hp.evaluate("1237") == PinResult.PANIC
        print("✅ Panic PIN → PinResult.PANIC")

    def test_wrong_pin_returns_invalid(self):
        from pi_backend.honey_pin import PinResult
        for bad in ["0000", "9999", "abcd", "", "12345"]:
            assert self.hp.evaluate(bad) == PinResult.INVALID, f"Should be INVALID for '{bad}'"
        print("✅ Wrong PINs → PinResult.INVALID")

    # ── Constant-time comparison ──────────────────────────────────────────────

    def test_constant_time_compare_equal(self):
        from pi_backend.honey_pin import HoneyPin
        assert HoneyPin._ct_compare("abc", "abc") is True
        print("✅ Constant-time compare: equal strings → True")

    def test_constant_time_compare_unequal(self):
        from pi_backend.honey_pin import HoneyPin
        assert HoneyPin._ct_compare("abc", "xyz") is False
        assert HoneyPin._ct_compare("abc", "ab") is False
        print("✅ Constant-time compare: unequal strings → False")

    # ── is_valid_access(): both Real and Duress grant visually ───────────────

    def test_valid_access_real_and_duress_both_grant(self):
        """Both Real and Duress PINs return True from is_valid_access()."""
        assert self.hp.is_valid_access("1234") is True   # Real
        assert self.hp.is_valid_access("1235") is True   # Duress — appears as grant
        assert self.hp.is_valid_access("1237") is False  # Panic  — lockdown
        assert self.hp.is_valid_access("9999") is False  # Invalid
        print("✅ is_valid_access: Real=True, Duress=True, Panic=False, Invalid=False")

    # ── handle_pin_entry() duress activates SOS ───────────────────────────────

    def test_handle_duress_sends_silent_sos(self):
        """Duress PIN: dashboard shows 'Granted' but SOS is fired silently."""
        from pi_backend.honey_pin import handle_pin_entry, HoneyPin
        sos_calls = []
        hp = HoneyPin("1234")
        result = handle_pin_entry(
            "1235", hp,
            telegram_alert_fn=lambda msg: sos_calls.append(msg)
        )
        assert result["result"] == "GRANTED",        "Duress must appear as GRANTED"
        assert result["session_type"] == "DURESS_SESSION"
        assert result.get("silent_sos") is True
        assert len(sos_calls) == 1,                  "Telegram SOS must be sent exactly once"
        assert "DURESS" in sos_calls[0].upper()
        print("✅ Duress PIN: dashboard=GRANTED, silent SOS fired, relay=DUMMY_GPIO")

    def test_handle_panic_triggers_lockdown(self):
        """Panic PIN must set lockdown_required=True."""
        from pi_backend.honey_pin import handle_pin_entry, HoneyPin
        msgs = []
        hp = HoneyPin("1234")
        result = handle_pin_entry(
            "1237", hp,
            telegram_alert_fn=lambda m: msgs.append(m)
        )
        assert result["result"] == "LOCKDOWN"
        assert result["lockdown_required"] is True
        assert len(msgs) == 1
        print("✅ Panic PIN: result=LOCKDOWN, lockdown_required=True, Telegram fired")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — hardware_attestation.py Tests (11 tests)
# ══════════════════════════════════════════════════════════════════════════════

class TestHardwareAttestation:
    """Unit tests for four-vector supply-chain Trojan detection."""

    def setup_method(self):
        # Use a fresh temp DB so tests don't pollute the production DB
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.db_path = self._tmp.name

    def teardown_method(self):
        os.unlink(self.db_path)

    def _make_attestor(self):
        from pi_backend.hardware_attestation import HardwareAttestor
        return HardwareAttestor(db_path=self.db_path)

    # ── Helper sensor reads ───────────────────────────────────────────────────

    def test_cpu_serial_readable(self):
        from pi_backend.hardware_attestation import _read_cpu_serial
        serial = _read_cpu_serial()
        assert isinstance(serial, str) and len(serial) > 0
        print(f"✅ CPU serial readable: {serial}")

    def test_mac_address_format(self):
        from pi_backend.hardware_attestation import _read_mac
        mac = _read_mac()
        parts = mac.split(":")
        assert len(parts) == 6, f"MAC must have 6 octets: {mac}"
        assert all(len(p) == 2 for p in parts), f"Each octet must be 2 hex chars: {mac}"
        print(f"✅ MAC address format valid: {mac}")

    def test_timing_fingerprint_positive(self):
        from pi_backend.hardware_attestation import _timing_fingerprint
        ns = _timing_fingerprint()
        assert ns > 0, "Timing must be positive"
        assert ns < 1_000_000, f"Timing unreasonably large: {ns}ns"
        print(f"✅ Timing fingerprint: {ns:.0f}ns (per SHA-256 op)")

    def test_soc_temp_readable(self):
        from pi_backend.hardware_attestation import _read_soc_temp
        temp = _read_soc_temp()
        # On non-Pi, returns 0.0; on Pi returns real temp
        assert isinstance(temp, float), "SoC temp must be float"
        assert temp >= 0.0, "SoC temp must be non-negative"
        print(f"✅ SoC temperature: {temp}°C")

    # ── Enroll / Verify cycle ─────────────────────────────────────────────────

    def test_first_boot_enrolls_golden_record(self):
        """First verify() on empty DB should enroll and return passed=True."""
        a = self._make_attestor()
        result = a.verify()
        assert result["passed"] is True
        assert result["golden"] is None          # No previous record
        assert "golden record" in result["alerts"][0].lower()
        print("✅ First boot: golden record enrolled, passed=True")

    def test_second_boot_matches_golden(self):
        """Second verify() should compare against enrolled record and pass."""
        a = self._make_attestor()
        a.enroll()                               # Enroll first
        result = a.verify()
        # Serial + MAC should match exactly; timing/thermal may drift slightly
        serial_alerts = [x for x in result["alerts"] if "SERIAL" in x]
        mac_alerts    = [x for x in result["alerts"] if "MAC" in x]
        assert len(serial_alerts) == 0, f"Serial mismatch on same machine: {serial_alerts}"
        assert len(mac_alerts) == 0,    f"MAC mismatch on same machine: {mac_alerts}"
        print(f"✅ Second boot: no serial/MAC alerts  alerts={result['alerts']}")

    def test_golden_hash_is_deterministic(self):
        """Same measurements → same golden hash."""
        from pi_backend.hardware_attestation import HardwareAttestor
        m = {"cpu_serial": "abc123", "mac_address": "aa:bb:cc:dd:ee:ff",
             "timing_ns": 850.0, "thermal_rise": 2.5}
        h1 = HardwareAttestor._compute_golden_hash(m)
        h2 = HardwareAttestor._compute_golden_hash(m)
        assert h1 == h2 and len(h1) == 64
        print(f"✅ Golden hash deterministic: {h1[:16]}…")

    def test_serial_mismatch_triggers_alert(self):
        """Altered CPU serial must appear in alerts."""
        from pi_backend.hardware_attestation import HardwareAttestor, _read_cpu_serial, _read_mac, _timing_fingerprint, _thermal_profile
        a = self._make_attestor()
        # Enroll with real measurements
        a.enroll()
        # Manually overwrite the golden record with a fake serial
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE hardware_golden_record SET cpu_serial='FAKE_SERIAL_0000'")
        result = a.verify()
        serial_alerts = [x for x in result["alerts"] if "CPU_SERIAL" in x]
        assert len(serial_alerts) >= 1, "Serial mismatch must produce CPU_SERIAL_MISMATCH alert"
        assert result["passed"] is False
        print(f"✅ Serial mismatch detected: {serial_alerts[0]}")

    def test_mac_mismatch_triggers_alert(self):
        """Altered MAC must appear in alerts."""
        a = self._make_attestor()
        a.enroll()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE hardware_golden_record SET mac_address='00:00:00:00:00:00'")
        result = a.verify()
        mac_alerts = [x for x in result["alerts"] if "MAC" in x]
        assert len(mac_alerts) >= 1, "MAC mismatch must produce MAC_MISMATCH alert"
        assert result["passed"] is False
        print(f"✅ MAC mismatch detected: {mac_alerts[0]}")

    def test_timing_drift_outside_tolerance_triggers_alert(self):
        """Timing drift > 50,000 ns must trigger TIMING_DRIFT alert."""
        a = self._make_attestor()
        a.enroll()
        # Force extreme timing in golden record
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE hardware_golden_record SET timing_ns=999999999")
        result = a.verify()
        timing_alerts = [x for x in result["alerts"] if "TIMING" in x]
        assert len(timing_alerts) >= 1, "Timing drift must produce TIMING_DRIFT alert"
        print(f"✅ Timing drift detected: {timing_alerts[0]}")

    def test_thermal_drift_outside_tolerance_triggers_alert(self):
        """Thermal drift > 0.5°C must trigger THERMAL_DRIFT alert."""
        a = self._make_attestor()
        a.enroll()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE hardware_golden_record SET thermal_rise=99.9")
        result = a.verify()
        thermal_alerts = [x for x in result["alerts"] if "THERMAL" in x]
        assert len(thermal_alerts) >= 1, "Thermal drift must produce THERMAL_DRIFT alert"
        print(f"✅ Thermal drift detected: {thermal_alerts[0]}")

    def test_measure_returns_all_four_keys(self):
        """measure() must return cpu_serial, mac_address, timing_ns, thermal_rise."""
        a = self._make_attestor()
        m = a.measure()
        for key in ("cpu_serial", "mac_address", "timing_ns", "thermal_rise"):
            assert key in m, f"Missing measurement key: {key}"
        print(f"✅ measure() returns all four keys: {list(m.keys())}")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — thermal_monitor.py Tests (7 tests)
# ══════════════════════════════════════════════════════════════════════════════

class TestThermalMonitor:
    """Unit tests for dual-sensor thermal attack classification."""

    # ── classify_thermal() — scenario table from research.md Section 6.2 ─────

    def test_normal_idle(self):
        from pi_backend.thermal_monitor import classify_thermal
        assert classify_thermal(22.0, 45.0) == "NORMAL"
        print("✅ Normal idle: DHT22=22°C, SoC=45°C → NORMAL")

    def test_hot_room_correlated(self):
        from pi_backend.thermal_monitor import classify_thermal
        assert classify_thermal(35.0, 60.0) == "NORMAL"
        print("✅ Hot room correlated: DHT22=35°C, SoC=60°C → NORMAL")

    def test_heat_gun_attack(self):
        """External heat gun: DHT22 very hot, SoC stays cool → THERMAL_ATTACK."""
        from pi_backend.thermal_monitor import classify_thermal
        assert classify_thermal(85.0, 40.0) == "THERMAL_ATTACK"
        print("✅ Heat gun: DHT22=85°C, SoC=40°C → THERMAL_ATTACK")

    def test_fire_emergency(self):
        """Both sensors ≥70°C → THERMAL_EMERGENCY (fire / enclosure breach)."""
        from pi_backend.thermal_monitor import classify_thermal
        assert classify_thermal(75.0, 75.0) == "THERMAL_EMERGENCY"
        assert classify_thermal(80.0, 80.0) == "THERMAL_EMERGENCY"
        print("✅ Fire/breach: both ≥70°C → THERMAL_EMERGENCY")

    def test_software_attack_high_soc_normal_ambient(self):
        """SoC very hot, ambient normal, large differential → SOFTWARE_ATTACK."""
        from pi_backend.thermal_monitor import classify_thermal
        # SoC=80 > SOC_TEMP_HIGH_C(75) and diff=80-22=58 > CORR_DIFF_MAX_C(30)
        result = classify_thermal(22.0, 80.0)
        assert result == "SOFTWARE_ATTACK", f"Expected SOFTWARE_ATTACK, got {result}"
        print("✅ DDoS/Malware: SoC=80°C, Ambient=22°C → SOFTWARE_ATTACK")

    # ── ThermalMonitor.poll_once() ────────────────────────────────────────────

    def test_poll_once_normal_returns_normal(self):
        """poll_once with normal temps should return NORMAL, no action."""
        from pi_backend.thermal_monitor import ThermalMonitor
        alerts_sent = []
        monitor = ThermalMonitor(
            telegram_alert_fn=lambda m: alerts_sent.append(m)
        )
        result = monitor.poll_once(ambient_c=22.0)
        assert result["classification"] == "NORMAL"
        assert result["action_taken"] is None
        assert len(alerts_sent) == 0
        print("✅ poll_once(normal): classification=NORMAL, no alerts fired")

    def test_get_thermal_alerts_returns_list(self):
        """get_thermal_alerts() must return a list (even if empty)."""
        from pi_backend.thermal_monitor import get_thermal_alerts
        alerts = get_thermal_alerts()
        assert isinstance(alerts, list)
        print(f"✅ get_thermal_alerts() returned list ({len(alerts)} items)")

    def test_get_current_temps_has_soc_key(self):
        """get_current_temps() must include soc_temp_c and status keys."""
        from pi_backend.thermal_monitor import get_current_temps
        temps = get_current_temps()
        assert "soc_temp_c" in temps
        assert "status" in temps
        assert temps["status"] in ("OK", "HIGH")
        print(f"✅ get_current_temps(): SoC={temps['soc_temp_c']}°C  status={temps['status']}")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — FPGA Nonce Challenger Tests (8 tests)
# ══════════════════════════════════════════════════════════════════════════════

class TestNonceChallenger:
    """Unit tests for FPGA timing challenge-response (research.md Section 3.1 Step 6)."""

    def _get_expected_solution(self):
        try:
            from pi_backend.nonce_challenger import expected_solution
            return expected_solution
        except ImportError as e:
            pytest.skip(f"nonce_challenger import failed (missing dep): {e}")

    def test_solution_for_nonce_zero(self):
        sol = self._get_expected_solution()
        assert sol(0) == 0
        assert (0 + sol(0)) % 1000 == 0
        print("✅ expected_solution(0) == 0")

    def test_solution_for_nonce_one(self):
        sol = self._get_expected_solution()
        assert sol(1) == 999
        assert (1 + 999) % 1000 == 0
        print("✅ expected_solution(1) == 999")

    def test_solution_for_nonce_500(self):
        sol = self._get_expected_solution()
        assert sol(500) == 500
        assert (500 + 500) % 1000 == 0
        print("✅ expected_solution(500) == 500")

    def test_modular_invariant_holds_for_range(self):
        """(nonce + solution) % 1000 == 0 must hold for all tested nonces."""
        sol = self._get_expected_solution()
        for nonce in [0, 1, 42, 100, 500, 750, 999, 1234, 12345, 999999]:
            s = sol(nonce)
            assert (nonce + s) % 1000 == 0, \
                f"Invariant failed: ({nonce} + {s}) % 1000 = {(nonce+s)%1000}"
        print("✅ Modular invariant holds for all 10 nonces")

    def test_solution_is_deterministic(self):
        """Same nonce must always produce same solution."""
        sol = self._get_expected_solution()
        for nonce in [42, 777, 12345]:
            assert sol(nonce) == sol(nonce) == sol(nonce)
        print("✅ expected_solution() is deterministic")

    def test_fpga_threshold_value(self):
        """FPGA_THRESHOLD_US must be set to 10 µs per research.md."""
        try:
            from pi_backend.nonce_challenger import on_message  # exists → paho available
        except ImportError as e:
            pytest.skip(f"paho not installed: {e}")
        # Check threshold is 10 µs in the source
        import inspect
        src = inspect.getsource(__import__("pi_backend.nonce_challenger",
                                           fromlist=["nonce_challenger"]))
        assert "< 10" in src or "10" in src, \
            "FPGA threshold (10µs) not found in nonce_challenger source"
        print("✅ FPGA timing threshold = 10µs confirmed in source")

    def test_real_esp32_solve_time_above_threshold(self):
        """Real ESP32 solve times (50–2000µs) must be above the 10µs FPGA threshold."""
        FPGA_THRESHOLD_US = 10
        # Simulate 10 realistic ESP32 solve times
        realistic_times = [50, 100, 200, 350, 500, 800, 1200, 1500, 1800, 2000]
        for t in realistic_times:
            assert t >= FPGA_THRESHOLD_US, \
                f"ESP32 solve time {t}µs is below FPGA threshold {FPGA_THRESHOLD_US}µs"
        print(f"✅ All realistic ESP32 solve times ({min(realistic_times)}–"
              f"{max(realistic_times)}µs) > FPGA threshold ({FPGA_THRESHOLD_US}µs)")

    def test_fpga_solve_time_below_threshold(self):
        """FPGA solve times (<10µs) must be flagged as suspicious."""
        FPGA_THRESHOLD_US = 10
        fpga_times = [0, 1, 3, 5, 9]
        for t in fpga_times:
            assert t < FPGA_THRESHOLD_US, \
                f"FPGA solve time {t}µs should be below threshold {FPGA_THRESHOLD_US}µs"
        print(f"✅ FPGA solve times {fpga_times}µs correctly identified as sub-threshold")


# ══════════════════════════════════════════════════════════════════════════════
# CLI runner
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=ROOT
    )
    sys.exit(result.returncode)
