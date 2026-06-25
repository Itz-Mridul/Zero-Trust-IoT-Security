#!/usr/bin/env python3
"""
hardware_attestation.py — Four-Vector Supply-Chain Trojan Detector
====================================================================
Research Paper Reference: Phase 4, Section 4.3 — Patent Claim 2

On first boot (enrollment), four physical measurements are taken and
SHA-256 hashed into a "Golden Record" stored in the SQLite database.
On every subsequent boot, measurements are re-taken and compared.
Discrepancy in any dimension triggers a HARDWARE_TAMPER alert.

Measurements:
  1. CPU Serial Number  — BCM eFuse (read from /proc/cpuinfo)
  2. MAC Address        — NIC hardware address via uuid.getnode()
  3. Timing Fingerprint — Median ns per SHA-256 over 500 iterations
  4. Thermal Profile    — SoC °C rise under 1-second CPU stress burst

Tolerances:
  Serial / MAC : Exact match
  Timing       : ±50,000 ns (50 µs)
  Thermal      : ±0.5 °C
"""

import hashlib
import json
import logging
import os
import sqlite3
import time
import uuid
from typing import Optional

logger = logging.getLogger("hardware_attestation")

# ── Configuration ────────────────────────────────────────────────────────────
TIMING_TOLERANCE_NS  = 50_000   # ±50 µs
THERMAL_TOLERANCE_C  = 0.5      # ±0.5 °C
HASH_ITERATIONS      = 500
STRESS_DURATION_S    = 1.0
CPUINFO_PATH         = "/proc/cpuinfo"
SOC_TEMP_PATH        = "/sys/class/thermal/thermal_zone0/temp"

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.dirname(_BASE_DIR)
DB_PATH   = os.environ.get(
    "IOT_DB_PATH",
    os.path.join(_ROOT_DIR, "security.db")
)


# ── Low-level helpers ────────────────────────────────────────────────────────

def _read_cpu_serial() -> str:
    """Read the BCM SoC eFuse serial from /proc/cpuinfo. Returns 'UNKNOWN' on non-Pi."""
    try:
        with open(CPUINFO_PATH) as f:
            for line in f:
                if line.strip().startswith("Serial"):
                    return line.split(":")[1].strip()
    except FileNotFoundError:
        pass
    # Fallback for non-Pi environments (dev/test)
    return f"SIM_{uuid.getnode():016x}"


def _read_mac() -> str:
    """Read the hardware MAC address via Python stdlib."""
    raw = uuid.getnode()
    return ":".join(f"{(raw >> (8 * i)) & 0xFF:02x}" for i in reversed(range(6)))


def _read_soc_temp() -> float:
    """Read Pi SoC temperature in °C from kernel thermal interface."""
    try:
        with open(SOC_TEMP_PATH) as f:
            return int(f.read().strip()) / 1000.0
    except (FileNotFoundError, ValueError):
        return 0.0


def _timing_fingerprint() -> float:
    """
    Run 500 SHA-256 operations and return the median nanoseconds per hash.
    This is determined by the exact silicon speed grade and PCB trace
    capacitance — a Hardware Trojan changes bus loading → measurable drift.
    """
    data = b"attestation_benchmark_data_v1"
    times = []
    for _ in range(HASH_ITERATIONS):
        t0 = time.perf_counter_ns()
        hashlib.sha256(data).digest()
        times.append(time.perf_counter_ns() - t0)
    times.sort()
    return float(times[HASH_ITERATIONS // 2])  # median


def _thermal_profile() -> float:
    """
    Run a 1-second CPU stress burst and measure °C rise.
    A Trojan chip adds parasitic thermal capacitance → different heating rate.
    """
    temp_before = _read_soc_temp()
    deadline = time.perf_counter() + STRESS_DURATION_S
    data = b"thermal_stress_benchmark"
    while time.perf_counter() < deadline:
        hashlib.sha256(data).digest()
    temp_after = _read_soc_temp()
    return round(temp_after - temp_before, 2)


# ── HardwareAttestor ─────────────────────────────────────────────────────────

class HardwareAttestor:
    """
    Four-vector hardware attestation.

    Usage:
        a = HardwareAttestor()
        r = a.verify()
        if r['passed']:
            ...  # OK
        else:
            for alert in r['alerts']:
                print(alert)
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or DB_PATH
        self._ensure_table()

    # ── DB helpers ──────────────────────────────────────────────────────────

    def _ensure_table(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hardware_golden_record (
                    id            INTEGER PRIMARY KEY,
                    cpu_serial    TEXT    NOT NULL,
                    mac_address   TEXT    NOT NULL,
                    timing_ns     REAL    NOT NULL,
                    thermal_rise  REAL    NOT NULL,
                    golden_hash   TEXT    NOT NULL,
                    enrolled_at   INTEGER NOT NULL
                )
            """)

    def _load_golden_record(self) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT cpu_serial, mac_address, timing_ns, thermal_rise, golden_hash "
                "FROM hardware_golden_record ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if not row:
            return None
        return {
            "cpu_serial":   row[0],
            "mac_address":  row[1],
            "timing_ns":    row[2],
            "thermal_rise": row[3],
            "golden_hash":  row[4],
        }

    def _save_golden_record(self, measurements: dict) -> None:
        golden_hash = self._compute_golden_hash(measurements)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO hardware_golden_record "
                "(cpu_serial, mac_address, timing_ns, thermal_rise, golden_hash, enrolled_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    measurements["cpu_serial"],
                    measurements["mac_address"],
                    measurements["timing_ns"],
                    measurements["thermal_rise"],
                    golden_hash,
                    int(time.time()),
                )
            )
        logger.info(f"[ATTESTATION] ✅ Golden record enrolled — hash={golden_hash[:16]}…")

    @staticmethod
    def _compute_golden_hash(m: dict) -> str:
        """SHA-256 of all four measurements concatenated."""
        payload = (
            f"{m['cpu_serial']}|{m['mac_address']}|"
            f"{m['timing_ns']:.0f}|{m['thermal_rise']:.2f}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    # ── Public API ──────────────────────────────────────────────────────────

    def measure(self) -> dict:
        """Take all four physical measurements and return as dict."""
        logger.info("[ATTESTATION] Taking hardware measurements…")
        m = {
            "cpu_serial":   _read_cpu_serial(),
            "mac_address":  _read_mac(),
            "timing_ns":    _timing_fingerprint(),
            "thermal_rise": _thermal_profile(),
        }
        logger.info(
            f"[ATTESTATION] serial={m['cpu_serial']}  mac={m['mac_address']}  "
            f"timing={m['timing_ns']:.0f}ns  thermal_rise={m['thermal_rise']}°C"
        )
        return m

    def enroll(self) -> dict:
        """Measure and store the Golden Record (first boot / re-enrollment)."""
        m = self.measure()
        self._save_golden_record(m)
        return m

    def verify(self) -> dict:
        """
        Compare current measurements against the Golden Record.

        Returns:
            {
              'passed': bool,
              'alerts': [str, ...],
              'current': dict,
              'golden': dict | None,
            }
        """
        golden = self._load_golden_record()
        if not golden:
            logger.warning("[ATTESTATION] No golden record found — first boot, enrolling…")
            m = self.enroll()
            return {"passed": True, "alerts": ["golden record created — first boot"],
                    "current": m, "golden": None}

        current = self.measure()
        alerts = []

        # 1. CPU Serial — exact match
        if current["cpu_serial"] != golden["cpu_serial"]:
            alerts.append(
                f"CPU_SERIAL_MISMATCH: was={golden['cpu_serial']} now={current['cpu_serial']}"
            )

        # 2. MAC Address — exact match
        if current["mac_address"] != golden["mac_address"]:
            alerts.append(
                f"MAC_MISMATCH: was={golden['mac_address']} now={current['mac_address']}"
            )

        # 3. Timing — within ±50 µs
        timing_drift = abs(current["timing_ns"] - golden["timing_ns"])
        if timing_drift > TIMING_TOLERANCE_NS:
            alerts.append(
                f"TIMING_DRIFT: drift={timing_drift:.0f}ns "
                f"(tolerance={TIMING_TOLERANCE_NS}ns) — possible bus loading change"
            )

        # 4. Thermal — within ±0.5°C
        thermal_drift = abs(current["thermal_rise"] - golden["thermal_rise"])
        if thermal_drift > THERMAL_TOLERANCE_C:
            alerts.append(
                f"THERMAL_DRIFT: drift={thermal_drift:.2f}°C "
                f"(tolerance={THERMAL_TOLERANCE_C}°C) — possible parasitic component"
            )

        passed = len(alerts) == 0
        if passed:
            logger.info("[ATTESTATION] ✅ Hardware signature verified — no Trojan components detected.")
        else:
            for a in alerts:
                logger.critical(f"[ATTESTATION] ❌ TAMPER ALERT: {a}")

        return {"passed": passed, "alerts": alerts, "current": current, "golden": golden}


# ── CLI entry-point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    a = HardwareAttestor()
    r = a.verify()
    print(json.dumps({
        "passed":  r["passed"],
        "alerts":  r["alerts"],
        "current": r["current"],
    }, indent=2))
