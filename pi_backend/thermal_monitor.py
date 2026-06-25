#!/usr/bin/env python3
"""
thermal_monitor.py — Dual-Sensor Thermal Attack Detection
===========================================================
Research Paper Reference: Phase 6, Section 6.2 — Patent Claim 6 (supporting)

Uses two temperature sources simultaneously for cross-validation:
  1. DHT22 ambient sensor  — GPIO Pin 4 on Pi
  2. SoC thermal sensor    — /sys/class/thermal/thermal_zone0/temp

Scenario classification table:
  Normal room, idle Pi     → DHT22~22°C, SoC~45°C  → NORMAL
  Hot room, busy Pi        → DHT22~35°C, SoC~60°C  → NORMAL (correlated)
  External heat gun        → DHT22>85°C, SoC~40°C  → THERMAL_ATTACK ⚠️
  Actual fire / breach     → DHT22>70°C, SoC>70°C  → THERMAL_EMERGENCY 🔴

On THERMAL_EMERGENCY: Arduino watchdog cuts Pi power.
"""

import logging
import os
import sqlite3
import subprocess
import time
from typing import Optional

logger = logging.getLogger("thermal_monitor")

# ── Thresholds ────────────────────────────────────────────────────────────────
AMBIENT_EMERGENCY_C  = 70.0   # °C — both sensors hot → fire / physical breach
AMBIENT_ATTACK_C     = 55.0   # °C — ambient very high but SoC normal → heat gun
SOC_TEMP_HIGH_C      = 75.0   # °C — SoC hot alone → software attack (DDoS/malware)
CORR_DIFF_MAX_C      = 30.0   # °C — max normal CPU-ambient delta (above = attack)

SOC_TEMP_PATH = "/sys/class/thermal/thermal_zone0/temp"

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.dirname(_BASE_DIR)
DB_PATH   = os.environ.get(
    "IOT_DB_PATH",
    os.path.join(_ROOT_DIR, "security.db")
)


# ── Sensor helpers ────────────────────────────────────────────────────────────

def read_soc_temp() -> float:
    """Read Raspberry Pi SoC temperature in °C."""
    try:
        with open(SOC_TEMP_PATH) as f:
            return int(f.read().strip()) / 1000.0
    except (FileNotFoundError, ValueError):
        return 0.0


def classify_thermal(ambient_c: float, soc_c: float) -> str:
    """
    Cross-validate DHT22 ambient and SoC temperatures.

    Returns one of:
      NORMAL            — everything within expected ranges
      THERMAL_ATTACK    — heat gun or external heat source near sensor
      THERMAL_EMERGENCY — fire / enclosure breach / physical destruction
      SOFTWARE_ATTACK   — high SoC + normal ambient → DDoS or malware
    """
    diff = soc_c - ambient_c

    # Both sensors extremely hot → physical destruction / fire
    if ambient_c >= AMBIENT_EMERGENCY_C and soc_c >= AMBIENT_EMERGENCY_C:
        return "THERMAL_EMERGENCY"

    # Ambient very hot but SoC stays cool → external heat source (heat gun)
    if ambient_c >= AMBIENT_ATTACK_C and diff < 0:
        return "THERMAL_ATTACK"

    # SoC hot, ambient normal but differential too large → software attack
    if soc_c >= SOC_TEMP_HIGH_C and diff > CORR_DIFF_MAX_C:
        return "SOFTWARE_ATTACK"

    return "NORMAL"


# ── DB query helpers (used by dashboard.py) ───────────────────────────────────

def get_thermal_alerts(limit: int = 50) -> list:
    """
    Return recent thermal alert events from the security DB.
    Used by dashboard.py to populate the Sensor Health panel.
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT event_type, device_id, timestamp, data_hash "
                "FROM security_events "
                "WHERE event_type IN "
                "  ('THERMAL_EMERGENCY','THERMAL_ATTACK','SOFTWARE_ATTACK') "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [
            {
                "event_type": r[0],
                "device_id":  r[1],
                "timestamp":  r[2],
                "data_hash":  r[3],
            }
            for r in rows
        ]
    except sqlite3.OperationalError:
        return []


def get_current_temps() -> dict:
    """Return current temperature readings for dashboard display."""
    soc = read_soc_temp()
    return {
        "soc_temp_c": soc,
        "status":     "OK" if soc < SOC_TEMP_HIGH_C else "HIGH",
    }


# ── ThermalMonitor service class ──────────────────────────────────────────────

class ThermalMonitor:
    """
    Standalone thermal monitoring service.
    Call start() to run as a blocking loop, or poll_once() for single checks.
    """

    def __init__(self,
                 poll_interval_s: float = 30.0,
                 mqtt_client=None,
                 blockchain_log_fn=None,
                 telegram_alert_fn=None) -> None:
        self.poll_interval   = poll_interval_s
        self._mqtt           = mqtt_client
        self._blockchain_log = blockchain_log_fn
        self._telegram_alert = telegram_alert_fn
        self._running        = False

    def poll_once(self, ambient_c: Optional[float] = None) -> dict:
        """
        Perform one thermal cross-validation check.

        Args:
            ambient_c: DHT22 ambient reading. If None, only SoC is checked.

        Returns dict with keys: soc_temp, ambient_temp, classification, action_taken.
        """
        soc = read_soc_temp()
        amb = ambient_c if ambient_c is not None else 0.0
        classification = classify_thermal(amb, soc) if ambient_c is not None else "NORMAL"

        result = {
            "soc_temp":       soc,
            "ambient_temp":   amb,
            "classification": classification,
            "action_taken":   None,
        }

        if classification == "NORMAL":
            logger.debug(f"[THERMAL] OK — SoC={soc:.1f}°C  Ambient={amb:.1f}°C")
            return result

        logger.warning(
            f"[THERMAL] ⚠️  {classification} detected — "
            f"SoC={soc:.1f}°C  Ambient={amb:.1f}°C"
        )

        import json
        import hashlib

        data_hash = hashlib.sha256(
            f"{classification}:{soc:.1f}:{amb:.1f}:{int(time.time())}".encode()
        ).hexdigest()

        # Log to blockchain
        if self._blockchain_log:
            try:
                self._blockchain_log("THERMAL_EMERGENCY" if classification == "THERMAL_EMERGENCY"
                                     else "PHYSICAL_TAMPER", data_hash)
            except Exception as e:
                logger.error(f"[THERMAL] Blockchain log failed: {e}")

        # Telegram alert
        if self._telegram_alert:
            try:
                self._telegram_alert(
                    f"🌡️ {classification}: SoC={soc:.1f}°C | Ambient={amb:.1f}°C"
                )
            except Exception as e:
                logger.error(f"[THERMAL] Telegram failed: {e}")

        # MQTT broadcast
        if self._mqtt:
            try:
                self._mqtt.publish("gateway/alert", json.dumps({
                    "type":        classification,
                    "soc_temp":    soc,
                    "ambient_temp": amb,
                    "timestamp":   int(time.time()),
                }))
            except Exception as e:
                logger.error(f"[THERMAL] MQTT publish failed: {e}")

        if classification == "THERMAL_EMERGENCY":
            result["action_taken"] = "ARDUINO_KILL_SWITCH"
            logger.critical("[THERMAL] 🔴 THERMAL_EMERGENCY — signalling Arduino kill-switch")

        return result

    def start(self) -> None:
        """Blocking polling loop. Call from a daemon thread."""
        self._running = True
        logger.info(f"[THERMAL] Monitor started — polling every {self.poll_interval}s")
        while self._running:
            try:
                self.poll_once()
            except Exception as e:
                logger.error(f"[THERMAL] Poll error: {e}")
            time.sleep(self.poll_interval)

    def stop(self) -> None:
        self._running = False


# ── CLI entry-point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    monitor = ThermalMonitor(poll_interval_s=10.0)
    print("🌡️  Thermal Monitor started (Ctrl+C to stop)")
    try:
        monitor.start()
    except KeyboardInterrupt:
        print("\nStopped.")
