#!/usr/bin/env python3
"""
honey_pin.py — Three-Layer Coercion-Resistant PIN System
=========================================================
Research Paper Reference: Phase 4, Section 4.4 — Patent Claim 5

PIN tiers:
  Real PIN   → Normal access.
  Duress PIN → (last digit +1) Appears to grant access; silently sends SOS.
               Door relay rerouted to dummy GPIO (stays locked).
  Panic PIN  → (last digit +3) Full lockdown + blockchain locked read-only.

All three hashes are compared via constant-time XOR (no early exit) to
prevent timing side-channel attacks.
"""

import hashlib
import logging
import os
import time
from enum import Enum
from typing import Optional

logger = logging.getLogger("honey_pin")


class PinResult(Enum):
    INVALID = "INVALID"
    REAL    = "REAL"
    DURESS  = "DURESS"
    PANIC   = "PANIC"


class HoneyPin:
    """Three-layer coercion-resistant PIN evaluator with constant-time comparison."""

    def __init__(self, real_pin: Optional[str] = None) -> None:
        pin = real_pin or os.environ.get("REAL_PIN", "1234")
        self._real_pin   = pin
        self._duress_pin = self._derive_pin(pin, offset=1)
        self._panic_pin  = self._derive_pin(pin, offset=3)
        self._real_hash   = self._hash(self._real_pin)
        self._duress_hash = self._hash(self._duress_pin)
        self._panic_hash  = self._hash(self._panic_pin)
        logger.info("[HoneyPIN] ✅ Three-layer PIN architecture active")

    @staticmethod
    def _derive_pin(pin: str, offset: int) -> str:
        """Increment the last digit by offset (mod 10)."""
        if not pin:
            return pin
        return pin[:-1] + str((int(pin[-1]) + offset) % 10)

    @staticmethod
    def _hash(pin: str) -> str:
        return hashlib.sha256(pin.encode("utf-8")).hexdigest()

    @staticmethod
    def _ct_compare(a: str, b: str) -> bool:
        """Constant-time comparison — prevents timing side-channel attacks."""
        result = 0
        a = a.ljust(len(b), "\x00")
        b = b.ljust(len(a), "\x00")
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        return result == 0

    def evaluate(self, entered_pin: str) -> PinResult:
        """Evaluate PIN against all three layers simultaneously (no early exit)."""
        h = self._hash(entered_pin)
        is_real   = self._ct_compare(h, self._real_hash)
        is_duress = self._ct_compare(h, self._duress_hash)
        is_panic  = self._ct_compare(h, self._panic_hash)
        if is_panic:
            logger.critical("[HoneyPIN] 🚨 PANIC PIN — Full lockdown")
            return PinResult.PANIC
        if is_duress:
            logger.warning("[HoneyPIN] ⚠️  DURESS PIN — Honeypot auth active")
            return PinResult.DURESS
        if is_real:
            logger.info("[HoneyPIN] ✅ Real PIN accepted")
            return PinResult.REAL
        return PinResult.INVALID

    def is_valid_access(self, entered_pin: str) -> bool:
        """True for Real OR Duress (both appear to grant access to an attacker)."""
        return self.evaluate(entered_pin) in (PinResult.REAL, PinResult.DURESS)

    def get_session_type(self, entered_pin: str) -> str:
        mapping = {
            PinResult.REAL:    "REAL_SESSION",
            PinResult.DURESS:  "DURESS_SESSION",
            PinResult.PANIC:   "PANIC_SESSION",
            PinResult.INVALID: "REJECTED",
        }
        return mapping[self.evaluate(entered_pin)]

    def get_duress_pin(self) -> str:
        return self._duress_pin

    def get_panic_pin(self) -> str:
        return self._panic_pin


def handle_pin_entry(pin, honey_pin, publish_fn=None, blockchain_log_fn=None,
                     telegram_alert_fn=None) -> dict:
    """Full PIN entry handler called by iot_server.py."""
    import json
    result = honey_pin.evaluate(pin)

    if result == PinResult.REAL:
        return {"result": "GRANTED", "session_type": "REAL_SESSION",
                "dashboard_message": "✅ Access Granted", "lockdown_required": False}

    elif result == PinResult.DURESS:
        logger.critical("[HoneyPIN] DURESS MODE — activating honeypot response")
        if telegram_alert_fn:
            try:
                telegram_alert_fn("🚨 DURESS PIN — Admin under coercion! Silent SOS activated.")
            except Exception as e:
                logger.error(f"[HoneyPIN] Telegram SOS failed: {e}")
        if blockchain_log_fn:
            try:
                dh = hashlib.sha256(f"DURESS:{int(time.time())}".encode()).hexdigest()
                blockchain_log_fn("DURESS_DETECTED", dh)
            except Exception as e:
                logger.error(f"[HoneyPIN] Blockchain log failed: {e}")
        if publish_fn:
            try:
                publish_fn("security/duress", json.dumps(
                    {"event": "DURESS_SESSION", "timestamp": int(time.time()),
                     "action": "RELAY_REROUTED_TO_DUMMY_GPIO"}))
            except Exception as e:
                logger.error(f"[HoneyPIN] MQTT publish failed: {e}")
        return {"result": "GRANTED", "session_type": "DURESS_SESSION",
                "dashboard_message": "✅ Access Granted", "lockdown_required": False,
                "relay_action": "DUMMY_GPIO", "silent_sos": True}

    elif result == PinResult.PANIC:
        logger.critical("[HoneyPIN] PANIC PIN — full system lockdown")
        if telegram_alert_fn:
            try:
                telegram_alert_fn("🚨🚨 PANIC PIN — FULL LOCKDOWN! Emergency response required.")
            except Exception as e:
                logger.error(f"[HoneyPIN] Panic Telegram failed: {e}")
        if blockchain_log_fn:
            try:
                dh = hashlib.sha256(f"PANIC:{int(time.time())}".encode()).hexdigest()
                blockchain_log_fn("PANIC_LOCKDOWN", dh)
            except Exception as e:
                logger.error(f"[HoneyPIN] Panic blockchain failed: {e}")
        if publish_fn:
            try:
                publish_fn("security/lockdown", json.dumps(
                    {"event": "PANIC_LOCKDOWN", "timestamp": int(time.time()),
                     "action": "FULL_LOCKDOWN"}))
            except Exception as e:
                logger.error(f"[HoneyPIN] Panic MQTT failed: {e}")
        return {"result": "LOCKDOWN", "session_type": "PANIC_SESSION",
                "dashboard_message": "🔴 System Lockdown Initiated", "lockdown_required": True}

    return {"result": "DENIED", "session_type": "REJECTED",
            "dashboard_message": "❌ Access Denied", "lockdown_required": False}


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(name)s %(message)s")
    real = os.environ.get("REAL_PIN", "1234")
    hp = HoneyPin(real_pin=real)
    print(f"\n🔐 HoneyPIN Self-Test  Real={real}  Duress={hp.get_duress_pin()}  Panic={hp.get_panic_pin()}\n")
    tests = [(real, PinResult.REAL), (hp.get_duress_pin(), PinResult.DURESS),
             (hp.get_panic_pin(), PinResult.PANIC), ("9999", PinResult.INVALID)]
    all_pass = True
    for p, expected in tests:
        got = hp.evaluate(p)
        ok = got == expected
        if not ok:
            all_pass = False
        print(f"  [{'✅ PASS' if ok else '❌ FAIL'}] PIN={p!r}  Expected={expected.value}  Got={got.value}")
    print("\n✅ All tests passed!" if all_pass else "\n❌ Some tests FAILED!")
