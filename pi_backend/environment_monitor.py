#!/usr/bin/env python3
"""
environment_monitor.py — Differential Thermal Logic + Kinetic Tamper Defense

Layer 3: Physical & Environmental Sabotage Defense
  - High CPU + Low Ambient  → Software Attack  (DDoS / Malware running on Pi)
  - High CPU + High Ambient → Physical Sabotage (HVAC cut / Heat Gun / Lighter)
  - Vibration Sensor (SW-420) → Kinetic Wipe (volatile RAM kill)

ACOUSTIC OVERCLOCKING DEFENSE (new — hello.py)
  - Attacker plays high-frequency sound → crystal oscillator jitter → CPU
    temp spikes identically to a software DDoS → old logic can't distinguish.
  - Fix: track rate-of-rise (°C per poll). Legitimate software load heats the
    CPU gradually. An acoustic resonance event causes an *abrupt* spike that
    exceeds RATE_OF_RISE_THRESHOLD regardless of the DT pattern.
"""
import paho.mqtt.client as mqtt
import json
import os
import sys
import subprocess
import time
from collections import deque

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
MQTT_BROKER   = "localhost"
MQTT_PORT     = 1883

AMBIENT_TEMP_THRESHOLD  = 70.0   # °C — emergency shutdown if DHT22 exceeds this
CPU_TEMP_THRESHOLD      = 75.0   # °C — CPU hot enough to flag an attack
DIFFERENTIAL_THRESHOLD  = 15.0   # °C — CPU vs Ambient delta for software-attack flag

# Acoustic Overclocking defense — rate-of-rise
# Legitimate DDoS heats CPU at ~0.5–1 °C/poll under load.
# Acoustic resonance causes abrupt spikes > 3 °C/poll.
RATE_OF_RISE_THRESHOLD  = 3.0    # °C per reading — above this = acoustic attack
RATE_HISTORY_LEN        = 5      # sliding window of temperature readings

TAMPER_TOPIC = "gateway/tamper"
ENV_TOPIC    = "mailbox/environment"

# Sliding window of recent CPU temps for rate-of-rise calculation
_cpu_temp_history: deque = deque(maxlen=RATE_HISTORY_LEN)
_last_poll_time: float   = 0.0

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("🛡️  Environmental Monitoring Service Active")
        client.subscribe(ENV_TOPIC)
        client.subscribe(TAMPER_TOPIC)
    else:
        print(f"❌ Connection failed: {rc}")

def get_cpu_temp() -> float:
    """Read Raspberry Pi CPU temperature from the kernel thermal interface."""
    try:
        result = subprocess.run(
            ["cat", "/sys/class/thermal/thermal_zone0/temp"],
            capture_output=True, text=True, timeout=2
        )
        return int(result.stdout.strip()) / 1000.0   # millidegrees → °C
    except Exception:
        return 0.0


def get_rate_of_rise(current_temp: float) -> float:
    """
    Calculate the per-reading rise rate of CPU temperature.
    An abrupt spike > RATE_OF_RISE_THRESHOLD indicates acoustic resonance,
    not legitimate software load (which heats gradually).
    """
    global _last_poll_time
    _cpu_temp_history.append(current_temp)
    _last_poll_time = time.time()

    if len(_cpu_temp_history) < 2:
        return 0.0

    # Max rise over the last two readings
    rise = _cpu_temp_history[-1] - _cpu_temp_history[-2]
    return rise


def trigger_emergency_shutdown(reason: str, event_type: str = "TAMPER") -> None:
    """Wipe volatile keys and halt. Logs to forensic trail before exit."""
    print(f"\n🛑 EMERGENCY SHUTDOWN TRIGGERED: {reason}")
    print("🧨 WIPING VOLATILE RAM (keys, sessions)...")

    # --- Use key_vault for guaranteed secure wipe ---
    try:
        import sys as _sys
        _sys.path.insert(0, "/home/mridul/Master_IoT_Project")
        from pi_backend.key_vault import wipe_vault
        wipe_vault()
    except Exception as kve:
        # Fallback: manual wipe of /dev/shm if key_vault is unavailable
        print(f"⚠️  key_vault wipe failed ({kve}), attempting manual wipe...")
        shm_key_dir = "/dev/shm/iot_keys"
        if os.path.exists(shm_key_dir):
            for fname in os.listdir(shm_key_dir):
                try:
                    os.remove(os.path.join(shm_key_dir, fname))
                except OSError:
                    pass

    # Attempt forensic log before dying
    try:
        import sys as _sys
        _sys.path.insert(0, "/home/mridul/Master_IoT_Project")
        from pi_backend.forensic_logger import log_tamper, log_thermal
        if event_type == "THERMAL":
            log_thermal("VAULT_ENV_MONITOR", 0.0)   # temp already in reason string
        else:
            log_tamper("VAULT_ENV_MONITOR", reason)
    except Exception as fe:
        print(f"⚠️  Forensic log failed (still shutting down): {fe}")

    print("🔌 CUTTING POWER TO SYSTEM (hardware relay / sys.exit)...")
    sys.exit(1)


def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())

        if msg.topic == ENV_TOPIC:
            ambient_temp = data.get("temperature", 0.0)
            cpu_temp     = get_cpu_temp()
            diff         = cpu_temp - ambient_temp
            rise_rate    = get_rate_of_rise(cpu_temp)

            print(f"🌡️  CPU: {cpu_temp:.1f}°C  |  Ambient (DHT22): {ambient_temp:.1f}°C  "
                  f"|  ΔT: {diff:.1f}°C  |  Rise: {rise_rate:+.2f}°C/poll")

            # --- PRIORITY: Acoustic Overclocking Detection ---
            # Abrupt CPU spike regardless of differential pattern.
            # Legitimate DDoS/Malware heats gradually (~0.5-1°C/poll).
            # Acoustic resonance causes instantaneous jumps > RATE_OF_RISE_THRESHOLD.
            if rise_rate > RATE_OF_RISE_THRESHOLD:
                reason = (
                    f"ACOUSTIC/SIDE-CHANNEL ATTACK DETECTED: CPU rose {rise_rate:.2f}°C "
                    f"in one poll (threshold {RATE_OF_RISE_THRESHOLD}°C). "
                    "Possible crystal oscillator resonance or hardware attack."
                )
                print(f"🔊 [THERMAL] {reason}")
                client.publish("gateway/alert", json.dumps({
                    "type":         "ACOUSTIC_ATTACK",
                    "cpu_temp":     cpu_temp,
                    "ambient_temp": ambient_temp,
                    "rise_rate":    rise_rate,
                }))
                trigger_emergency_shutdown(reason, event_type="TAMPER")

            # --- Differential Thermal Logic ---
            elif cpu_temp > CPU_TEMP_THRESHOLD and diff > DIFFERENTIAL_THRESHOLD:
                # CPU hot, ambient cool → software attack (malware/DDoS)
                print("⚠️  [THERMAL] High CPU + Low Ambient → SOFTWARE ATTACK DETECTED (DDoS/Malware)")
                client.publish("gateway/alert", json.dumps({
                    "type":         "THERMAL_SOFTWARE_ATTACK",
                    "cpu_temp":     cpu_temp,
                    "ambient_temp": ambient_temp,
                    "diff":         diff,
                }))

            elif ambient_temp > AMBIENT_TEMP_THRESHOLD:
                # Both hot → physical sabotage (HVAC cut / heat gun / lighter)
                print("🔥 [THERMAL] High CPU + High Ambient → PHYSICAL SABOTAGE DETECTED (HVAC/Heat Gun)")
                trigger_emergency_shutdown(
                    f"Physical thermal sabotage: Ambient {ambient_temp:.1f}°C, CPU {cpu_temp:.1f}°C",
                    event_type="THERMAL"
                )

        elif msg.topic == TAMPER_TOPIC:
            sensor = data.get("sensor", "unknown")
            if sensor == "Vibration":
                trigger_emergency_shutdown(
                    "Physical Tampering / Kinetic Shock Detected (SW-420)",
                    event_type="TAMPER"
                )

    except Exception as e:
        print(f"❌ Error in environmental logic: {e}")


if __name__ == "__main__":
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_forever()
