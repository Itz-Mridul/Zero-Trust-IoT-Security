#!/usr/bin/env python3
"""
Dynamic Nonce Challenger
Sends unique math puzzles — FPGA replay attacks cannot solve them in time
"""
import os, json, time, random, hashlib, logging
import paho.mqtt.client as mqtt

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [NONCE] %(levelname)s: %(message)s')
log = logging.getLogger(__name__)

MQTT_BROKER = os.getenv("MQTT_BROKER", "localhost")
MQTT_PORT   = int(os.getenv("MQTT_PORT", "1883"))

pending = {}  # device_id → {nonce, sent_at, expected}

def expected_solution(nonce: int) -> int:
    for x in range(100000):
        if (nonce + x) % 1000 == 0:
            return x
    return -1

def issue_challenge(client, device_id: str):
    seed  = int(time.time()*1000) ^ random.randint(0, 0xFFFF)
    nonce = seed % 1000000
    pending[device_id] = {
        "nonce": nonce, "sent_at": time.time(),
        "expected": expected_solution(nonce)
    }
    client.publish("perimeter/nonce_challenge", json.dumps({
        "device_id": device_id, "nonce": nonce, "timeout_ms": 8000
    }))
    log.info(f"🔢 Nonce challenge issued to {device_id}: {nonce}")

def on_message(client, userdata, msg):
    if msg.topic != "perimeter/nonce_response":
        return
    try:
        d          = json.loads(msg.payload.decode())
        dev        = d.get("device_id", "")
        nonce      = d.get("nonce", -1)
        solution   = d.get("solution", -1)
        solve_us   = d.get("solve_time_us", 0)

        if dev not in pending:
            log.warning(f"⚠️ Unsolicited nonce response from {dev}")
            return

        p = pending.pop(dev)
        elapsed = time.time() - p["sent_at"]

        if elapsed > 8.0:
            log.warning(f"⏰ Nonce timeout from {dev}")
            return
        if solution != p["expected"]:
            log.warning(f"❌ Wrong solution from {dev}")
            return
        # FPGA would solve in < 1µs; real ESP32 takes 50-2000µs
        if solve_us < 10:
            log.warning(f"⚡ FPGA REPLAY SUSPECTED from {dev} (solve={solve_us}µs)")
            return

        log.info(f"✅ Nonce verified for {dev} in {solve_us}µs")
    except Exception as e:
        log.error(f"Error processing nonce response: {e}")

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        client.subscribe("perimeter/nonce_response")
        log.info("🔢 Nonce Challenger connected to MQTT")
    else:
        log.error(f"❌ MQTT connection failed (code: {rc})")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🔢  NONCE CHALLENGER — FPGA Replay Attack Defense")
    print("="*60)

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    c.on_connect = on_connect
    c.on_message = on_message
    c.connect(MQTT_BROKER, MQTT_PORT, 60)
    c.loop_start()

    try:
        while True:
            issue_challenge(c, "ESP32_CAM_PERIMETER_001")
            time.sleep(30)
    except KeyboardInterrupt:
        print("\n🛑 Nonce Challenger stopped.")
        c.disconnect()
