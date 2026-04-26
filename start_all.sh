#!/usr/bin/env bash
# ===========================================================
#  Zero-Trust IoT Security Platform — Unified Launch Script
#  Usage: bash start_all.sh
#
#  Starts all 7 services as per FINAL_COMPLETION_GUIDE.md:
#   1. iot_server.py          (port 5005 — receives ESP32 heartbeats)
#   2. mqtt_ai_engine.py      (CNN-LSTM authentication + dead-man's switch)
#   3. defense_sensors.py     (SW-420 vibration + DHT22 thermal)
#   4. telegram_alert.py      (mobile push notifications)
#   5. nonce_challenger.py    (FPGA replay attack defeat)
#   6. dashboard.py           (Flask web UI, port 5001)
#   7. blockchain_bridge.py   (Ganache event logger, port 5010)
# ===========================================================

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$PROJECT_DIR/venv/bin/activate"
LOG_DIR="$PROJECT_DIR/logs"
BACKEND="$PROJECT_DIR/pi_backend"

# Create log directory
mkdir -p "$LOG_DIR"

# Load .env if present
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    # shellcheck source=/dev/null
    source "$PROJECT_DIR/.env"
    set +a
fi

# Activate virtual environment
if [ -f "$VENV" ]; then
    # shellcheck source=/dev/null
    source "$VENV"
else
    echo "⚠️  venv not found at $VENV — using system Python"
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  🛡️  ZERO-TRUST IoT SECURITY PLATFORM            ║"
echo "║     Starting all 7 services…                     ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── Kill any previous instances ────────────────────────────────────────
echo "🔄 Stopping old instances…"
pkill -f "iot_server.py"           2>/dev/null || true
pkill -f "mqtt_ai_engine.py"       2>/dev/null || true
pkill -f "enhanced_mqtt_handler.py" 2>/dev/null || true
pkill -f "defense_sensors.py"      2>/dev/null || true
pkill -f "environment_monitor.py"  2>/dev/null || true
pkill -f "telegram_alert.py"       2>/dev/null || true
pkill -f "nonce_challenger.py"     2>/dev/null || true
pkill -f "dashboard.py"            2>/dev/null || true
pkill -f "blockchain_bridge.py"    2>/dev/null || true
sleep 1

# ── Mount vault RAM disk if not already mounted ────────────────────────
if ! mountpoint -q /mnt/vault_keys 2>/dev/null; then
    echo "🔐 Mounting vault RAM disk…"
    sudo mkdir -p /mnt/vault_keys
    sudo mount -t tmpfs -o size=16m,noexec,nosuid,nodev tmpfs /mnt/vault_keys 2>/dev/null \
        && echo "   ✅ /mnt/vault_keys mounted" \
        || echo "   ⚠️  Could not mount vault RAM disk (no sudo?)"
fi

# ── Helper: launch a service ──────────────────────────────────────────
launch() {
    local num="$1"
    local label="$2"
    local script="$3"
    local logfile="$4"
    echo "🚀 [$num/7] Starting $label…"
    nohup python3 "$script" > "$logfile" 2>&1 &
    echo "   PID: $!  →  ${logfile#$PROJECT_DIR/}"
    sleep 1
}

# ── [1] Blockchain Bridge (start first — others may need it) ───────────
launch "1" "Blockchain Bridge      (port 5010)" \
    "$BACKEND/blockchain_bridge.py" \
    "$LOG_DIR/blockchain_bridge.log"

# Extra delay for Web3 + Flask to be ready before ML engine starts
sleep 2

# ── [2] MQTT + AI Engine ───────────────────────────────────────────────
launch "2" "MQTT + AI Engine" \
    "$BACKEND/mqtt_ai_engine.py" \
    "$LOG_DIR/mqtt_ai_engine.log"

# ── [3] Defense Sensors (SW-420 + DHT22) ──────────────────────────────
launch "3" "Defense Sensors" \
    "$BACKEND/defense_sensors.py" \
    "$LOG_DIR/defense_sensors.log"

# ── [4] Telegram Alert Service ────────────────────────────────────────
launch "4" "Telegram Alert Service" \
    "$BACKEND/telegram_alert.py" \
    "$LOG_DIR/telegram_alert.log"

# ── [5] Nonce Challenger ──────────────────────────────────────────────
launch "5" "Nonce Challenger" \
    "$BACKEND/nonce_challenger.py" \
    "$LOG_DIR/nonce_challenger.log"

# ── [6] Security Dashboard ────────────────────────────────────────────
launch "6" "Security Dashboard    (port 5001)" \
    "$BACKEND/dashboard.py" \
    "$LOG_DIR/dashboard.log"

# ── [7] IoT Telemetry Server ──────────────────────────────────────────
launch "7" "IoT Telemetry Server  (port 5005)" \
    "$BACKEND/iot_server.py" \
    "$LOG_DIR/iot_server.log"

PI_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  ✅  ALL 7 SERVICES RUNNING                      ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "  📊 Dashboard       →  http://${PI_IP}:5001"
echo "  📡 IoT Server      →  http://${PI_IP}:5005"
echo "  ⛓️  Blockchain      →  http://${PI_IP}:5010"
echo ""
echo "  📂 Logs            →  $LOG_DIR/"
echo ""
echo "  Verify all 7 processes:"
echo "    ps aux | grep python3 | grep -v grep"
echo ""
echo "  To stop all:"
echo "    pkill -f 'mqtt_ai_engine|defense_sensors|telegram_alert|nonce_challenger|dashboard|blockchain_bridge|iot_server'"
echo ""
