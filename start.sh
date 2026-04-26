#!/usr/bin/env bash
# =============================================================================
# start.sh — Zero-Trust IoT Gateway startup script (Raspberry Pi)
# Run: bash start.sh
# =============================================================================

set -e   # exit immediately on any error

# ---------------------------------------------------------------------------
# COLOURS
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'  # no colour

log()  { echo -e "${GREEN}[START]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN] ${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ---------------------------------------------------------------------------
# CREDENTIAL CHECKS
# ---------------------------------------------------------------------------
log "Checking environment variables..."

if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then
    warn "Telegram credentials not set. Alerts will NOT be sent."
    warn "To fix, run:"
    warn "  export TELEGRAM_BOT_TOKEN='your_token'"
    warn "  export TELEGRAM_CHAT_ID='your_chat_id'"
fi

if [ -z "$BLOCKCHAIN_URL" ]; then
    warn "BLOCKCHAIN_URL not set — blockchain logging disabled (using default localhost:7545)."
fi

# ---------------------------------------------------------------------------
# ROOT CHECK (scapy needs it)
# ---------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    warn "Not running as root. 'ultimate_gateway.py' needs sudo for raw packet capture."
    warn "Re-run with: sudo -E bash start.sh"
fi

# ---------------------------------------------------------------------------
# PATHS
# ---------------------------------------------------------------------------
IOT_ROOT="$(cd "$(dirname "$0")" && pwd)"
GATEWAY="$IOT_ROOT/gateway_logic/ultimate_gateway.py"
TELEGRAM="$IOT_ROOT/pi_backend/telegram_alert.py"
IOT_SERVER="$IOT_ROOT/pi_backend/iot_server.py"
DASHBOARD="$IOT_ROOT/pi_backend/dashboard.py"

log "IoT Gateway root : $IOT_ROOT"

# ---------------------------------------------------------------------------
# LAUNCH SERVICES (each in its own background process)
# ---------------------------------------------------------------------------
log "Starting IoT heartbeat server    → http://0.0.0.0:5005"
python3 "$IOT_SERVER" &
IOT_SERVER_PID=$!

log "Starting Security Dashboard       → http://0.0.0.0:5001"
python3 "$DASHBOARD" &
DASHBOARD_PID=$!

log "Starting Telegram alert notifier..."
python3 "$TELEGRAM" &
TELEGRAM_PID=$!

log "Starting Zero-Trust Gateway      → http://0.0.0.0:5000"
python3 "$GATEWAY" &
GATEWAY_PID=$!

log "All services started."
echo ""
echo -e "  ${GREEN}Dashboard   :${NC} http://$(hostname -I | awk '{print $1}'):5001"
echo -e "  ${GREEN}IoT Server  :${NC} http://$(hostname -I | awk '{print $1}'):5005"
echo -e "  ${GREEN}Gateway CMD :${NC} http://$(hostname -I | awk '{print $1}'):5000"
echo -e "  ${GREEN}IoT Health  :${NC} http://$(hostname -I | awk '{print $1}'):5005/stats"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop all services.${NC}"

# ---------------------------------------------------------------------------
# WAIT AND HANDLE SHUTDOWN
# ---------------------------------------------------------------------------
trap 'log "Stopping all services..."; kill $IOT_SERVER_PID $DASHBOARD_PID $TELEGRAM_PID $GATEWAY_PID 2>/dev/null; log "Done."; exit 0' SIGINT SIGTERM

wait
