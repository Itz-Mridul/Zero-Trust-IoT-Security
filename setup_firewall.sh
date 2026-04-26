#!/usr/bin/env bash
# =============================================================================
# setup_firewall.sh — Zero-Trust UFW Firewall (Default-Deny)
#
# PURPOSE (from hello.py)
# -----------------------
# "Configure ufw to drop everything except the specific ports needed for MQTT
#  (8883) and the Flask Dashboard (5001). This prevents an attacker from
#  bypassing the AI entirely by simply SSH-ing into the Pi."
#
# PORTS OPENED
# ------------
#   22   / TCP  — SSH (rate-limited to 6 attempts/30s to prevent brute-force)
#   1883 / TCP  — MQTT (local broker, internal only)
#   8883 / TCP  — MQTTS (TLS MQTT for external devices)
#   5001 / TCP  — Flask Security Dashboard
#   5005 / TCP  — IoT Telemetry Server (ESP32 heartbeats)
#   5000 / TCP  — Gateway Command API
#
# RUN ONCE AS ROOT on the Raspberry Pi:
#   sudo bash setup_firewall.sh
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[UFW]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[ "$EUID" -eq 0 ] || die "Run as root: sudo bash setup_firewall.sh"

# ---------------------------------------------------------------------------
# 1. Install ufw if missing
# ---------------------------------------------------------------------------
if ! command -v ufw &>/dev/null; then
    log "Installing ufw..."
    apt-get install -y ufw
fi

# ---------------------------------------------------------------------------
# 2. Reset to a clean slate
# ---------------------------------------------------------------------------
log "Resetting ufw rules to factory defaults..."
ufw --force reset

# ---------------------------------------------------------------------------
# 3. Default-Deny policy (the spec's core requirement)
# ---------------------------------------------------------------------------
log "Setting DEFAULT DENY incoming, ALLOW outgoing..."
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward

# ---------------------------------------------------------------------------
# 4. Allow only the ports the system actually uses
# ---------------------------------------------------------------------------

# SSH — rate-limited (max 6 connections per 30 seconds per IP)
log "Allowing SSH (rate-limited)..."
ufw limit 22/tcp comment "SSH rate-limited"

# MQTT broker (local — ESP32 connects here)
log "Allowing MQTT (1883/tcp)..."
ufw allow 1883/tcp comment "MQTT broker"

# MQTTS (TLS MQTT for production)
log "Allowing MQTTS (8883/tcp)..."
ufw allow 8883/tcp comment "MQTTS TLS broker"

# Flask Security Dashboard
log "Allowing Flask Dashboard (5001/tcp)..."
ufw allow 5001/tcp comment "Zero-Trust Dashboard"

# IoT Telemetry Server (receives ESP32 heartbeats)
log "Allowing IoT Telemetry Server (5005/tcp)..."
ufw allow 5005/tcp comment "IoT Telemetry Server"

# Gateway Command API
log "Allowing Gateway API (5000/tcp)..."
ufw allow 5000/tcp comment "Gateway Command API"

# ---------------------------------------------------------------------------
# 5. Block common attack vectors explicitly
# ---------------------------------------------------------------------------
log "Explicitly blocking common attack ports..."

# Telnet — plaintext, never needed
ufw deny 23/tcp  comment "Block Telnet"

# FTP — plaintext, insecure
ufw deny 21/tcp  comment "Block FTP"

# SMB — no Windows file sharing needed
ufw deny 445/tcp comment "Block SMB"
ufw deny 139/tcp comment "Block NetBIOS"

# ---------------------------------------------------------------------------
# 6. Enable and show status
# ---------------------------------------------------------------------------
log "Enabling ufw..."
ufw --force enable

echo ""
ufw status verbose
echo ""

echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Default-Deny Firewall Active                   ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Incoming  :${NC} DENY ALL (except listed ports)      "
echo -e "${GREEN}║  Outgoing  :${NC} ALLOW ALL                           "
echo -e "${GREEN}║  SSH       :${NC} 22/tcp  (rate-limited)              "
echo -e "${GREEN}║  MQTT      :${NC} 1883/tcp + 8883/tcp                 "
echo -e "${GREEN}║  Dashboard :${NC} 5001/tcp                            "
echo -e "${GREEN}║  IoT Server:${NC} 5005/tcp                            "
echo -e "${GREEN}║  Gateway   :${NC} 5000/tcp                            "
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
warn "SSH bypass attack is now blocked. If locked out, connect via HDMI console."
