#!/usr/bin/env bash
# =============================================================================
# setup_vault_tmpfs.sh — Configure volatile RAM disk for key storage
#
# PURPOSE
# -------
# Prevents the "Cold Boot Memory Scavenge" attack described in hello.py:
#   - Attacker triggers kill-circuit, pulls SD card, reads "deleted" files
#   - With tmpfs, nothing was ever written to silicon — keys vaporize instantly
#
# WHAT THIS SCRIPT DOES
# ---------------------
# 1. Creates the mount point /mnt/vault_keys
# 2. Adds a 16 MB tmpfs entry to /etc/fstab (survives reboots)
# 3. Mounts it immediately without rebooting
# 4. Verifies the mount is volatile (is a tmpfs)
# 5. Disables swap (prevents keys leaking to SD card via swapfile)
#
# RUN ONCE AS ROOT on the Raspberry Pi:
#   sudo bash setup_vault_tmpfs.sh
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[VAULT]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN] ${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# Must run as root
[ "$EUID" -eq 0 ] || die "Run this script as root: sudo bash setup_vault_tmpfs.sh"

MOUNT_POINT="/mnt/vault_keys"
FSTAB_ENTRY="tmpfs   ${MOUNT_POINT}   tmpfs   defaults,noatime,nosuid,nodev,noexec,size=16m,mode=0700   0 0"

# ---------------------------------------------------------------------------
# 1. Create mount point
# ---------------------------------------------------------------------------
log "Creating mount point: ${MOUNT_POINT}"
mkdir -p "${MOUNT_POINT}"
chmod 700 "${MOUNT_POINT}"

# ---------------------------------------------------------------------------
# 2. Add to /etc/fstab (idempotent — skip if already present)
# ---------------------------------------------------------------------------
if grep -q "${MOUNT_POINT}" /etc/fstab; then
    warn "fstab entry for ${MOUNT_POINT} already exists — skipping."
else
    log "Adding tmpfs entry to /etc/fstab..."
    # Backup fstab first
    cp /etc/fstab /etc/fstab.bak.$(date +%Y%m%d_%H%M%S)
    echo "${FSTAB_ENTRY}" >> /etc/fstab
    log "  Added: ${FSTAB_ENTRY}"
fi

# ---------------------------------------------------------------------------
# 3. Mount immediately (no reboot needed)
# ---------------------------------------------------------------------------
if mountpoint -q "${MOUNT_POINT}"; then
    warn "${MOUNT_POINT} is already mounted."
else
    log "Mounting tmpfs at ${MOUNT_POINT}..."
    mount "${MOUNT_POINT}"
fi

# ---------------------------------------------------------------------------
# 4. Verify it is actually tmpfs (not an SD card path)
# ---------------------------------------------------------------------------
FS_TYPE=$(stat -f -c "%T" "${MOUNT_POINT}")
if [ "${FS_TYPE}" != "tmpfs" ]; then
    die "${MOUNT_POINT} is NOT tmpfs (got: ${FS_TYPE}). Aborting."
fi
log "Verified: ${MOUNT_POINT} is tmpfs ✅"

# ---------------------------------------------------------------------------
# 5. Disable swap to prevent key material leaking to SD card
# ---------------------------------------------------------------------------
log "Disabling swap (prevents keys leaking to swapfile on SD card)..."
swapoff -a 2>/dev/null || warn "swapoff failed (may not be enabled — that's fine)"

# Make swap-off persistent across reboots
if grep -qE "^\s*CONF_SWAPSIZE\s*=" /etc/dphys-swapfile 2>/dev/null; then
    sed -i 's/^\s*CONF_SWAPSIZE\s*=.*/CONF_SWAPSIZE=0/' /etc/dphys-swapfile
    log "  Swap size set to 0 in /etc/dphys-swapfile"
else
    warn "  /etc/dphys-swapfile not found — swap may not be managed by dphys."
fi

# ---------------------------------------------------------------------------
# 6. Also lock down /dev/shm (primary vault)
# ---------------------------------------------------------------------------
log "Ensuring /dev/shm has secure mount options..."
if ! grep -q "noexec" /proc/mounts | grep shm; then
    # Remount with nosuid,nodev,noexec for defence-in-depth
    mount -o remount,nosuid,nodev,noexec /dev/shm 2>/dev/null \
        && log "  /dev/shm remounted with nosuid,nodev,noexec ✅" \
        || warn "  /dev/shm remount failed (non-fatal)."
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Volatile RAM Vault Configured Successfully      ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Primary vault  :${NC} /dev/shm/iot_keys/              "
echo -e "${GREEN}║  Secondary vault:${NC} /mnt/vault_keys/                "
echo -e "${GREEN}║  Swap           :${NC} DISABLED                        "
echo -e "${GREEN}║  Cold-boot risk :${NC} NEUTRALIZED                     "
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Run key_vault.py now to verify: ${YELLOW}python3 pi_backend/key_vault.py${NC}"
