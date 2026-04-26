#!/usr/bin/env python3
"""
key_vault.py — Volatile RAM Key Storage (Cold-Boot Attack Defense)

SECURITY MODEL
--------------
All cryptographic key material is split into two XOR shares and written ONLY
to a tmpfs (RAM) mount — never to SD card blocks.  When the SW-420 kinetic
sensor triggers the Kill Circuit (power cut), the RAM loses its charge and
both shares vaporize in < 500 ms, leaving nothing for a cold-boot scavenger.

STORAGE PATH
------------
Primary  : /dev/shm/iot_keys/   ← Linux shared-memory tmpfs (always available)
Secondary: /mnt/vault_keys/     ← dedicated 16 MB tmpfs (see setup_vault_tmpfs.sh)

XOR SPLIT SCHEME
----------------
secret = share_A XOR share_B
share_A → /dev/shm/iot_keys/share_a.bin
share_B → /mnt/vault_keys/share_b.bin  (separate mount — two-fault tolerance)

A cold-boot attacker who pulls the SD card gets NEITHER share because both
were only ever in RAM.
"""

import os
import secrets
import hashlib
import json
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# PATHS (both on tmpfs mounts — never on SD card)
# ---------------------------------------------------------------------------
PRIMARY_VAULT   = Path("/dev/shm/iot_keys")        # Linux shm — always tmpfs
SECONDARY_VAULT = Path("/mnt/vault_keys")          # dedicated mount (fstab)

PRIMARY_SHARE_FILE   = PRIMARY_VAULT   / "share_a.bin"
SECONDARY_SHARE_FILE = SECONDARY_VAULT / "share_b.bin"
MANIFEST_FILE        = PRIMARY_VAULT   / "manifest.json"


def _ensure_vault_dirs() -> None:
    """Create vault directories on the RAM disk (harmless if already exist)."""
    PRIMARY_VAULT.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Secondary mount might not be configured yet — fail gracefully
    if SECONDARY_VAULT.exists():
        SECONDARY_VAULT.mkdir(mode=0o700, parents=True, exist_ok=True)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# PUBLIC API
# ---------------------------------------------------------------------------

def store_key(key_id: str, secret: bytes) -> bool:
    """
    Split `secret` into two XOR shares and store each on a separate tmpfs.

    Parameters
    ----------
    key_id  : human-readable label, e.g. "blockchain_privkey"
    secret  : raw key bytes

    Returns
    -------
    True on full success, False if secondary mount unavailable (single-share mode).
    """
    _ensure_vault_dirs()

    # Generate a cryptographically random share A; derive share B
    share_a = secrets.token_bytes(len(secret))
    share_b = _xor_bytes(secret, share_a)

    # Write share A to primary (shm)
    with open(PRIMARY_SHARE_FILE, "wb") as fh:
        fh.write(share_a)
    os.chmod(PRIMARY_SHARE_FILE, 0o600)

    # Write share B to secondary (dedicated tmpfs) if available
    dual_share = False
    if SECONDARY_VAULT.exists() and SECONDARY_VAULT.is_mount():
        with open(SECONDARY_SHARE_FILE, "wb") as fh:
            fh.write(share_b)
        os.chmod(SECONDARY_SHARE_FILE, 0o600)
        dual_share = True
    else:
        # Fallback: keep share B in primary vault (still RAM-only)
        fallback = PRIMARY_VAULT / "share_b_fallback.bin"
        with open(fallback, "wb") as fh:
            fh.write(share_b)
        os.chmod(fallback, 0o600)

    # Write manifest (no secret data — just metadata)
    manifest = {
        "key_id":     key_id,
        "length":     len(secret),
        "sha256":     hashlib.sha256(secret).hexdigest(),
        "stored_at":  time.time(),
        "dual_share": dual_share,
    }
    with open(MANIFEST_FILE, "w") as fh:
        json.dump(manifest, fh, indent=2)

    mode = "DUAL-SHARE (two-fault tolerant)" if dual_share else "SINGLE-SHARE (primary only)"
    print(f"🔐 [KeyVault] '{key_id}' stored in volatile RAM | Mode: {mode}")
    return dual_share


def retrieve_key(key_id: str) -> bytes:
    """
    Reconstruct the secret from the two XOR shares.

    Returns
    -------
    The original secret bytes, or raises RuntimeError if shares are missing.
    """
    _ensure_vault_dirs()

    if not PRIMARY_SHARE_FILE.exists():
        raise RuntimeError("KeyVault: share_a missing — vault may have been wiped")

    with open(PRIMARY_SHARE_FILE, "rb") as fh:
        share_a = fh.read()

    # Try secondary mount first, then fallback file
    secondary = SECONDARY_VAULT / "share_b.bin"
    fallback   = PRIMARY_VAULT  / "share_b_fallback.bin"

    if SECONDARY_VAULT.exists() and SECONDARY_VAULT.is_mount() and secondary.exists():
        with open(secondary, "rb") as fh:
            share_b = fh.read()
    elif fallback.exists():
        with open(fallback, "rb") as fh:
            share_b = fh.read()
    else:
        raise RuntimeError("KeyVault: share_b missing — vault may have been wiped")

    secret = _xor_bytes(share_a, share_b)

    # Verify integrity against manifest
    if MANIFEST_FILE.exists():
        with open(MANIFEST_FILE) as fh:
            manifest = json.load(fh)
        expected_hash = manifest.get("sha256", "")
        if hashlib.sha256(secret).hexdigest() != expected_hash:
            raise RuntimeError("KeyVault: SHA-256 integrity check FAILED — possible tamper")
        print(f"🔓 [KeyVault] '{manifest.get('key_id', key_id)}' retrieved | Integrity: ✅ OK")

    return secret


def wipe_vault() -> None:
    """
    Immediately overwrite and delete all key shares from RAM.
    Called by environment_monitor.py before sys.exit() on tamper/thermal events.
    """
    zeroes = b'\x00' * 4096  # overwrite buffer

    for path in [PRIMARY_SHARE_FILE,
                 SECONDARY_VAULT / "share_b.bin",
                 PRIMARY_VAULT / "share_b_fallback.bin",
                 MANIFEST_FILE]:
        if path.exists():
            try:
                # Overwrite with zeroes before unlink (defence-in-depth on some kernels)
                size = path.stat().st_size
                with open(path, "r+b") as fh:
                    written = 0
                    while written < size:
                        chunk = zeroes[:size - written]
                        if not chunk:
                            break   # guard: size == 0 or slice is empty → nothing to write
                        fh.write(chunk)
                        written += len(chunk)
                path.unlink()
            except OSError:
                pass  # file may already be gone if power was cut

    print("💥 [KeyVault] All key shares WIPED from volatile RAM.")


# ---------------------------------------------------------------------------
# STANDALONE TEST
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n" + "="*60)
    print("🔐  KEY VAULT — Volatile RAM Storage Test")
    print("="*60)

    test_secret = b"blockchain_private_key_material_32b"

    print("\n[1] Storing key...")
    store_key("test_key", test_secret)

    print("\n[2] Retrieving key...")
    recovered = retrieve_key("test_key")
    assert recovered == test_secret, "❌ Key mismatch!"
    print(f"    Recovered: {recovered[:10]}... ✅")

    print("\n[3] Wiping vault...")
    wipe_vault()

    print("\n[4] Verifying wipe (should fail)...")
    try:
        retrieve_key("test_key")
        print("    ❌ ERROR: Key still accessible after wipe!")
    except RuntimeError as e:
        print(f"    ✅ Wipe confirmed: {e}")

    print("\n✅ Key Vault test complete.\n")
