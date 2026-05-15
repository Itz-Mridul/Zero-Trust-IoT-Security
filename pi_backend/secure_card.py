#!/usr/bin/env python3
"""
==============================================================================
🔐 RFID KEY HARDENING — Change Card Keys from Default to Secure
==============================================================================
Moves card security from the default "FF FF FF FF FF FF" to a custom 
Zero-Trust key stored in the Pi's vault.

Usage:
  python3 secure_card.py

WARNING: If you lose the key, the card becomes a brick!
==============================================================================
"""

import sys
import os
import json
from pathlib import Path

# Try to load custom key from vault
VAULT_KEY_PATH = "/mnt/vault_keys/rfid_master.key"
DEFAULT_KEY = [0xFF] * 6

def get_secure_key():
    if os.path.exists(VAULT_KEY_PATH):
        with open(VAULT_KEY_PATH, "r") as f:
            key_hex = f.read().strip()
            return [int(key_hex[i:i+2], 16) for i in range(0, 12, 2)]
    else:
        # Generate a random 6-byte key if not exists
        import secrets
        new_key = secrets.token_bytes(6)
        os.makedirs(os.path.dirname(VAULT_KEY_PATH), exist_ok=True)
        with open(VAULT_KEY_PATH, "w") as f:
            f.write(new_key.hex())
        print(f"✨ Generated new Master Key and stored in vault: {new_key.hex()}")
        return list(new_key)

def secure_card():
    try:
        from mfrc522 import MFRC522
        import RPi.GPIO as GPIO
    except ImportError:
        print("Install: pip install mfrc522 RPi.GPIO spidev")
        sys.exit(1)

    SECURE_KEY = get_secure_key()
    reader = MFRC522()

    print("\n  ⚠️  LOCKING CARD TO ZERO-TRUST MASTER KEY")
    print("  Place card on reader...")

    while True:
        status, tag_type = reader.MFRC522_Request(reader.PICC_REQIDL)
        if status == reader.MI_OK: break

    status, uid = reader.MFRC522_Anticoll()
    if status != reader.MI_OK: return

    uid_str = ''.join(f'{b:02X}' for b in uid[:4])
    print(f"  🆔 Card UID: {uid_str}")
    reader.MFRC522_SelectTag(uid)

    # 1. Authenticate with DEFAULT key first to gain access
    status = reader.MFRC522_Auth(reader.PICC_AUTHENT1A, 7, DEFAULT_KEY, uid)
    if status != reader.MI_OK:
        print("  ❌ Could not authenticate with default key. Is it already secured?")
        return

    # 2. Build new Sector Trailer for Sector 1 (Block 7)
    # [Key A (6)] [Access Bits (4)] [Key B (6)]
    # Access Bits 7F 07 88 00 is standard (Key A for everything)
    new_trailer = SECURE_KEY + [0x7F, 0x07, 0x88, 0x40] + SECURE_KEY

    print(f"  🔒 Writing new Secure Keys to Sector 1...")
    status = reader.MFRC522_Write(7, new_trailer)
    
    if status == reader.MI_OK:
        print("  ✅ SUCCESS! Sector 1 is now locked with your Master Vault Key.")
        print("  Note: You must now update write_card.py and read_card.py to use this key.")
    else:
        print("  ❌ FAILED to write new keys.")

    reader.MFRC522_StopCrypto1()
    GPIO.cleanup()

if __name__ == "__main__":
    secure_card()
