#!/usr/bin/env python3
"""
==============================================================================
📖 MIFARE CARD READER — Read Name + Gender + Code from RFID Card
==============================================================================
Run this on Raspberry Pi with RC522 connected to SPI.

Usage:
  python3 read_card.py

Installs needed:
  pip install mfrc522 RPi.GPIO spidev
==============================================================================
"""

import sys
import time

def read_card():
    try:
        from mfrc522 import MFRC522
        import RPi.GPIO as GPIO
    except ImportError:
        print("Install: pip install mfrc522 RPi.GPIO spidev")
        sys.exit(1)

    try:
        reader = MFRC522()
        print("\n  🔍 Waiting for RFID card...")
        
        while True:
            status, tag_type = reader.MFRC522_Request(reader.PICC_REQIDL)
            if status == reader.MI_OK:
                break
            time.sleep(0.1)

        status, uid = reader.MFRC522_Anticoll()
        if status != reader.MI_OK:
            print("  ❌ Could not read UID")
            return

        uid_str = ''.join(f'{b:02X}' for b in uid[:4])
        print(f"  🆔 Card UID: {uid_str}")

        reader.MFRC522_SelectTag(uid)
        
        # Use secure key from vault if available, else default
        import os
        VAULT_KEY_PATH = "/mnt/vault_keys/rfid_master.key"
        key = [0xFF] * 6
        if os.path.exists(VAULT_KEY_PATH):
            with open(VAULT_KEY_PATH, "r") as f:
                key_hex = f.read().strip()
                key = [int(key_hex[i:i+2], 16) for i in range(0, 12, 2)]
            print(f"  🔐 Using Secure Master Key from vault")
        else:
            print(f"  🔓 Using default FF:FF:FF:FF:FF:FF key")

        # Authenticate Sector 1 (trailer = block 7)
        status = reader.MFRC522_Auth(reader.PICC_AUTHENT1A, 7, key, uid)
        if status != reader.MI_OK:
            print("  ❌ Auth failed. Card might be empty or uses a non-default key.")
            return

        print("\n  📂 Reading data blocks...")

        # Read Block 4 (name)
        status, name_data = reader.MFRC522_Read(4)
        if status == reader.MI_OK:
            try:
                name = bytes(name_data).decode('ascii').strip()
                print(f"    👤 Name:   '{name}'")
            except:
                print(f"    👤 Name:   (Raw) {bytes(name_data).hex()}")
        
        # Read Block 5 (gender + code)
        status, meta_data = reader.MFRC522_Read(5)
        if status == reader.MI_OK:
            gender = chr(meta_data[0])
            code = "".join(chr(b) for b in meta_data[1:5])
            print(f"    🚻 Gender: '{gender}'")
            print(f"    🔑 Code:   '{code}'")

        reader.MFRC522_StopCrypto1()
        print(f"\n  ✅ Read complete.")

    except Exception as e:
        print(f"  ❌ Error: {e}")
    finally:
        GPIO.cleanup()

if __name__ == "__main__":
    read_card()
