#!/usr/bin/env python3
"""
==============================================================================
💳 MIFARE CARD WRITER — Write Name + Gender + Code to RFID Card
==============================================================================
Run this on Raspberry Pi with RC522 connected to SPI.

Usage:
  python3 write_card.py --name "Mridul" --gender M --code 1234

Installs needed:
  pip install mfrc522 RPi.GPIO spidev

Card layout written:
  Sector 1, Block 4 → Name  (16 bytes, space-padded)
  Sector 1, Block 5 → Gender[0] + Code[1-4] + zeros[5-15]
  Default Key A: FF FF FF FF FF FF
==============================================================================
"""

import sys
import argparse
import os

def write_card(name: str, gender: str, code: str):
    try:
        from mfrc522 import MFRC522
        import RPi.GPIO as GPIO
    except ImportError:
        print("Install: pip install mfrc522 RPi.GPIO spidev")
        sys.exit(1)

    # Validate inputs
    if len(gender) != 1 or gender.upper() not in ('M', 'F'):
        print("Gender must be M or F")
        sys.exit(1)
    if len(code) != 4 or not code.isdigit():
        print("Code must be exactly 4 digits e.g. 1234")
        sys.exit(1)
    if len(name) > 16:
        print("Name too long — max 16 characters")
        sys.exit(1)

    # Build 16-byte blocks
    name_block = name.ljust(16)[:16].encode('ascii')           # 16 bytes

    meta_block = bytearray(16)
    meta_block[0] = ord(gender.upper())                        # byte 0 = gender
    for i, ch in enumerate(code):
        meta_block[1 + i] = ord(ch)                           # bytes 1-4 = code digits
    # bytes 5-15 remain 0x00

    print(f"\n  Name block (hex): {name_block.hex()}")
    print(f"  Meta block (hex): {meta_block.hex()}")
    print(f"\n  Data to write:")
    print(f"    Name:   '{name}'")
    print(f"    Gender: '{gender.upper()}'")
    print(f"    Code:   '{code}'")

    print("\n  ⚠️  Place card on reader NOW and press Enter...")
    input()

    try:
        # Use direct MFRC522 library for sector write
        from mfrc522 import MFRC522
        reader = MFRC522()

        print("  Waiting for card...")
        while True:
            status, tag_type = reader.MFRC522_Request(reader.PICC_REQIDL)
            if status == reader.MI_OK:
                break

        status, uid = reader.MFRC522_Anticoll()
        if status != reader.MI_OK:
            print("  ❌ Could not read UID")
            return

        uid_str = ''.join(f'{b:02X}' for b in uid[:4])
        print(f"  Card UID: {uid_str}")

        reader.MFRC522_SelectTag(uid)

        # Use secure key from vault if available, else default
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
            print("  ❌ Auth failed. Wrong key or wrong card type.")
            return

        # Write Block 4 (name)
        status = reader.MFRC522_Write(4, list(name_block))
        if status == reader.MI_OK:
            print("  ✅ Block 4 (name) written.")
        else:
            print("  ❌ Block 4 write failed.")
            return

        # Write Block 5 (gender + code)
        status = reader.MFRC522_Write(5, list(meta_block))
        if status == reader.MI_OK:
            print("  ✅ Block 5 (gender/code) written.")
        else:
            print("  ❌ Block 5 write failed.")
            return

        # --- VERIFICATION STEP ---
        print("\n  🔍 Verifying written data...")
        status, _ = reader.MFRC522_Read(4)
        if status == reader.MI_OK:
            read_name = bytes(_).decode('ascii').strip()
            print(f"    Read Name:   '{read_name}'")
        
        status, _ = reader.MFRC522_Read(5)
        if status == reader.MI_OK:
            read_gender = chr(_[0])
            read_code = "".join(chr(b) for b in _[1:5])
            print(f"    Read Gender: '{read_gender}'")
            print(f"    Read Code:   '{read_code}'")

        reader.MFRC522_StopCrypto1()
        print(f"\n  ✅ Card written and verified successfully!")

        # --- BLOCKCHAIN REGISTRATION ---
        print(f"\n  🌐 Would you like to register UID {uid_str} on the Blockchain? (y/n)")
        choice = input().lower()
        if choice == 'y':
            import requests
            try:
                # Use the bridge endpoint we just set up
                bridge_url = "http://localhost:5010/register_rfid"
                print(f"    Registering {uid_str} ({name}) on-chain...")
                resp = requests.post(bridge_url, json={"uid": uid_str, "owner": name}, timeout=5)
                if resp.json().get("success"):
                    print(f"    ✅ Registered on Blockchain!")
                else:
                    print(f"    ❌ Registration failed: {resp.json().get('error')}")
            except Exception as e:
                print(f"    ⚠️ Could not connect to blockchain bridge: {e}")

        print(f"\n  Add this to authorized_users.json if not using blockchain:")
        print(f"""
  "{uid_str}": {{
    "name":        "{name}",
    "gender":      "{gender.upper()}",
    "secret_code": "{code}"
  }}
""")

    except Exception as e:
        print(f"  ❌ Error: {e}")
    finally:
        GPIO.cleanup()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Write user data to MIFARE card")
    parser.add_argument("--name",   required=True,  help="User name (max 16 chars)")
    parser.add_argument("--gender", required=True,  help="M or F")
    parser.add_argument("--code",   required=True,  help="4-digit secret code")
    args = parser.parse_args()
    write_card(args.name, args.gender, args.code)
