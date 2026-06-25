# 💳 Zero-Trust RFID Sub-System

This sub-system handles the physical identity layer of the Zero-Trust IoT platform. It uses MIFARE Classic 1K cards to store encrypted/protected user metadata that is verified against a decentralized blockchain registry.

## 📁 Components

1.  **`pi_backend/write_card.py`**: The "Provisioning" tool. Used to encode cards with a Name, Gender, and a 4-digit Secret Code. It also triggers on-chain registration.
2.  **`pi_backend/read_card.py`**: A debugging tool to read and verify the contents of a provisioned card.
3.  **`esp32_firmware/perimeter_scanner/`**: The "Sentry" firmware. Reads the UID and Secret Code, triggers the RGB challenge, and forwards all data to the Pi for verification.
4.  **`simulate_rfid.py`**: A software-based test tool to verify the backend logic without hardware.

## 🛠️ Card Layout (Sector 1)

We use **Sector 1** (Blocks 4-7) to store our zero-trust metadata, leaving Sector 0 (Manufacturer data) untouched.
*   **Block 4:** User Name (ASCII, space-padded).
*   **Block 5:** Metadata:
    *   `Byte 0`: Gender ('M' or 'F').
    *   `Bytes 1-4`: 4-digit Secret Code (e.g., '1234').
*   **Block 7:** Sector Trailer (Default Key A: `FF FF FF FF FF FF`).

## 🚀 Getting Started

### 1. Provision a New Card
Run this on the Pi with the RC522 attached:
```bash
python3 pi_backend/write_card.py --name "Mridul" --gender M --code 1234
```
Follow the prompts to place the card and (optionally) register it on the blockchain.

### 2. Verify On-Chain
You can manually check if a UID is registered via the Blockchain Bridge:
```bash
curl -X POST http://localhost:5010/check_rfid \
     -H "Content-Type: application/json" \
     -d '{"uid": "AABBCCDD", "secret_code": "1234"}'
```

### 3. Test the Full Loop
To test the backend logic (Bridge -> Server -> Blockchain -> Dashboard):
1.  Start the services: `bash start_all.sh`
2.  Run the simulator: `python3 simulate_rfid.py`

## 🚨 Security Features
*   **Duress Code:** If a user is forced to scan their card, they can use the **Duress Code (`9999`)**. The system will silently deny access and log an immutable **EMERGENCY DURESS** alert to the blockchain.
*   **Tamper Evidence:** Since the Secret Code is stored on the card (and not just linked to the UID in a DB), a cloned card without the matching internal block data will fail authentication.
