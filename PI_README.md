# 🛡️ Zero-Trust IoT Gateway — Raspberry Pi Runtime

This folder contains **all the code that runs on the Raspberry Pi**.  
The Arduino firmware and development files stay on the Mac (`Master_IoT_Project/`).

---

## 📁 Folder Structure

```
iot_gateway/
├── blockchain_bridge.py        ← Web3 helper (connects to Ganache on Mac)
├── start.sh                    ← One-command startup script
│
├── gateway_logic/              ← Core Pi gateway services
│   ├── ultimate_gateway.py     ← MAIN: sniffing + DPI + firewall + dashboard
│   ├── dpi.py                  ← Standalone DNS deep packet inspector
│   ├── sniffer.py              ← Standalone Zero-Trust packet sniffer
│   ├── brain.py                ← mitmproxy addon (HTTP threat keyword blocker)
│   ├── app.py                  ← Security alert dashboard (Flask, port 5000)
│   ├── spoofer.py              ← ARP spoofer (for testing / demo only)
│   └── alerts.json             ← Alert log (auto-written by brain.py)
│
├── ml/                         ← Machine Learning (device fingerprinting)
│   ├── collect_data.py         ← Simple MQTT heartbeat collector
│   ├── collect_training_data.py← Advanced MQTT collector (via mqtt_services/)
│   ├── train_authentication_model.py ← Train the Random Forest model
│   ├── fingerprint_model.pkl   ← Pre-trained model (ready to use)
│   └── training_data.db        ← SQLite training data
│
├── mqtt_services/              ← MQTT-based background services
│   ├── telegram_alert.py       ← Sends Telegram alerts on tamper events
│   └── collect_training_data.py← ML training data collector
│
└── data_tools/                 ← IoT data server & analysis
    ├── iot_server.py           ← Flask server (receives ESP32 heartbeats, port 5005)
    └── analyze_data.py         ← Analyses heartbeat DB for IPD stats
```

---

## 🚀 Quick Start

### 1. Set credentials (one time per terminal session)
```bash
export TELEGRAM_BOT_TOKEN="your_bot_token_here"
export TELEGRAM_CHAT_ID="your_chat_id_here"

# Optional — only if Ganache is running on the Mac
export BLOCKCHAIN_URL="http://<mac-ip>:7545"
export CONTRACT_ADDRESS="0x..."
```

### 2. Start everything at once
```bash
cd /home/mridul/iot_gateway
sudo -E bash start.sh
```

> `sudo -E` is required so that Scapy can capture raw packets AND the env vars (Telegram token) are passed through to root.

### 3. Or start services individually
```bash
# Terminal 1 — Main gateway (root required)
sudo -E python3 gateway_logic/ultimate_gateway.py

# Terminal 2 — IoT heartbeat receiver
python3 data_tools/iot_server.py

# Terminal 3 — Telegram tamper notifier
python3 mqtt_services/telegram_alert.py

# Terminal 4 — ML training data collector
python3 mqtt_services/collect_training_data.py
```

---

## 🌐 Web Interfaces (open in browser on any device on your network)

| Service | URL |
|---|---|
| Zero-Trust Command Center | `http://<pi-ip>:5000` |
| Alert Dashboard | `http://<pi-ip>:5000` (via `app.py`) |
| IoT Heartbeat Server | `http://<pi-ip>:5005` |
| Health Check | `http://<pi-ip>:5005/health` |
| Device List | `http://<pi-ip>:5005/devices` |

Find your Pi's IP with: `hostname -I`

---

## 🤖 ML Workflow (Training a new model)

```bash
# Step 1 — Collect live heartbeat data from ESP32 (200+ samples recommended)
python3 mqtt_services/collect_training_data.py

# Step 2 — Train the fingerprinting model
python3 ml/train_authentication_model.py

# Output: ml/fingerprint_model.pkl
```

---

## 🔧 Configuration

All IPs and keys can be set via environment variables:

| Variable | Default | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | *(required)* | Your Telegram bot token |
| `TELEGRAM_CHAT_ID` | *(required)* | Your Telegram chat ID |
| `BLOCKCHAIN_URL` | `http://127.0.0.1:7545` | Ganache node URL |
| `CONTRACT_ADDRESS` | *(set in blockchain_bridge.py)* | Deployed contract address |
| `MQTT_BROKER` | `127.0.0.1` | MQTT broker IP |
| `MQTT_PORT` | `1883` | MQTT port |
| `TRAINING_DB_PATH` | `ml/training_data.db` | Override DB location |
| `ANALYZE_DB_PATH` | `data_tools/iot_data.db` | Override analysis DB |

---

## ⚠️ Notes

- `ultimate_gateway.py`, `dpi.py`, `sniffer.py` **must run as root** (`sudo`) — they use raw sockets
- `spoofer.py` is a **research/demo tool only** — it restores ARP tables on exit
- The blockchain logging is **optional** — if Ganache is offline, events are just logged locally
- Interface is set to `wlan0` — change in `gateway_logic/ultimate_gateway.py` if using `eth0`
