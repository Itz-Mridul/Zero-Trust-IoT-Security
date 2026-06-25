# 📱 Hotspot Migration Guide
## Zero-Trust IoT Security Platform — Switching from Home WiFi to Mobile Hotspot

> **Current network IPs (home WiFi)**
> - Pi: `192.168.1.113`   Mac: `192.168.1.105`   Mobile: `192.168.1.101`

---

## ⚠️ The Key Problem

When you switch to mobile hotspot, **ALL IP addresses change**.
The hotspot assigns new IPs — usually `192.168.43.x` (Android) or `172.20.10.x` (iPhone).

You **cannot know the new IPs until every device connects**. Follow steps in order.

---

## Step 1 — Enable Mobile Hotspot

- **Android**: Settings → Network → Hotspot → Turn on
- **iPhone**: Settings → Personal Hotspot → Turn on

Note your hotspot **SSID** and **password** — needed in Steps 4 and 7.

---

## Step 2 — Connect Pi to Hotspot (do this BEFORE switching Mac)

### Safest: SSH while still on home WiFi
```bash
ssh pi@192.168.1.113

sudo bash -c "cat >> /etc/wpa_supplicant/wpa_supplicant.conf << 'EOF'

network={
    ssid=\"YourHotspotName\"
    psk=\"YourHotspotPassword\"
    priority=10
}
EOF"
sudo reboot
```

Pi will boot directly onto the hotspot from now on.

---

## Step 3 — Connect Mac to Hotspot

WiFi icon → select your hotspot name → enter password.

---

## Step 4 — Find New IPs

### Pi's new IP
From the hotspot phone's "connected devices" list, or:
```bash
# After Pi reboots onto hotspot, from Mac:
arp -a | grep -v incomplete      # scan ARP table
# Or ping-sweep:
for i in $(seq 1 254); do ping -c1 -W1 192.168.43.$i &>/dev/null && echo "192.168.43.$i"; done
```

### Mac's new IP
```bash
ipconfig getifaddr en0
# → e.g. 192.168.43.104
```

> 📝 Write these down — you need them in Step 5.

---

## Step 5 — Update `.env` on Pi

SSH into Pi with its **new IP**:
```bash
ssh pi@<NEW_PI_IP>
cd /home/mridul/Master_IoT_Project
nano .env
```

Update these values:
```ini
WIFI_SSID="YourHotspotName"
WIFI_PASSWORD="YourHotspotPassword"

MQTT_BROKER=<NEW_PI_IP>
PI_LOCAL_IP=<NEW_PI_IP>

MAC_IP=<NEW_MAC_IP>
BLOCKCHAIN_URL="http://<NEW_MAC_IP>:7545"
```

Sync to pi_backend:
```bash
cp .env pi_backend/.env
```

---

## Step 6 — Configure Ganache on Mac

Ganache must listen on `0.0.0.0` so the Pi can reach it.

1. Open **Ganache** → Settings (gear icon) → Server
2. **Hostname**: change `127.0.0.1` → `0.0.0.0`
3. **Port**: `7545`
4. **Save and Restart**

Verify from Pi:
```bash
curl http://<NEW_MAC_IP>:7545
# → should return JSON (not "connection refused")
```

---

## Step 7 — Re-flash ESP32 Firmware

ESP32 WiFi is hardcoded — must re-flash for new network.

### Gateway_Node.ino (`firmware_and_data/Gateway_Node/`)
```cpp
const char* WIFI_SSID     = "YourHotspotName";
const char* WIFI_PASSWORD = "YourHotspotPassword";
const char* MQTT_SERVER   = "<NEW_PI_IP>";   // e.g. "192.168.43.87"
```

### Sentry_Node.ino (`firmware_and_data/Sentry_Node/`)
```cpp
const char* WIFI_SSID     = "YourHotspotName";
const char* WIFI_PASSWORD = "YourHotspotPassword";
const char* MQTT_SERVER   = "<NEW_PI_IP>";
```

### config.h (`esp32_firmware/perimeter_scanner/`)
```cpp
#define WIFI_SSID    "YourHotspotName"
#define WIFI_PASS    "YourHotspotPassword"
#define MQTT_BROKER  "<NEW_PI_IP>"
```

Then in Arduino IDE:
1. Plug each ESP32 into Mac via USB
2. Select correct board + port
3. Upload
4. Open Serial Monitor (115200 baud) → confirm `MQTT: [ OK ]`

---

## Step 8 — Start Pi Services

```bash
ssh pi@<NEW_PI_IP>
cd /home/mridul/Master_IoT_Project
bash start_all.sh
```

Expected output:
```
[1/6] IoT + AI Engine   → port 5005  ✅
[2/6] Defense Sensors   → background ✅
[3/6] Dashboard         → http://<NEW_PI_IP>:5001 ✅
[4/6] Blockchain Bridge → port 5010  ✅
[5/6] Nonce Challenger  → background ✅
[6/6] Telegram Alerts   → active     ✅
```

---

## Step 9 — Verify Stack

```bash
# 1. MQTT heartbeats arriving from ESP32
mosquitto_sub -h localhost -t "gateway/heartbeat" -v

# 2. Dashboard accessible (from Mac browser)
http://<NEW_PI_IP>:5001

# 3. Blockchain bridge health
curl http://localhost:5010/health

# 4. Ganache reachable from Pi
curl http://<NEW_MAC_IP>:7545

# 5. Run test suite
cd /home/mridul/Master_IoT_Project
python3 -m pytest tests/ -v -q
```

---

## Files Changed

| File | Change |
|---|---|
| `.env` | `MQTT_BROKER`, `PI_LOCAL_IP`, `MAC_IP`, `BLOCKCHAIN_URL`, WiFi creds |
| `pi_backend/.env` | Synced copy of above |
| `Gateway_Node.ino` | WiFi SSID/pass → hotspot **(needs re-flash)** |
| `Sentry_Node.ino` | WiFi SSID/pass → hotspot **(needs re-flash)** |
| `config.h` | WiFi SSID/pass → hotspot **(needs re-flash)** |
| `telegram_alert.py` | Fallback dashboard IP → reads `PI_LOCAL_IP` env var |
| `enhanced_mqtt_handler.py` | Blockchain URL fallback updated to Mac IP |

---

## 💡 Pro Tip — Keep Two .env Files

```bash
# On Pi — save current working config for each network:
cp .env .env.home      # home WiFi backup
cp .env .env.hotspot   # hotspot config (after Step 5)

# Switch back to home WiFi later:
cp .env.home .env && cp .env pi_backend/.env
```

---

*Zero-Trust IoT Security Platform | Hotspot Migration Guide*
