# Physical Attack Detection System (IoT Security)

An enterprise-grade, dual-node IoT security system designed to detect physical tampering and instantly capture visual evidence. Built with ESP32 microcontrollers and a Raspberry Pi MQTT broker.

## 🏗️ System Architecture

This project consists of three main components communicating via a local MQTT network:

1. **Gateway Node (ESP32)** - **Role:** Environmental monitoring and physical attack detection.
   - **Hardware:** ESP32, DHT22 (Temperature/Humidity), SW-420 (Vibration/Tamper).
   - **Features:** Utilizes FreeRTOS dual-core processing to maintain a non-blocking wireless connection on Core 0 while rendering a local serial dashboard on Core 1.

2. **Sentry Node (ESP32-CAM)**
   - **Role:** Visual evidence capture and web dashboard hosting.
   - **Hardware:** AI-Thinker ESP32-CAM with OV2640 lens.
   - **Features:** Subscribes to MQTT topics. Upon receiving a tamper alert from the Gateway, it fires the flash LED and captures a high-resolution snapshot. Also hosts a built-in Dark Mode HTML/CSS Web GUI for manual triggers and live viewing.

3. **Message Broker (Raspberry Pi)**
   - **Role:** The local server routing JSON telemetry and event triggers via Mosquitto MQTT.

## 🚀 Setup & Installation

### 1. Configure the Network
Open `Gateway_Node.ino` and `Sentry_Node.ino` and update the configuration blocks with your local credentials:
```cpp
const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
const char* MQTT_SERVER = "192.156.1.X"; // Your Raspberry Pi IP
