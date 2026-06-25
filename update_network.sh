#!/usr/bin/env bash
# ============================================================
#  update_network.sh — Zero-Trust IoT Security Gateway
#  Automatically update the network IP across the project
# ============================================================

NEW_IP="$1"

if [ -z "$NEW_IP" ]; then
    echo "Usage: bash $0 <new_ip_address>"
    echo "Example: bash $0 10.163.217.94"
    exit 1
fi

echo -e "\033[0;32m⚡ Updating IP to $NEW_IP...\033[0m"

# Update .env
if [ -f ".env" ]; then
    sed -i "s/^MQTT_BROKER=.*/MQTT_BROKER=$NEW_IP/" .env
    sed -i "s/^PI_LOCAL_IP=.*/PI_LOCAL_IP=$NEW_IP/" .env
    sed -i "s/^MAC_IP=.*/MAC_IP=$NEW_IP/" .env
    sed -i "s|BLOCKCHAIN_URL=.*|BLOCKCHAIN_URL=\"http://$NEW_IP:7545\"|" .env
    echo "✅ Updated .env"
else
    echo "⚠️ .env file not found!"
fi

# Update ESP32 firmware config
CONFIG_FILE="esp32_firmware/perimeter_scanner/config.h"
if [ -f "$CONFIG_FILE" ]; then
    sed -i "s/#define MQTT_BROKER.*/#define MQTT_BROKER  \"$NEW_IP\"   \/\/ Server IP/" "$CONFIG_FILE"
    echo "✅ Updated ESP32 config.h"
else
    echo "⚠️ ESP32 config.h not found!"
fi

# Update example config
CONFIG_EXAMPLE="esp32_firmware/perimeter_scanner/config.example.h"
if [ -f "$CONFIG_EXAMPLE" ]; then
    sed -i "s/#define MQTT_BROKER.*/#define MQTT_BROKER  \"$NEW_IP\"   \/\/ Server IP/" "$CONFIG_EXAMPLE"
fi

echo -e "\n\033[0;36mRestarting services with new configuration...\033[0m"
bash start_all.sh

echo -e "\n\033[1;33m⚠️ CRITICAL NEXT STEP: You MUST reflash the ESP32 boards in Arduino IDE for the firmware to pick up the new IP ($NEW_IP)!\033[0m"
