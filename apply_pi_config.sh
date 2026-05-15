#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "🚀 Applying Zero-Trust Raspberry Pi System Configurations..."

# 1. Set Static IP
echo "🌐 Configuring Static IP (192.168.1.113)..."
if ! grep -q "static ip_address=192.168.1.113" /etc/dhcpcd.conf; then
    echo -e "\ninterface wlan0\nstatic ip_address=192.168.1.113/24\nstatic routers=192.168.1.1\nstatic domain_name_servers=8.8.8.8 1.1.1.1" >> /etc/dhcpcd.conf
    echo "   ✅ Added static IP to /etc/dhcpcd.conf"
else
    echo "   ✅ Static IP already configured in /etc/dhcpcd.conf"
fi

# 2. Configure Mosquitto
echo "📡 Configuring Mosquitto MQTT Broker..."
apt update && apt install -y mosquitto mosquitto-clients
mkdir -p /etc/mosquitto/conf.d
if ! grep -q "listener 1883 0.0.0.0" /etc/mosquitto/conf.d/local.conf 2>/dev/null; then
    echo -e "listener 1883 0.0.0.0\nallow_anonymous true" > /etc/mosquitto/conf.d/local.conf
    systemctl restart mosquitto
    echo "   ✅ Mosquitto configured for remote connections and restarted"
else
    echo "   ✅ Mosquitto already configured"
fi

# 3. Enable SPI
echo "🔌 Enabling SPI (for MCP3008 ADC)..."
raspi-config nonint do_spi 0
echo "   ✅ SPI enabled"

echo ""
echo "🎉 System configurations applied successfully!"
echo "⚠️  Please run 'sudo reboot' to apply the static IP and SPI changes."
