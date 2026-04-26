/*
 * ZERO-TRUST PERIMETER SCANNER
 * ESP32-CAM with RC522 RFID + RGB Anti-Spoofing + Door Relay
 * Board: AI Thinker ESP32-CAM
 *
 * See ZERO_TRUST_IOT_COMPLETE_GUIDE.md Section 5 for full documentation.
 *
 * IMPORTANT: Copy config.example.h to config.h and fill in your credentials
 *            before uploading.
 */

// If you have a config.h with your credentials, uncomment this:
// #include "config.h"

// Otherwise, fill in directly:
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <SPI.h>
#include <MFRC522.h>
#include <esp_camera.h>
#include <mbedtls/md.h>

// ─── CREDENTIALS (from config.h — never commit config.h) ──────────────
#include "config.h"
// config.h defines: WIFI_SSID, WIFI_PASS, MQTT_BROKER, MQTT_PORT, DEVICE_ID


// ─── PINS ─────────────────────────────────────────────────────────────
// RFID RC522 (SPI)
#define SS_PIN    12
#define RST_PIN   2
// RGB LED
#define RGB_R     33
#define RGB_G     32
#define RGB_B     25
// Door Relay (active HIGH = unlock)
#define RELAY_PIN 26
// Camera flash
#define FLASH_PIN 4

// ─── CAMERA CONFIG (AI-Thinker) ───────────────────────────────────────
#define PWDN_GPIO_NUM  32
#define RESET_GPIO_NUM -1
#define XCLK_GPIO_NUM   0
#define SIOD_GPIO_NUM  26
#define SIOC_GPIO_NUM  27
#define Y9_GPIO_NUM    35
#define Y8_GPIO_NUM    34
#define Y7_GPIO_NUM    39
#define Y6_GPIO_NUM    36
#define Y5_GPIO_NUM    21
#define Y4_GPIO_NUM    19
#define Y3_GPIO_NUM    18
#define Y2_GPIO_NUM     5
#define VSYNC_GPIO_NUM 25
#define HREF_GPIO_NUM  23
#define PCLK_GPIO_NUM  22

// ─── OBJECTS ──────────────────────────────────────────────────────────
WiFiClient   espClient;
PubSubClient mqtt(espClient);
MFRC522      rfid(SS_PIN, RST_PIN);

// ─── STATE ────────────────────────────────────────────────────────────
String  pendingChallenge    = "";
bool    awaitingChallenge   = false;
unsigned long lastHeartbeat = 0;
const unsigned long HEARTBEAT_MS = 500;  // 500ms dead-man's switch

// ─── HELPERS ──────────────────────────────────────────────────────────
String sha256(uint8_t* data, size_t len) {
  byte hash[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, data, len);
  mbedtls_md_finish(&ctx, hash);
  mbedtls_md_free(&ctx);
  String out = "";
  for (int i = 0; i < 32; i++) { char b[3]; sprintf(b, "%02x", hash[i]); out += b; }
  return out;
}

void setRGB(bool r, bool g, bool b) {
  digitalWrite(RGB_R, r ? HIGH : LOW);
  digitalWrite(RGB_G, g ? HIGH : LOW);
  digitalWrite(RGB_B, b ? HIGH : LOW);
}

void flashColor(String color, int times = 3) {
  for (int i = 0; i < times; i++) {
    if      (color == "RED")     setRGB(1,0,0);
    else if (color == "GREEN")   setRGB(0,1,0);
    else if (color == "BLUE")    setRGB(0,0,1);
    else if (color == "YELLOW")  setRGB(1,1,0);
    else if (color == "MAGENTA") setRGB(1,0,1);
    else if (color == "CYAN")    setRGB(0,1,1);
    else if (color == "WHITE")   setRGB(1,1,1);
    delay(200);
    setRGB(0,0,0);
    delay(100);
  }
}

// ─── CAMERA ───────────────────────────────────────────────────────────
bool initCamera() {
  camera_config_t cfg;
  cfg.ledc_channel = LEDC_CHANNEL_0;
  cfg.ledc_timer   = LEDC_TIMER_0;
  cfg.pin_d0 = Y2_GPIO_NUM; cfg.pin_d1 = Y3_GPIO_NUM;
  cfg.pin_d2 = Y4_GPIO_NUM; cfg.pin_d3 = Y5_GPIO_NUM;
  cfg.pin_d4 = Y6_GPIO_NUM; cfg.pin_d5 = Y7_GPIO_NUM;
  cfg.pin_d6 = Y8_GPIO_NUM; cfg.pin_d7 = Y9_GPIO_NUM;
  cfg.pin_xclk  = XCLK_GPIO_NUM; cfg.pin_pclk  = PCLK_GPIO_NUM;
  cfg.pin_vsync = VSYNC_GPIO_NUM; cfg.pin_href  = HREF_GPIO_NUM;
  cfg.pin_sscb_sda = SIOD_GPIO_NUM; cfg.pin_sscb_scl = SIOC_GPIO_NUM;
  cfg.pin_pwdn  = PWDN_GPIO_NUM;  cfg.pin_reset = RESET_GPIO_NUM;
  cfg.xclk_freq_hz = 20000000;
  cfg.pixel_format = PIXFORMAT_JPEG;
  cfg.frame_size   = FRAMESIZE_VGA;   // 640x480 for speed
  cfg.jpeg_quality = 12;
  cfg.fb_count     = 2;
  return esp_camera_init(&cfg) == ESP_OK;
}

// ─── CAPTURE + HASH ───────────────────────────────────────────────────
void captureAndSend(String rfidUID, String challengeColor) {
  digitalWrite(FLASH_PIN, HIGH);
  flashColor(challengeColor, 1);

  delay(150);

  camera_fb_t* fb = esp_camera_fb_get();
  if (!fb) { Serial.println("Camera capture failed"); digitalWrite(FLASH_PIN, LOW); return; }

  String imgHash = sha256(fb->buf, fb->len);

  StaticJsonDocument<512> doc;
  doc["device_id"]       = DEVICE_ID;
  doc["rfid_uid"]        = rfidUID;
  doc["image_hash"]      = imgHash;
  doc["rgb_challenge"]   = challengeColor;
  doc["timestamp"]       = millis();
  doc["image_size"]      = fb->len;

  char buf[512];
  serializeJson(doc, buf);
  mqtt.publish("perimeter/access_attempt", buf);

  Serial.printf("📸 Captured: %s | Hash: %s...\n", rfidUID.c_str(), imgHash.substring(0,16).c_str());

  esp_camera_fb_return(fb);
  digitalWrite(FLASH_PIN, LOW);
  setRGB(0,0,0);
}

// ─── MQTT CALLBACK ────────────────────────────────────────────────────
void mqttCallback(char* topic, byte* payload, unsigned int length) {
  String msg = "";
  for (unsigned int i = 0; i < length; i++) msg += (char)payload[i];

  if (String(topic) == "perimeter/challenge") {
    StaticJsonDocument<128> doc;
    deserializeJson(doc, msg);
    pendingChallenge  = doc["color"].as<String>();
    awaitingChallenge = true;
    Serial.printf("🎨 RGB Challenge received: %s\n", pendingChallenge.c_str());

  } else if (String(topic) == "perimeter/door_command") {
    StaticJsonDocument<64> doc;
    deserializeJson(doc, msg);
    String action = doc["action"].as<String>();

    if (action == "UNLOCK") {
      digitalWrite(RELAY_PIN, HIGH);
      flashColor("GREEN", 2);
      delay(5000);
      digitalWrite(RELAY_PIN, LOW);
      Serial.println("✅ Door UNLOCKED for 5 seconds");
    } else {
      digitalWrite(RELAY_PIN, LOW);
      flashColor("RED", 3);
      Serial.println("⛔ Door LOCKED");
    }
  }
}

// ─── MQTT RECONNECT ───────────────────────────────────────────────────
void reconnectMQTT() {
  while (!mqtt.connected()) {
    Serial.print("MQTT reconnecting...");
    if (mqtt.connect(DEVICE_ID)) {
      mqtt.subscribe("perimeter/challenge");
      mqtt.subscribe("perimeter/door_command");
      Serial.println(" ✅");
    } else {
      delay(2000);
    }
  }
}

// ─── HEARTBEAT (500ms Dead-Man's Switch) ──────────────────────────────
void sendHeartbeat() {
  unsigned long now = millis();
  unsigned long ipd = now - lastHeartbeat;

  StaticJsonDocument<256> doc;
  doc["device_id"]           = DEVICE_ID;
  doc["timestamp"]           = now;
  doc["inter_packet_delay"]  = ipd;       // ⭐ ML fingerprint
  doc["free_heap"]           = ESP.getFreeHeap();
  doc["rssi"]                = WiFi.RSSI();
  doc["packet_size"]         = measureJson(doc);

  char buf[256];
  serializeJson(doc, buf);
  mqtt.publish("perimeter/heartbeat", buf);

  lastHeartbeat = now;
}

// ─── SETUP ────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);

  pinMode(RGB_R, OUTPUT); pinMode(RGB_G, OUTPUT); pinMode(RGB_B, OUTPUT);
  pinMode(RELAY_PIN, OUTPUT); pinMode(FLASH_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, LOW);  // Fail-secure (locked)
  setRGB(0,0,0);

  SPI.begin();
  rfid.PCD_Init();

  if (!initCamera()) {
    Serial.println("❌ Camera init FAILED");
    flashColor("RED", 10);
    ESP.restart();
  }

  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println(" ✅");

  mqtt.setServer(MQTT_BROKER, MQTT_PORT);
  mqtt.setCallback(mqttCallback);
  reconnectMQTT();

  flashColor("GREEN", 2);
  Serial.println("\n✅ Perimeter Scanner Ready");
}

// ─── LOOP ─────────────────────────────────────────────────────────────
void loop() {
  if (!mqtt.connected()) reconnectMQTT();
  mqtt.loop();

  // 500ms heartbeat
  if (millis() - lastHeartbeat >= HEARTBEAT_MS) sendHeartbeat();

  // RFID scan
  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return;

  // Read UID
  String uid = "";
  for (byte i = 0; i < rfid.uid.size; i++) {
    char h[3]; sprintf(h, "%02X", rfid.uid.uidByte[i]);
    uid += String(h);
  }
  rfid.PICC_HaltA();

  Serial.printf("\n🔑 RFID Scanned: %s\n", uid.c_str());
  flashColor("YELLOW", 1);

  // Notify Pi, wait for RGB challenge
  StaticJsonDocument<128> doc;
  doc["device_id"] = DEVICE_ID;
  doc["rfid_uid"]  = uid;
  char buf[128];
  serializeJson(doc, buf);
  mqtt.publish("perimeter/rfid_scan", buf);

  // Wait up to 3 seconds for RGB challenge from Pi
  awaitingChallenge = false;
  unsigned long waitStart = millis();
  while (!awaitingChallenge && millis() - waitStart < 3000) {
    mqtt.loop();
    delay(50);
  }

  if (awaitingChallenge) {
    captureAndSend(uid, pendingChallenge);
    awaitingChallenge = false;
  } else {
    Serial.println("⏰ Challenge timeout — Pi may be offline");
    flashColor("RED", 3);
  }
}
