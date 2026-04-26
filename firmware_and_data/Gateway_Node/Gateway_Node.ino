// ==========================================
// Gateway_Node.ino — ESP32 Telemetry Node
// Sends temperature, humidity, RSSI, and
// vibration tamper alerts over MQTT.
// ==========================================

#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <DHT.h>

// ==========================================
// 1. CONFIGURATION  ← FILL THESE IN
// ==========================================

// --- WiFi ---
const char* WIFI_SSID     = "YOUR_WIFI_SSID";      // ← your network name
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";  // ← your network password

// --- MQTT Broker (your Raspberry Pi IP) ---
// Find with:  hostname -I   on the Pi
const char* MQTT_SERVER = "192.168.1.113";  // ← Raspberry Pi IP
const int   MQTT_PORT   = 1883;

// --- Device identity ---
const char* DEVICE_ID = "ESP32_GATEWAY_001";

// ==========================================
// 2. COMPILE-TIME GUARDS
//    These will cause a build error if you
//    forget to fill in the fields above.
// ==========================================
#if defined(WIFI_SSID) && (sizeof(WIFI_SSID) <= 1)
  #error "Please set WIFI_SSID to your network name."
#endif
#if defined(MQTT_SERVER) && (sizeof(MQTT_SERVER) <= 1)
  #error "Please set MQTT_SERVER to your Raspberry Pi IP address."
#endif

// ==========================================
// 3. TIMING CONSTANTS
// ==========================================
const unsigned long HEARTBEAT_INTERVAL_MS = 5000;   // send sensor data every 5 s
const unsigned long DASHBOARD_INTERVAL_MS =  100;   // refresh serial dashboard every 100 ms
const unsigned long DHT_READ_INTERVAL_MS  = 2000;   // re-read DHT22 every 2 s
const unsigned long VIB_HOLD_MS           =  400;   // keep vibration flag up for 400 ms
const unsigned long TAMPER_DEBOUNCE_MS    = 1000;   // minimum gap between tamper publishes

// ==========================================
// 4. PIN DEFINITIONS
// ==========================================
#define DHTPIN    4
#define DHTTYPE   DHT22
DHT dht(DHTPIN, DHTTYPE);

#ifndef D5
  #define D5 5
#endif
#define VIB_PIN D5

// ==========================================
// 5. GLOBALS
// ==========================================
WiFiClient   espClient;
PubSubClient mqtt(espClient);

portMUX_TYPE stateMux = portMUX_INITIALIZER_UNLOCKED;

unsigned long lastDashboardMs  = 0;
unsigned long lastDhtReadMs    = 0;
unsigned long vibTriggerTime   = 0;

float lastHumidity    = 0.0f;
float lastTemperature = 0.0f;
int   mqttState       = 0;   // 0 = disconnected, 1 = connected
unsigned long sentCount = 0;

volatile bool vibrationLatched = false;
bool pendingTamperAlert        = false;
int  visualVibLevel            = 0;

// ==========================================
// 6. HARDWARE HELPERS
// ==========================================
void IRAM_ATTR vibrationISR() {
  vibrationLatched = true;
}

void updateDhtCache(bool forceRead = false) {
  unsigned long now = millis();
  if (!forceRead && now - lastDhtReadMs < DHT_READ_INTERVAL_MS) return;
  lastDhtReadMs = now;

  float h = dht.readHumidity();
  float t = dht.readTemperature();

  if (!isnan(h) && !isnan(t)) {
    portENTER_CRITICAL(&stateMux);
    lastHumidity    = h;
    lastTemperature = t;
    portEXIT_CRITICAL(&stateMux);
  }
}

// ==========================================
// 7. SERIAL DASHBOARD  (Core 1 — UI)
// ==========================================
void printDashboard() {
  float temp, hum;
  int   status, vib;
  unsigned long count;

  portENTER_CRITICAL(&stateMux);
  temp   = lastTemperature;
  hum    = lastHumidity;
  status = mqttState;
  vib    = visualVibLevel;
  count  = sentCount;
  portEXIT_CRITICAL(&stateMux);

  const char* connStr = (status == 1) ? "[ OK ]" : "[FAIL]";
  const char* vibStr  = (vib   >  0)  ? "ALERT " : "SAFE  ";

  Serial.printf(
    "PKT:%-5lu | MQTT:%-6s | TEMP:%5.2fC | HUM:%5.2f%% | VIB:%-6s | RSSI:%-4d dBm\n",
    count, connStr, temp, hum, vibStr, WiFi.RSSI()
  );
}

// ==========================================
// 8. NETWORK TASK  (Core 0 — background)
// ==========================================
void networkTask(void* pvParameters) {
  unsigned long lastHeartbeatMs    = 0;
  unsigned long lastTamperPublishMs = 0;

  mqtt.setServer(MQTT_SERVER, MQTT_PORT);

  for (;;) {
    unsigned long now = millis();

    // --- Maintain WiFi ---
    if (WiFi.status() != WL_CONNECTED) {
      portENTER_CRITICAL(&stateMux);
      mqttState = 0;
      portEXIT_CRITICAL(&stateMux);

      WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
      while (WiFi.status() != WL_CONNECTED) {
        vTaskDelay(500 / portTICK_PERIOD_MS);
      }
      continue;
    }

    // --- Maintain MQTT ---
    if (!mqtt.connected()) {
      portENTER_CRITICAL(&stateMux);
      mqttState = 0;
      portEXIT_CRITICAL(&stateMux);

      if (!mqtt.connect(DEVICE_ID)) {
        vTaskDelay(2000 / portTICK_PERIOD_MS);
        continue;
      }
    } else {
      portENTER_CRITICAL(&stateMux);
      mqttState = 1;
      portEXIT_CRITICAL(&stateMux);
    }

    mqtt.loop();

    // --- Publish tamper alert ---
    bool localTamper = false;
    portENTER_CRITICAL(&stateMux);
    if (pendingTamperAlert) {
      localTamper        = true;
      pendingTamperAlert = false;
    }
    portEXIT_CRITICAL(&stateMux);

    if (localTamper && (now - lastTamperPublishMs >= TAMPER_DEBOUNCE_MS)) {
      lastTamperPublishMs = now;

      StaticJsonDocument<192> doc;
      doc["device_id"] = DEVICE_ID;
      doc["event"]     = "TAMPER_ALERT";
      doc["sensor"]    = "SW-420";
      doc["rssi"]      = WiFi.RSSI();
      doc["uptime_ms"] = now;

      char buf[192];
      serializeJson(doc, buf);
      mqtt.publish("mailbox/tamper", buf);

      portENTER_CRITICAL(&stateMux);
      sentCount++;
      portEXIT_CRITICAL(&stateMux);
    }

    // --- Publish 5-second heartbeat (now includes free_heap) ---
    if (now - lastHeartbeatMs >= HEARTBEAT_INTERVAL_MS) {
      lastHeartbeatMs = now;

      float t, h;
      portENTER_CRITICAL(&stateMux);
      t = lastTemperature;
      h = lastHumidity;
      portEXIT_CRITICAL(&stateMux);

      StaticJsonDocument<256> doc;
      doc["device_id"]  = DEVICE_ID;
      doc["temperature"] = t;
      doc["humidity"]    = h;
      doc["rssi"]        = WiFi.RSSI();
      doc["free_heap"]   = esp_get_free_heap_size();  // ← added: useful for health monitoring
      doc["uptime_ms"]   = now;

      char buf[256];
      serializeJson(doc, buf);
      mqtt.publish("gateway/heartbeat", buf);   // matches collect_training_data.py topic

      portENTER_CRITICAL(&stateMux);
      sentCount++;
      portEXIT_CRITICAL(&stateMux);
    }

    vTaskDelay(10 / portTICK_PERIOD_MS);
  }
}

// ==========================================
// 9. SETUP & LOOP
// ==========================================
void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("\n===================================================");
  Serial.println("   ESP32 TELEMETRY NODE — BOOTING");
  Serial.println("===================================================\n");

  dht.begin();
  pinMode(VIB_PIN, INPUT);
  attachInterrupt(digitalPinToInterrupt(VIB_PIN), vibrationISR, RISING);
  updateDhtCache(true);   // get initial sensor reading before first heartbeat

  // Spawn network task on Core 0 (leaves Core 1 for UI / sensor reading)
  xTaskCreatePinnedToCore(networkTask, "NetworkTask", 8192, NULL, 1, NULL, 0);
}

void loop() {
  unsigned long now = millis();
  updateDhtCache();

  // --- Vibration latch handling ---
  if (vibrationLatched) {
    vibrationLatched = false;
    vibTriggerTime   = now;

    portENTER_CRITICAL(&stateMux);
    visualVibLevel  = 1;
    pendingTamperAlert = true;
    portEXIT_CRITICAL(&stateMux);

  } else if (now - vibTriggerTime > VIB_HOLD_MS) {
    portENTER_CRITICAL(&stateMux);
    visualVibLevel = 0;
    portEXIT_CRITICAL(&stateMux);
  }

  // --- Serial dashboard ---
  if (now - lastDashboardMs >= DASHBOARD_INTERVAL_MS) {
    lastDashboardMs = now;
    printDashboard();
  }
}
