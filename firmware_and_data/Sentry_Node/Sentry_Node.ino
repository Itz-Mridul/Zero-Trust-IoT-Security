#include <WiFi.h>
#include <PubSubClient.h>
#include <WebServer.h>
#include "esp_camera.h"
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"
#include "mbedtls/sha256.h"

// ==========================================
// 1. CONFIGURATION  ← FILL THESE IN BEFORE COMPILING
// ==========================================

// --- WiFi ---
const char* WIFI_SSID     = "";               // ← your network name, e.g. "MyHomeWiFi"
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";  // ← your network password

// --- MQTT Broker (your Raspberry Pi IP) ---
// Run  hostname -I  on the Pi to find its IP address.
const char* MQTT_SERVER = "192.168.1.113";                 // ← e.g. "192.168.1.113"
const int   MQTT_PORT   = 1883;

// --- Device identity ---
const char* DEVICE_ID = "ESP32_CAM_EVIDENCE_001";

// ==========================================
// 2. COMPILE-TIME GUARDS
//    Build will FAIL here if you forget to
//    fill in WIFI_SSID or MQTT_SERVER above.
// ==========================================
static_assert(sizeof("") != sizeof(WIFI_SSID),
  "ERROR: WIFI_SSID is empty. Set it to your WiFi network name before compiling.");
static_assert(sizeof("") != sizeof(MQTT_SERVER),
  "ERROR: MQTT_SERVER is empty. Set it to your Raspberry Pi IP address before compiling.");

const char* TAMPER_TOPIC = "mailbox/tamper";
const char* STATUS_TOPIC = "mailbox/camera_status";

const unsigned long MQTT_RETRY_INTERVAL_MS = 2000;
const unsigned long STATUS_INTERVAL_MS = 10000;
const unsigned long FLASH_ON_MS = 120;

#define FLASH_LED_PIN 4

WiFiClient espClient;
PubSubClient mqtt(espClient);
WebServer server(80);

volatile bool captureTriggered = false;
unsigned long lastMqttRetryMs = 0;
unsigned long lastStatusMs = 0;
unsigned long captureCount = 0;
unsigned long lastCaptureMs = 0;
size_t lastImageSize = 0;
bool lastCaptureOk = false;
String lastTriggerSource = "none";

// ==========================================
// 2. CAMERA PINS (AI-THINKER ESP32-CAM)
// ==========================================
#define PWDN_GPIO_NUM     32
#define RESET_GPIO_NUM    -1
#define XCLK_GPIO_NUM      0
#define SIOD_GPIO_NUM     26
#define SIOC_GPIO_NUM     27
#define Y9_GPIO_NUM       35
#define Y8_GPIO_NUM       34
#define Y7_GPIO_NUM       39
#define Y6_GPIO_NUM       36
#define Y5_GPIO_NUM       21
#define Y4_GPIO_NUM       19
#define Y3_GPIO_NUM       18
#define Y2_GPIO_NUM        5
#define VSYNC_GPIO_NUM    25
#define HREF_GPIO_NUM     23
#define PCLK_GPIO_NUM     22

// ==========================================
// 3. WEB GUI
// ==========================================
String htmlPage() {
  String html = R"rawliteral(
<!doctype html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ESP32-CAM Sentry</title>
  <style>
    :root {
      --bg:#0d1117; --card:#161b22; --line:#30363d; --text:#e6edf3;
      --muted:#8b949e; --ok:#2ea043; --bad:#f85149; --accent:#f2cc60;
    }
    body {
      margin:0; background:radial-gradient(circle at top,#1f2937,#0d1117 60%);
      color:var(--text); font-family:Georgia, 'Times New Roman', serif;
    }
    main { max-width:860px; margin:0 auto; padding:28px; }
    h1 { font-size:34px; margin:0 0 6px; letter-spacing:.5px; }
    p { color:var(--muted); line-height:1.5; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; }
    .card {
      background:rgba(22,27,34,.92); border:1px solid var(--line); border-radius:18px;
      padding:18px; box-shadow:0 16px 40px rgba(0,0,0,.22);
    }
    .label { color:var(--muted); font-size:13px; text-transform:uppercase; letter-spacing:.08em; }
    .value { font-size:24px; margin-top:8px; overflow-wrap:anywhere; }
    .ok { color:var(--ok); } .bad { color:var(--bad); } .accent { color:var(--accent); }
    button, a.button {
      display:inline-block; border:0; border-radius:999px; padding:13px 18px; margin:8px 8px 0 0;
      background:var(--accent); color:#111; font-weight:700; text-decoration:none; cursor:pointer;
    }
    img { width:100%; border-radius:16px; border:1px solid var(--line); background:#000; }
    code { color:var(--accent); }
  </style>
</head>
<body>
  <main>
    <h1>ESP32-CAM Evidence Sentry</h1>
    <p>Subscribes to <code>mailbox/tamper</code>. When the vibration gateway reports tampering, this camera flashes, captures evidence, and reports status over MQTT.</p>
    <section class="grid">
      <div class="card"><div class="label">WiFi</div><div id="wifi" class="value">...</div></div>
      <div class="card"><div class="label">MQTT</div><div id="mqtt" class="value">...</div></div>
      <div class="card"><div class="label">Captures</div><div id="captures" class="value">...</div></div>
      <div class="card"><div class="label">Last Image</div><div id="imageSize" class="value">...</div></div>
    </section>
    <section class="card" style="margin-top:14px">
      <div class="label">Controls</div>
      <button onclick="triggerCapture()">Manual Evidence Capture</button>
      <a class="button" href="/capture" target="_blank">Open Snapshot</a>
      <p id="message"></p>
    </section>
    <section class="card" style="margin-top:14px">
      <div class="label">Live Snapshot</div>
      <p>Refreshes every 5 seconds. Use this for demo visibility, not high-FPS streaming.</p>
      <img id="snapshot" src="/capture">
    </section>
  </main>
  <script>
    async function refreshStatus() {
      const res = await fetch('/status');
      const s = await res.json();
      document.getElementById('wifi').innerHTML = s.wifi ? '<span class="ok">Connected</span>' : '<span class="bad">Down</span>';
      document.getElementById('mqtt').innerHTML = s.mqtt ? '<span class="ok">Connected</span>' : '<span class="bad">Down</span>';
      document.getElementById('captures').textContent = s.capture_count + ' total';
      document.getElementById('imageSize').textContent = s.last_image_size + ' bytes';
      document.getElementById('message').textContent = 'Last trigger: ' + s.last_trigger + ' | IP: ' + s.ip;
    }
    async function triggerCapture() {
      document.getElementById('message').textContent = 'Triggering camera...';
      await fetch('/trigger', { method:'POST' });
      await refreshStatus();
      document.getElementById('snapshot').src = '/capture?t=' + Date.now();
    }
    setInterval(refreshStatus, 1500);
    setInterval(() => document.getElementById('snapshot').src = '/capture?t=' + Date.now(), 5000);
    refreshStatus();
  </script>
</body>
</html>
)rawliteral";
  return html;
}

void handleRoot() {
  server.send(200, "text/html", htmlPage());
}

void handleStatus() {
  String json = "{";
  json += "\"device_id\":\"" + String(DEVICE_ID) + "\",";
  json += "\"wifi\":" + String(WiFi.status() == WL_CONNECTED ? "true" : "false") + ",";
  json += "\"mqtt\":" + String(mqtt.connected() ? "true" : "false") + ",";
  json += "\"ip\":\"" + WiFi.localIP().toString() + "\",";
  json += "\"capture_count\":" + String(captureCount) + ",";
  json += "\"last_image_size\":" + String(lastImageSize) + ",";
  json += "\"last_capture_ok\":" + String(lastCaptureOk ? "true" : "false") + ",";
  json += "\"last_trigger\":\"" + lastTriggerSource + "\",";
  json += "\"uptime_ms\":" + String(millis());
  json += "}";
  server.send(200, "application/json", json);
}

void handleTrigger() {
  lastTriggerSource = "web_gui";
  captureTriggered = true;
  server.send(202, "application/json", "{\"status\":\"capture_queued\"}");
}

void handleCapture() {
  digitalWrite(FLASH_LED_PIN, HIGH);
  delay(FLASH_ON_MS);

  camera_fb_t* fb = esp_camera_fb_get();
  digitalWrite(FLASH_LED_PIN, LOW);

  if (!fb) {
    server.send(500, "text/plain", "Camera capture failed");
    return;
  }

  server.send_P(200, "image/jpeg", (const char*)fb->buf, fb->len);
  esp_camera_fb_return(fb);
}

// ==========================================
// 4. MQTT
// ==========================================
void mqttCallback(char* topic, byte* payload, unsigned int length) {
  if (strcmp(topic, TAMPER_TOPIC) == 0) {
    lastTriggerSource = "mqtt_tamper";
    captureTriggered = true;
  }
}

void reconnectMQTT() {
  if (mqtt.connected()) {
    return;
  }

  unsigned long now = millis();
  if (now - lastMqttRetryMs < MQTT_RETRY_INTERVAL_MS) {
    return;
  }

  lastMqttRetryMs = now;

  Serial.print("Connecting to MQTT broker...");
  if (mqtt.connect(DEVICE_ID)) {
    Serial.println(" connected.");
    mqtt.subscribe(TAMPER_TOPIC);
    Serial.print("Subscribed to ");
    Serial.println(TAMPER_TOPIC);
  } else {
    Serial.print(" failed, state=");
    Serial.println(mqtt.state());
  }
}

void publishStatus(const char* eventName) {
  if (!mqtt.connected()) {
    return;
  }

  String payload = "{";
  payload += "\"device_id\":\"" + String(DEVICE_ID) + "\",";
  payload += "\"event\":\"" + String(eventName) + "\",";
  payload += "\"capture_count\":" + String(captureCount) + ",";
  payload += "\"last_image_size\":" + String(lastImageSize) + ",";
  payload += "\"last_capture_ok\":" + String(lastCaptureOk ? "true" : "false") + ",";
  payload += "\"ip\":\"" + WiFi.localIP().toString() + "\",";
  payload += "\"uptime_ms\":" + String(millis());
  payload += "}";

  mqtt.publish(STATUS_TOPIC, payload.c_str());
}

// ==========================================
// 5. CAMERA
// ==========================================
bool initCamera() {
  camera_config_t config;
  config.ledc_channel = LEDC_CHANNEL_0;
  config.ledc_timer = LEDC_TIMER_0;
  config.pin_d0 = Y2_GPIO_NUM;
  config.pin_d1 = Y3_GPIO_NUM;
  config.pin_d2 = Y4_GPIO_NUM;
  config.pin_d3 = Y5_GPIO_NUM;
  config.pin_d4 = Y6_GPIO_NUM;
  config.pin_d5 = Y7_GPIO_NUM;
  config.pin_d6 = Y8_GPIO_NUM;
  config.pin_d7 = Y9_GPIO_NUM;
  config.pin_xclk = XCLK_GPIO_NUM;
  config.pin_pclk = PCLK_GPIO_NUM;
  config.pin_vsync = VSYNC_GPIO_NUM;
  config.pin_href = HREF_GPIO_NUM;
  config.pin_sscb_sda = SIOD_GPIO_NUM;
  config.pin_sscb_scl = SIOC_GPIO_NUM;
  config.pin_pwdn = PWDN_GPIO_NUM;
  config.pin_reset = RESET_GPIO_NUM;
  config.xclk_freq_hz = 20000000;
  config.pixel_format = PIXFORMAT_JPEG;

  if (psramFound()) {
    config.frame_size = FRAMESIZE_VGA;
    config.jpeg_quality = 10;
    config.fb_count = 2;
  } else {
    config.frame_size = FRAMESIZE_QVGA;
    config.jpeg_quality = 12;
    config.fb_count = 1;
  }

  esp_err_t err = esp_camera_init(&config);
  if (err != ESP_OK) {
    Serial.printf("Camera init failed with error 0x%x\n", err);
    return false;
  }

  sensor_t* sensor = esp_camera_sensor_get();
  if (sensor) {
    sensor->set_brightness(sensor, 1);
    sensor->set_contrast(sensor, 1);
    sensor->set_saturation(sensor, 0);
  }

  return true;
}

void captureEvidence() {
  Serial.println("Evidence capture burst triggered (10 photos).");

  for (int i = 0; i < 10; i++) {
    digitalWrite(FLASH_LED_PIN, HIGH);
    delay(FLASH_ON_MS);

    camera_fb_t* fb = esp_camera_fb_get();
    digitalWrite(FLASH_LED_PIN, LOW);

    if (!fb) {
      Serial.printf("Frame %d: Capture failed.\n", i + 1);
      publishStatus("capture_failed");
      continue;
    }

    captureCount++;
    lastCaptureMs = millis();
    lastCaptureOk = true;
    lastImageSize = fb->len;

    // --- SHA-256 Hashing ---
    unsigned char hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // 0 for SHA-256
    mbedtls_sha256_update(&ctx, fb->buf, fb->len);
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    char hashStr[65];
    for (int j = 0; j < 32; j++) {
      sprintf(&hashStr[j * 2], "%02x", hash[j]);
    }

    Serial.printf("Frame %d: Hash = %s\n", i + 1, hashStr);

    // --- Publish Evidence Hash ---
    String payload = "{";
    payload += "\"device_id\":\"" + String(DEVICE_ID) + "\",";
    payload += "\"event\":\"evidence_hash\",";
    payload += "\"frame\":" + String(i + 1) + ",";
    payload += "\"hash\":\"" + String(hashStr) + "\",";
    payload += "\"size\":" + String(fb->len) + ",";
    payload += "\"uptime_ms\":" + String(millis());
    payload += "}";

    mqtt.publish("mailbox/evidence", payload.c_str());

    esp_camera_fb_return(fb);
    
    // Short delay between frames to allow for flash recharge and serial print
    delay(300);
  }

  publishStatus("burst_completed");
  Serial.println("Evidence burst sequence completed.");
}

// ==========================================
// 6. CONNECTIVITY
// ==========================================
void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWiFi connected.");
  Serial.print("Open GUI: http://");
  Serial.println(WiFi.localIP());
}

void setupWebServer() {
  server.on("/", HTTP_GET, handleRoot);
  server.on("/status", HTTP_GET, handleStatus);
  server.on("/trigger", HTTP_POST, handleTrigger);
  server.on("/capture", HTTP_GET, handleCapture);
  server.begin();
}

// ==========================================
// 7. SETUP & LOOP
// ==========================================
void setup() {
  WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);

  Serial.begin(115200);
  Serial.setDebugOutput(false);
  delay(500);

  pinMode(FLASH_LED_PIN, OUTPUT);
  digitalWrite(FLASH_LED_PIN, LOW);

  Serial.println();
  Serial.println("ESP32-CAM Evidence Sentry booting...");

  if (!initCamera()) {
    Serial.println("Camera unavailable. Restarting in 5 seconds.");
    delay(5000);
    ESP.restart();
  }

  connectWiFi();
  setupWebServer();

  mqtt.setServer(MQTT_SERVER, MQTT_PORT);
  mqtt.setCallback(mqttCallback);
  mqtt.setKeepAlive(30);
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }

  reconnectMQTT();
  mqtt.loop();
  server.handleClient();

  if (captureTriggered) {
    captureTriggered = false;
    captureEvidence();
  }

  unsigned long now = millis();
  if (now - lastStatusMs >= STATUS_INTERVAL_MS) {
    lastStatusMs = now;
    publishStatus("camera_alive");
  }
}
