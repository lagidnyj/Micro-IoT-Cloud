#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>

// --- WiFi setup ---
const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";

// --- Cloud API setup ---
const char* cloudUrl = "https://your-domain.com/backend/api.php?device=esp32_test";
const char* apiToken = "REPLACE_WITH_API_TOKEN";

// --- NTP setup ---
const char* ntpServer = "pool.ntp.org";
const long gmtOffset_sec = 2 * 3600;     // Kyiv time UTC+2
const int daylightOffset_sec = 3600;     // summer time offset

unsigned long lastSend = 0;
const unsigned long sendInterval = 30000; // 30 sec

void initTime() {
  Serial.println("[NTP] Synchronizing time...");
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);

  struct tm timeinfo;
  for (int i = 0; i < 20; i++) {
    if (getLocalTime(&timeinfo)) {
      Serial.println("[NTP] Time synchronized.");
      Serial.print("[NTP] Current time: ");
      Serial.println(asctime(&timeinfo));
      return;
    }
    delay(500);
    Serial.print(".");
  }

  Serial.println("\n[NTP] Failed to get time. HTTPS certificate validation may still fail.");
}

void connectWiFi() {
  Serial.println("\n[WiFi] Connecting...");
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println();
  Serial.print("[WiFi] Connected. IP: ");
  Serial.println(WiFi.localIP());
}

String buildTestJson() {
  time_t now = time(nullptr);
  struct tm timeinfo;
  localtime_r(&now, &timeinfo);

  char timestamp[30];
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", &timeinfo);

  String json = "{";
  json += "\"device\":\"esp32_test\",";
  json += "\"timestamp\":\"" + String(timestamp) + "\",";
  json += "\"temperature\":" + String(21.7) + ",";
  json += "\"humidity\":" + String(52.4) + ",";
  json += "\"pressure\":" + String(1013.2) + ",";
  json += "\"status\":\"ok\",";
  json += "\"uptime_ms\":" + String(millis()) + ",";
  json += "\"wifi_rssi\":" + String(WiFi.RSSI()) + "";
  json += "}";
  return json;
}

void printHttpDebug(const String& label, const String& value) {
  Serial.println("--------------------------------------------------");
  Serial.print("[HTTP] ");
  Serial.println(label);
  Serial.println(value);
}

void sendCloudTest() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[HTTP] WiFi not connected. Trying reconnect...");
    connectWiFi();
    return;
  }

  String jsonPayload = buildTestJson();

  Serial.println("\n[HTTP] Preparing POST request to cloud...");
  printHttpDebug("JSON payload", jsonPayload);

  WiFiClientSecure client;
  client.setInsecure();  // For self-signed or local HTTPS certs

  HTTPClient http;
  http.setTimeout(15000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);

  Serial.print("[HTTP] begin -> ");
  Serial.println(cloudUrl);

  if (!http.begin(client, cloudUrl)) {
    Serial.println("[HTTP] Failed to begin connection");
    return;
  }

  http.addHeader("Content-Type", "application/json");
  http.addHeader("Authorization", String("Bearer ") + apiToken);

  Serial.println("[HTTP] Sending request...");
  int httpCode = http.POST(jsonPayload);

  Serial.print("[HTTP] Response code: ");
  Serial.println(httpCode);

  if (httpCode > 0) {
    String response = http.getString();
    printHttpDebug("Response body", response);
  } else {
    String error = http.errorToString(httpCode);
    printHttpDebug("Request failed", error);
  }

  http.end();
  Serial.println("[HTTP] Connection closed.");
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("\n=== ESP32 Cloud Test ===");
  Serial.println("Project: Micro IoT Cloud");
  Serial.println("Target: backend/api.php");
  Serial.println("Set your WiFi SSID, password, URL, and token before upload.");

  connectWiFi();
  initTime();
  sendCloudTest();
}

void loop() {
  if (millis() - lastSend >= sendInterval) {
    lastSend = millis();
    Serial.println("\n[Loop] Sending test packet to cloud...");
    sendCloudTest();
  }

  delay(1000);
}
