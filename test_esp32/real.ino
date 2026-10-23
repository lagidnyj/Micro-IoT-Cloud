#include <Arduino.h>
#include <NimBLEDevice.h>
#include <WiFi.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>

// parseDevice und InfoparseData
// webserver

// Enable or disable debugging output
#define DEBUG_ENABLED true

// Debugging macro
#if DEBUG_ENABLED
#define DEBUG_PRINT(...) Serial.print(__VA_ARGS__)
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#define DEBUG_PRINTLN(...)
#define DEBUG_PRINTF(...)
#endif


// WiFi credentials
const char* ssid = "Hz";
const char* password = "LosingMark3tFa111slandReview";
WebServer server(80);  // Webserver auf Port 80


//********************************************
// Micro IoT Cloud integration
//********************************************
const bool CLOUD_ENABLED = true;
const char* CLOUD_API_URL = "https://360.denied.org.ua/backend/api.php?device=esp32_test";
const char* CLOUD_AUTH_TOKEN = "laserwrite";
const char* CLOUD_DEVICE_ID = "jk_bms_esp32";
const char* CLOUD_ROOT_CA_CERT = R"EOF()EOF";
const unsigned long CLOUD_UPLOAD_INTERVAL_MS = 6000;
bool cloudConfigurationReady = true;
unsigned long lastCloudUpload = 0;



uint32_t minFreeHeap = UINT32_MAX;
unsigned long lastHeapUpdate = 0;

unsigned long lastMillis = 0;
uint32_t totalSeconds = 0;

void calculateUptime() {
  unsigned long currentMillis = millis();
  unsigned long elapsedMillis = currentMillis - lastMillis;

  // Überlauf von millis() behandeln
  if (currentMillis < lastMillis) {
    // Ein Überlauf ist aufgetreten
    elapsedMillis = UINT32_MAX - lastMillis + currentMillis;
  }

  
 if (elapsedMillis >= 1000) {
    // Vergangene Sekunden addieren
    totalSeconds += elapsedMillis / 1000;

    // Aktuellen millis()-Wert speichern
    lastMillis = currentMillis;
  }
}

void monitorFreeHeap() {
  uint32_t currentFreeHeap = ESP.getFreeHeap();

  if (currentFreeHeap < minFreeHeap) {
    minFreeHeap = currentFreeHeap;
  }

  if (millis() - lastHeapUpdate >= 1000) {
    minFreeHeap = UINT32_MAX;
    lastHeapUpdate = millis();
  }
}

void setupLittleFS() {
//  if (!LittleFS.begin()) {
//    DEBUG_PRINTLN("LittleFS Mount Failed");
//    return;
//  }
//  DEBUG_PRINTLN("LittleFS Mounted Successfully");

if (!LittleFS.begin()) {
    Serial.println("LittleFS mount failed, formatting...");
    if (LittleFS.format()) {
        Serial.println("LittleFS formatted successfully.");
        if (LittleFS.begin()) {
            Serial.println("LittleFS mounted successfully.");
        }
    }
}


}

// lesbare Anzeige der Speichergrößen
void formatBytes(size_t bytes, char* buffer, size_t bufferSize) {
  if (bytes < 1024) {
    snprintf_P(buffer, bufferSize, PSTR("%zu%s"), bytes, PSTR(" Byte"));
  } else if (bytes < 1048576) {
    dtostrf(static_cast<float>(bytes) / 1024.0, 6, 2, buffer);
    strcat_P(buffer, PSTR(" KB"));
  } else {
    dtostrf(static_cast<float>(bytes) / 1048576.0, 6, 2, buffer);
    strcat_P(buffer, PSTR(" MB"));
  }
}


void getCoreVersion(char* version) {
  // Schreibe die Version in den char-Array
  sprintf(version, "%d.%d.%d", ESP_ARDUINO_VERSION_MAJOR, ESP_ARDUINO_VERSION_MINOR, ESP_ARDUINO_VERSION_PATCH);
}

void getSketchName(char* sketchName) {
  const char* filename = __FILE__;
  int slashIndex = 0;
  for (int i = 0; i < strlen(filename); i++) {
    char c = filename[i];
    if (c == '\\' || c == '/') slashIndex = i + 1;
  }
  int nameLength = 0;
  for (int i = slashIndex; i < strlen(filename); i++) {
    char c = filename[i];
    if (c == '.') break;
    sketchName[nameLength++] = c;
  }
  sketchName[nameLength] = '\0';
}

String getSketchInfo() {
  char coreVersion[20];
  getCoreVersion(coreVersion);

  char sketchName[50];
  getSketchName(sketchName);

  // Compilation date and time
  String compileDate = __DATE__;
  String compileTime = __TIME__;

  // Create JSON object
  DynamicJsonDocument doc(200);
  doc["sketch_name"] = sketchName;
  doc["compile_date"] = compileDate;
  doc["compile_time"] = compileTime;
  doc["esp_core_version"] = coreVersion;

  String jsonResponse;
  serializeJson(doc, jsonResponse);
  return jsonResponse;
}

String formatUptime(uint32_t totalSeconds) {
  uint32_t days = totalSeconds / 86400;
  uint32_t hours = (totalSeconds % 86400) / 3600;
  uint32_t minutes = (totalSeconds % 3600) / 60;
  uint32_t seconds = totalSeconds % 60;

  char buffer[50];
  snprintf(buffer, sizeof(buffer), "%lu days, %02lu:%02lu:%02lu", days, hours, minutes, seconds);
  return String(buffer);
}

//********************************************
// JKBMS Class Definition
//********************************************
class JKBMS {
public:
  JKBMS(const std::string& mac)
    : targetMAC(mac) {}

  // BLE Components
  NimBLERemoteCharacteristic* pChr = nullptr;
  const NimBLEAdvertisedDevice* advDevice = nullptr;
  bool doConnect = false;
  bool connected = false;
  uint32_t lastNotifyTime = 0;
  std::string targetMAC;

  // Data Processing
  byte receivedBytes[320];
  int frame = 0;
  bool received_start = false;
  bool received_complete = false;
  bool new_data = false;
  int ignoreNotifyCount = 0;

  // BMS Data Fields
  float cellVoltage[16] = { 0 };
  float wireResist[16] = { 0 };
  float Average_Cell_Voltage = 0;
  float Delta_Cell_Voltage = 0;
  float Battery_Voltage = 0;
  float Battery_Power = 0;
  float Charge_Current = 0;
  float Battery_T1 = 0;
  float Battery_T2 = 0;
  float MOS_Temp = 0;
  int Percent_Remain = 0;
  float Capacity_Remain = 0;
  float Nominal_Capacity = 0;
  float Cycle_Count = 0;
  float Cycle_Capacity = 0;
  uint32_t Uptime;
  uint8_t sec, mi, hr, days;
  float Balance_Curr = 0;
  bool Balance = false;
  bool Charge = false;
  bool Discharge = false;
  int Balancing_Action = 0;

  float balance_trigger_voltage = 0;
  float cell_voltage_undervoltage_protection = 0;
  float cell_voltage_undervoltage_recovery = 0;
  float cell_voltage_overvoltage_protection = 0;
  float cell_voltage_overvoltage_recovery = 0;
  float power_off_voltage = 0;
  float max_charge_current = 0;
  float charge_overcurrent_protection_delay = 0;
  float charge_overcurrent_protection_recovery_time = 0;
  float max_discharge_current = 0;
  float discharge_overcurrent_protection_delay = 0;
  float discharge_overcurrent_protection_recovery_time = 0;
  float short_circuit_protection_recovery_time = 0;
  float max_balance_current = 0;
  float charge_overtemperature_protection = 0;
  float charge_overtemperature_protection_recovery = 0;
  float discharge_overtemperature_protection = 0;
  float discharge_overtemperature_protection_recovery = 0;
  float charge_undertemperature_protection = 0;
  float charge_undertemperature_protection_recovery = 0;
  float power_tube_overtemperature_protection = 0;
  float power_tube_overtemperature_protection_recovery = 0;
  int cell_count = 0;
  float total_battery_capacity = 0;
  float short_circuit_protection_delay = 0;
  float balance_starting_voltage = 0;




  // Methods
  bool connectToServer();
  void parseDeviceInfo();
  void parseData();
  void bms_settings();
  void writeRegister(uint8_t address, uint32_t value, uint8_t length);
  void handleNotification(uint8_t* pData, size_t length);

private:
  uint8_t crc(const uint8_t data[], uint16_t len) {
    uint8_t crc = 0;
    for (uint16_t i = 0; i < len; i++) crc += data[i];
    return crc;
  }
};

//********************************************
// Global Variables and Callbacks
//********************************************
JKBMS jkBmsDevices[] = {
  JKBMS("c8:47:80:22:0f:e0"),  // Only one device configured 408092D0264
  JKBMS("c8:47:80:49:01:6a"),    // Add more devices here 51027BI2A000452
  JKBMS("c8:47:80:71:3f:ad"),    // Add more devices here 51027BI2A000452
  // JKBMS("MAC_ADDRESS_3")
};

const int bmsDeviceCount = sizeof(jkBmsDevices) / sizeof(jkBmsDevices[0]);  // Dynamic device count

NimBLEScan* pScan;
unsigned long lastScanTime = 0;

class ClientCallbacks : public NimBLEClientCallbacks {
  JKBMS* bms;
public:
  ClientCallbacks(JKBMS* bmsInstance)
    : bms(bmsInstance) {}

  void onConnect(NimBLEClient* pClient) {
    bms->connected = true;
  }

  void onDisconnect(NimBLEClient* pClient, int reason) {
    DEBUG_PRINTF("BMS %s disconnected (reason %d)\n", bms->targetMAC.c_str(), reason);
    bms->connected = false;
    bms->doConnect = false;
  }
};

class ScanCallbacks : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* advertisedDevice) {
    for (int i = 0; i < bmsDeviceCount; i++) {
      if (jkBmsDevices[i].targetMAC.empty()) continue;  // Skip empty MAC addresses
      if (advertisedDevice->getAddress().toString() == jkBmsDevices[i].targetMAC && !jkBmsDevices[i].connected && !jkBmsDevices[i].doConnect) {
        DEBUG_PRINTF("Target BMS found: %s (RSSI %d dBm)\n", jkBmsDevices[i].targetMAC.c_str(), advertisedDevice->getRSSI());
        jkBmsDevices[i].advDevice = advertisedDevice;
        jkBmsDevices[i].doConnect = true;
        NimBLEDevice::getScan()->stop();
      }
    }
  }
} scanCallbacks;

void notifyCB(NimBLERemoteCharacteristic* pChr, uint8_t* pData, size_t length, bool isNotify) {
  for (int i = 0; i < bmsDeviceCount; i++) {
    if (jkBmsDevices[i].pChr == pChr) {
      jkBmsDevices[i].handleNotification(pData, length);
      break;
    }
  }
}

//********************************************
// JKBMS Method Implementation
//********************************************
bool JKBMS::connectToServer() {
  NimBLEClient* pClient = NimBLEDevice::getClientByPeerAddress(advDevice->getAddress());

  if (!pClient) {
    pClient = NimBLEDevice::createClient();
    pClient->setClientCallbacks(new ClientCallbacks(this), true);
    pClient->setConnectionParams(12, 12, 0, 150);
    pClient->setConnectTimeout(5000);
  }

  if (!pClient->connect(advDevice)) {
    DEBUG_PRINTF("BMS connection failed: %s\n", targetMAC.c_str());
    return false;
  }

  NimBLERemoteService* pSvc = pClient->getService("ffe0");
  if (pSvc) {
    pChr = pSvc->getCharacteristic("ffe1");
    if (pChr && pChr->canNotify()) {
      if (pChr->subscribe(true, notifyCB)) {
        DEBUG_PRINTF("BMS connected: %s (RSSI %d dBm)\n", targetMAC.c_str(), pClient->getRssi());
        delay(500);
        writeRegister(0x97, 0x00000000, 0x00);  // COMMAND_DEVICE_INFO
        delay(500);
        writeRegister(0x96, 0x00000000, 0x00);  // COMMAND_CELL_INFO
        return true;
      }
    }
  }
  DEBUG_PRINTLN("Service or Characteristic not found or unable to subscribe.");
  return false;
}

void JKBMS::handleNotification(uint8_t* pData, size_t length) {
  lastNotifyTime = millis();

  if (ignoreNotifyCount > 0) {
    ignoreNotifyCount--;
    return;
  }

  // Check for start of data frame
  if (pData[0] == 0x55 && pData[1] == 0xAA && pData[2] == 0xEB && pData[3] == 0x90) {
    frame = 0;
    received_start = true;
    received_complete = false;

    // Store the received data
    for (int i = 0; i < length; i++) {
      receivedBytes[frame++] = pData[i];
    }
  } else if (received_start && !received_complete) {
    for (int i = 0; i < length; i++) {
      receivedBytes[frame++] = pData[i];
      if (frame >= 300) {
        received_complete = true;
        received_start = false;
        new_data = true;

        // Determine the type of data frame based on pData[4]
        switch (receivedBytes[4]) {  // Use receivedBytes[4] instead of pData[4]
          case 0x01:
            bms_settings();
            break;
          case 0x02:
            parseData();
            break;
          case 0x03:
            parseDeviceInfo();
            break;
          default:
            break;
        }

        break;  // Exit the loop after processing the complete frame
      }
    }
  }
}

void JKBMS::writeRegister(uint8_t address, uint32_t value, uint8_t length) {
  uint8_t frame[20] = { 0xAA, 0x55, 0x90, 0xEB, address, length };

  // Insert value (Little-Endian)
  frame[6] = value >> 0;  // LSB
  frame[7] = value >> 8;
  frame[8] = value >> 16;
  frame[9] = value >> 24;  // MSB

  // Calculate CRC
  frame[19] = crc(frame, 19);

  if (pChr) {
    pChr->writeValue((uint8_t*)frame, (size_t)sizeof(frame));
  }
}

void JKBMS::bms_settings() {
  cell_voltage_undervoltage_protection = ((receivedBytes[13] << 24 | receivedBytes[12] << 16 | receivedBytes[11] << 8 | receivedBytes[10]) * 0.001);
  cell_voltage_undervoltage_recovery = ((receivedBytes[17] << 24 | receivedBytes[16] << 16 | receivedBytes[15] << 8 | receivedBytes[14]) * 0.001);
  cell_voltage_overvoltage_protection = ((receivedBytes[21] << 24 | receivedBytes[20] << 16 | receivedBytes[19] << 8 | receivedBytes[18]) * 0.001);
  cell_voltage_overvoltage_recovery = ((receivedBytes[25] << 24 | receivedBytes[24] << 16 | receivedBytes[23] << 8 | receivedBytes[22]) * 0.001);
  balance_trigger_voltage = ((receivedBytes[29] << 24 | receivedBytes[28] << 16 | receivedBytes[27] << 8 | receivedBytes[26]) * 0.001);
  power_off_voltage = ((receivedBytes[49] << 24 | receivedBytes[48] << 16 | receivedBytes[47] << 8 | receivedBytes[46]) * 0.001);
  max_charge_current = ((receivedBytes[53] << 24 | receivedBytes[52] << 16 | receivedBytes[51] << 8 | receivedBytes[50]) * 0.001);
  charge_overcurrent_protection_delay = ((receivedBytes[57] << 24 | receivedBytes[56] << 16 | receivedBytes[55] << 8 | receivedBytes[54]));
  charge_overcurrent_protection_recovery_time = ((receivedBytes[61] << 24 | receivedBytes[60] << 16 | receivedBytes[59] << 8 | receivedBytes[58]));
  max_discharge_current = ((receivedBytes[65] << 24 | receivedBytes[64] << 16 | receivedBytes[63] << 8 | receivedBytes[62]) * 0.001);
  discharge_overcurrent_protection_delay = ((receivedBytes[69] << 24 | receivedBytes[68] << 16 | receivedBytes[67] << 8 | receivedBytes[66]));
  discharge_overcurrent_protection_recovery_time = ((receivedBytes[73] << 24 | receivedBytes[72] << 16 | receivedBytes[71] << 8 | receivedBytes[70]));
  short_circuit_protection_recovery_time = ((receivedBytes[77] << 24 | receivedBytes[76] << 16 | receivedBytes[75] << 8 | receivedBytes[74]));
  max_balance_current = ((receivedBytes[81] << 24 | receivedBytes[80] << 16 | receivedBytes[79] << 8 | receivedBytes[78]) * 0.001);
  charge_overtemperature_protection = ((receivedBytes[85] << 24 | receivedBytes[84] << 16 | receivedBytes[83] << 8 | receivedBytes[82]) * 0.1);
  charge_overtemperature_protection_recovery = ((receivedBytes[89] << 24 | receivedBytes[88] << 16 | receivedBytes[87] << 8 | receivedBytes[86]) * 0.1);
  discharge_overtemperature_protection = ((receivedBytes[93] << 24 | receivedBytes[92] << 16 | receivedBytes[91] << 8 | receivedBytes[90]) * 0.1);
  discharge_overtemperature_protection_recovery = ((receivedBytes[97] << 24 | receivedBytes[96] << 16 | receivedBytes[95] << 8 | receivedBytes[94]) * 0.1);
  charge_undertemperature_protection = ((receivedBytes[101] << 24 | receivedBytes[100] << 16 | receivedBytes[99] << 8 | receivedBytes[98]) * 0.1);
  charge_undertemperature_protection_recovery = ((receivedBytes[105] << 24 | receivedBytes[104] << 16 | receivedBytes[103] << 8 | receivedBytes[102]) * 0.1);
  power_tube_overtemperature_protection = ((receivedBytes[109] << 24 | receivedBytes[108] << 16 | receivedBytes[107] << 8 | receivedBytes[106]) * 0.1);
  power_tube_overtemperature_protection_recovery = ((receivedBytes[113] << 24 | receivedBytes[112] << 16 | receivedBytes[111] << 8 | receivedBytes[110]) * 0.1);
  cell_count = ((receivedBytes[117] << 24 | receivedBytes[116] << 16 | receivedBytes[115] << 8 | receivedBytes[114]));
  // 118   4   0x01 0x00 0x00 0x00    Charge switch
  // 122   4   0x01 0x00 0x00 0x00    Discharge switch
  // 126   4   0x01 0x00 0x00 0x00    Balancer switch
  total_battery_capacity = ((receivedBytes[133] << 24 | receivedBytes[132] << 16 | receivedBytes[131] << 8 | receivedBytes[130]) * 0.001);
  short_circuit_protection_delay = ((receivedBytes[137] << 24 | receivedBytes[136] << 16 | receivedBytes[135] << 8 | receivedBytes[134]) * 1);
  balance_starting_voltage = ((receivedBytes[141] << 24 | receivedBytes[140] << 16 | receivedBytes[139] << 8 | receivedBytes[138]) * 0.001);
}

void JKBMS::parseDeviceInfo() {
  new_data = false;

  // Überprüfen, ob genügend Daten empfangen wurden
  if (frame < 134) {  // 134 Bytes sind für die Geräteinformationen erforderlich
    DEBUG_PRINTF("Incomplete device info from BMS %s (%d bytes)\n", targetMAC.c_str(), frame);
    return;
  }

  // Extrahieren der Geräteinformationen aus den empfangenen Bytes
  std::string hardwareVersion(receivedBytes + 22, receivedBytes + 22 + 8);
  std::string softwareVersion(receivedBytes + 30, receivedBytes + 30 + 8);
  uint32_t uptime = (receivedBytes[41] << 24) | (receivedBytes[40] << 16) | (receivedBytes[39] << 8) | receivedBytes[38];
  std::string deviceName(receivedBytes + 46, receivedBytes + 46 + 16);
  DEBUG_PRINTF("BMS info: %s, HW %s, FW %s, uptime %lu s\n",
               deviceName.c_str(), hardwareVersion.c_str(), softwareVersion.c_str(),
               static_cast<unsigned long>(uptime));
}

void JKBMS::parseData() {
  new_data = false;
  ignoreNotifyCount = 10;
  // Cell voltages
  for (int j = 0, i = 7; i < 38; j++, i += 2) {
    cellVoltage[j] = ((receivedBytes[i] << 8 | receivedBytes[i - 1]) * 0.001);
  }

  Average_Cell_Voltage = (((int)receivedBytes[75] << 8 | receivedBytes[74]) * 0.001);

  Delta_Cell_Voltage = (((int)receivedBytes[77] << 8 | receivedBytes[76]) * 0.001);

  for (int j = 0, i = 81; i < 112; j++, i += 2) {
    wireResist[j] = (((int)receivedBytes[i] << 8 | receivedBytes[i - 1]) * 0.001);
  }

  if (receivedBytes[145] == 0xFF) {
    MOS_Temp = ((0xFF << 24 | 0xFF << 16 | receivedBytes[145] << 8 | receivedBytes[144]) * 0.1);
  } else {
    MOS_Temp = ((receivedBytes[145] << 8 | receivedBytes[144]) * 0.1);
  }

  // Battery voltage
  Battery_Voltage = ((receivedBytes[153] << 24 | receivedBytes[152] << 16 | receivedBytes[151] << 8 | receivedBytes[150]) * 0.001);

  Charge_Current = ((receivedBytes[161] << 24 | receivedBytes[160] << 16 | receivedBytes[159] << 8 | receivedBytes[158]) * 0.001);

  Battery_Power = Battery_Voltage * Charge_Current;

  if (receivedBytes[163] == 0xFF) {
    Battery_T1 = ((0xFF << 24 | 0xFF << 16 | receivedBytes[163] << 8 | receivedBytes[162]) * 0.1);
  } else {
    Battery_T1 = ((receivedBytes[163] << 8 | receivedBytes[162]) * 0.1);
  }

  if (receivedBytes[165] == 0xFF) {
    Battery_T2 = ((0xFF << 24 | 0xFF << 16 | receivedBytes[165] << 8 | receivedBytes[164]) * 0.1);
  } else {
    Battery_T2 = ((receivedBytes[165] << 8 | receivedBytes[164]) * 0.1);
  }

  if ((receivedBytes[171] & 0xF0) == 0x0) {
    Balance_Curr = ((receivedBytes[171] << 8 | receivedBytes[170]) * 0.001);
  } else if ((receivedBytes[171] & 0xF0) == 0xF0) {
    Balance_Curr = (((receivedBytes[171] & 0x0F) << 8 | receivedBytes[170]) * -0.001);
  }

  Balancing_Action = receivedBytes[172];
  Percent_Remain = (receivedBytes[173]);
  Capacity_Remain = ((receivedBytes[177] << 24 | receivedBytes[176] << 16 | receivedBytes[175] << 8 | receivedBytes[174]) * 0.001);
  Nominal_Capacity = ((receivedBytes[181] << 24 | receivedBytes[180] << 16 | receivedBytes[179] << 8 | receivedBytes[178]) * 0.001);
  Cycle_Count = ((receivedBytes[185] << 24 | receivedBytes[184] << 16 | receivedBytes[183] << 8 | receivedBytes[182]));
  Cycle_Capacity = ((receivedBytes[189] << 24 | receivedBytes[188] << 16 | receivedBytes[187] << 8 | receivedBytes[186]) * 0.001);

  Uptime = receivedBytes[196] << 16 | receivedBytes[195] << 8 | receivedBytes[194];
  sec = Uptime % 60;
  Uptime /= 60;
  mi = Uptime % 60;
  Uptime /= 60;
  hr = Uptime % 24;
  days = Uptime / 24;

  if (receivedBytes[198] > 0) {
    Charge = true;
  } else if (receivedBytes[198] == 0) {
    Charge = false;
  }
  if (receivedBytes[199] > 0) {
    Discharge = true;
  } else if (receivedBytes[199] == 0) {
    Discharge = false;
  }
  if (receivedBytes[201] > 0) {
    Balance = true;
  } else if (receivedBytes[201] == 0) {
    Balance = false;
  }


  DEBUG_PRINTF("BMS %s: %d%%, %.2f/%.2f Ah, %.2f V, %.2f A, uptime %ud %uh %um\n",
               targetMAC.c_str(), Percent_Remain, Capacity_Remain, Nominal_Capacity,
               Battery_Voltage, Charge_Current, static_cast<unsigned>(days),
               static_cast<unsigned>(hr), static_cast<unsigned>(mi));
}


void handleRoot() {
  if (LittleFS.exists("/index.html")) {
    server.sendHeader("Location", "/main");
    server.send(302, "text/plain", "Umleitung auf /main");
  } else {
    String redirectPage = "<html><body style='text-align:center;'>";
    redirectPage += "<p>index.html wurde nicht gefunden.</p>";
    redirectPage += "<p><a href='/fs'>File-Server</a></p>";
    redirectPage += "</body></html>";

    server.send(200, "text/html", redirectPage);
  }
}

bool buildDataJson(String& jsonResponse) {
  const size_t capacity = JSON_OBJECT_SIZE(bmsDeviceCount)
                          + bmsDeviceCount * (JSON_OBJECT_SIZE(50) + 2 * JSON_ARRAY_SIZE(16) + 2000);
  DynamicJsonDocument doc(capacity);


  for (int i = 0; i < bmsDeviceCount; i++) {
    JKBMS& bms = jkBmsDevices[i];
    JsonObject device = doc.createNestedObject(bms.targetMAC);

    // Allgemeine Informationen
    device["battery_voltage"] = bms.Battery_Voltage;
    device["battery_power"] = bms.Battery_Power;
    device["charge_current"] = bms.Charge_Current;
    device["connected"] = bms.connected;
    device["percent_remain"] = bms.Percent_Remain;
    device["capacity_remain"] = bms.Capacity_Remain;
    device["nominal_capacity"] = bms.Nominal_Capacity;
    device["cycle_count"] = bms.Cycle_Count;
    device["cycle_capacity"] = bms.Cycle_Capacity;
    device["uptime"] = String(bms.days) + "d " + String(bms.hr) + "h " + String(bms.mi) + "m";

    // Temperaturen
    device["battery_t1"] = bms.Battery_T1;
    device["battery_t2"] = bms.Battery_T2;
    device["mos_temp"] = bms.MOS_Temp;

    // Zellspannungen
    JsonArray cell_voltages = device.createNestedArray("cell_voltages");
    for (int j = 0; j < bms.cell_count; j++) {
      cell_voltages.add(bms.cellVoltage[j]);
    }
    device["average_cell_voltage"] = bms.Average_Cell_Voltage;
    device["delta_cell_voltage"] = bms.Delta_Cell_Voltage;

    // Widerstände
    JsonArray wire_resist = device.createNestedArray("wire_resist");
    for (int j = 0; j < bms.cell_count; j++) {
      wire_resist.add(bms.wireResist[j]);
    }

    // Statusflags
    device["charge"] = bms.Charge;
    device["discharge"] = bms.Discharge;
    device["balance"] = bms.Balance;
    device["balancing_action"] = bms.Balancing_Action;
    device["balance_curr"] = bms.Balance_Curr;

    // BMS Einstellungen
    device["cell_count"] = bms.cell_count;
    device["total_battery_capacity"] = bms.total_battery_capacity;
    device["balance_trigger_voltage"] = bms.balance_trigger_voltage;
    device["balance_starting_voltage"] = bms.balance_starting_voltage;
    device["max_charge_current"] = bms.max_charge_current;
    device["max_discharge_current"] = bms.max_discharge_current;
    device["max_balance_current"] = bms.max_balance_current;
    device["cell_undervoltage_protection"] = bms.cell_voltage_undervoltage_protection;
    device["cell_undervoltage_recovery"] = bms.cell_voltage_undervoltage_recovery;
    device["cell_overvoltage_protection"] = bms.cell_voltage_overvoltage_protection;
    device["cell_overvoltage_recovery"] = bms.cell_voltage_overvoltage_recovery;
    device["power_off_voltage"] = bms.power_off_voltage;
    device["charge_overcurrent_protection_delay"] = bms.charge_overcurrent_protection_delay;
    device["charge_overcurrent_protection_recovery_time"] = bms.charge_overcurrent_protection_recovery_time;
    device["discharge_overcurrent_protection_delay"] = bms.discharge_overcurrent_protection_delay;
    device["discharge_overcurrent_protection_recovery_time"] = bms.discharge_overcurrent_protection_recovery_time;
    device["short_circuit_protection_recovery_time"] = bms.short_circuit_protection_recovery_time;
    device["charge_overtemperature_protection"] = bms.charge_overtemperature_protection;
    device["charge_overtemperature_protection_recovery"] = bms.charge_overtemperature_protection_recovery;
    device["discharge_overtemperature_protection"] = bms.discharge_overtemperature_protection;
    device["discharge_overtemperature_protection_recovery"] = bms.discharge_overtemperature_protection_recovery;
    device["charge_undertemperature_protection"] = bms.charge_undertemperature_protection;
    device["charge_undertemperature_protection_recovery"] = bms.charge_undertemperature_protection_recovery;
    device["power_tube_overtemperature_protection"] = bms.power_tube_overtemperature_protection;
    device["power_tube_overtemperature_protection_recovery"] = bms.power_tube_overtemperature_protection_recovery;
    device["short_circuit_protection_delay"] = bms.short_circuit_protection_delay;
  }
  if (doc.overflowed()) {
    return false;
  }

  jsonResponse.clear();
  const size_t serializedSize = serializeJson(doc, jsonResponse);
  return serializedSize > 0 && serializedSize == jsonResponse.length();
}

void handleJSON() {
  String jsonResponse;
  if (!buildDataJson(jsonResponse)) {
    server.send(500, "text/plain", "Failed to build JSON response");
    return;
  }

  server.send(200, "application/json", jsonResponse);
}

bool isValidCloudDeviceId() {
  const size_t length = strlen(CLOUD_DEVICE_ID);
  if (length == 0 || length > 64) {
    return false;
  }

  for (size_t i = 0; i < length; i++) {
    const char c = CLOUD_DEVICE_ID[i];
    const bool isLetter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    const bool isDigit = c >= '0' && c <= '9';
    if (!isLetter && !isDigit && c != '_' && c != '-') {
      return false;
    }
  }
  return true;
}

void uploadCloudData() {
  if (!cloudConfigurationReady || millis() - lastCloudUpload < CLOUD_UPLOAD_INTERVAL_MS) {
    return;
  }
  lastCloudUpload = millis();

  String payload;
  if (!buildDataJson(payload)) {
    DEBUG_PRINTLN(F("[Cloud] Failed to build BMS JSON"));
    return;
  }

  WiFiClientSecure tlsClient;
  tlsClient.setCACert(CLOUD_ROOT_CA_CERT);

  HTTPClient http;
  const String url = String(CLOUD_API_URL) + "?device=" + CLOUD_DEVICE_ID;
  http.setConnectTimeout(5000);
  http.setTimeout(5000);
  if (!http.begin(tlsClient, url)) {
    DEBUG_PRINTLN(F("[Cloud] Failed to initialize HTTPS request"));
    return;
  }

  http.addHeader("Authorization", CLOUD_AUTH_TOKEN);
  http.addHeader("Content-Type", "application/json");
  const int responseCode = http.POST(payload);
  if (responseCode == HTTP_CODE_OK) {
    DEBUG_PRINTLN(F("[Cloud] BMS data uploaded"));
  } else {
    DEBUG_PRINTF("[Cloud] Upload failed, HTTP status: %d\n", responseCode);
  }
  http.end();
}

void handleControl() {
  if (server.method() == HTTP_POST) {
    // JSON-Daten aus dem Request lesen
    DynamicJsonDocument doc(200);
    DeserializationError error = deserializeJson(doc, server.arg("plain"));
    if (error) {
      server.send(400, "text/plain", "Invalid JSON");
      return;
    }

    // Daten aus dem JSON-Objekt extrahieren
    String mac = doc["mac"];
    String action = doc["action"];
    String state = doc["state"];

    // Parameter für writeRegister() bestimmen
    uint8_t address;
    uint32_t value;

    if (action == "charging") {
      address = 0x1D;
    } else if (action == "discharging") {
      address = 0x1E;
    } else if (action == "balancing") {
      address = 0x1F;
    } else {
      server.send(400, "text/plain", "Invalid action");
      return;
    }

    if (state == "on") {
      value = 0x0000001;
    } else if (state == "off") {
      value = 0x00000000;
    } else {
      server.send(400, "text/plain", "Invalid state");
      return;
    }

    // writeRegister() für das entsprechende BMS aufrufen
    for (int i = 0; i < bmsDeviceCount; i++) {
      if (jkBmsDevices[i].targetMAC == mac.c_str()) {
        jkBmsDevices[i].writeRegister(address, value, 0x04);
        server.send(200, "text/plain", "Command executed");
        return;
      }
    }

    server.send(404, "text/plain", "BMS not found");
  } else {
    server.send(405, "text/plain", "Method Not Allowed");
  }
}

void handleSketchInfo() {
  String sketchInfo = getSketchInfo();
  server.send(200, "application/json", sketchInfo);
}

void handleFreeHeap() {
  char formattedHeap[20];
  formatBytes(minFreeHeap, formattedHeap, sizeof(formattedHeap));

  // JSON-Objekt erstellen
  DynamicJsonDocument doc(100);
  doc["free_heap"] = formattedHeap;

  String jsonResponse;
  serializeJson(doc, jsonResponse);
  server.send(200, "application/json", jsonResponse);
}

void handleUptime() {
  calculateUptime();
  DynamicJsonDocument doc(100);
  doc["uptime_seconds"] = totalSeconds;
  doc["uptime_formatted"] = formatUptime(totalSeconds);

  String jsonResponse;
  serializeJson(doc, jsonResponse);
  server.send(200, "application/json", jsonResponse);
}

void fileserverSetup() {
  server.on("/fs", HTTP_GET, handleFileList);
  server.on("/upload", HTTP_POST, sendResponce, handleFileUpload);
  server.on("/delete", HTTP_GET, handleFileDelete);
  server.on("/view", HTTP_GET, handleFileView);
  server.on("/format", HTTP_GET, handleFormat);
}

void handleFileList() {
  String files;
  File root = LittleFS.open("/");
  File file = root.openNextFile();

  while (file) {
    char buffer1[20];
    size_t sizeofFile = file.size();
    formatBytes(sizeofFile, buffer1, sizeof(buffer1));
    files += "<div class='file-container'>";
    files += "<span class='filename'>" + String(file.name()) + "</span>";
    files += "<span class='file-size'>" + String(buffer1) + "</span>";
    files += "<span class='file-date'>" + getLastModified(file) + "</span>";
    files += "<span class='file-actions'>";
    files += "<a href='/delete?file=/" + String(file.name()) + "'>Delete</a>";
    files += "<a href='/view?file=" + String(file.name()) + "'>View</a>";
    files += "</span></div>";
    file = root.openNextFile();
  }

  String html = "<html><head>";
  html += "<style>body { text-align: center; }";
  html += ".container { display: inline-block; text-align: center; padding: 20px; border: 1px solid #ccc; border-radius: 10px; }";
  html += ".file-container { margin: 10px 0; display: flex; align-items: center; }";
  html += ".filename { flex: 1; margin-right: 10px; text-align: left; }";
  html += ".file-size { font-size: 60%; margin-right: 10px; }";
  html += ".file-date { font-size: 60%; margin-right: 10px; }";
  html += ".file-actions { display: flex; }";
  html += ".file-actions a { margin-right: 5px; text-decoration: none; color: #007BFF; }";
  html += "</style></head><body>";
  html += "<div class='container'>";
  html += "<h2 style='margin-top: 0;'>Files on LittleFS</h2>";
  html += "<div class='file-list'>" + files + "</div>";
  html += "<br>";
  html += "<hr>";
  html += "<h3>Upload</h3>";
  html += "<form method='post' action='/upload' enctype='multipart/form-data'>";
  html += "<input type='file' name='upload[]' id='uploadFile' multiple>";
  html += "<input type='submit' value='Upload'>";
  html += "</form>";
  html += "<br>";
  html += "<hr>";
  html += "<h3>Format Filesystem</h3>";
  html += "<form method='get' action='/format'>";
  html += "<input type='submit' value='Format'>";
  html += "</form>";
  html += "</div></body></html>";

  server.send(200, "text/html", html);
}

void handleFileUpload() {
  if (server.uri() != "/upload") return;
  HTTPUpload& upload = server.upload();
  static File file;

  if (upload.status == UPLOAD_FILE_START) {
    String filename = "/" + upload.filename;
    DEBUG_PRINTLN("Upload started: " + filename);
    file = LittleFS.open(filename, "w");
    if (!file) {
      DEBUG_PRINTLN(F("Failed to open file for writing"));
      return;
    }
    DEBUG_PRINTLN(F("File opened for writing"));
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (file) {
      size_t bytesWritten = file.write(upload.buf, upload.currentSize);
      if (bytesWritten != upload.currentSize) {
        DEBUG_PRINTLN(F("Error writing to file"));
      } else {
        DEBUG_PRINTLN("Bytes written to file: " + String(upload.currentSize));
      }
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (file) {
      file.close();
      DEBUG_PRINTLN(F("Upload finished. File closed"));
    } else {
      DEBUG_PRINTLN(F("Upload finished, but file was not open"));
    }
  }
}

void handleFileDelete() {
  String filename = server.arg("file");
  DEBUG_PRINTLN("Delete: " + filename);

  if (LittleFS.remove(filename)) {
    DEBUG_PRINTLN(F("File deleted"));
  } else {
    DEBUG_PRINTLN(F("Failed to delete file"));
  }
  sendResponce();
}

void handleFileView() {
  String filename = server.arg("file");
  DEBUG_PRINTLN("View: " + filename);

  if (!filename.startsWith("/")) {
    filename = "/" + filename;
  }

  File file = LittleFS.open(filename, "r");
  if (!file) {
    DEBUG_PRINTLN(F("Failed to open file for reading"));
    server.send(404, "text/plain", "File not found");
    return;
  }

  String content = file.readString();
  file.close();

  String html = "<html><body><h2>File Viewer</h2><p>Content of " + filename + ":</p><pre>" + content + "</pre></body></html>";
  server.send(200, "text/html", html);
}

void handleFormat() {
  LittleFS.format();
  DEBUG_PRINTLN(F("Formating LittleFS"));
  sendResponce();
}

void sendResponce() {
  server.sendHeader("Location", "/fs");
  server.send(303, "message/http");
}

String getLastModified(File file) {
  time_t lastWriteTime = file.getLastWrite();
  struct tm* timeinfo;
  char buffer[20];
  timeinfo = localtime(&lastWriteTime);
  strftime(buffer, sizeof(buffer), "%d:%m:%y %H:%M", timeinfo);
  return String(buffer);
}





//********************************************
// Main Program
//********************************************
void setup() {
  Serial.begin(115200);
  lastMillis = millis();
  // WiFi initialisieren
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());


  if (CLOUD_ENABLED) {
    const bool httpsUrl = strncmp(CLOUD_API_URL, "https://", 8) == 0;
    if (httpsUrl && strlen(CLOUD_AUTH_TOKEN) > 0 && strlen(CLOUD_ROOT_CA_CERT) > 0 && isValidCloudDeviceId()) {
      cloudConfigurationReady = true;
      lastCloudUpload = millis() - CLOUD_UPLOAD_INTERVAL_MS;
      DEBUG_PRINTLN(F("[Cloud] Upload enabled"));
    } else {
      Serial.println(F("[Cloud] Upload enabled, but configuration is incomplete or invalid"));
    }
  } else {
    DEBUG_PRINTLN(F("[Cloud] Upload disabled"));
  }



  configTime(0, 0, "fritz.box", "de.pool.ntp.org");
  setupLittleFS();
  server.serveStatic("/main", LittleFS, "/index.html");
  server.serveStatic("/style.css", LittleFS, "/style.css", "text/css");
  server.on("/", HTTP_GET, handleRoot);
  server.on("/data", HTTP_GET, handleJSON);
  server.on("/control", HTTP_POST, handleControl);
  server.on("/sketchinfo", HTTP_GET, handleSketchInfo);
  server.on("/freeheap", HTTP_GET, handleFreeHeap);
  server.on("/uptime", HTTP_GET, handleUptime);
  fileserverSetup();
  server.begin();


  DEBUG_PRINTLN("Initializing NimBLE Client...");

  NimBLEDevice::init("MultiJKBMS-Client");
  NimBLEDevice::setPower(3);

  pScan = NimBLEDevice::getScan();
  pScan->setScanCallbacks(&scanCallbacks);
  pScan->setInterval(100);
  pScan->setWindow(100);
  pScan->setActiveScan(true);
}

void loop() {
  calculateUptime();
  monitorFreeHeap();

  server.handleClient();
   uploadCloudData();
  // Connection management
  int connectedCount = 0;  // Counter for connected devices

  for (int i = 0; i < bmsDeviceCount; i++) {
    if (jkBmsDevices[i].targetMAC.empty()) continue;  // Skip empty MAC addresses

    if (jkBmsDevices[i].doConnect && !jkBmsDevices[i].connected) {
      jkBmsDevices[i].connectToServer();
      jkBmsDevices[i].doConnect = false;
    }

    if (jkBmsDevices[i].connected) {
      connectedCount++;  // Increment counter for each connected device
      if (millis() - jkBmsDevices[i].lastNotifyTime > 20000) {
        DEBUG_PRINTF("%s connection timeout\n", jkBmsDevices[i].targetMAC.c_str());
        NimBLEClient* pClient = NimBLEDevice::getClientByPeerAddress(jkBmsDevices[i].advDevice->getAddress());
        if (pClient) pClient->disconnect();
      }
    }
  }

  // Start scan only if not all devices are connected
  if (connectedCount < bmsDeviceCount && (millis() - lastScanTime >= 10000)) {
    DEBUG_PRINTLN("Starting scan...");
    pScan->start(5000, false, true);
    lastScanTime = millis();
  }

  delay(10);
}
