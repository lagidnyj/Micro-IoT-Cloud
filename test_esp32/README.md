# ESP32 Cloud Test

`test.ino` is a test sketch for compiling on an ESP32 and checking that the
Micro-IoT-Cloud upload API is reachable and accepts data. It sends a sample
JSON payload to `backend/api.php` every 30 seconds and prints the request
payload, HTTP response code, and response body to the Serial Monitor.

The sketch has been compiled and used successfully to verify cloud operation.
It sends generated test values; it does not read data from a physical sensor
or BMS.

## Before uploading

Set the following values near the beginning of `test.ino`:

- `ssid` and `password` — Wi-Fi network credentials.
- `cloudUrl` — the HTTPS URL for `backend/api.php`, including the device ID.
- `apiToken` — the individual `device_token` created for `esp32_test` in the
  cloud database/admin panel. The sketch sends it as a Bearer token; it is no
  longer a shared API token.

Upload the sketch to an ESP32 and open the Serial Monitor at **115200 baud**.
The sketch connects to Wi-Fi, synchronizes its clock through NTP, sends a test
packet during startup, then continues sending packets every 30 seconds.

## TLS note

The sketch currently calls `client.setInsecure()`, which disables HTTPS
certificate verification. This is convenient for testing servers with
self-signed certificates, but does not authenticate the server and should not
be used as-is for production deployments.
