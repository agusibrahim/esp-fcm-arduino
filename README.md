# FCMReceiver Arduino Library

A Firebase Cloud Messaging (FCM) receiver library for ESP32 (Arduino framework). This library allows your ESP32 to receive real-time push notifications directly from FCM via the MCS (Mobile Connection Server) protocol with WebPush `aesgcm` decryption.

## Features
- **Auto-registration** — only `api_key`, `app_id`, and `project_id` are needed. All device credentials (ECDH keys, GCM token, FCM token) are generated on-device automatically.
- **NVS persistence** — generated credentials are saved to flash and reused across reboots. Registration only happens once.
- **Topic subscription** — subscribe to FCM topics to receive broadcast messages.
- **Encrypted push** — decrypts WebPush `aesgcm` payloads on-device using mbedTLS.
- **Persistent MCS connection** — maintains a long-lived TLS connection to Google's MCS server for instant message delivery.
- **Low overhead** — runs in a dedicated FreeRTOS task, no HTTP polling required.

## Supported Hardware
- ESP32 (all variants: ESP32, ESP32-S2, ESP32-S3, ESP32-C3, ESP32-C6, ESP32-H2)

> **Note:** ESP8266 is not supported. This library uses ESP-IDF APIs (NVS, esp_http_client, mbedTLS) available only on ESP32.

## Installation

### PlatformIO
Add the following to your `platformio.ini`:
```ini
[env:my_board]
platform = espressif32
board = esp32-c3-devkitc-02
framework = arduino
monitor_speed = 115200
lib_ldf_mode = deep+
build_flags =
    -D ARDUINO_LOOP_STACK_SIZE=16384
lib_deps =
    https://github.com/agusibrahim/esp-fcm-arduino.git
```

You also need a `sdkconfig.defaults` file in your project root to enable required mbedTLS features:
```
CONFIG_MBEDTLS_HKDF_C=y
CONFIG_MBEDTLS_ECDH_C=y
CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED=y
CONFIG_MBEDTLS_GCM_C=y
CONFIG_MBEDTLS_PK_PARSE_EC_EXTENDED=y
CONFIG_MBEDTLS_PK_WRITE_C=y
```

> After adding or changing `sdkconfig.defaults`, do a clean build (`pio run -t clean && pio run`) so the settings take effect.

### Arduino IDE
1. Download this repository as a `.zip` file.
2. In the Arduino IDE, go to **Sketch > Include Library > Add .ZIP Library...**
3. Select the downloaded `.zip` file.

## Quick Start

```cpp
#include <Arduino.h>
#include <WiFi.h>
#include <FCMReceiver.h>

// Only 3 fields needed — credentials auto-generated and saved to NVS
static const fcm_config_t fcm_cfg = {
    .api_key    = "YOUR_FIREBASE_API_KEY",
    .app_id     = "YOUR_FIREBASE_APP_ID",
    .project_id = "YOUR_FIREBASE_PROJECT_ID",
};

static void on_message(const fcm_message_t *msg) {
    if (msg->notif_data) {
        Serial.printf("Title: %s\n", msg->notif_data->title);
        Serial.printf("Body:  %s\n", msg->notif_data->body);
    }
}

static void mcs_task(void *arg) {
    fcm_start(on_message);     // blocks forever, listening for messages
    vTaskDelay(pdMS_TO_TICKS(3000));
    esp_restart();
}

void setup() {
    Serial.begin(115200);
    WiFi.begin("SSID", "PASSWORD");
    while (WiFi.status() != WL_CONNECTED) delay(500);

    fcm_init(&fcm_cfg);                  // auto-registers on first boot
    fcm_subscribe("my_topic");            // subscribe to a topic
    xTaskCreate(mcs_task, "mcs", 16384, NULL, 5, NULL);
}

void loop() { delay(1000); }
```

See the [BasicReceive example](./lib/FCMReceiver/examples/BasicReceive/BasicReceive.ino) for a complete working sketch.

## How It Works

On first boot, `fcm_init()` performs a 4-step registration:

1. **GCM Checkin** — registers as a Chrome browser client, receives `android_id` and `security_token`.
2. **GCM Register** — exchanges the device identity for a `gcm_token`.
3. **FCM Install** — creates a Firebase Installation and obtains an auth token.
4. **FCM Register** — registers for WebPush and receives the final `fcm_token`.

All credentials (including the generated ECDH private key and auth secret) are persisted to NVS. On subsequent boots, credentials are loaded from NVS and registration is skipped.

After initialization, `fcm_start()` opens a TLS connection to `mtalk.google.com:5228` and listens for incoming messages using the MCS protobuf protocol.

## Where to Find Your Firebase Credentials

1. Go to the [Firebase Console](https://console.firebase.google.com/)
2. Select your project (or create one)
3. Go to **Project Settings** (gear icon)
4. Under **General**, find:
   - **Project ID** — listed at the top
   - **Web API Key** — listed as "Web API Key"
5. Under **Your apps**, find or create an app:
   - **App ID** — the full app ID string (e.g. `1:123456789:android:abcdef123456`)

## API Reference

### `fcm_init(const fcm_config_t *config)`
Initialize FCM. Auto-registers if no credentials exist in NVS.

### `fcm_subscribe(const char *topic)`
Subscribe to an FCM topic. Requires `fcm_init()` to be called first.

### `fcm_start(fcm_message_cb_t callback)`
Connect to MCS and listen for messages. **Blocks indefinitely.** Run this in a dedicated FreeRTOS task with at least 16KB stack.

### `fcm_config_t`
```c
typedef struct {
    const char *api_key;        // Firebase API key (required)
    const char *app_id;         // Firebase app ID (required)
    const char *project_id;     // Firebase project ID (required)

    // Optional: pre-generated credentials (skip auto-registration)
    uint64_t    android_id;
    uint64_t    security_token;
    const char *fcm_token;
    const char *private_key_b64;
    const char *auth_secret_b64;
} fcm_config_t;
```

## License
MIT
