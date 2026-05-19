# FCMReceiver Arduino Library

A Firebase Cloud Messaging (FCM) receiver library for ESP32 and ESP8266 (Arduino framework). Receive real-time push notifications directly from FCM via the MCS (Mobile Connection Server) protocol with WebPush `aesgcm` decryption.

## Features
- **Auto-registration (ESP32)** — only `api_key`, `app_id`, and `project_id` are needed. All device credentials (ECDH keys, GCM token, FCM token) are generated on-device automatically.
- **Pre-generated credentials** — supply `android_id`, `security_token`, `fcm_token`, `private_key_b64`, `auth_secret_b64` directly to skip registration entirely. Required for ESP8266.
- **NVS persistence (ESP32)** — generated credentials are saved to flash and reused across reboots. Registration only happens once.
- **Topic subscription (ESP32)** — subscribe and unsubscribe to FCM topics to manage broadcast messages dynamically.
- **Encrypted push** — decrypts WebPush `aesgcm` payloads on-device using mbedTLS (ESP32) or via an external decrypt endpoint (ESP8266 server-decrypt mode).
- **Persistent MCS connection** — maintains a long-lived TLS connection to Google's MCS server for instant message delivery.
- **Auto Reconnect** — built-in reconnect handler with exponential backoff and network watchdog.
- **Low overhead** — ESP32 runs in a dedicated FreeRTOS task; ESP8266 runs cooperatively from `loop()`.

## Supported Hardware
- ESP32 (all variants: ESP32, ESP32-S2, ESP32-S3, ESP32-C3, ESP32-C6, ESP32-H2)
- ESP8266 (NodeMCU/ESP-12E and similar) with pre-generated credentials only

## Installation

### PlatformIO

ESP32:
```ini
[env:my_esp32]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200
lib_ldf_mode = deep+
build_flags =
    -D ARDUINO_LOOP_STACK_SIZE=16384
lib_deps =
    https://github.com/agusibrahim/esp-fcm-arduino.git
```

ESP8266 (server-side decrypt):
```ini
[env:nodemcuv2]
platform = espressif8266
board = nodemcuv2
framework = arduino
board_build.f_cpu = 160000000L
monitor_speed = 115200
lib_ldf_mode = deep+
build_flags =
    -D FCM_REQUIRE_PREGENERATED_CREDENTIALS=1
    -D FCM_DECRYPT_VIA_SERVER=1
lib_deps =
    https://github.com/agusibrahim/esp-fcm-arduino.git
```

For ESP32 you also need an `sdkconfig.defaults` file in your project root to enable required mbedTLS features:
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

## Quick Start (ESP32)

```cpp
#include <Arduino.h>
#include <WiFi.h>
#include <FCMReceiver.h>

// Only 3 fields needed — credentials auto-generated and saved to NVS
static const fcm_config_t fcm_cfg = {
    .api_key    = "YOUR_FIREBASE_API_KEY",
    .app_id     = "YOUR_FIREBASE_APP_ID",
    .project_id = "YOUR_FIREBASE_PROJECT_ID",
    .auto_reconnect = true,
    .status_cb = [](fcm_status_t status) {
        Serial.printf("FCM Status: %d\n", status);
    }
};

static void on_message(const fcm_message_t *msg) {
    if (msg->notif_data) {
        Serial.printf("Title: %s\n", msg->notif_data->title);
        Serial.printf("Body:  %s\n", msg->notif_data->body);
    }
}

static void mcs_task(void *arg) {
    while (1) {
        fcm_start(on_message);
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

void setup() {
    Serial.begin(115200);
    WiFi.begin("SSID", "PASSWORD");
    while (WiFi.status() != WL_CONNECTED) delay(500);

    fcm_init(&fcm_cfg);
    fcm_subscribe("my_topic");
    xTaskCreate(mcs_task, "mcs", FCM_MIN_STACK_SIZE, NULL, 5, NULL);
}

void loop() { delay(1000); }
```

## Quick Start (ESP8266 with server-side decrypt)

ESP8266 cannot run on-device WebPush ECDH/AES-GCM reliably, so the library
delegates decryption to an HTTP endpoint such as the companion
[fcm_credentials_gen](https://github.com/agusibrahim/fcm_credentials_gen) Cloudflare Worker.

```cpp
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <FCMReceiver.h>

#define FCM_DECRYPT_API "http://your-worker.example.com/api/decrypt"

static const fcm_config_t fcm_cfg = {
    .android_id      = 0000000000000000000ULL,
    .security_token  = 0000000000000000000ULL,
    .fcm_token       = "YOUR_FCM_TOKEN",
    .private_key_b64 = "YOUR_PKCS8_PRIVATE_KEY_BASE64",
    .auth_secret_b64 = "YOUR_AUTH_SECRET_BASE64",
    .auto_reconnect  = false,
    .status_cb = [](fcm_status_t status) {
        Serial.printf("FCM Status: %d\n", status);
    },
    .decrypt_api_url = FCM_DECRYPT_API
};

static void on_message(const fcm_message_t *msg) {
    if (msg->notif_data) {
        Serial.printf("Title: %s\n", msg->notif_data->title);
        Serial.printf("Body:  %s\n", msg->notif_data->body);
    }
}

void setup() {
    Serial.begin(115200);
    WiFi.begin("SSID", "PASSWORD");
    while (WiFi.status() != WL_CONNECTED) delay(500);
    fcm_init(&fcm_cfg);
}

void loop() {
    fcm_start(on_message);
    delay(1000);
}
```

## Examples

See the bundled example sketches under `lib/FCMReceiver/examples/`:

- `BasicReceive` — simplest ESP32 receiver with auto-registration.
- `ESP32_AutoRegister` — same as BasicReceive, with status callback.
- `ESP32_PreGenerated` — ESP32 with pre-generated credentials.
- `ESP32_TopicSubscribe` — ESP32 subscribing to multiple topics.
- `ESP8266_RawData` — ESP8266 receiving raw MCS messages without decrypt.
- `ESP8266_DecryptViaServer` — ESP8266 with server-side decrypt endpoint.

## How It Works

### ESP32

On first boot, `fcm_init()` performs a 4-step registration:

1. **GCM Checkin** — registers as a Chrome browser client, receives `android_id` and `security_token`.
2. **GCM Register** — exchanges the device identity for a `gcm_token`.
3. **FCM Install** — creates a Firebase Installation and obtains an auth token.
4. **FCM Register** — registers for WebPush and receives the final `fcm_token`.

All credentials (including the generated ECDH private key and auth secret) are persisted to NVS. On subsequent boots, credentials are loaded from NVS and registration is skipped.

After initialization, `fcm_start()` opens a TLS connection to `mtalk.google.com:5228` and listens for incoming messages using the MCS protobuf protocol.

### ESP8266

ESP8266 must use pre-generated credentials (no on-device registration in this milestone). On encrypted messages with `FCM_DECRYPT_VIA_SERVER=1`, the library:

1. Receives an MCS `DataMessageStanza` with `crypto-key`, `encryption`, and encrypted `raw_data`.
2. Closes the MCS TLS connection to free heap.
3. POSTs the encrypted payload, server public key, salt, and your `private_key_b64` / `auth_secret_b64` to your `decrypt_api_url` endpoint.
4. Parses the JSON response and invokes the user callback with `msg->json_data` and `msg->notif_data` populated, identical in shape to the ESP32 path.
5. Persists the message timestamp via LittleFS so duplicates are skipped on reconnect.

## Where to Find Your Firebase Credentials

1. Go to the [Firebase Console](https://console.firebase.google.com/)
2. Select your project (or create one)
3. Go to **Project Settings** (gear icon)
4. Under **General**, find:
   - **Project ID** — listed at the top
   - **Web API Key** — listed as "Web API Key"
5. Under **Your apps**, find or create an app:
   - **App ID** — the full app ID string (e.g. `1:123456789:android:abcdef123456`)

To generate `fcm_token`, `private_key_b64`, `auth_secret_b64`, `android_id`, and `security_token` for ESP8266, use the companion [fcm_credentials_gen](https://github.com/agusibrahim/fcm_credentials_gen) Cloudflare Worker.

## API Reference

### `fcm_init(const fcm_config_t *config)`
Initialize FCM. ESP32: auto-registers if no credentials exist in NVS. ESP8266: requires pre-generated credentials.

### `fcm_clear_credentials(void)`
Wipes out NVS-stored credentials on demand (e.g. for factory reset). ESP32 only.

### `fcm_get_token(void)`
Returns the current FCM token, or empty string if not initialized.

### `fcm_set_heartbeat_interval(uint32_t seconds)`
Overrides the default 600s ping interval to check network connection vitality.

### `fcm_subscribe(const char *topic)` / `fcm_unsubscribe(const char *topic)`
Subscribe or unsubscribe to an FCM topic. ESP32 only.

### `fcm_start(fcm_message_cb_t callback)`
Connect to MCS and listen for messages. On ESP32, blocks indefinitely if `auto_reconnect` is true and should run in a FreeRTOS task with at least `FCM_MIN_STACK_SIZE` (16KB). On ESP8266, returns when the MCS connection closes (e.g. after server-side decrypt) and should be re-invoked from `loop()`.

### `fcm_config_t`
```c
typedef struct {
    const char *api_key;        // Firebase API key (ESP32 auto-register)
    const char *app_id;         // Firebase app ID (ESP32 auto-register)
    const char *project_id;     // Firebase project ID (ESP32 auto-register)

    // Pre-generated credentials (skip auto-registration; required on ESP8266)
    uint64_t    android_id;
    uint64_t    security_token;
    const char *fcm_token;
    const char *private_key_b64;
    const char *auth_secret_b64;

    bool        auto_reconnect;
    fcm_status_cb_t status_cb;

    // ESP8266 server-side decrypt endpoint (used when FCM_DECRYPT_VIA_SERVER=1)
    const char *decrypt_api_url;
} fcm_config_t;
```

## License
MIT
