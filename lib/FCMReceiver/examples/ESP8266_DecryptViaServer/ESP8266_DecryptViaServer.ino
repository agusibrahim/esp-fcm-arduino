// ESP8266 example: receive encrypted FCM/WebPush messages on NodeMCU/ESP-12E.
//
// ESP8266 cannot run on-device WebPush decrypt reliably, so this example
// uses a server-side decrypt endpoint configured via decrypt_api_url.
// Library handles the HTTPS POST internally and the callback gets
// already-decrypted notif_data/json_data, just like ESP32.
//
// Build flags expected (platformio.ini):
//   -D FCM_REQUIRE_PREGENERATED_CREDENTIALS=1
//   -D FCM_DECRYPT_VIA_SERVER=1
//
// Use http:// for the decrypt URL if your worker accepts plain HTTP — TLS
// after closing the MCS socket can be unreliable on ESP8266 heap. Otherwise
// use https:// and accept occasional retry on -1 / connection lost.

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <FCMReceiver.h>

#define WIFI_SSID       "YOUR_WIFI_SSID"
#define WIFI_PASS       "YOUR_WIFI_PASSWORD"
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
        Serial.println("=== FCM Notification ===");
        Serial.printf("  title: %s\n", msg->notif_data->title);
        Serial.printf("  body:  %s\n", msg->notif_data->body);
        Serial.println("========================");
    } else if (msg->json_data) {
        Serial.printf("[FCM] JSON: %s\n", msg->json_data);
    }
}

void setup() {
    system_update_cpu_freq(160);
    Serial.begin(115200);
    delay(500);

    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.printf("\nWiFi: %s\n", WiFi.localIP().toString().c_str());

    if (fcm_init(&fcm_cfg) != ESP_OK) {
        Serial.println("fcm_init failed");
        return;
    }
    Serial.print("FCM Token: ");
    Serial.println(fcm_get_token());
}

void loop() {
    fcm_start(on_message);
    delay(1000);
}
