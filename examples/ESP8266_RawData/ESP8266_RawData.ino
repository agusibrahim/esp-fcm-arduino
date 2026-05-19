// ESP8266 example: receive FCM/MCS messages without on-device decrypt and
// without a server-side decrypt endpoint. The callback only inspects raw
// MCS fields exposed by the library:
//
//   msg->id
//   msg->persistent_id
//   msg->from
//   msg->app_data[]      (key/value pairs from the MCS DataMessageStanza)
//   msg->raw_data        (encrypted WebPush payload, if any)
//
// Use this when you only need un-encrypted FCM data messages (e.g. those
// sent without the `notification` payload), or when you want to forward
// the encrypted payload to your own backend for processing.
//
// Build flags expected (platformio.ini):
//   -D FCM_REQUIRE_PREGENERATED_CREDENTIALS=1

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <FCMReceiver.h>

#define WIFI_SSID  "YOUR_WIFI_SSID"
#define WIFI_PASS  "YOUR_WIFI_PASSWORD"

static const fcm_config_t fcm_cfg = {
    .android_id      = 0000000000000000000ULL,
    .security_token  = 0000000000000000000ULL,
    .fcm_token       = "YOUR_FCM_TOKEN",
    .private_key_b64 = "YOUR_PKCS8_PRIVATE_KEY_BASE64",
    .auth_secret_b64 = "YOUR_AUTH_SECRET_BASE64",
    .auto_reconnect  = false,
    .status_cb = [](fcm_status_t status) {
        Serial.printf("FCM Status: %d\n", status);
    }
};

static void on_message(const fcm_message_t *msg) {
    Serial.println("=== FCM Raw Message ===");
    Serial.printf("  id:    %s\n", msg->id);
    Serial.printf("  pid:   %s\n", msg->persistent_id);
    Serial.printf("  from:  %s\n", msg->from);
    for (int i = 0; i < msg->app_data_count; i++) {
        Serial.printf("  %s = %s\n",
                      msg->app_data[i].key,
                      msg->app_data[i].value);
    }
    if (msg->raw_data && msg->raw_data_len > 0) {
        Serial.printf("  raw_data: %u bytes (encrypted)\n",
                      (unsigned)msg->raw_data_len);
    }
    Serial.println("=======================");
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
