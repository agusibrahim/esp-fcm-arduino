// ESP32 example: skip auto-registration by supplying pre-generated FCM
// credentials directly. Useful when device credentials are issued by an
// external service (e.g. a Cloudflare Worker) and you want to flash them.
//
// android_id and security_token must be non-zero to bypass registration.

#include <Arduino.h>
#include <WiFi.h>
#include <FCMReceiver.h>

#define WIFI_SSID  "YOUR_WIFI_SSID"
#define WIFI_PASS  "YOUR_WIFI_PASSWORD"

static const fcm_config_t fcm_cfg = {
    .android_id      = 0000000000000000000ULL,
    .security_token  = 0000000000000000000ULL,
    .fcm_token       = "YOUR_FCM_TOKEN",
    .private_key_b64 = "YOUR_PKCS8_PRIVATE_KEY_BASE64",
    .auth_secret_b64 = "YOUR_AUTH_SECRET_BASE64",
    .auto_reconnect  = true,
    .status_cb = [](fcm_status_t status) {
        Serial.printf("FCM Status: %d\n", status);
    }
};

static void on_message(const fcm_message_t *msg) {
    if (msg->notif_data) {
        Serial.printf("[FCM] %s | %s\n",
                      msg->notif_data->title,
                      msg->notif_data->body);
    } else if (msg->json_data) {
        Serial.printf("[FCM] JSON: %s\n", msg->json_data);
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
    delay(500);

    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
    }
    Serial.printf("WiFi: %s\n", WiFi.localIP().toString().c_str());

    if (fcm_init(&fcm_cfg) != ESP_OK) {
        Serial.println("fcm_init failed");
        return;
    }

    xTaskCreate(mcs_task, "mcs_task", FCM_MIN_STACK_SIZE, NULL, 5, NULL);
}

void loop() {
    delay(1000);
}
