#include <Arduino.h>
#include <WiFi.h>
#include <FCMReceiver.h>

// ── Configuration ──

#define WIFI_SSID       "YOUR_WIFI_SSID"
#define WIFI_PASS       "YOUR_WIFI_PASSWORD"
#define FCM_TOPIC       "testtopic123"

// Replace these values with your actual device credentials generated via the push receiver script
static const fcm_config_t fcm_cfg = {
    .android_id       = 4744667548749788366ULL,
    .security_token   = 5844494356801553287ULL,
    .fcm_token        = "YOUR_FCM_TOKEN_HERE",
    .app_id           = "YOUR_FIREBASE_APP_ID",
    .private_key_b64  = "YOUR_PRIVATE_KEY_BASE64",
    .auth_secret_b64  = "YOUR_AUTH_SECRET_BASE64",
};

// ── FCM message callback ──

static void on_message(const fcm_message_t *msg) {
    if (msg->notif_data) {
        Serial.println("=== FCM Notification ===");
        Serial.printf("  pid:   %s\n", msg->persistent_id);
        Serial.printf("  title: %s\n", msg->notif_data->title);
        Serial.printf("  body:  %s\n", msg->notif_data->body);
        Serial.printf("  msgId: %s\n", msg->notif_data->fcm_message_id);
        for (int i = 0; i < msg->notif_data->data_count; i++) {
            Serial.printf("  data[%s]: %s\n",
                          msg->notif_data->data[i].key,
                          msg->notif_data->data[i].value);
        }
        Serial.println("========================");
    } else if (msg->json_data) {
        Serial.printf("[FCM] Raw JSON: %s\n", msg->json_data);
    } else {
        Serial.printf("[FCM] Unprocessed message, id: %s\n", msg->id);
    }
}

// ── MCS task (runs in dedicated FreeRTOS task with large stack) ──

static void mcs_task(void *arg) {
    esp_err_t err = fcm_start(on_message);
    Serial.printf("MCS listener exited: %d\n", err);

    Serial.println("Restarting in 3 seconds...");
    vTaskDelay(pdMS_TO_TICKS(3000));
    esp_restart();
}

// ── Arduino setup & loop ──

void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println("ESP32 FCM Receiver Example");

    // Connect to WiFi
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    Serial.printf("Connecting to WiFi '%s'", WIFI_SSID);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.printf("\nWiFi connected, IP: %s\n", WiFi.localIP().toString().c_str());

    // Initialize FCM
    esp_err_t ret = fcm_init(&fcm_cfg);
    if (ret != ESP_OK) {
        Serial.printf("fcm_init failed: %d\n", ret);
        return;
    }
    Serial.println("FCM initialized");

    // Subscribe to topic
    ret = fcm_subscribe(FCM_TOPIC);
    if (ret != ESP_OK) {
        Serial.printf("fcm_subscribe failed: %d (continuing anyway)\n", ret);
    } else {
        Serial.println("Topic subscription successful");
    }

    // Start MCS listener in dedicated task (TLS needs ~16KB stack)
    Serial.println("Starting MCS listener...");
    xTaskCreate(mcs_task, "mcs_task", 16384, NULL, 5, NULL);
}

void loop() {
    delay(1000);
}
