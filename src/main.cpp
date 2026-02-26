#include <Arduino.h>
#include <WiFi.h>
#include <FCMReceiver.h>

// ── Configuration ──

#define WIFI_SSID       "Kaylaa"
#define WIFI_PASS       "agus00000"
#define FCM_TOPIC       "testtopic123"

static const fcm_config_t fcm_cfg = {
    .android_id       = 4744667548749788366ULL,
    .security_token   = 5844494356801553287ULL,
    .fcm_token        = "c0EijweI0KE98LQC2IZ0gD:APA91bHiFk8LJESzPu6Vcg6iqsvVEbXOVIqcDdeUj3DTM6IWatuCvPcBHTlweu705gXHsPK9AkNVR558qvrvh2aAYnXZFef37-3x6QbytxKlxJsi8Klgjpc",
    .app_id           = "1:1097968069254:android:e6c01d44c6789e69f23f07",
    .private_key_b64  = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2Wq+fDvrnNPYqfCcOi0ifUS+96wd8958Uvk5VZyy7dyhRANCAARllWmFFT3aJhLwaqwEW4m+j5yGrStjEY/f+ugjWoAJIovbF2EX4L9Ki9NX6xlQtW6M1t91mBvoZ8+H7HiZKw55",
    .auth_secret_b64  = "76CNtQWr3r4Am1v/Cl8aWA==",
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

    Serial.println("Restarting in 5 seconds...");
    vTaskDelay(pdMS_TO_TICKS(3000));
    esp_restart();
}

// ── Arduino setup & loop ──

void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println("ESP32 FCM Receiver (Arduino)");

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
