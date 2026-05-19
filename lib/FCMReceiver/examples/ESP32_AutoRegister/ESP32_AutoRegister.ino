// ESP32 example: auto-register a new device with Firebase using api_key,
// app_id, and project_id only. Credentials are generated and persisted in NVS.
//
// Hardware: any ESP32 board with WiFi.
// Library: FCMReceiver (this folder).

#include <Arduino.h>
#include <WiFi.h>
#include <FCMReceiver.h>

#define WIFI_SSID  "YOUR_WIFI_SSID"
#define WIFI_PASS  "YOUR_WIFI_PASSWORD"

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
        Serial.println("=== FCM Notification ===");
        Serial.printf("  title: %s\n", msg->notif_data->title);
        Serial.printf("  body:  %s\n", msg->notif_data->body);
        for (int i = 0; i < msg->notif_data->data_count; i++) {
            Serial.printf("  data[%s]: %s\n",
                          msg->notif_data->data[i].key,
                          msg->notif_data->data[i].value);
        }
        Serial.println("========================");
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
        Serial.print(".");
    }
    Serial.printf("\nWiFi: %s\n", WiFi.localIP().toString().c_str());

    if (fcm_init(&fcm_cfg) != ESP_OK) {
        Serial.println("fcm_init failed");
        return;
    }
    Serial.printf("FCM Token: %s\n", fcm_get_token());

    xTaskCreate(mcs_task, "mcs_task", FCM_MIN_STACK_SIZE, NULL, 5, NULL);
}

void loop() {
    delay(1000);
}
