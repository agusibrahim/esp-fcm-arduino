// ESP32 example: subscribe and unsubscribe from FCM topics so the device can
// receive broadcast messages addressed to a topic instead of an individual
// token. Topics are subscribed via Firebase HTTP after registration.

#include <Arduino.h>
#include <WiFi.h>
#include <FCMReceiver.h>

#define WIFI_SSID  "YOUR_WIFI_SSID"
#define WIFI_PASS  "YOUR_WIFI_PASSWORD"

#define TOPIC_NEWS   "news"
#define TOPIC_PROMO  "promotions"

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
        Serial.printf("[FCM] %s | %s\n",
                      msg->notif_data->title,
                      msg->notif_data->body);
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
    while (WiFi.status() != WL_CONNECTED) delay(500);
    Serial.printf("WiFi: %s\n", WiFi.localIP().toString().c_str());

    if (fcm_init(&fcm_cfg) != ESP_OK) {
        Serial.println("fcm_init failed");
        return;
    }
    Serial.printf("FCM Token: %s\n", fcm_get_token());

    if (fcm_subscribe(TOPIC_NEWS) == ESP_OK) {
        Serial.printf("Subscribed: %s\n", TOPIC_NEWS);
    }
    if (fcm_subscribe(TOPIC_PROMO) == ESP_OK) {
        Serial.printf("Subscribed: %s\n", TOPIC_PROMO);
    }

    // Example: unsubscribe later when you no longer want a topic.
    // fcm_unsubscribe(TOPIC_PROMO);

    xTaskCreate(mcs_task, "mcs_task", FCM_MIN_STACK_SIZE, NULL, 5, NULL);
}

void loop() {
    delay(1000);
}
