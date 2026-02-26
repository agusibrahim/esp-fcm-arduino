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
    Serial.println("=== FCM Message Received ===");
    // if (msg->id[0])            Serial.printf("  id:       %s\n", msg->id);
    // if (msg->from[0])          Serial.printf("  from:     %s\n", msg->from);
    // if (msg->category[0])      Serial.printf("  category: %s\n", msg->category);
    // if (msg->persistent_id[0]) Serial.printf("  pid:      %s\n", msg->persistent_id);

    // Print app_data key-value pairs
    const char *crypto_key_str = NULL;
    const char *encryption_str = NULL;

    for (int i = 0; i < msg->app_data_count; i++) {
        // Serial.printf("  app_data[%d]: %s = %s\n", i,
        //          msg->app_data[i].key, msg->app_data[i].value);

        if (strcmp(msg->app_data[i].key, "crypto-key") == 0) {
            crypto_key_str = msg->app_data[i].value;
        } else if (strcmp(msg->app_data[i].key, "encryption") == 0) {
            encryption_str = msg->app_data[i].value;
        }
    }

    // If encrypted message, try to decrypt
    if (crypto_key_str && encryption_str && msg->raw_data && msg->raw_data_len > 0) {
        // Serial.printf("  raw_data: %d bytes (encrypted)\n", (int)msg->raw_data_len);

        // Extract dh= from crypto-key
        const char *dh_start = strstr(crypto_key_str, "dh=");
        if (!dh_start) {
            Serial.println("  No dh= in crypto-key");
            return;
        }
        dh_start += 3;
        const char *dh_end = strchr(dh_start, ';');
        size_t dh_len = dh_end ? (size_t)(dh_end - dh_start) : strlen(dh_start);

        uint8_t server_pub[128];
        size_t server_pub_len = 0;
        if (fcm_base64url_decode(dh_start, dh_len, server_pub, sizeof(server_pub), &server_pub_len) != 0) {
            Serial.println("  Failed to decode dh=");
            return;
        }

        // Extract salt= from encryption
        const char *salt_start = strstr(encryption_str, "salt=");
        if (!salt_start) {
            Serial.println("  No salt= in encryption");
            return;
        }
        salt_start += 5;
        const char *salt_end = strchr(salt_start, ';');
        size_t salt_str_len = salt_end ? (size_t)(salt_end - salt_start) : strlen(salt_start);

        uint8_t salt[64];
        size_t salt_len = 0;
        if (fcm_base64url_decode(salt_start, salt_str_len, salt, sizeof(salt), &salt_len) != 0) {
            Serial.println("  Failed to decode salt=");
            return;
        }

        // Decrypt
        uint8_t *plaintext = (uint8_t *)malloc(msg->raw_data_len);
        size_t plaintext_len = 0;
        esp_err_t err = fcm_decrypt(server_pub, server_pub_len,
                                     salt, salt_len,
                                     msg->raw_data, msg->raw_data_len,
                                     plaintext, &plaintext_len);
        if (err == ESP_OK && plaintext_len > 0) {
            // Null-terminate for printing
            uint8_t *printbuf = (uint8_t *)malloc(plaintext_len + 1);
            memcpy(printbuf, plaintext, plaintext_len);
            printbuf[plaintext_len] = '\0';
            Serial.printf("%s\n", (char *)printbuf);
            free(printbuf);
        } else {
            Serial.println("  Decryption failed");
        }
        free(plaintext);
    } else if (msg->raw_data && msg->raw_data_len > 0) {
        // Raw unencrypted data
        uint8_t *printbuf = (uint8_t *)malloc(msg->raw_data_len + 1);
        memcpy(printbuf, msg->raw_data, msg->raw_data_len);
        printbuf[msg->raw_data_len] = '\0';
        Serial.printf("  raw_data (%d bytes): %s\n", (int)msg->raw_data_len, (char *)printbuf);
        free(printbuf);
    }

    Serial.println("============================");
}

// ── MCS task (runs in dedicated FreeRTOS task with large stack) ──

static void mcs_task(void *arg) {
    esp_err_t err = fcm_start(on_message);
    Serial.printf("MCS listener exited: %d\n", err);

    Serial.println("Restarting in 5 seconds...");
    vTaskDelay(pdMS_TO_TICKS(5000));
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
    // ret = fcm_subscribe(FCM_TOPIC);
    // if (ret != ESP_OK) {
    //     Serial.printf("fcm_subscribe failed: %d (continuing anyway)\n", ret);
    // } else {
    //     Serial.println("Topic subscription successful");
    // }

    // Start MCS listener in dedicated task (TLS needs ~16KB stack)
    Serial.println("Starting MCS listener...");
    xTaskCreate(mcs_task, "mcs_task", 16384, NULL, 5, NULL);
}

void loop() {
    delay(1000);
}
