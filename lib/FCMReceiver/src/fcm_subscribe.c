#include "FCMReceiver.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_http_client.h"
#include "fcm_root_ca.h"

#define REGISTER_URL "https://android.clients.google.com/c2dm/register3"
#define RESPONSE_BUF_SIZE 2048

static char s_response_buf[RESPONSE_BUF_SIZE];
static int  s_response_len;

static esp_err_t http_event_handler(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            if (s_response_len + evt->data_len < RESPONSE_BUF_SIZE - 1) {
                memcpy(s_response_buf + s_response_len, evt->data, evt->data_len);
                s_response_len += evt->data_len;
                s_response_buf[s_response_len] = '\0';
            }
            break;
        default:
            break;
    }
    return ESP_OK;
}

esp_err_t fcm_subscribe(const char *topic) {
    const fcm_config_t *cfg = fcm_get_config();
    if (!cfg) return ESP_FAIL;

    // Build Authorization header
    char auth_header[128];
    snprintf(auth_header, sizeof(auth_header), "AidLogin %llu:%llu",
             (unsigned long long)cfg->android_id,
             (unsigned long long)cfg->security_token);

    // Build topic path
    char topic_path[256];
    snprintf(topic_path, sizeof(topic_path), "/topics/%s", topic);

    // Generate a random X-kid value
    uint32_t kid_rand = (uint32_t)(esp_random() % 999999 + 1);
    char kid_str[32];
    snprintf(kid_str, sizeof(kid_str), "|ID|%u|", (unsigned)kid_rand);

    // Build form-encoded body
    char body[2048];
    int body_len = snprintf(body, sizeof(body),
        "X-subtype=%s"
        "&sender=%s"
        "&X-gcm.topic=%s"
        "&X-scope=%s"
        "&X-subscription=%s"
        "&X-kid=%s"
        "&app=org.chromium.linux"
        "&device=%llu"
        "&X-gms_app_id=%s",
        cfg->fcm_token,
        cfg->fcm_token,
        topic_path,
        topic_path,
        cfg->fcm_token,
        kid_str,
        (unsigned long long)cfg->android_id,
        cfg->app_id);

    printf("[FCM] Subscribing to topic: %s\n", topic_path);

    s_response_len = 0;
    s_response_buf[0] = '\0';

    esp_http_client_config_t config = {
        .url = REGISTER_URL,
        .method = HTTP_METHOD_POST,
        .event_handler = http_event_handler,
        .cert_pem = GOOGLE_ROOT_CA_PEM,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);

    esp_http_client_set_header(client, "Authorization", auth_header);
    esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
    esp_http_client_set_post_field(client, body, body_len);

    esp_err_t err = esp_http_client_perform(client);
    int status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        printf("[FCM] ERROR: HTTP request failed: %s\n", esp_err_to_name(err));
        return err;
    }

    printf("[FCM] Subscribe response (HTTP %d): %s\n", status_code, s_response_buf);

    if (status_code != 200) {
        printf("[FCM] ERROR: Subscribe HTTP error: %d\n", status_code);
        return ESP_FAIL;
    }

    // Check for error in response
    if (strstr(s_response_buf, "Error=") != NULL) {
        printf("[FCM] ERROR: Subscribe error: %s\n", s_response_buf);
        return ESP_FAIL;
    }

    // Check for success
    if (strstr(s_response_buf, "token=") != NULL) {
        printf("[FCM] Topic subscription successful\n");
        return ESP_OK;
    }

    printf("[FCM] Unexpected subscribe response, continuing anyway\n");
    return ESP_OK;
}
