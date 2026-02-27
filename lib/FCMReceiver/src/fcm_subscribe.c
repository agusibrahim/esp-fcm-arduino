#include "FCMReceiver.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_http_client.h"
#include "fcm_root_ca.h"

#define REGISTER_URL "https://android.clients.google.com/c2dm/register3"
#define RESPONSE_BUF_SIZE 2048

typedef struct {
    char *buf;
    int len;
    int cap;
} http_resp_t;

static esp_err_t http_event_handler(esp_http_client_event_t *evt) {
    http_resp_t *resp = (http_resp_t *)evt->user_data;
    if (!resp) return ESP_OK;

    switch (evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            if (resp->len + evt->data_len < resp->cap - 1) {
                memcpy(resp->buf + resp->len, evt->data, evt->data_len);
                resp->len += evt->data_len;
                resp->buf[resp->len] = '\0';
            }
            break;
        default:
            break;
    }
    return ESP_OK;
}

esp_err_t fcm_subscribe(const char *topic) {
    // Build Authorization header
    char auth_header[128];
    snprintf(auth_header, sizeof(auth_header), "AidLogin %llu:%llu",
             (unsigned long long)g_fcm_state.android_id,
             (unsigned long long)g_fcm_state.security_token);

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
        g_fcm_state.fcm_token,
        g_fcm_state.fcm_token,
        topic_path,
        topic_path,
        g_fcm_state.fcm_token,
        kid_str,
        (unsigned long long)g_fcm_state.android_id,
        g_fcm_state.app_id);

    printf("[FCM] Subscribing to topic: %s\n", topic_path);

    http_resp_t resp;
    resp.buf = (char *)malloc(RESPONSE_BUF_SIZE);
    if (!resp.buf) return ESP_ERR_NO_MEM;
    resp.len = 0;
    resp.cap = RESPONSE_BUF_SIZE;
    resp.buf[0] = '\0';

    esp_http_client_config_t config = {
        .url = REGISTER_URL,
        .method = HTTP_METHOD_POST,
        .event_handler = http_event_handler,
        .user_data = &resp,
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
        free(resp.buf);
        return err;
    }

    printf("[FCM] Subscribe response (HTTP %d): %s\n", status_code, resp.buf);

    if (status_code != 200) {
        printf("[FCM] ERROR: Subscribe HTTP error: %d\n", status_code);
        free(resp.buf);
        return ESP_FAIL;
    }

    // Check for error in response
    if (strstr(resp.buf, "Error=") != NULL) {
        printf("[FCM] ERROR: Subscribe error: %s\n", resp.buf);
        free(resp.buf);
        return ESP_FAIL;
    }

    // Check for success
    if (strstr(resp.buf, "token=") != NULL) {
        printf("[FCM] Topic subscription successful\n");
        free(resp.buf);
        return ESP_OK;
    }

    printf("[FCM] Unexpected subscribe response, continuing anyway\n");
    free(resp.buf);
    return ESP_OK;
}

esp_err_t fcm_unsubscribe(const char *topic) {
    // Build Authorization header
    char auth_header[128];
    snprintf(auth_header, sizeof(auth_header), "AidLogin %llu:%llu",
             (unsigned long long)g_fcm_state.android_id,
             (unsigned long long)g_fcm_state.security_token);

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
        "&X-delete=1"
        "&app=org.chromium.linux"
        "&device=%llu"
        "&X-gms_app_id=%s",
        g_fcm_state.fcm_token,
        g_fcm_state.fcm_token,
        topic_path,
        topic_path,
        g_fcm_state.fcm_token,
        kid_str,
        (unsigned long long)g_fcm_state.android_id,
        g_fcm_state.app_id);

    printf("[FCM] Unsubscribing from topic: %s\n", topic_path);

    http_resp_t resp;
    resp.buf = (char *)malloc(RESPONSE_BUF_SIZE);
    if (!resp.buf) return ESP_ERR_NO_MEM;
    resp.len = 0;
    resp.cap = RESPONSE_BUF_SIZE;
    resp.buf[0] = '\0';

    esp_http_client_config_t config = {
        .url = REGISTER_URL,
        .method = HTTP_METHOD_POST,
        .event_handler = http_event_handler,
        .user_data = &resp,
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
        free(resp.buf);
        return err;
    }

    printf("[FCM] Unsubscribe response (HTTP %d): %s\n", status_code, resp.buf);

    if (status_code != 200) {
        printf("[FCM] ERROR: Unsubscribe HTTP error: %d\n", status_code);
        free(resp.buf);
        return ESP_FAIL;
    }

    // Check for error in response
    if (strstr(resp.buf, "Error=") != NULL) {
        printf("[FCM] ERROR: Unsubscribe error: %s\n", resp.buf);
        free(resp.buf);
        return ESP_FAIL;
    }

    printf("[FCM] Topic unsubscription successful\n");
    free(resp.buf);
    return ESP_OK;
}
