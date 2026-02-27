#include "FCMReceiver.h"
#include "fcm_proto.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>

#include "esp_http_client.h"
#include "esp_system.h"
#include "fcm_root_ca.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// Internal declarations (defined in fcm_crypto.c)
extern esp_err_t fcm_generate_fid(char *fid_out, size_t fid_cap);

// FCM server key (NIST P-256 uncompressed public key)
static const uint8_t FCM_SERVER_KEY[65] = {
    0x04,0x33,0x94,0xf7,0xdf,0xa1,0xeb,0xb1,0xdc,0x03,0xa2,0x5e,0x15,0x71,0xdb,0x48,
    0xd3,0x2e,0xed,0xed,0xb2,0x34,0xdb,0xb7,0x47,0x3a,0x0c,0x8f,0xc4,0xcc,0xe1,0x6f,
    0x3c,0x8c,0x84,0xdf,0xab,0xb6,0x66,0x3e,0xf2,0x0c,0xd4,0x8b,0xfe,0xe3,0xf9,0x76,
    0x2f,0x14,0x1c,0x63,0x08,0x6a,0x6f,0x2d,0xb1,0x1a,0x95,0xb0,0xce,0x37,0xc0,0x9c,0x6e
};

#define CHECKIN_URL   "https://android.clients.google.com/checkin"
#define REGISTER_URL  "https://android.clients.google.com/c2dm/register3"

#define RESPONSE_BUF_SIZE 4096

// ── HTTP response buffer ──

typedef struct {
    char   *buf;
    size_t  len;
    size_t  cap;
} http_response_t;

static esp_err_t http_event_handler(esp_http_client_event_t *evt) {
    http_response_t *resp = (http_response_t *)evt->user_data;
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

// ── HTTP Retry helper ──

static esp_err_t http_perform_with_retry(esp_http_client_handle_t client, int *out_status) {
    int retries = 3;
    int delay_ms = 2000;
    esp_err_t err;

    while (retries > 0) {
        err = esp_http_client_perform(client);
        *out_status = esp_http_client_get_status_code(client);

        if (err == ESP_OK && *out_status < 500) {
            return ESP_OK; // Success or non-transient error
        }

        printf("[FCM] WARNING: HTTP transient failure (err=%s status=%d), retrying in %d ms...\n",
               esp_err_to_name(err), *out_status, delay_ms);

        vTaskDelay(pdMS_TO_TICKS(delay_ms));
        delay_ms *= 2; // exponential backoff
        retries--;
    }

    return err;
}

// ── Step 1: GCM Checkin ──

static esp_err_t fcm_gcm_checkin(uint64_t *android_id_out, uint64_t *security_token_out) {
    printf("[FCM] Step 1: GCM Checkin\n");

    // Build chrome_build sub-message
    pb_encoder_t chrome_enc;
    pb_encoder_init(&chrome_enc);
    pb_encode_int32(&chrome_enc, 1, 3);                      // platform = CHROME
    pb_encode_string(&chrome_enc, 2, "63.0.3234.0");         // chrome_version
    pb_encode_int32(&chrome_enc, 3, 1);                      // channel = STABLE
    size_t chrome_len;
    uint8_t *chrome_bytes = pb_encoder_detach(&chrome_enc, &chrome_len);

    // Build checkin sub-message
    pb_encoder_t checkin_enc;
    pb_encoder_init(&checkin_enc);
    pb_encode_int32(&checkin_enc, 12, 3);                    // type = CHROME_BROWSER
    pb_encode_bytes(&checkin_enc, 13, chrome_bytes, chrome_len); // chrome_build
    size_t checkin_len;
    uint8_t *checkin_bytes = pb_encoder_detach(&checkin_enc, &checkin_len);
    free(chrome_bytes);

    // Build root message
    pb_encoder_t root_enc;
    pb_encoder_init(&root_enc);
    pb_encode_int64(&root_enc, 2, 0);                        // android_id = 0 (new device)
    pb_encode_bytes(&root_enc, 4, checkin_bytes, checkin_len); // checkin
    pb_encode_int32(&root_enc, 14, 3);                       // version = 3
    size_t body_len;
    uint8_t *body = pb_encoder_detach(&root_enc, &body_len);
    free(checkin_bytes);

    // HTTP POST
    http_response_t resp = {
        .buf = (char *)malloc(RESPONSE_BUF_SIZE),
        .len = 0,
        .cap = RESPONSE_BUF_SIZE
    };

    esp_http_client_config_t http_cfg = {
        .url = CHECKIN_URL,
        .method = HTTP_METHOD_POST,
        .event_handler = http_event_handler,
        .user_data = &resp,
        .cert_pem = GOOGLE_ROOT_CA_PEM,
        .timeout_ms = 15000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&http_cfg);
    esp_http_client_set_header(client, "Content-Type", "application/x-protobuf");
    esp_http_client_set_post_field(client, (const char *)body, (int)body_len);

    int status = 0;
    esp_err_t err = http_perform_with_retry(client, &status);
    esp_http_client_cleanup(client);
    free(body);

    if (err != ESP_OK || status != 200) {
        printf("[FCM] ERROR: Checkin HTTP failed: err=%s status=%d\n", esp_err_to_name(err), status);
        free(resp.buf);
        return ESP_FAIL;
    }

    printf("[FCM] Checkin response: %d bytes\n", (int)resp.len);

    // Parse protobuf response
    pb_decoder_t d;
    pb_decoder_init(&d, (const uint8_t *)resp.buf, resp.len);

    *android_id_out = 0;
    *security_token_out = 0;

    while (pb_decoder_remaining(&d) > 0) {
        uint32_t field;
        uint8_t wt;
        if (pb_decode_field(&d, &field, &wt) != 0) break;

        if (field == 7) {
            // android_id: could be fixed64 (wire type 1) or varint (wire type 0)
            if (wt == PB_WIRE_BIT64) {
                pb_decode_fixed64(&d, android_id_out);
            } else if (wt == PB_WIRE_VARINT) {
                pb_decode_uint64(&d, android_id_out);
            } else {
                pb_skip_field(&d, wt);
            }
        } else if (field == 8) {
            // security_token: could be fixed64 or varint
            if (wt == PB_WIRE_BIT64) {
                pb_decode_fixed64(&d, security_token_out);
            } else if (wt == PB_WIRE_VARINT) {
                pb_decode_uint64(&d, security_token_out);
            } else {
                pb_skip_field(&d, wt);
            }
        } else {
            pb_skip_field(&d, wt);
        }
    }

    free(resp.buf);

    if (*android_id_out == 0 || *security_token_out == 0) {
        printf("[FCM] ERROR: Checkin failed: missing android_id or security_token\n");
        return ESP_FAIL;
    }

    printf("[FCM] Checkin OK: android_id=%" PRIu64 " security_token=%" PRIu64 "\n",
             *android_id_out, *security_token_out);
    return ESP_OK;
}

// ── URL-encode helper for form values ──
// Encodes per WHATWG application/x-www-form-urlencoded:
// safe chars: A-Z a-z 0-9 * - . _
// space -> +, everything else -> %XX

static size_t url_encode(const char *src, char *dst, size_t dst_cap) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_cap - 3; i++) {
        char c = src[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '*' || c == '-' || c == '.' || c == '_') {
            dst[j++] = c;
        } else if (c == ' ') {
            dst[j++] = '+';
        } else {
            if (j + 3 >= dst_cap) break;
            snprintf(dst + j, 4, "%%%02X", (unsigned char)c);
            j += 3;
        }
    }
    dst[j] = '\0';
    return j;
}

// ── Step 2: GCM Register ──

static esp_err_t fcm_gcm_register(uint64_t android_id, uint64_t security_token,
                                    const char *app_id, char *gcm_token_out, size_t gcm_cap) {
    printf("[FCM] Step 2: GCM Register\n");

    // Base64url encode the FCM server key
    char server_key_b64url[128];
    if (fcm_base64url_encode(FCM_SERVER_KEY, sizeof(FCM_SERVER_KEY),
                              server_key_b64url, sizeof(server_key_b64url), NULL) != 0) {
        printf("[FCM] ERROR: Failed to encode server key\n");
        return ESP_FAIL;
    }

    // Build Authorization header
    char auth_header[128];
    snprintf(auth_header, sizeof(auth_header), "AidLogin %" PRIu64 ":%" PRIu64,
             android_id, security_token);

    // URL-encode values that contain special characters
    char app_id_enc[256];
    url_encode(app_id, app_id_enc, sizeof(app_id_enc));

    char sender_enc[256];
    url_encode(server_key_b64url, sender_enc, sizeof(sender_enc));

    // Build form body with URL-encoded values (matching Rust form_urlencoded::Serializer)
    char body[1024];
    int body_len = snprintf(body, sizeof(body),
        "X-subtype=%s"
        "&sender=%s"
        "&app=org.chromium.linux"
        "&device=%" PRIu64
        "&X-gms_app_id=%s",
        app_id_enc,
        sender_enc,
        android_id,
        app_id_enc);

    http_response_t resp = {
        .buf = (char *)malloc(RESPONSE_BUF_SIZE),
        .len = 0,
        .cap = RESPONSE_BUF_SIZE
    };

    esp_http_client_config_t http_cfg = {
        .url = REGISTER_URL,
        .method = HTTP_METHOD_POST,
        .event_handler = http_event_handler,
        .user_data = &resp,
        .cert_pem = GOOGLE_ROOT_CA_PEM,
        .timeout_ms = 15000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&http_cfg);
    esp_http_client_set_header(client, "Authorization", auth_header);
    esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
    esp_http_client_set_header(client, "User-Agent", "");
    esp_http_client_set_post_field(client, body, body_len);

    int status = 0;
    esp_err_t err = http_perform_with_retry(client, &status);
    esp_http_client_cleanup(client);

    if (err != ESP_OK || status != 200) {
        printf("[FCM] ERROR: GCM Register HTTP failed: err=%s status=%d resp=%s\n",
                 esp_err_to_name(err), status, resp.buf);
        free(resp.buf);
        return ESP_FAIL;
    }

    printf("[FCM] GCM Register response: %s\n", resp.buf);

    // Parse "token=..." from response
    char *token_start = strstr(resp.buf, "token=");
    if (!token_start) {
        printf("[FCM] ERROR: GCM Register: no token in response\n");
        free(resp.buf);
        return ESP_FAIL;
    }
    token_start += 6;  // skip "token="

    // Copy token (until end of string or newline)
    size_t i = 0;
    while (token_start[i] && token_start[i] != '\n' && token_start[i] != '\r' && i < gcm_cap - 1) {
        gcm_token_out[i] = token_start[i];
        i++;
    }
    gcm_token_out[i] = '\0';

    free(resp.buf);

    printf("[FCM] GCM Register OK: gcm_token=%s\n", gcm_token_out);
    return ESP_OK;
}

// ── Minimal JSON parser helpers ──

static const char *json_find_string(const char *json, const char *key, char *out, size_t out_cap) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *pos = strstr(json, search);
    if (!pos) return NULL;

    pos += strlen(search);
    while (*pos && *pos != ':') pos++;
    if (!*pos) return NULL;
    pos++; // skip ':'

    // Skip whitespace
    while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r')) pos++;

    if (*pos == '"') {
        pos++; // skip opening quote
        size_t i = 0;
        while (pos[i] && pos[i] != '"' && i < out_cap - 1) {
            out[i] = pos[i];
            i++;
        }
        out[i] = '\0';
        return out;
    }

    return NULL;
}

// ── Step 3: FCM Install ──

static esp_err_t fcm_fcm_install(const fcm_config_t *cfg, const char *fid,
                                   char *install_auth_out, size_t auth_cap) {
    printf("[FCM] Step 3: FCM Install\n");

    // Build URL
    char url[256];
    snprintf(url, sizeof(url),
             "https://firebaseinstallations.googleapis.com/v1/projects/%s/installations",
             cfg->project_id);

    // Build JSON body
    char body[512];
    int body_len = snprintf(body, sizeof(body),
        "{\"fid\":\"%s\",\"appId\":\"%s\",\"authVersion\":\"FIS_v2\",\"sdkVersion\":\"w:0.6.4\"}",
        fid, cfg->app_id);

    http_response_t resp = {
        .buf = (char *)malloc(RESPONSE_BUF_SIZE),
        .len = 0,
        .cap = RESPONSE_BUF_SIZE
    };

    esp_http_client_config_t http_cfg = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .event_handler = http_event_handler,
        .user_data = &resp,
        .cert_pem = GOOGLE_ROOT_CA_PEM,
        .timeout_ms = 15000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&http_cfg);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "Accept", "application/json");
    esp_http_client_set_header(client, "x-goog-api-key", cfg->api_key);
    esp_http_client_set_header(client, "x-firebase-client", "fire-installations/0.6.4");
    esp_http_client_set_post_field(client, body, body_len);

    int status = 0;
    esp_err_t err = http_perform_with_retry(client, &status);
    esp_http_client_cleanup(client);

    if (err != ESP_OK || status != 200) {
        printf("[FCM] ERROR: FCM Install HTTP failed: err=%s status=%d resp=%s\n",
                 esp_err_to_name(err), status, resp.buf);
        free(resp.buf);
        return ESP_FAIL;
    }

    printf("[FCM] FCM Install response: %s\n", resp.buf);

    // Parse authToken.token from nested JSON
    const char *auth_section = strstr(resp.buf, "\"authToken\"");
    if (!auth_section) {
        printf("[FCM] ERROR: FCM Install: no authToken in response\n");
        free(resp.buf);
        return ESP_FAIL;
    }

    char token[512];
    if (!json_find_string(auth_section, "token", token, sizeof(token))) {
        printf("[FCM] ERROR: FCM Install: no token in authToken\n");
        free(resp.buf);
        return ESP_FAIL;
    }

    strncpy(install_auth_out, token, auth_cap - 1);
    install_auth_out[auth_cap - 1] = '\0';

    free(resp.buf);

    printf("[FCM] FCM Install OK\n");
    return ESP_OK;
}

// ── Step 4: FCM Register ──

static esp_err_t fcm_fcm_register(const fcm_config_t *cfg,
                                    const char *install_auth_token,
                                    const char *gcm_token,
                                    const char *pub_key_b64url,
                                    const char *auth_secret_b64url,
                                    char *fcm_token_out, size_t fcm_cap) {
    printf("[FCM] Step 4: FCM Register\n");

    // Build URL (uses project_id, matching the Rust reference implementation)
    char url[256];
    snprintf(url, sizeof(url),
             "https://fcmregistrations.googleapis.com/v1/projects/%s/registrations",
             cfg->project_id);

    // Build endpoint URL
    char endpoint[640];
    snprintf(endpoint, sizeof(endpoint),
             "https://fcm.googleapis.com/fcm/send/%s", gcm_token);

    // Build JSON body (applicationPubKey is empty, matching Rust reference)
    char body[2048];
    int body_len = snprintf(body, sizeof(body),
        "{\"web\":{\"applicationPubKey\":\"\","
        "\"auth\":\"%s\","
        "\"endpoint\":\"%s\","
        "\"p256dh\":\"%s\"}}",
        auth_secret_b64url,
        endpoint,
        pub_key_b64url);

    printf("[FCM] URL: %s\n", url);
    printf("[FCM] Body (%d bytes): %s\n", body_len, body);

    // Use low-level HTTP API to avoid esp_http_client_perform's 401 retry logic
    esp_http_client_config_t http_cfg = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .cert_pem = GOOGLE_ROOT_CA_PEM,
        .timeout_ms = 15000,
        .buffer_size = 2048,
        .buffer_size_tx = 2048,
    };

    esp_http_client_handle_t client = esp_http_client_init(&http_cfg);

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "Accept", "application/json");
    esp_http_client_set_header(client, "x-goog-api-key", cfg->api_key);
    esp_http_client_set_header(client, "x-goog-firebase-installations-auth", install_auth_token);

    // Open connection and send headers
    esp_err_t err = esp_http_client_open(client, body_len);
    if (err != ESP_OK) {
        printf("[FCM] ERROR: FCM Register: failed to open connection: %s\n", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    // Write body
    int written = esp_http_client_write(client, body, body_len);
    if (written < 0) {
        printf("[FCM] ERROR: FCM Register: failed to write body\n");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    // Fetch response headers
    int content_length = esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);

    printf("[FCM] FCM Register response: status=%d content_length=%d\n", status, content_length);

    // Read response body
    char *resp_buf = (char *)malloc(RESPONSE_BUF_SIZE);
    int resp_len = 0;
    int read_len;
    while ((read_len = esp_http_client_read(client, resp_buf + resp_len,
                                             RESPONSE_BUF_SIZE - 1 - resp_len)) > 0) {
        resp_len += read_len;
    }
    resp_buf[resp_len] = '\0';

    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    printf("[FCM] FCM Register response body: %s\n", resp_buf);

    if (status != 200) {
        printf("[FCM] ERROR: FCM Register HTTP failed: status=%d\n", status);
        free(resp_buf);
        return ESP_FAIL;
    }

    // Parse "token" from response JSON
    char token[512];
    if (!json_find_string(resp_buf, "token", token, sizeof(token))) {
        printf("[FCM] ERROR: FCM Register: no token in response\n");
        free(resp_buf);
        return ESP_FAIL;
    }

    strncpy(fcm_token_out, token, fcm_cap - 1);
    fcm_token_out[fcm_cap - 1] = '\0';

    free(resp_buf);

    printf("[FCM] FCM Register OK: fcm_token=%s\n", fcm_token_out);
    return ESP_OK;
}

// ── Registration result type ──

typedef struct {
    uint64_t android_id;
    uint64_t security_token;
    char     gcm_token[512];
    char     fcm_token[512];
} fcm_registration_t;

// ── Public: 4-step registration ──

esp_err_t fcm_register(const fcm_config_t *cfg,
                        const char *pub_key_b64url,
                        const char *auth_secret_b64url,
                        fcm_registration_t *result) {
    esp_err_t err;

    uint32_t free_heap = esp_get_free_heap_size();
    printf("[FCM] Free heap before registration: %u bytes\n", (unsigned)free_heap);

    // Warn/Fail if heap is dangerously low
    if (free_heap < 40000) {
        printf("[FCM] ERROR: Insufficient heap for registration (%u < 40KB)\n", (unsigned)free_heap);
        return ESP_ERR_NO_MEM;
    }

    // Step 1: GCM Checkin
    err = fcm_gcm_checkin(&result->android_id, &result->security_token);
    if (err != ESP_OK) return err;

    printf("[FCM] Free heap after Step 1: %u bytes\n", (unsigned)esp_get_free_heap_size());
    vTaskDelay(pdMS_TO_TICKS(1000));  // Let lwIP clean up sockets

    // Step 2: GCM Register
    err = fcm_gcm_register(result->android_id, result->security_token,
                            cfg->app_id, result->gcm_token, sizeof(result->gcm_token));
    if (err != ESP_OK) return err;

    printf("[FCM] Free heap after Step 2: %u bytes\n", (unsigned)esp_get_free_heap_size());
    vTaskDelay(pdMS_TO_TICKS(1000));

    // Step 3: FCM Install
    char fid[32];
    err = fcm_generate_fid(fid, sizeof(fid));
    if (err != ESP_OK) return err;

    char install_auth[512];
    err = fcm_fcm_install(cfg, fid, install_auth, sizeof(install_auth));
    if (err != ESP_OK) return err;

    printf("[FCM] Free heap after Step 3: %u bytes\n", (unsigned)esp_get_free_heap_size());
    vTaskDelay(pdMS_TO_TICKS(1000));

    // Step 4: FCM Register
    err = fcm_fcm_register(cfg, install_auth, result->gcm_token,
                            pub_key_b64url, auth_secret_b64url,
                            result->fcm_token, sizeof(result->fcm_token));
    if (err != ESP_OK) return err;

    printf("[FCM] Registration complete!\n");
    return ESP_OK;
}
