#include "FCMReceiver.h"
#include "fcm_proto.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include "esp_tls.h"
#include "fcm_root_ca.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"

// ── Message dedup using persistent_id timestamp (persisted in NVS) ──
// persistent_id format: "0:1772068660657995%7031b2e6f9fd7ecd"
// The number between ':' and '%' is a monotonically increasing timestamp.

static uint64_t s_last_ts = 0;
static bool     s_ts_loaded = false;

static uint64_t parse_pid_timestamp(const char *persistent_id) {
    if (!persistent_id || !persistent_id[0]) return 0;
    const char *colon = strchr(persistent_id, ':');
    if (!colon) return 0;
    return strtoull(colon + 1, NULL, 10);
}

static void load_last_timestamp(void) {
    if (s_ts_loaded) return;
    nvs_handle_t h;
    if (nvs_open("fcm", NVS_READONLY, &h) == ESP_OK) {
        nvs_get_u64(h, "last_ts", &s_last_ts);
        nvs_close(h);
    }
    s_ts_loaded = true;
    printf("[FCM] Last timestamp: %" PRIu64 "\n", s_last_ts);
}

static void save_last_timestamp(uint64_t ts) {
    s_last_ts = ts;
    nvs_handle_t h;
    if (nvs_open("fcm", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u64(h, "last_ts", ts);
        nvs_commit(h);
        nvs_close(h);
    }
}

// ── Parse decrypted JSON into notif_data struct ──
// Returns malloc'd fcm_notif_data_t or NULL if JSON structure doesn't match.

static fcm_notif_data_t *parse_notif_json(const char *json_str) {
    if (!json_str) return NULL;

    cJSON *root = cJSON_Parse(json_str);
    if (!root) return NULL;

    fcm_notif_data_t *nd = (fcm_notif_data_t *)calloc(1, sizeof(fcm_notif_data_t));
    if (!nd) { cJSON_Delete(root); return NULL; }

    // "notification" object
    cJSON *notif = cJSON_GetObjectItem(root, "notification");
    if (notif && cJSON_IsObject(notif)) {
        cJSON *title = cJSON_GetObjectItem(notif, "title");
        if (title && cJSON_IsString(title))
            snprintf(nd->title, sizeof(nd->title), "%s", title->valuestring);
        cJSON *body = cJSON_GetObjectItem(notif, "body");
        if (body && cJSON_IsString(body))
            snprintf(nd->body, sizeof(nd->body), "%s", body->valuestring);
    }

    // "fcmMessageId"
    cJSON *mid = cJSON_GetObjectItem(root, "fcmMessageId");
    if (mid && cJSON_IsString(mid))
        snprintf(nd->fcm_message_id, sizeof(nd->fcm_message_id), "%s", mid->valuestring);

    // "from"
    cJSON *from = cJSON_GetObjectItem(root, "from");
    if (from && cJSON_IsString(from))
        snprintf(nd->from, sizeof(nd->from), "%s", from->valuestring);

    // "priority"
    cJSON *prio = cJSON_GetObjectItem(root, "priority");
    if (prio && cJSON_IsString(prio))
        snprintf(nd->priority, sizeof(nd->priority), "%s", prio->valuestring);

    // "data" object → key-value pairs
    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (data && cJSON_IsObject(data)) {
        cJSON *item = NULL;
        cJSON_ArrayForEach(item, data) {
            if (nd->data_count >= 8) break;
            snprintf(nd->data[nd->data_count].key, sizeof(nd->data[0].key), "%s", item->string);
            if (cJSON_IsString(item))
                snprintf(nd->data[nd->data_count].value, sizeof(nd->data[0].value), "%s", item->valuestring);
            else {
                char *printed = cJSON_PrintUnformatted(item);
                if (printed) {
                    snprintf(nd->data[nd->data_count].value, sizeof(nd->data[0].value), "%s", printed);
                    free(printed);
                }
            }
            nd->data_count++;
        }
    }

    cJSON_Delete(root);
    return nd;
}

// MCS constants
#define MCS_HOST         "mtalk.google.com"
#define MCS_PORT         5228
#define KMCS_VERSION     41
#define K_LOGIN_REQUEST_TAG   2

// MCS message tags
#define TAG_HEARTBEAT_PING    0
#define TAG_HEARTBEAT_ACK     1
#define TAG_LOGIN_RESPONSE    3
#define TAG_CLOSE             4
#define TAG_IQ_STANZA         7
#define TAG_DATA_MESSAGE      8

// State machine states
#define STATE_VERSION    0
#define STATE_TAG        1
#define STATE_SIZE       2
#define STATE_PROTO      3

// Heartbeat interval (600 seconds)
#define HEARTBEAT_INTERVAL_US  (600LL * 1000000LL)

// Read buffer
#define READ_BUF_SIZE    (32 * 1024)

// ── Login request builder ──

static uint8_t *build_login_request(size_t *out_len) {
    // Build the setting submessage: {name="new_vc", value="1"}
    pb_encoder_t setting_enc;
    pb_encoder_init(&setting_enc);
    pb_encode_string(&setting_enc, 1, "new_vc");
    pb_encode_string(&setting_enc, 2, "1");
    size_t setting_len;
    uint8_t *setting_bytes = pb_encoder_detach(&setting_enc, &setting_len);

    // Format IDs
    char android_id_str[32];
    char security_token_str[32];
    char device_id_str[48];
    snprintf(android_id_str, sizeof(android_id_str), "%" PRIu64, g_fcm_state.android_id);
    snprintf(security_token_str, sizeof(security_token_str), "%" PRIu64, g_fcm_state.security_token);
    snprintf(device_id_str, sizeof(device_id_str), "android-%" PRIx64, g_fcm_state.android_id);

    // Build login request protobuf
    pb_encoder_t enc;
    pb_encoder_init(&enc);
    pb_encode_string(&enc, 1, "chrome-63.0.3234.0");  // id
    pb_encode_string(&enc, 2, "mcs.android.com");      // domain
    pb_encode_string(&enc, 3, android_id_str);          // user
    pb_encode_string(&enc, 4, android_id_str);          // resource
    pb_encode_string(&enc, 5, security_token_str);      // auth_token
    pb_encode_string(&enc, 6, device_id_str);           // device_id
    pb_encode_bytes(&enc, 8, setting_bytes, setting_len); // setting
    pb_encode_bool(&enc, 12, false);                    // adaptive_heartbeat
    pb_encode_bool(&enc, 14, true);                     // use_rmq2
    pb_encode_int32(&enc, 16, 2);                       // auth_service = ANDROID_ID
    pb_encode_int32(&enc, 17, 1);                       // network_type = WIFI

    size_t payload_len;
    uint8_t *payload = pb_encoder_detach(&enc, &payload_len);
    free(setting_bytes);

    // Build packet: [version][tag][varint(len)][payload]
    uint8_t varint_buf[5];
    int varint_len = pb_put_uvarint(varint_buf, sizeof(varint_buf), (uint64_t)payload_len);

    size_t packet_len = 2 + varint_len + payload_len;
    uint8_t *packet = (uint8_t *)malloc(packet_len);
    packet[0] = KMCS_VERSION;
    packet[1] = K_LOGIN_REQUEST_TAG;
    memcpy(packet + 2, varint_buf, varint_len);
    memcpy(packet + 2 + varint_len, payload, payload_len);
    free(payload);

    *out_len = packet_len;
    return packet;
}

// ── DataMessageStanza parser ──

static void parse_app_data(const uint8_t *data, size_t len, fcm_app_data_t *out) {
    pb_decoder_t d;
    pb_decoder_init(&d, data, len);
    out->key[0] = '\0';
    out->value[0] = '\0';
    while (pb_decoder_remaining(&d) > 0) {
        uint32_t field;
        uint8_t wt;
        if (pb_decode_field(&d, &field, &wt) != 0) break;
        switch (field) {
            case 1:
                pb_decode_string(&d, out->key, sizeof(out->key), NULL);
                break;
            case 2:
                pb_decode_string(&d, out->value, sizeof(out->value), NULL);
                break;
            default:
                pb_skip_field(&d, wt);
                break;
        }
    }
}

static void parse_data_message(const uint8_t *data, size_t len, fcm_message_t *msg) {
    memset(msg, 0, sizeof(*msg));
    pb_decoder_t d;
    pb_decoder_init(&d, data, len);

    while (pb_decoder_remaining(&d) > 0) {
        uint32_t field;
        uint8_t wt;
        if (pb_decode_field(&d, &field, &wt) != 0) break;
        switch (field) {
            case 2: // id
                pb_decode_string(&d, msg->id, sizeof(msg->id), NULL);
                break;
            case 3: // from
                pb_decode_string(&d, msg->from, sizeof(msg->from), NULL);
                break;
            case 4: // to
                pb_decode_string(&d, msg->to, sizeof(msg->to), NULL);
                break;
            case 5: // category
                pb_decode_string(&d, msg->category, sizeof(msg->category), NULL);
                break;
            case 7: { // app_data submessage
                const uint8_t *sub;
                size_t sub_len;
                if (pb_decode_bytes(&d, &sub, &sub_len) == 0) {
                    if (msg->app_data_count < 16) {
                        parse_app_data(sub, sub_len, &msg->app_data[msg->app_data_count]);
                        msg->app_data_count++;
                    }
                }
                break;
            }
            case 9: // persistent_id
                pb_decode_string(&d, msg->persistent_id, sizeof(msg->persistent_id), NULL);
                break;
            case 17: { // ttl
                int32_t ttl;
                if (pb_decode_int32(&d, &ttl) == 0) msg->ttl = ttl;
                break;
            }
            case 21: { // raw_data
                const uint8_t *raw;
                size_t raw_len;
                if (pb_decode_bytes(&d, &raw, &raw_len) == 0) {
                    msg->raw_data = (uint8_t *)malloc(raw_len);
                    if (msg->raw_data) {
                        memcpy(msg->raw_data, raw, raw_len);
                        msg->raw_data_len = raw_len;
                    }
                }
                break;
            }
            case 24: { // immediate_ack
                bool ack;
                if (pb_decode_bool(&d, &ack) == 0) msg->immediate_ack = ack;
                break;
            }
            default:
                pb_skip_field(&d, wt);
                break;
        }
    }
}

// ── MCS connection and listen loop ──

esp_err_t fcm_start(fcm_message_cb_t callback) {
    // Load last seen timestamp from NVS
    load_last_timestamp();

    // TLS connect
    esp_tls_cfg_t tls_cfg = {
        .cacert_buf = (const unsigned char *)GOOGLE_ROOT_CA_PEM,
        .cacert_bytes = sizeof(GOOGLE_ROOT_CA_PEM),
    };

    printf("[FCM] Connecting to %s:%d\n", MCS_HOST, MCS_PORT);
    esp_tls_t *tls = esp_tls_init();
    if (!tls) {
        printf("[FCM] ERROR: Failed to init TLS\n");
        return ESP_FAIL;
    }

    int ret = esp_tls_conn_new_sync(MCS_HOST, strlen(MCS_HOST), MCS_PORT, &tls_cfg, tls);
    if (ret != 1) {
        printf("[FCM] ERROR: TLS connection failed\n");
        esp_tls_conn_destroy(tls);
        return ESP_FAIL;
    }
    printf("[FCM] TLS connected to MCS\n");

    // Send login request
    size_t login_len;
    uint8_t *login_pkt = build_login_request(&login_len);
    printf("[FCM] Sending login request (%d bytes)\n", (int)login_len);

    size_t written = 0;
    while (written < login_len) {
        ssize_t w = esp_tls_conn_write(tls, login_pkt + written, login_len - written);
        if (w < 0) {
            printf("[FCM] ERROR: Failed to send login request\n");
            free(login_pkt);
            esp_tls_conn_destroy(tls);
            return ESP_FAIL;
        }
        written += w;
    }
    free(login_pkt);
    printf("[FCM] Login request sent\n");

    // State machine
    uint8_t *buffer = (uint8_t *)malloc(READ_BUF_SIZE);
    size_t buf_len = 0;
    uint8_t state = STATE_VERSION;
    uint8_t message_tag = 0;
    size_t message_size = 0;
    int64_t last_heartbeat = esp_timer_get_time();

    while (1) {
        // Process buffered data
        bool progress = true;
        while (progress) {
            progress = false;
            switch (state) {
                case STATE_VERSION:
                    if (buf_len >= 1) {
                        uint8_t version = buffer[0];
                        memmove(buffer, buffer + 1, buf_len - 1);
                        buf_len--;
                        if (version < KMCS_VERSION && version != 38) {
                            printf("[FCM] ERROR: Invalid MCS version: %d\n", version);
                            goto cleanup;
                        }
                        printf("[FCM] MCS version: %d\n", version);
                        state = STATE_TAG;
                        progress = true;
                    }
                    break;

                case STATE_TAG:
                    if (buf_len >= 1) {
                        message_tag = buffer[0];
                        memmove(buffer, buffer + 1, buf_len - 1);
                        buf_len--;
                        state = STATE_SIZE;
                        progress = true;
                    }
                    break;

                case STATE_SIZE: {
                    size_t size_val, consumed;
                    int vr = pb_try_read_varint(buffer, buf_len, &size_val, &consumed);
                    if (vr == 1) {
                        memmove(buffer, buffer + consumed, buf_len - consumed);
                        buf_len -= consumed;
                        message_size = size_val;
                        if (message_size == 0) {
                            // Dispatch empty message
                            if (message_tag == TAG_HEARTBEAT_PING) {
                                printf("[FCM] HeartbeatPing (empty), responding\n");
                                uint8_t hb[] = {TAG_HEARTBEAT_PING, 0};
                                esp_tls_conn_write(tls, hb, 2);
                            } else if (message_tag == TAG_LOGIN_RESPONSE) {
                                printf("[FCM] LoginResponse received (empty)\n");
                            } else if (message_tag == TAG_CLOSE) {
                                printf("[FCM] ERROR: Server sent Close\n");
                                goto cleanup;
                            }
                            state = STATE_TAG;
                        } else {
                            state = STATE_PROTO;
                        }
                        progress = true;
                    } else if (vr == -1) {
                        printf("[FCM] ERROR: Invalid varint\n");
                        goto cleanup;
                    }
                    break;
                }

                case STATE_PROTO:
                    if (buf_len >= message_size) {
                        // Extract payload
                        uint8_t *payload = (uint8_t *)malloc(message_size);
                        memcpy(payload, buffer, message_size);
                        memmove(buffer, buffer + message_size, buf_len - message_size);
                        buf_len -= message_size;

                        // Dispatch
                        switch (message_tag) {
                            case TAG_HEARTBEAT_PING:
                                printf("[FCM] HeartbeatPing, responding\n");
                                {
                                    uint8_t hb[] = {TAG_HEARTBEAT_PING, 0};
                                    esp_tls_conn_write(tls, hb, 2);
                                }
                                break;
                            case TAG_HEARTBEAT_ACK:
                                break;
                            case TAG_LOGIN_RESPONSE:
                                printf("[FCM] LoginResponse received (%d bytes)\n", (int)message_size);
                                break;
                            case TAG_CLOSE:
                                printf("[FCM] ERROR: Server sent Close\n");
                                free(payload);
                                goto cleanup;
                            case TAG_IQ_STANZA:
                                break;
                            case TAG_DATA_MESSAGE: {
                                printf("[FCM] DataMessageStanza (%d bytes)\n", (int)message_size);
                                fcm_message_t msg;
                                parse_data_message(payload, message_size, &msg);

                                // Skip internal FCM messages (e.g. deleted_messages)
                                bool is_internal = false;
                                for (int i = 0; i < msg.app_data_count; i++) {
                                    if (strcmp(msg.app_data[i].key, "message_type") == 0) {
                                        printf("[FCM] Internal message: %s (skipped)\n",
                                               msg.app_data[i].value);
                                        is_internal = true;
                                        break;
                                    }
                                }
                                if (is_internal) {
                                    // Save timestamp as reference even for internal messages
                                    uint64_t its = parse_pid_timestamp(msg.persistent_id);
                                    if (its > s_last_ts) {
                                        save_last_timestamp(its);
                                    }
                                    free(msg.raw_data);
                                    break;
                                }

                                // Filter old messages by persistent_id timestamp
                                uint64_t msg_ts = parse_pid_timestamp(msg.persistent_id);
                                if (msg_ts > 0 && msg_ts <= s_last_ts) {
                                    printf("[FCM] Skipped ts: %" PRIu64 " | ref ts: %" PRIu64 "\n",
                                           msg_ts, s_last_ts);
                                    free(msg.raw_data);
                                    break;
                                }

                                if (msg_ts > 0) {
                                    save_last_timestamp(msg_ts);
                                }

                                // Auto-decrypt if crypto-key and encryption headers present
                                msg.json_data = NULL;
                                const char *crypto_key_str = NULL;
                                const char *encryption_str = NULL;
                                for (int i = 0; i < msg.app_data_count; i++) {
                                    if (strcmp(msg.app_data[i].key, "crypto-key") == 0)
                                        crypto_key_str = msg.app_data[i].value;
                                    else if (strcmp(msg.app_data[i].key, "encryption") == 0)
                                        encryption_str = msg.app_data[i].value;
                                }

                                if (crypto_key_str && encryption_str &&
                                    msg.raw_data && msg.raw_data_len > 0) {
                                    // Extract dh= from crypto-key
                                    const char *dh_start = strstr(crypto_key_str, "dh=");
                                    if (dh_start) {
                                        dh_start += 3;
                                        const char *dh_end = strchr(dh_start, ';');
                                        size_t dh_len = dh_end ? (size_t)(dh_end - dh_start) : strlen(dh_start);

                                        uint8_t server_pub[128];
                                        size_t server_pub_len = 0;

                                        // Extract salt= from encryption
                                        const char *salt_start = strstr(encryption_str, "salt=");
                                        if (salt_start &&
                                            fcm_base64url_decode(dh_start, dh_len, server_pub,
                                                                  sizeof(server_pub), &server_pub_len) == 0) {
                                            salt_start += 5;
                                            const char *salt_end = strchr(salt_start, ';');
                                            size_t salt_str_len = salt_end ? (size_t)(salt_end - salt_start) : strlen(salt_start);

                                            uint8_t salt[64];
                                            size_t salt_len = 0;
                                            if (fcm_base64url_decode(salt_start, salt_str_len, salt,
                                                                      sizeof(salt), &salt_len) == 0) {
                                                uint8_t *plaintext = (uint8_t *)malloc(msg.raw_data_len);
                                                size_t plaintext_len = 0;
                                                if (plaintext &&
                                                    fcm_decrypt(server_pub, server_pub_len,
                                                                salt, salt_len,
                                                                msg.raw_data, msg.raw_data_len,
                                                                plaintext, &plaintext_len) == ESP_OK &&
                                                    plaintext_len > 0) {
                                                    msg.json_data = (char *)malloc(plaintext_len + 1);
                                                    if (msg.json_data) {
                                                        memcpy(msg.json_data, plaintext, plaintext_len);
                                                        msg.json_data[plaintext_len] = '\0';
                                                    }
                                                }
                                                free(plaintext);
                                            }
                                        }
                                    }
                                }

                                // Parse JSON into notif_data struct (safe if json_data is NULL)
                                msg.notif_data = parse_notif_json(msg.json_data);

                                if (callback) callback(&msg);
                                free(msg.notif_data);
                                free(msg.json_data);
                                free(msg.raw_data);
                                break;
                            }
                            default:
                                break;
                        }
                        free(payload);
                        state = STATE_TAG;
                        progress = true;
                    }
                    break;
            }
        }

        // Periodic heartbeat
        int64_t now = esp_timer_get_time();
        if (now - last_heartbeat >= HEARTBEAT_INTERVAL_US) {
            printf("[FCM] Sending periodic heartbeat\n");
            uint8_t hb[] = {TAG_HEARTBEAT_PING, 0};
            esp_tls_conn_write(tls, hb, 2);
            last_heartbeat = now;
        }

        // Read from socket
        uint8_t tmp[4096];
        ssize_t r = esp_tls_conn_read(tls, tmp, sizeof(tmp));
        if (r > 0) {
            if (buf_len + r > READ_BUF_SIZE) {
                printf("[FCM] ERROR: Buffer overflow\n");
                goto cleanup;
            }
            memcpy(buffer + buf_len, tmp, r);
            buf_len += r;
        } else if (r == 0) {
            printf("[FCM] ERROR: Connection closed by peer\n");
            goto cleanup;
        } else {
            // esp_tls_conn_read returns negative mbedtls error codes
            // MBEDTLS_ERR_SSL_WANT_READ = -0x6900, just retry
            if (r == -0x6900) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            printf("[FCM] ERROR: TLS read error: %d\n", (int)r);
            goto cleanup;
        }
    }

cleanup:
    free(buffer);
    esp_tls_conn_destroy(tls);
    return ESP_FAIL;
}
