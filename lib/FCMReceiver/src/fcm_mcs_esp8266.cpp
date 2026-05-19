#if defined(ESP8266) || defined(ARDUINO_ARCH_ESP8266)

#include "FCMReceiver.h"
#include "fcm_proto.h"
#include "fcm_root_ca.h"

#include <ESP8266WiFi.h>
#include <WiFiClientSecureBearSSL.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MCS_HOST         "mtalk.google.com"
#define MCS_PORT         5228
#define KMCS_VERSION     41
#define K_LOGIN_REQUEST_TAG   2
#define TAG_HEARTBEAT_PING    0
#define TAG_HEARTBEAT_ACK     1
#define TAG_LOGIN_RESPONSE    3
#define TAG_CLOSE             4
#define TAG_IQ_STANZA         7
#define TAG_DATA_MESSAGE      8
#ifndef FCM_READ_BUF_SIZE
#define FCM_READ_BUF_SIZE 8192
#endif

const fcm_config_t *s_current_config = NULL;
static uint32_t g_fcm_heartbeat_interval_ms = 600000UL;

extern "C" void fcm_set_heartbeat_interval(uint32_t seconds) {
    g_fcm_heartbeat_interval_ms = seconds * 1000UL;
}

typedef struct {
    uint8_t *data;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t length;
} ringbuf_t;

static void rb_init(ringbuf_t *rb, size_t capacity) {
    rb->data = (uint8_t *)malloc(capacity);
    rb->capacity = rb->data ? capacity : 0;
    rb->head = 0;
    rb->tail = 0;
    rb->length = 0;
}

static void rb_free(ringbuf_t *rb) {
    free(rb->data);
    rb->data = NULL;
}

static size_t rb_write(ringbuf_t *rb, const uint8_t *data, size_t len) {
    if (rb->length + len > rb->capacity) len = rb->capacity - rb->length;
    if (len == 0) return 0;
    size_t first = rb->capacity - rb->tail;
    if (len <= first) {
        memcpy(rb->data + rb->tail, data, len);
    } else {
        memcpy(rb->data + rb->tail, data, first);
        memcpy(rb->data, data + first, len - first);
    }
    rb->tail = (rb->tail + len) % rb->capacity;
    rb->length += len;
    return len;
}

static void rb_consume(ringbuf_t *rb, size_t len) {
    if (len > rb->length) len = rb->length;
    rb->head = (rb->head + len) % rb->capacity;
    rb->length -= len;
}

static size_t rb_peek(ringbuf_t *rb, uint8_t *out, size_t len) {
    if (len > rb->length) len = rb->length;
    if (len == 0) return 0;
    size_t first = rb->capacity - rb->head;
    if (len <= first) {
        memcpy(out, rb->data + rb->head, len);
    } else {
        memcpy(out, rb->data + rb->head, first);
        memcpy(out + first, rb->data, len - first);
    }
    return len;
}

static uint8_t rb_peek_byte(ringbuf_t *rb) {
    return rb->data[rb->head];
}

static uint8_t *build_login_request(size_t *out_len) {
    pb_encoder_t setting_enc;
    pb_encoder_init(&setting_enc);
    pb_encode_string(&setting_enc, 1, "new_vc");
    pb_encode_string(&setting_enc, 2, "1");
    size_t setting_len;
    uint8_t *setting_bytes = pb_encoder_detach(&setting_enc, &setting_len);

    char android_id_str[32];
    char security_token_str[32];
    char device_id_str[48];
    snprintf(android_id_str, sizeof(android_id_str), "%llu", (unsigned long long)g_fcm_state.android_id);
    snprintf(security_token_str, sizeof(security_token_str), "%llu", (unsigned long long)g_fcm_state.security_token);
    snprintf(device_id_str, sizeof(device_id_str), "android-%llx", (unsigned long long)g_fcm_state.android_id);

    pb_encoder_t enc;
    pb_encoder_init(&enc);
    pb_encode_string(&enc, 1, "chrome-63.0.3234.0");
    pb_encode_string(&enc, 2, "mcs.android.com");
    pb_encode_string(&enc, 3, android_id_str);
    pb_encode_string(&enc, 4, android_id_str);
    pb_encode_string(&enc, 5, security_token_str);
    pb_encode_string(&enc, 6, device_id_str);
    pb_encode_bytes(&enc, 8, setting_bytes, setting_len);
    pb_encode_bool(&enc, 12, false);
    pb_encode_bool(&enc, 14, true);
    pb_encode_int32(&enc, 16, 2);
    pb_encode_int32(&enc, 17, 1);

    size_t payload_len;
    uint8_t *payload = pb_encoder_detach(&enc, &payload_len);
    free(setting_bytes);

    uint8_t varint_buf[5];
    int varint_len = pb_put_uvarint(varint_buf, sizeof(varint_buf), payload_len);
    size_t packet_len = 2 + varint_len + payload_len;
    uint8_t *packet = (uint8_t *)malloc(packet_len);
    if (!packet) {
        free(payload);
        return NULL;
    }
    packet[0] = KMCS_VERSION;
    packet[1] = K_LOGIN_REQUEST_TAG;
    memcpy(packet + 2, varint_buf, varint_len);
    memcpy(packet + 2 + varint_len, payload, payload_len);
    free(payload);
    *out_len = packet_len;
    return packet;
}

static void parse_app_data(const uint8_t *data, size_t len, fcm_app_data_t *out) {
    pb_decoder_t d;
    pb_decoder_init(&d, data, len);
    out->key[0] = '\0';
    out->value[0] = '\0';
    while (pb_decoder_remaining(&d) > 0) {
        uint32_t field;
        uint8_t wt;
        if (pb_decode_field(&d, &field, &wt) != 0) break;
        if (field == 1) pb_decode_string(&d, out->key, sizeof(out->key), NULL);
        else if (field == 2) pb_decode_string(&d, out->value, sizeof(out->value), NULL);
        else pb_skip_field(&d, wt);
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
            case 2: pb_decode_string(&d, msg->id, sizeof(msg->id), NULL); break;
            case 3: pb_decode_string(&d, msg->from, sizeof(msg->from), NULL); break;
            case 4: pb_decode_string(&d, msg->to, sizeof(msg->to), NULL); break;
            case 5: pb_decode_string(&d, msg->category, sizeof(msg->category), NULL); break;
            case 7: {
                const uint8_t *sub;
                size_t sub_len;
                if (pb_decode_bytes(&d, &sub, &sub_len) == 0 && msg->app_data_count < 16) {
                    parse_app_data(sub, sub_len, &msg->app_data[msg->app_data_count++]);
                }
                break;
            }
            case 9: pb_decode_string(&d, msg->persistent_id, sizeof(msg->persistent_id), NULL); break;
            case 17: { int32_t ttl; if (pb_decode_int32(&d, &ttl) == 0) msg->ttl = ttl; break; }
            case 21: {
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
            case 24: { bool ack; if (pb_decode_bool(&d, &ack) == 0) msg->immediate_ack = ack; break; }
            default: pb_skip_field(&d, wt); break;
        }
    }
}

static void decrypt_message_if_needed(fcm_message_t *msg) {
    const char *crypto_key_str = NULL;
    const char *encryption_str = NULL;
    for (int i = 0; i < msg->app_data_count; i++) {
        if (strcmp(msg->app_data[i].key, "crypto-key") == 0) crypto_key_str = msg->app_data[i].value;
        else if (strcmp(msg->app_data[i].key, "encryption") == 0) encryption_str = msg->app_data[i].value;
    }
    if (!crypto_key_str || !encryption_str || !msg->raw_data || msg->raw_data_len == 0) {
        printf("[FCM] ESP8266 message has no encrypted payload\n");
        return;
    }
    printf("[FCM] ESP8266 encrypted payload raw=%u heap=%u\n", (unsigned)msg->raw_data_len, ESP.getFreeHeap());

    const char *dh_start = strstr(crypto_key_str, "dh=");
    const char *salt_start = strstr(encryption_str, "salt=");
    if (!dh_start || !salt_start) return;
    dh_start += 3;
    salt_start += 5;
    const char *dh_end = strchr(dh_start, ';');
    const char *salt_end = strchr(salt_start, ';');
    size_t dh_len = dh_end ? (size_t)(dh_end - dh_start) : strlen(dh_start);
    size_t salt_str_len = salt_end ? (size_t)(salt_end - salt_start) : strlen(salt_start);

    uint8_t server_pub[128];
    size_t server_pub_len = 0;
    uint8_t salt[64];
    size_t salt_len = 0;
    if (fcm_base64url_decode(dh_start, dh_len, server_pub, sizeof(server_pub), &server_pub_len) != 0) return;
    if (fcm_base64url_decode(salt_start, salt_str_len, salt, sizeof(salt), &salt_len) != 0) return;
    printf("[FCM] ESP8266 decoded dh=%u salt=%u\n", (unsigned)server_pub_len, (unsigned)salt_len);
#ifndef FCM_ESP8266_ENABLE_BLOCKING_ECDH
    printf("[FCM] ESP8266 encrypted payload received; decrypt skipped to avoid WDT reset\n");
    return;
#endif

    uint8_t *plaintext = (uint8_t *)malloc(msg->raw_data_len);
    size_t plaintext_len = 0;
    if (!plaintext) return;
    if (fcm_decrypt(server_pub, server_pub_len, salt, salt_len,
                    msg->raw_data, msg->raw_data_len, plaintext, &plaintext_len) == ESP_OK && plaintext_len > 0) {
        msg->json_data = (char *)malloc(plaintext_len + 1);
        if (msg->json_data) {
            memcpy(msg->json_data, plaintext, plaintext_len);
            msg->json_data[plaintext_len] = '\0';
        }
    }
    free(plaintext);
}

static esp_err_t send_heartbeat(BearSSL::WiFiClientSecure *client) {
    uint8_t pkt[2] = { KMCS_VERSION, TAG_HEARTBEAT_PING };
    return client->write(pkt, sizeof(pkt)) == sizeof(pkt) ? ESP_OK : ESP_FAIL;
}

static esp_err_t send_ack(BearSSL::WiFiClientSecure *client, const char *id) {
    pb_encoder_t ack_enc;
    pb_encoder_init(&ack_enc);
    pb_encode_string(&ack_enc, 3, id);
    size_t ack_len;
    uint8_t *ack_payload = pb_encoder_detach(&ack_enc, &ack_len);
    if (!ack_payload) return ESP_ERR_NO_MEM;

    uint8_t varint[5];
    int var_len = pb_put_uvarint(varint, sizeof(varint), ack_len);
    size_t pkt_len = 2 + var_len + ack_len;
    uint8_t *pkt = (uint8_t *)malloc(pkt_len);
    if (!pkt) {
        free(ack_payload);
        return ESP_ERR_NO_MEM;
    }
    pkt[0] = KMCS_VERSION;
    pkt[1] = TAG_IQ_STANZA;
    memcpy(pkt + 2, varint, var_len);
    memcpy(pkt + 2 + var_len, ack_payload, ack_len);
    size_t written = client->write(pkt, pkt_len);
    free(pkt);
    free(ack_payload);
    return written == pkt_len ? ESP_OK : ESP_FAIL;
}

static esp_err_t fcm_start_internal(fcm_message_cb_t callback) {
    BearSSL::WiFiClientSecure client;
    client.setBufferSizes(512, 512);
    client.setTimeout(100);
    client.setNoDelay(true);
#if defined(FCM_ESP8266_STRICT_TLS)
    BearSSL::X509List cert(GOOGLE_ROOT_CA_PEM);
    client.setTrustAnchors(&cert);
#else
    client.setInsecure();
#endif

    printf("[FCM] ESP8266 connecting to %s:%d, free heap=%u\n", MCS_HOST, MCS_PORT, ESP.getFreeHeap());
    if (!client.connect(MCS_HOST, MCS_PORT)) {
        printf("[FCM] ERROR: ESP8266 MCS TLS connect failed, free heap=%u\n", ESP.getFreeHeap());
        client.stop();
        delay(100);
        return ESP_FAIL;
    }
    printf("[FCM] ESP8266 MCS TLS connected, free heap=%u\n", ESP.getFreeHeap());

    size_t login_len;
    uint8_t *login = build_login_request(&login_len);
    if (!login) return ESP_ERR_NO_MEM;
    if (client.write(login, login_len) != login_len) {
        free(login);
        return ESP_FAIL;
    }
    free(login);
    client.flush();
    ESP.wdtFeed();
    yield();
    printf("[FCM] ESP8266 MCS login request sent, free heap=%u\n", ESP.getFreeHeap());

    if (s_current_config && s_current_config->status_cb) s_current_config->status_cb(FCM_STATUS_CONNECTED);

    ringbuf_t rb;
    rb_init(&rb, FCM_READ_BUF_SIZE);
    if (!rb.data) return ESP_ERR_NO_MEM;

    uint8_t temp[512];
    uint8_t state = 0;
    uint8_t current_tag = 0;
    size_t expected_size = 0;
    uint32_t last_heartbeat = millis();
    uint32_t last_poll = 0;
    esp_err_t result = ESP_OK;

    while (client.connected()) {
        ESP.wdtFeed();
        delay(1);
        if (millis() - last_poll < 50) continue;
        last_poll = millis();
        int available = client.available();
        if (available > 0) {
            int to_read = available > (int)sizeof(temp) ? (int)sizeof(temp) : available;
            int n = client.read(temp, to_read);
            if (n > 0) {
                printf("[FCM] ESP8266 read %d bytes\n", n);
                rb_write(&rb, temp, (size_t)n);
            }
        } else {
            delay(50);
        }

        bool progress;
        do {
            ESP.wdtFeed();
            progress = false;
            if (state == 0 && rb.length >= 1) {
                uint8_t version = rb_peek_byte(&rb);
                rb_consume(&rb, 1);
                if (version != KMCS_VERSION) {
                    result = ESP_FAIL;
                    goto done;
                }
                state = 1;
                progress = true;
            } else if (state == 1 && rb.length >= 1) {
                current_tag = rb_peek_byte(&rb);
                rb_consume(&rb, 1);
                state = 2;
                progress = true;
            } else if (state == 2) {
                uint8_t vbuf[5];
                size_t peek_len = rb.length < sizeof(vbuf) ? rb.length : sizeof(vbuf);
                rb_peek(&rb, vbuf, peek_len);
                size_t consumed = 0;
                int vr = pb_try_read_varint(vbuf, peek_len, &expected_size, &consumed);
                if (vr == 1) {
                    rb_consume(&rb, consumed);
                    if (expected_size == 0) {
                        if (current_tag == TAG_HEARTBEAT_PING) {
                            printf("[FCM] ESP8266 HeartbeatPing (empty)\n");
                        } else if (current_tag == TAG_HEARTBEAT_ACK) {
                            printf("[FCM] ESP8266 HeartbeatAck received\n");
                        } else if (current_tag == TAG_LOGIN_RESPONSE) {
                            printf("[FCM] ESP8266 LoginResponse received (empty)\n");
                        } else if (current_tag == TAG_CLOSE) {
                            printf("[FCM] ERROR: ESP8266 server sent Close\n");
                            result = ESP_FAIL;
                            goto done;
                        }
                        state = 1;
                    } else {
                        state = 3;
                    }
                    progress = true;
                } else if (vr < 0) {
                    printf("[FCM] ERROR: ESP8266 invalid varint\n");
                    result = ESP_FAIL;
                    goto done;
                }
            } else if (state == 3 && rb.length >= expected_size) {
                uint8_t *payload = (uint8_t *)malloc(expected_size);
                if (!payload) {
                    result = ESP_ERR_NO_MEM;
                    goto done;
                }
                rb_peek(&rb, payload, expected_size);
                rb_consume(&rb, expected_size);

                if (current_tag == TAG_LOGIN_RESPONSE) {
                    printf("[FCM] ESP8266 LoginResponse received (%u bytes)\n", (unsigned)expected_size);
                } else if (current_tag == TAG_HEARTBEAT_PING) {
                    printf("[FCM] ESP8266 HeartbeatPing\n");
                } else if (current_tag == TAG_HEARTBEAT_ACK) {
                    printf("[FCM] ESP8266 HeartbeatAck received\n");
                } else if (current_tag == TAG_DATA_MESSAGE) {
                    printf("[FCM] ESP8266 DataMessageStanza (%u bytes), heap=%u\n", (unsigned)expected_size, ESP.getFreeHeap());
                    fcm_message_t msg;
                    parse_data_message(payload, expected_size, &msg);
                    printf("[FCM] ESP8266 parsed msg id=%s raw=%u app_data=%d ack=%d heap=%u\n",
                           msg.id, (unsigned)msg.raw_data_len, msg.app_data_count, msg.immediate_ack, ESP.getFreeHeap());
                    if (msg.immediate_ack) {
                        printf("[FCM] ESP8266 sending ACK\n");
                        send_ack(&client, msg.id);
                    }
                    printf("[FCM] ESP8266 decrypt check\n");
                    decrypt_message_if_needed(&msg);
                    printf("[FCM] ESP8266 decrypt done json=%s heap=%u\n", msg.json_data ? "yes" : "no", ESP.getFreeHeap());
                    if (callback) callback(&msg);
                    free(msg.json_data);
                    free(msg.raw_data);
                } else if (current_tag == TAG_CLOSE) {
                    free(payload);
                    result = ESP_FAIL;
                    goto done;
                }

                free(payload);
                state = 1;
                progress = true;
            }
        } while (progress);

        if (millis() - last_heartbeat > g_fcm_heartbeat_interval_ms) {
            last_heartbeat = millis();
        }
    }

    result = ESP_FAIL;

done:
    rb_free(&rb);
    client.stop();
    return result;
}

extern "C" esp_err_t fcm_start(fcm_message_cb_t callback) {
    if (!s_current_config) return ESP_ERR_INVALID_STATE;
    bool auto_reconnect = s_current_config->auto_reconnect;
    esp_err_t last_err;
    do {
        if (s_current_config->status_cb) s_current_config->status_cb(FCM_STATUS_CONNECTING);
        last_err = fcm_start_internal(callback);
        if (s_current_config->status_cb) s_current_config->status_cb(FCM_STATUS_DISCONNECTED);
        if (auto_reconnect) delay(5000);
    } while (auto_reconnect);
    return last_err;
}

#endif
