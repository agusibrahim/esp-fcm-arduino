#if defined(ESP8266) || defined(ARDUINO_ARCH_ESP8266)

#include "FCMReceiver.h"
#include "fcm_proto.h"
#include "fcm_root_ca.h"

#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecureBearSSL.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <LittleFS.h>

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
static fcm_should_stop_cb_t s_should_stop_cb = NULL;
static uint64_t s_last_ts = 0;
static bool s_ts_loaded = false;
static fcm_message_t *s_pending_server_msg = NULL;
static fcm_message_cb_t s_pending_callback = NULL;

static uint64_t parse_pid_timestamp(const char *persistent_id);
static void save_last_timestamp(uint64_t ts);

extern "C" void fcm_set_heartbeat_interval(uint32_t seconds) {
    g_fcm_heartbeat_interval_ms = seconds * 1000UL;
}

extern "C" void fcm_set_should_stop_callback(fcm_should_stop_cb_t callback) {
    s_should_stop_cb = callback;
}

extern "C" esp_err_t fcm_mark_message_processed(const char *persistent_id) {
    uint64_t ts = parse_pid_timestamp(persistent_id);
    if (ts == 0) return ESP_ERR_INVALID_ARG;
    if (ts > s_last_ts) save_last_timestamp(ts);
    return ESP_OK;
}

static uint64_t parse_pid_timestamp(const char *persistent_id) {
    if (!persistent_id || !persistent_id[0]) return 0;
    const char *colon = strchr(persistent_id, ':');
    if (!colon) return 0;
    return strtoull(colon + 1, NULL, 10);
}

static void load_last_timestamp(void) {
    if (s_ts_loaded) return;
    s_ts_loaded = true;
    if (!LittleFS.begin()) return;
    File f = LittleFS.open("/fcm_last_ts", "r");
    if (!f) return;
    s_last_ts = strtoull(f.readString().c_str(), NULL, 10);
    f.close();
}

static void save_last_timestamp(uint64_t ts) {
    s_last_ts = ts;
    if (!LittleFS.begin()) return;
    File f = LittleFS.open("/fcm_last_ts", "w");
    if (!f) return;
    f.print((unsigned long long)ts);
    f.close();
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

static const char *find_app_data(const fcm_message_t *msg, const char *key) {
    for (int i = 0; i < msg->app_data_count; i++) {
        if (strcmp(msg->app_data[i].key, key) == 0) return msg->app_data[i].value;
    }
    return NULL;
}

static String json_string_value(const String &json, const char *key) {
    String needle = String("\"") + key + "\":\"";
    int start = json.indexOf(needle);
    if (start < 0) return String();
    start += needle.length();
    int end = start;
    while (end < (int)json.length()) {
        if (json[end] == '\\') {
            end += 2;
            continue;
        }
        if (json[end] == '\"') break;
        end++;
    }
    String value = json.substring(start, end);
    value.replace("\\\"", "\"");
    value.replace("\\/", "/");
    return value;
}

static fcm_notif_data_t *parse_notif_json_esp8266(const char *json_str) {
    if (!json_str) return NULL;
    String json(json_str);
    fcm_notif_data_t *nd = (fcm_notif_data_t *)calloc(1, sizeof(fcm_notif_data_t));
    if (!nd) return NULL;

    String title = json_string_value(json, "title");
    String body = json_string_value(json, "body");
    String message_id = json_string_value(json, "fcmMessageId");
    String from = json_string_value(json, "from");
    String priority = json_string_value(json, "priority");
    if (title.length()) snprintf(nd->title, sizeof(nd->title), "%s", title.c_str());
    if (body.length()) snprintf(nd->body, sizeof(nd->body), "%s", body.c_str());
    if (message_id.length()) snprintf(nd->fcm_message_id, sizeof(nd->fcm_message_id), "%s", message_id.c_str());
    if (from.length()) snprintf(nd->from, sizeof(nd->from), "%s", from.c_str());
    if (priority.length()) snprintf(nd->priority, sizeof(nd->priority), "%s", priority.c_str());

    if (!nd->title[0] && !nd->body[0] && !nd->fcm_message_id[0]) {
        free(nd);
        return NULL;
    }
    return nd;
}

static esp_err_t decrypt_message_via_server(fcm_message_t *msg) {
    if (!s_current_config || !s_current_config->decrypt_api_url || !s_current_config->decrypt_api_url[0]) return ESP_ERR_INVALID_STATE;
    const char *crypto_key = find_app_data(msg, "crypto-key");
    const char *encryption = find_app_data(msg, "encryption");
    if (!crypto_key || !encryption || !msg->raw_data || msg->raw_data_len == 0) return ESP_ERR_INVALID_ARG;

    size_t raw_b64_len = ((msg->raw_data_len * 4) + 2) / 3 + 1;
    char *raw_b64 = (char *)malloc(raw_b64_len);
    if (!raw_b64) return ESP_ERR_NO_MEM;

    size_t encoded_len = 0;
    if (fcm_base64url_encode(msg->raw_data, msg->raw_data_len, raw_b64, raw_b64_len, &encoded_len) != 0) {
        free(raw_b64);
        return ESP_FAIL;
    }

    size_t body_len = strlen(g_fcm_state.private_key_b64) + strlen(g_fcm_state.auth_secret_b64) +
                      strlen(crypto_key) + strlen(encryption) + strlen(raw_b64) + 160;
    char *body = (char *)malloc(body_len);
    if (!body) {
        free(raw_b64);
        return ESP_ERR_NO_MEM;
    }

    snprintf(body, body_len,
             "{\"privateKey\":\"%s\",\"authSecret\":\"%s\",\"cryptoKey\":\"%s\",\"encryption\":\"%s\",\"rawData\":\"%s\"}",
             g_fcm_state.private_key_b64,
             g_fcm_state.auth_secret_b64,
             crypto_key,
             encryption,
             raw_b64);

    bool is_https = strncmp(s_current_config->decrypt_api_url, "https://", 8) == 0;
    BearSSL::WiFiClientSecure tls_client;
    WiFiClient plain_client;
    WiFiClient *client_ptr = NULL;
    if (is_https) {
        tls_client.setInsecure();
        client_ptr = &tls_client;
    } else {
        client_ptr = &plain_client;
    }
    HTTPClient http;
    esp_err_t result = ESP_FAIL;
    if (http.begin(*client_ptr, s_current_config->decrypt_api_url)) {
        http.setReuse(false);
        http.setTimeout(15000);
        http.useHTTP10(true);
        http.addHeader("Content-Type", "application/json");
        http.addHeader("Connection", "close");
        int code = http.POST((uint8_t *)body, strlen(body));
        if (code >= 200 && code < 300) {
            String response = http.getString();
            if (response.indexOf("\"success\":true") >= 0) {
                String text = json_string_value(response, "text");
                if (text.length()) {
                    msg->json_data = (char *)malloc(text.length() + 1);
                    if (msg->json_data) {
                        memcpy(msg->json_data, text.c_str(), text.length() + 1);
                        msg->notif_data = parse_notif_json_esp8266(msg->json_data);
                        result = ESP_OK;
                    } else {
                        result = ESP_ERR_NO_MEM;
                    }
                }
            }
        } else {
            printf("[FCM] Server decrypt failed: %d\n", code);
        }
        http.end();
    }

    free(body);
    free(raw_b64);
    return result;
}

static void decrypt_message_if_needed(fcm_message_t *msg) {
    const char *crypto_key_str = NULL;
    const char *encryption_str = NULL;
    for (int i = 0; i < msg->app_data_count; i++) {
        if (strcmp(msg->app_data[i].key, "crypto-key") == 0) crypto_key_str = msg->app_data[i].value;
        else if (strcmp(msg->app_data[i].key, "encryption") == 0) encryption_str = msg->app_data[i].value;
    }
    if (!crypto_key_str || !encryption_str || !msg->raw_data || msg->raw_data_len == 0) {
        return;
    }

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
#ifndef FCM_ESP8266_ENABLE_BLOCKING_ECDH
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
    uint8_t pkt[2] = { TAG_HEARTBEAT_PING, 0 };
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
    if (WiFi.status() != WL_CONNECTED) {
        printf("[FCM] ESP8266 WiFi disconnected, waiting reconnect\n");
        uint32_t deadline = millis() + 30000;
        while (WiFi.status() != WL_CONNECTED && millis() < deadline) {
            delay(500);
            yield();
        }
        if (WiFi.status() != WL_CONNECTED) {
            return ESP_FAIL;
        }
    }
    BearSSL::WiFiClientSecure *client = new BearSSL::WiFiClientSecure();
    if (!client) return ESP_ERR_NO_MEM;
    client->setBufferSizes(512, 512);
    client->setTimeout(100);
    client->setNoDelay(true);
#if defined(FCM_ESP8266_STRICT_TLS)
    BearSSL::X509List cert(GOOGLE_ROOT_CA_PEM);
    client->setTrustAnchors(&cert);
#else
    client->setInsecure();
#endif

    printf("[FCM] ESP8266 connecting to %s:%d, free heap=%u\n", MCS_HOST, MCS_PORT, ESP.getFreeHeap());
    if (!client->connect(MCS_HOST, MCS_PORT)) {
        printf("[FCM] ERROR: ESP8266 MCS TLS connect failed, free heap=%u\n", ESP.getFreeHeap());
        client->stop();
        delete client;
        delay(100);
        return ESP_FAIL;
    }

    size_t login_len;
    uint8_t *login = build_login_request(&login_len);
    if (!login) return ESP_ERR_NO_MEM;
    if (client->write(login, login_len) != login_len) {
        free(login);
        return ESP_FAIL;
    }
    free(login);
    client->flush();
    ESP.wdtFeed();
    yield();
    load_last_timestamp();

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

    while (client->connected()) {
        if (s_should_stop_cb && s_should_stop_cb()) {
            result = ESP_OK;
            goto done;
        }
        ESP.wdtFeed();
        delay(1);
        if (millis() - last_poll < 50) continue;
        last_poll = millis();
        int available = client->available();
        if (available > 0) {
            int to_read = available > (int)sizeof(temp) ? (int)sizeof(temp) : available;
            int n = client->read(temp, to_read);
            if (n > 0) {
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
                            send_heartbeat(client);
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

                if (current_tag == TAG_HEARTBEAT_PING) {
                    send_heartbeat(client);
                } else if (current_tag == TAG_HEARTBEAT_ACK || current_tag == TAG_LOGIN_RESPONSE || current_tag == TAG_IQ_STANZA) {
                } else if (current_tag == TAG_DATA_MESSAGE) {
                    fcm_message_t *msg = (fcm_message_t *)calloc(1, sizeof(fcm_message_t));
                    if (!msg) {
                        result = ESP_ERR_NO_MEM;
                        goto done;
                    }
                    parse_data_message(payload, expected_size, msg);

                    uint64_t msg_ts = parse_pid_timestamp(msg->persistent_id);
                    if (msg_ts > 0 && msg_ts <= s_last_ts) {
                        free(msg->raw_data);
                        free(msg);
                        free(payload);
                        state = 1;
                        progress = true;
                        continue;
                    }
                    if (msg->immediate_ack) {
                        send_ack(client, msg->id);
                    }

#if defined(FCM_DECRYPT_VIA_SERVER)
                    s_pending_server_msg = msg;
                    s_pending_callback = callback;
                    free(payload);
                    result = ESP_OK;
                    goto done;
#else
                    if (msg_ts > 0) {
                        save_last_timestamp(msg_ts);
                    }
                    decrypt_message_if_needed(msg);
                    msg->notif_data = parse_notif_json_esp8266(msg->json_data);
                    if (callback) callback(msg);
                    free(msg->notif_data);
                    free(msg->json_data);
                    free(msg->raw_data);
                    free(msg);
#endif
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
            if (send_heartbeat(client) != ESP_OK) {
                printf("[FCM] ERROR: ESP8266 heartbeat send failed\n");
                result = ESP_FAIL;
                goto done;
            }
            last_heartbeat = millis();
        }
    }

    result = ESP_FAIL;

done:
    rb_free(&rb);
    if (client) {
        client->stop();
        delete client;
    }
    return result;
}

static void process_pending_server_decrypt(void) {
    if (!s_pending_server_msg) return;
    fcm_message_t *msg = s_pending_server_msg;
    fcm_message_cb_t callback = s_pending_callback;
    s_pending_server_msg = NULL;
    s_pending_callback = NULL;

    uint64_t msg_ts = parse_pid_timestamp(msg->persistent_id);
    delay(2000);
    yield();
    printf("[FCM] ESP8266 starting server decrypt, free heap=%u\n", ESP.getFreeHeap());
    if (decrypt_message_via_server(msg) == ESP_OK) {
        if (callback) callback(msg);
        if (msg_ts > 0) save_last_timestamp(msg_ts);
    }
    free(msg->notif_data);
    free(msg->json_data);
    free(msg->raw_data);
    free(msg);
}

extern "C" esp_err_t fcm_start(fcm_message_cb_t callback) {
    if (!s_current_config) return ESP_ERR_INVALID_STATE;
    bool auto_reconnect = s_current_config->auto_reconnect;
    esp_err_t last_err;
    do {
        if (s_current_config->status_cb) s_current_config->status_cb(FCM_STATUS_CONNECTING);
        last_err = fcm_start_internal(callback);
        if (s_current_config->status_cb) s_current_config->status_cb(FCM_STATUS_DISCONNECTED);
        process_pending_server_decrypt();
        if (auto_reconnect) delay(5000);
    } while (auto_reconnect);
    return last_err;
}

#endif
