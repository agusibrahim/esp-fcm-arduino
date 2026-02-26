#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// ── Configuration ──

typedef struct {
    // Required for auto-registration:
    const char *api_key;       // Firebase API key
    const char *app_id;        // Firebase app ID
    const char *project_id;    // Firebase project ID

    // Optional: pre-generated credentials (skip registration if android_id != 0)
    uint64_t    android_id;
    uint64_t    security_token;
    const char *fcm_token;
    const char *private_key_b64;
    const char *auth_secret_b64;
} fcm_config_t;

// ── Runtime state (populated by fcm_init, read by other modules) ──

typedef struct {
    uint64_t android_id;
    uint64_t security_token;
    char     fcm_token[512];
    char     private_key_b64[256];
    char     auth_secret_b64[64];
    char     app_id[128];
    char     project_id[128];
    char     api_key[128];
} fcm_state_t;

// Global runtime state — set by fcm_init(), read by fcm_mcs, fcm_subscribe
extern fcm_state_t g_fcm_state;

// ── Message types ──

typedef struct {
    char key[128];
    char value[512];
} fcm_app_data_t;

typedef struct {
    char key[64];
    char value[256];
} fcm_data_kv_t;

typedef struct {
    char          title[256];
    char          body[512];
    char          fcm_message_id[128];
    char          from[64];
    char          priority[16];
    fcm_data_kv_t data[8];
    int           data_count;
} fcm_notif_data_t;

typedef struct {
    char          id[128];
    char          from[256];
    char          to[256];
    char          category[256];
    char          persistent_id[256];
    int32_t       ttl;
    uint8_t      *raw_data;
    size_t        raw_data_len;
    fcm_app_data_t app_data[16];
    int           app_data_count;
    bool          immediate_ack;
    char         *json_data;       // Decrypted JSON string (null-terminated), or NULL
    fcm_notif_data_t *notif_data;  // Parsed notification struct, or NULL
} fcm_message_t;

typedef void (*fcm_message_cb_t)(const fcm_message_t *msg);

// ── Public API ──

// Initialize FCM: load or generate credentials, init crypto.
// If config has pre-generated credentials (android_id != 0), uses them directly.
// Otherwise tries NVS, then runs auto-registration.
esp_err_t fcm_init(const fcm_config_t *config);

// Subscribe to a topic via GCM register3 endpoint.
esp_err_t fcm_subscribe(const char *topic);

// Connect to MCS, login, and listen for messages. Blocks forever.
// Run this in a FreeRTOS task with >= 16KB stack.
esp_err_t fcm_start(fcm_message_cb_t callback);

// ── Decryption helpers (for use in message callback) ──

// Decrypt a WebPush aesgcm payload.
esp_err_t fcm_decrypt(const uint8_t *crypto_key, size_t crypto_key_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *raw_data, size_t raw_data_len,
                       uint8_t *out, size_t *out_len);

// Base64URL decode helper.
int fcm_base64url_decode(const char *input, size_t input_len,
                          uint8_t *output, size_t output_cap, size_t *output_len);

// Base64URL encode (no padding).
int fcm_base64url_encode(const uint8_t *input, size_t input_len,
                          char *output, size_t output_cap, size_t *output_len);

#ifdef __cplusplus
}
#endif
