#include "FCMReceiver.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "nvs_flash.h"
#include "nvs.h"

// Internal declarations (defined in fcm_crypto.c)
extern esp_err_t fcm_crypto_init_with_keys(const char *private_key_b64, const char *auth_secret_b64);
extern esp_err_t fcm_crypto_generate_keys(char *priv_key_b64, size_t priv_cap,
                                            char *pub_key_b64url, size_t pub_cap,
                                            char *auth_secret_b64url, size_t auth_cap);

// Registration result type (must match fcm_register.c)
typedef struct {
    uint64_t android_id;
    uint64_t security_token;
    char     gcm_token[512];
    char     fcm_token[512];
} fcm_registration_t;

extern esp_err_t fcm_register(const fcm_config_t *cfg,
                                const char *pub_key_b64url,
                                const char *auth_secret_b64url,
                                fcm_registration_t *result);

#define NVS_NAMESPACE "fcm_cred"

// Global runtime state
fcm_state_t g_fcm_state;

// Internal references
extern const fcm_config_t *s_current_config;

// ── NVS helpers ──

static esp_err_t nvs_load_credentials(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        printf("[FCM] No NVS credentials found (namespace not found)\n");
        return ESP_ERR_NOT_FOUND;
    }

    // Load android_id
    err = nvs_get_u64(handle, "android_id", &g_fcm_state.android_id);
    if (err != ESP_OK) { nvs_close(handle); return ESP_ERR_NOT_FOUND; }

    // Load security_token
    err = nvs_get_u64(handle, "sec_token", &g_fcm_state.security_token);
    if (err != ESP_OK) { nvs_close(handle); return ESP_ERR_NOT_FOUND; }

    // Load fcm_token
    size_t len = sizeof(g_fcm_state.fcm_token);
    err = nvs_get_str(handle, "fcm_token", g_fcm_state.fcm_token, &len);
    if (err != ESP_OK || strlen(g_fcm_state.fcm_token) == 0) { nvs_close(handle); return ESP_ERR_NOT_FOUND; }

    // Load private_key_b64
    len = sizeof(g_fcm_state.private_key_b64);
    err = nvs_get_str(handle, "priv_key", g_fcm_state.private_key_b64, &len);
    if (err != ESP_OK || strlen(g_fcm_state.private_key_b64) == 0) { nvs_close(handle); return ESP_ERR_NOT_FOUND; }

    // Load auth_secret_b64
    len = sizeof(g_fcm_state.auth_secret_b64);
    err = nvs_get_str(handle, "auth_secret", g_fcm_state.auth_secret_b64, &len);
    if (err != ESP_OK || strlen(g_fcm_state.auth_secret_b64) == 0) { nvs_close(handle); return ESP_ERR_NOT_FOUND; }

    nvs_close(handle);

    printf("[FCM] Loaded credentials from NVS: android_id=%" PRIu64 "\n", g_fcm_state.android_id);
    printf("[FCM] FCM token: %s\n", g_fcm_state.fcm_token);
    return ESP_OK;
}

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static esp_err_t nvs_save_credentials(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        printf("[FCM] ERROR: Failed to open NVS for writing: %s\n", esp_err_to_name(err));
        return err;
    }

    nvs_set_u64(handle, "android_id", g_fcm_state.android_id);
    nvs_set_u64(handle, "sec_token", g_fcm_state.security_token);
    nvs_set_str(handle, "fcm_token", g_fcm_state.fcm_token);
    nvs_set_str(handle, "priv_key", g_fcm_state.private_key_b64);
    nvs_set_str(handle, "auth_secret", g_fcm_state.auth_secret_b64);

    int retries = 3;
    while (retries > 0) {
        err = nvs_commit(handle);
        if (err == ESP_OK) break;
        printf("[FCM] WARNING: Failed to commit NVS (retrying): %s\n", esp_err_to_name(err));
        retries--;
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    nvs_close(handle);

    if (err != ESP_OK) {
        printf("[FCM] ERROR: Failed to commit NVS after retries: %s\n", esp_err_to_name(err));
        return err;
    }

    printf("[FCM] Saved credentials to NVS\n");
    return ESP_OK;
}

// ── Public API ──

esp_err_t fcm_clear_credentials(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        nvs_erase_all(handle);
        nvs_commit(handle);
        nvs_close(handle);
    }
    memset(&g_fcm_state, 0, sizeof(g_fcm_state));
    return err;
}

const char* fcm_get_token(void) {
    return g_fcm_state.fcm_token;
}

esp_err_t fcm_init(const fcm_config_t *config) {
    if (!config) {
        printf("[FCM] ERROR: Null config provided to fcm_init\n");
        return ESP_ERR_INVALID_ARG;
    }

    memset(&g_fcm_state, 0, sizeof(g_fcm_state));
    s_current_config = config;

    // Copy config fields that are always needed
    if (config->app_id) strncpy(g_fcm_state.app_id, config->app_id, sizeof(g_fcm_state.app_id) - 1);
    if (config->project_id) strncpy(g_fcm_state.project_id, config->project_id, sizeof(g_fcm_state.project_id) - 1);
    if (config->api_key) strncpy(g_fcm_state.api_key, config->api_key, sizeof(g_fcm_state.api_key) - 1);

    // Path 1: Pre-generated credentials provided
    if (config->android_id != 0 && config->fcm_token && config->private_key_b64 && config->auth_secret_b64) {
        printf("[FCM] Using pre-generated credentials\n");
        g_fcm_state.android_id = config->android_id;
        g_fcm_state.security_token = config->security_token;
        strncpy(g_fcm_state.fcm_token, config->fcm_token, sizeof(g_fcm_state.fcm_token) - 1);
        strncpy(g_fcm_state.private_key_b64, config->private_key_b64, sizeof(g_fcm_state.private_key_b64) - 1);
        strncpy(g_fcm_state.auth_secret_b64, config->auth_secret_b64, sizeof(g_fcm_state.auth_secret_b64) - 1);

        // Init crypto
        esp_err_t err = fcm_crypto_init_with_keys(g_fcm_state.private_key_b64, g_fcm_state.auth_secret_b64);
        if (err != ESP_OK) {
            printf("[FCM] ERROR: Crypto init failed\n");
            return err;
        }
        return ESP_OK;
    }

    // Path 2: Try loading from NVS
    if (nvs_load_credentials() == ESP_OK && g_fcm_state.android_id != 0) {
        printf("[FCM] Using credentials from NVS\n");
        esp_err_t err = fcm_crypto_init_with_keys(g_fcm_state.private_key_b64, g_fcm_state.auth_secret_b64);
        if (err != ESP_OK) {
            printf("[FCM] ERROR: Crypto init from NVS credentials failed\n");
            return err;
        }
        return ESP_OK;
    }

    // Path 3: Auto-registration
    printf("[FCM] No credentials found, starting auto-registration...\n");

    if (!config->api_key || !config->app_id || !config->project_id) {
        printf("[FCM] ERROR: Auto-registration requires api_key, app_id, and project_id\n");
        return ESP_ERR_INVALID_ARG;
    }

    // Generate ECDH keys and auth secret
    char pub_key_b64url[128];
    char auth_secret_b64url[32];

    esp_err_t err = fcm_crypto_generate_keys(
        g_fcm_state.private_key_b64, sizeof(g_fcm_state.private_key_b64),
        pub_key_b64url, sizeof(pub_key_b64url),
        auth_secret_b64url, sizeof(auth_secret_b64url));
    if (err != ESP_OK) {
        printf("[FCM] ERROR: Key generation failed\n");
        return err;
    }

    // Store auth secret in state (base64url format)
    strncpy(g_fcm_state.auth_secret_b64, auth_secret_b64url, sizeof(g_fcm_state.auth_secret_b64) - 1);

    // Run 4-step registration
    fcm_registration_t reg;
    err = fcm_register(config, pub_key_b64url, auth_secret_b64url, &reg);
    if (err != ESP_OK) {
        printf("[FCM] ERROR: Registration failed\n");
        return err;
    }

    // Populate state from registration result
    g_fcm_state.android_id = reg.android_id;
    g_fcm_state.security_token = reg.security_token;
    strncpy(g_fcm_state.fcm_token, reg.fcm_token, sizeof(g_fcm_state.fcm_token) - 1);

    // Save to NVS
    err = nvs_save_credentials();
    if (err != ESP_OK) {
        printf("[FCM] WARNING: Failed to save credentials to NVS (will re-register on reboot)\n");
    }

    // Init crypto with generated keys
    err = fcm_crypto_init_with_keys(g_fcm_state.private_key_b64, g_fcm_state.auth_secret_b64);
    if (err != ESP_OK) {
        printf("[FCM] ERROR: Crypto init with generated keys failed\n");
        return err;
    }

    printf("[FCM] Auto-registration complete!\n");
    printf("[FCM] FCM token: %s\n", g_fcm_state.fcm_token);
    return ESP_OK;
}
