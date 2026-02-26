#include "FCMReceiver.h"
#include <string.h>

// Internal: crypto module init (defined in fcm_crypto.c)
esp_err_t fcm_crypto_init(void);

static fcm_config_t s_config;
static bool s_config_stored = false;

esp_err_t fcm_init(const fcm_config_t *config) {
    if (!config) return ESP_ERR_INVALID_ARG;

    // Store config (copy struct — caller's string pointers must remain valid)
    memcpy(&s_config, config, sizeof(fcm_config_t));
    s_config_stored = true;

    // Initialize crypto keys from config
    return fcm_crypto_init();
}

const fcm_config_t *fcm_get_config(void) {
    return s_config_stored ? &s_config : NULL;
}
