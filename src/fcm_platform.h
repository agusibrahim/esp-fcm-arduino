#pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
#include "esp_err.h"
#include "esp_random.h"

static inline void fcm_platform_random(uint8_t *buf, size_t len) {
    esp_fill_random(buf, len);
}

#elif defined(ESP8266) || defined(ARDUINO_ARCH_ESP8266)
#include <Arduino.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <user_interface.h>
#ifdef __cplusplus
}
#endif

typedef int esp_err_t;

#ifndef ESP_OK
#define ESP_OK 0
#endif
#ifndef ESP_FAIL
#define ESP_FAIL -1
#endif
#ifndef ESP_ERR_NO_MEM
#define ESP_ERR_NO_MEM 0x101
#endif
#ifndef ESP_ERR_INVALID_ARG
#define ESP_ERR_INVALID_ARG 0x102
#endif
#ifndef ESP_ERR_INVALID_STATE
#define ESP_ERR_INVALID_STATE 0x103
#endif
#ifndef ESP_ERR_NOT_FOUND
#define ESP_ERR_NOT_FOUND 0x105
#endif
#ifndef ESP_ERR_NOT_SUPPORTED
#define ESP_ERR_NOT_SUPPORTED 0x106
#endif

static inline const char *esp_err_to_name(esp_err_t err) {
    switch (err) {
        case ESP_OK: return "ESP_OK";
        case ESP_FAIL: return "ESP_FAIL";
        case ESP_ERR_NO_MEM: return "ESP_ERR_NO_MEM";
        case ESP_ERR_INVALID_ARG: return "ESP_ERR_INVALID_ARG";
        case ESP_ERR_INVALID_STATE: return "ESP_ERR_INVALID_STATE";
        case ESP_ERR_NOT_FOUND: return "ESP_ERR_NOT_FOUND";
        case ESP_ERR_NOT_SUPPORTED: return "ESP_ERR_NOT_SUPPORTED";
        default: return "ESP_ERR_UNKNOWN";
    }
}

static inline void fcm_platform_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)os_random();
    }
}

#else
typedef int esp_err_t;
#ifndef ESP_OK
#define ESP_OK 0
#endif
#ifndef ESP_FAIL
#define ESP_FAIL -1
#endif
#ifndef ESP_ERR_NO_MEM
#define ESP_ERR_NO_MEM 0x101
#endif
#ifndef ESP_ERR_INVALID_ARG
#define ESP_ERR_INVALID_ARG 0x102
#endif
#ifndef ESP_ERR_INVALID_STATE
#define ESP_ERR_INVALID_STATE 0x103
#endif
#ifndef ESP_ERR_NOT_FOUND
#define ESP_ERR_NOT_FOUND 0x105
#endif
#ifndef ESP_ERR_NOT_SUPPORTED
#define ESP_ERR_NOT_SUPPORTED 0x106
#endif
static inline const char *esp_err_to_name(esp_err_t err) { (void)err; return "ESP_ERR_UNKNOWN"; }
static inline void fcm_platform_random(uint8_t *buf, size_t len) { (void)buf; (void)len; }
#endif
