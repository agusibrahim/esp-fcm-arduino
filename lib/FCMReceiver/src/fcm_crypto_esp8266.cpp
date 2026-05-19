#if defined(ESP8266) || defined(ARDUINO_ARCH_ESP8266)

#include "FCMReceiver.h"

#include <bearssl/bearssl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static uint8_t s_private_key[32];
static uint8_t s_auth_secret[32];
static size_t s_auth_secret_len;
static uint8_t s_client_pub[65];
static size_t s_client_pub_len;
static bool s_initialized = false;

static int base64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    if (c == '=') return -2;
    return -1;
}

int fcm_base64url_decode(const char *input, size_t input_len,
                          uint8_t *output, size_t output_cap, size_t *output_len) {
    size_t out_len = 0;
    uint32_t acc = 0;
    int bits = 0;

    for (size_t i = 0; i < input_len; i++) {
        int v = base64_value(input[i]);
        if (v == -2) break;
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out_len >= output_cap) return -1;
            output[out_len++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }

    if (output_len) *output_len = out_len;
    return 0;
}

int fcm_base64url_encode(const uint8_t *input, size_t input_len,
                          char *output, size_t output_cap, size_t *output_len) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t out_len = ((input_len * 4) + 2) / 3;
    if (output_cap <= out_len) return -1;

    size_t i = 0;
    size_t j = 0;
    while (i < input_len) {
        uint32_t a = input[i++];
        uint32_t b = i < input_len ? input[i++] : 0;
        uint32_t c = i < input_len ? input[i++] : 0;
        uint32_t n = (a << 16) | (b << 8) | c;

        output[j++] = alphabet[(n >> 18) & 63];
        output[j++] = alphabet[(n >> 12) & 63];
        if (j < out_len) output[j++] = alphabet[(n >> 6) & 63];
        if (j < out_len) output[j++] = alphabet[n & 63];
    }

    output[j] = '\0';
    if (output_len) *output_len = j;
    return 0;
}

static int fcm_base64_decode_std(const char *input, size_t input_len,
                                 uint8_t *output, size_t output_cap, size_t *output_len) {
    return fcm_base64url_decode(input, input_len, output, output_cap, output_len);
}

static const void *find_bytes(const uint8_t *haystack, size_t haystack_len,
                              const uint8_t *needle, size_t needle_len) {
    if (needle_len == 0 || haystack_len < needle_len) return NULL;
    for (size_t i = 0; i + needle_len <= haystack_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) return haystack + i;
        if ((i & 0x0F) == 0) ESP.wdtFeed();
    }
    return NULL;
}

static bool extract_pkcs8_p256_key_material(const uint8_t *der, size_t der_len,
                                            uint8_t private_out[32],
                                            uint8_t public_out[65]) {
    static const uint8_t oid_ec_public_key[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    static const uint8_t oid_prime256v1[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

    if (der_len < 100) return false;
    if (!find_bytes(der, der_len, oid_ec_public_key, sizeof(oid_ec_public_key))) return false;
    if (!find_bytes(der, der_len, oid_prime256v1, sizeof(oid_prime256v1))) return false;

    bool found_private = false;
    bool found_public = false;
    for (size_t i = 0; i + 67 <= der_len; i++) {
        if (!found_private && i + 34 <= der_len && der[i] == 0x04 && der[i + 1] == 0x20) {
            memcpy(private_out, der + i + 2, 32);
            found_private = true;
        }
        if (!found_public && der[i] == 0x03 && der[i + 1] == 0x42 && der[i + 2] == 0x00 && der[i + 3] == 0x04) {
            memcpy(public_out, der + i + 3, 65);
            found_public = true;
        }
        if (found_private && found_public) return true;
        if ((i & 0x0F) == 0) ESP.wdtFeed();
    }
    return false;
}

static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[32]) {
    br_hmac_key_context kc;
    br_hmac_context hc;
    br_hmac_key_init(&kc, &br_sha256_vtable, key, key_len);
    br_hmac_init(&hc, &kc, 32);
    br_hmac_update(&hc, data, data_len);
    br_hmac_out(&hc, out);
    return 0;
}

static int hkdf_extract(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        uint8_t prk[32]) {
    return hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

static int hkdf_expand(const uint8_t *prk, size_t prk_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len) {
    uint8_t t[32];
    size_t t_len = 0;
    size_t offset = 0;
    uint8_t counter = 1;

    while (offset < okm_len) {
        br_hmac_key_context kc;
        br_hmac_context hc;
        br_hmac_key_init(&kc, &br_sha256_vtable, prk, prk_len);
        br_hmac_init(&hc, &kc, 32);
        if (t_len > 0) br_hmac_update(&hc, t, t_len);
        br_hmac_update(&hc, info, info_len);
        br_hmac_update(&hc, &counter, 1);
        br_hmac_out(&hc, t);

        size_t copy = okm_len - offset;
        if (copy > sizeof(t)) copy = sizeof(t);
        memcpy(okm + offset, t, copy);
        offset += copy;
        t_len = sizeof(t);
        counter++;
    }

    memset(t, 0, sizeof(t));
    return 0;
}

extern "C" esp_err_t fcm_crypto_init_with_keys(const char *private_key_b64, const char *auth_secret_b64) {
    if (s_initialized) return ESP_OK;

    printf("[FCM] ESP8266 crypto init start, free heap=%u\n", ESP.getFreeHeap());
    ESP.wdtFeed();
    yield();

    uint8_t der[256];
    size_t der_len = 0;
    if (fcm_base64_decode_std(private_key_b64, strlen(private_key_b64), der, sizeof(der), &der_len) != 0) {
        printf("[FCM] ERROR: Failed to base64 decode private key\n");
        return ESP_FAIL;
    }
    printf("[FCM] ESP8266 private key decoded (%u bytes)\n", (unsigned)der_len);
    ESP.wdtFeed();
    yield();
    if (!extract_pkcs8_p256_key_material(der, der_len, s_private_key, s_client_pub)) {
        printf("[FCM] ERROR: Unsupported ESP8266 private key format\n");
        return ESP_FAIL;
    }
    s_client_pub_len = 65;
    printf("[FCM] ESP8266 key material extracted\n");
    ESP.wdtFeed();
    yield();

    if (fcm_base64_decode_std(auth_secret_b64, strlen(auth_secret_b64),
                              s_auth_secret, sizeof(s_auth_secret), &s_auth_secret_len) != 0) {
        printf("[FCM] ERROR: Failed to decode auth secret\n");
        return ESP_FAIL;
    }

    s_initialized = true;
    printf("[FCM] ESP8266 crypto initialized (pub key %d bytes, auth secret %d bytes)\n",
           (int)s_client_pub_len, (int)s_auth_secret_len);
    return ESP_OK;
}

extern "C" esp_err_t fcm_crypto_generate_keys(char *priv_key_b64, size_t priv_cap,
                                               char *pub_key_b64url, size_t pub_cap,
                                               char *auth_secret_b64url, size_t auth_cap) {
    (void)priv_key_b64;
    (void)priv_cap;
    (void)pub_key_b64url;
    (void)pub_cap;
    (void)auth_secret_b64url;
    (void)auth_cap;
    return ESP_ERR_NOT_SUPPORTED;
}

extern "C" esp_err_t fcm_generate_fid(char *fid_out, size_t fid_cap) {
    (void)fid_out;
    (void)fid_cap;
    return ESP_ERR_NOT_SUPPORTED;
}

extern "C" esp_err_t fcm_decrypt(const uint8_t *server_pub, size_t server_pub_len,
                                  const uint8_t *salt, size_t salt_len,
                                  const uint8_t *raw_data, size_t raw_data_len,
                                  uint8_t *out, size_t *out_len) {
    if (!s_initialized) return ESP_FAIL;
    if (server_pub_len != 65 || raw_data_len < 16) return ESP_FAIL;

    printf("[FCM] ESP8266 decrypt start raw=%u heap=%u\n", (unsigned)raw_data_len, ESP.getFreeHeap());
    uint8_t shared_point[65];
    memcpy(shared_point, server_pub, server_pub_len);
    ESP.wdtFeed();
    ESP.wdtDisable();
    uint32_t ecdh_start = millis();
    const br_ec_impl *ec = br_ec_get_default();
    uint32_t ecdh_ok = ec->mul(shared_point, sizeof(shared_point), s_private_key, sizeof(s_private_key), BR_EC_secp256r1);
    ESP.wdtEnable(0);
    ESP.wdtFeed();
    printf("[FCM] ESP8266 ECDH done ok=%u elapsed=%lu ms\n", (unsigned)ecdh_ok, (unsigned long)(millis() - ecdh_start));
    if (!ecdh_ok) {
        printf("[FCM] ERROR: ESP8266 ECDH failed\n");
        return ESP_FAIL;
    }

    uint8_t shared_buf[32];
    memcpy(shared_buf, shared_point + 1, sizeof(shared_buf));

    uint8_t prk1[32];
    if (hkdf_extract(s_auth_secret, s_auth_secret_len, shared_buf, sizeof(shared_buf), prk1) != 0) return ESP_FAIL;

    const uint8_t auth_info[] = "Content-Encoding: auth\0";
    uint8_t ikm2[32];
    if (hkdf_expand(prk1, sizeof(prk1), auth_info, 23, ikm2, sizeof(ikm2)) != 0) return ESP_FAIL;

    uint8_t prk2[32];
    if (hkdf_extract(salt, salt_len, ikm2, sizeof(ikm2), prk2) != 0) return ESP_FAIL;

    size_t key_context_len = 6 + 2 + s_client_pub_len + 2 + server_pub_len;
    uint8_t *key_context = (uint8_t *)malloc(key_context_len);
    if (!key_context) return ESP_ERR_NO_MEM;
    size_t ci = 0;
    memcpy(key_context + ci, "P-256", 6); ci += 6;
    key_context[ci++] = (uint8_t)((s_client_pub_len >> 8) & 0xFF);
    key_context[ci++] = (uint8_t)(s_client_pub_len & 0xFF);
    memcpy(key_context + ci, s_client_pub, s_client_pub_len); ci += s_client_pub_len;
    key_context[ci++] = (uint8_t)((server_pub_len >> 8) & 0xFF);
    key_context[ci++] = (uint8_t)(server_pub_len & 0xFF);
    memcpy(key_context + ci, server_pub, server_pub_len); ci += server_pub_len;

    size_t cek_info_len = 25 + key_context_len;
    uint8_t *cek_info = (uint8_t *)malloc(cek_info_len);
    if (!cek_info) { free(key_context); return ESP_ERR_NO_MEM; }
    memcpy(cek_info, "Content-Encoding: aesgcm", 25);
    memcpy(cek_info + 25, key_context, key_context_len);
    uint8_t cek[16];
    if (hkdf_expand(prk2, sizeof(prk2), cek_info, cek_info_len, cek, sizeof(cek)) != 0) {
        free(cek_info);
        free(key_context);
        return ESP_FAIL;
    }
    free(cek_info);

    size_t nonce_info_len = 24 + key_context_len;
    uint8_t *nonce_info = (uint8_t *)malloc(nonce_info_len);
    if (!nonce_info) { free(key_context); return ESP_ERR_NO_MEM; }
    memcpy(nonce_info, "Content-Encoding: nonce", 24);
    memcpy(nonce_info + 24, key_context, key_context_len);
    uint8_t nonce[12];
    int nonce_ret = hkdf_expand(prk2, sizeof(prk2), nonce_info, nonce_info_len, nonce, sizeof(nonce));
    free(nonce_info);
    free(key_context);
    if (nonce_ret != 0) return ESP_FAIL;

    size_t ciphertext_len = raw_data_len - 16;
    memcpy(out, raw_data, ciphertext_len);

    br_aes_small_ctr_keys aes_ctx;
    br_gcm_context gcm;
    br_aes_small_ctr_init(&aes_ctx, cek, sizeof(cek));
    br_gcm_init(&gcm, (const br_block_ctr_class **)&aes_ctx, &br_ghash_ctmul32);
    br_gcm_reset(&gcm, nonce, sizeof(nonce));
    br_gcm_flip(&gcm);
    br_gcm_run(&gcm, 0, out, ciphertext_len);
    ESP.wdtFeed();
    printf("[FCM] ESP8266 GCM run done\n");
    if (!br_gcm_check_tag(&gcm, raw_data + ciphertext_len)) {
        printf("[FCM] ERROR: ESP8266 GCM decrypt failed\n");
        return ESP_FAIL;
    }

    if (ciphertext_len >= 2) {
        uint16_t pad_len = ((uint16_t)out[0] << 8) | out[1];
        size_t header = 2 + pad_len;
        if (header <= ciphertext_len) {
            *out_len = ciphertext_len - header;
            memmove(out, out + header, *out_len);
        } else {
            *out_len = ciphertext_len;
        }
    } else {
        *out_len = ciphertext_len;
    }

    memset(shared_buf, 0, sizeof(shared_buf));
    memset(prk1, 0, sizeof(prk1));
    memset(ikm2, 0, sizeof(ikm2));
    memset(prk2, 0, sizeof(prk2));
    memset(cek, 0, sizeof(cek));
    memset(nonce, 0, sizeof(nonce));
    return ESP_OK;
}

#endif
