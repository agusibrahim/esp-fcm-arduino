#include "FCMReceiver.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "mbedtls/pk.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "mbedtls/bignum.h"
#include "esp_random.h"

// RNG callback required by mbedTLS for ECDH blinding
static int rng_func(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

// Key material
static mbedtls_ecp_group s_grp;
static mbedtls_mpi       s_d;         // private scalar
static mbedtls_ecp_point s_Q;         // public point
static uint8_t s_auth_secret[32];
static size_t  s_auth_secret_len;
static uint8_t s_client_pub[65];      // uncompressed public key
static size_t  s_client_pub_len;
static bool    s_initialized = false;

// ── Base64URL decode ──

int fcm_base64url_decode(const char *input, size_t input_len,
                          uint8_t *output, size_t output_cap, size_t *output_len) {
    size_t padded_len = input_len;
    while (padded_len % 4 != 0) padded_len++;

    char *buf = (char *)malloc(padded_len + 1);
    if (!buf) return -1;

    for (size_t i = 0; i < input_len; i++) {
        if (input[i] == '-')
            buf[i] = '+';
        else if (input[i] == '_')
            buf[i] = '/';
        else
            buf[i] = input[i];
    }
    for (size_t i = input_len; i < padded_len; i++) {
        buf[i] = '=';
    }
    buf[padded_len] = '\0';

    size_t olen = 0;
    int ret = mbedtls_base64_decode(output, output_cap, &olen,
                                     (const unsigned char *)buf, padded_len);
    free(buf);

    if (ret != 0) return -1;
    if (output_len) *output_len = olen;
    return 0;
}

// ── HKDF helpers (manual implementation, Arduino SDK lacks mbedtls_hkdf) ──

// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
static int hkdf_extract(const uint8_t *salt, size_t salt_len,
                          const uint8_t *ikm, size_t ikm_len,
                          uint8_t *prk) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk);
}

// HKDF-Expand: OKM = T(1) || T(2) || ... truncated to okm_len
// T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
static int hkdf_expand(const uint8_t *prk, size_t prk_len,
                         const uint8_t *info, size_t info_len,
                         uint8_t *okm, size_t okm_len) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    size_t hash_len = 32; // SHA-256
    uint8_t t[32];
    size_t t_len = 0;
    uint8_t counter = 1;
    size_t offset = 0;
    int ret;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    ret = mbedtls_md_setup(&ctx, md, 1); // 1 = HMAC
    if (ret != 0) { mbedtls_md_free(&ctx); return ret; }

    while (offset < okm_len) {
        ret = mbedtls_md_hmac_starts(&ctx, prk, prk_len);
        if (ret != 0) { mbedtls_md_free(&ctx); return ret; }
        if (t_len > 0) {
            ret = mbedtls_md_hmac_update(&ctx, t, t_len);
            if (ret != 0) { mbedtls_md_free(&ctx); return ret; }
        }
        ret = mbedtls_md_hmac_update(&ctx, info, info_len);
        if (ret != 0) { mbedtls_md_free(&ctx); return ret; }
        ret = mbedtls_md_hmac_update(&ctx, &counter, 1);
        if (ret != 0) { mbedtls_md_free(&ctx); return ret; }
        ret = mbedtls_md_hmac_finish(&ctx, t);
        if (ret != 0) { mbedtls_md_free(&ctx); return ret; }
        t_len = hash_len;

        size_t copy = okm_len - offset;
        if (copy > hash_len) copy = hash_len;
        memcpy(okm + offset, t, copy);
        offset += copy;
        counter++;
    }

    mbedtls_md_free(&ctx);
    return 0;
}

// ── Init: load private key and auth secret from config ──

esp_err_t fcm_crypto_init(void) {
    if (s_initialized) return ESP_OK;

    const fcm_config_t *cfg = fcm_get_config();
    if (!cfg) return ESP_FAIL;

    mbedtls_ecp_group_init(&s_grp);
    mbedtls_mpi_init(&s_d);
    mbedtls_ecp_point_init(&s_Q);

    // Decode private key from base64 (PKCS8 DER)
    uint8_t der_buf[256];
    size_t der_len = 0;
    int ret = mbedtls_base64_decode(der_buf, sizeof(der_buf), &der_len,
                                     (const uint8_t *)cfg->private_key_b64,
                                     strlen(cfg->private_key_b64));
    if (ret != 0) {
        printf("[FCM] ERROR: Failed to base64 decode private key: %d\n", ret);
        return ESP_FAIL;
    }

    // Parse PKCS8 key
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_key(&pk, der_buf, der_len, NULL, 0);
    if (ret != 0) {
        printf("[FCM] ERROR: Failed to parse private key: -0x%04x\n", (unsigned)-ret);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }

    // Load secp256r1 group
    ret = mbedtls_ecp_group_load(&s_grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        printf("[FCM] ERROR: Failed to load ECP group\n");
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }

    // Export key components from the parsed PK context
    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(pk);
    ret = mbedtls_mpi_copy(&s_d, &ec->d);
    if (ret != 0) {
        printf("[FCM] ERROR: Failed to copy private key: -0x%04x\n", (unsigned)-ret);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }
    ret = mbedtls_ecp_copy(&s_Q, &ec->Q);
    if (ret != 0) {
        printf("[FCM] ERROR: Failed to copy public key: -0x%04x\n", (unsigned)-ret);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }
    mbedtls_pk_free(&pk);

    // Export uncompressed public key (0x04 || X || Y)
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&s_grp, &s_Q,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &olen, s_client_pub, sizeof(s_client_pub));
    if (ret != 0 || olen != 65) {
        printf("[FCM] ERROR: Failed to export public key: %d (len=%d)\n", ret, (int)olen);
        return ESP_FAIL;
    }
    s_client_pub_len = olen;

    // Decode auth secret
    ret = mbedtls_base64_decode(s_auth_secret, sizeof(s_auth_secret), &s_auth_secret_len,
                                 (const uint8_t *)cfg->auth_secret_b64,
                                 strlen(cfg->auth_secret_b64));
    if (ret != 0) {
        printf("[FCM] ERROR: Failed to base64 decode auth secret: %d\n", ret);
        return ESP_FAIL;
    }

    s_initialized = true;
    printf("[FCM] Crypto initialized (pub key %d bytes, auth secret %d bytes)\n",
             (int)s_client_pub_len, (int)s_auth_secret_len);
    return ESP_OK;
}

// ── Decrypt WebPush aesgcm ──

esp_err_t fcm_decrypt(const uint8_t *server_pub, size_t server_pub_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *raw_data, size_t raw_data_len,
                       uint8_t *out, size_t *out_len) {
    if (!s_initialized) return ESP_FAIL;
    if (raw_data_len < 16) return ESP_FAIL;

    int ret;

    // 1. Load server public key as ECP point
    mbedtls_ecp_point server_point;
    mbedtls_ecp_point_init(&server_point);
    ret = mbedtls_ecp_point_read_binary(&s_grp, &server_point,
                                         server_pub, server_pub_len);
    if (ret != 0) {
        printf("[FCM] ERROR: Failed to load server public key: -0x%04x\n", (unsigned)-ret);
        mbedtls_ecp_point_free(&server_point);
        return ESP_FAIL;
    }

    // 2. ECDH shared secret
    mbedtls_mpi shared_secret;
    mbedtls_mpi_init(&shared_secret);
    ret = mbedtls_ecdh_compute_shared(&s_grp, &shared_secret,
                                       &server_point, &s_d,
                                       rng_func, NULL);
    mbedtls_ecp_point_free(&server_point);
    if (ret != 0) {
        printf("[FCM] ERROR: ECDH failed: -0x%04x\n", (unsigned)-ret);
        mbedtls_mpi_free(&shared_secret);
        return ESP_FAIL;
    }

    // Export shared secret as 32 bytes
    uint8_t shared_buf[32];
    ret = mbedtls_mpi_write_binary(&shared_secret, shared_buf, 32);
    mbedtls_mpi_free(&shared_secret);
    if (ret != 0) {
        printf("[FCM] ERROR: Failed to export shared secret\n");
        return ESP_FAIL;
    }

    // 3. HKDF-Extract(auth_secret, shared_secret) -> prk1
    uint8_t prk1[32];
    ret = hkdf_extract(s_auth_secret, s_auth_secret_len, shared_buf, 32, prk1);
    if (ret != 0) {
        printf("[FCM] ERROR: HKDF extract 1 failed\n");
        return ESP_FAIL;
    }

    // Expand prk1 with info "Content-Encoding: auth\0" to get 32-byte ikm2
    const uint8_t auth_info[] = "Content-Encoding: auth\0";
    uint8_t ikm2[32];
    ret = hkdf_expand(prk1, 32, auth_info, 23, ikm2, 32);
    if (ret != 0) {
        printf("[FCM] ERROR: HKDF expand auth failed\n");
        return ESP_FAIL;
    }

    // 4. HKDF-Extract(salt, ikm2) -> prk2
    uint8_t prk2[32];
    ret = hkdf_extract(salt, salt_len, ikm2, 32, prk2);
    if (ret != 0) {
        printf("[FCM] ERROR: HKDF extract 2 failed\n");
        return ESP_FAIL;
    }

    // 5. Build key context per WebPush aesgcm spec:
    //    "P-256\0" + u16be(client_pub_len) + client_pub + u16be(server_pub_len) + server_pub
    size_t key_context_len = 6 + 2 + s_client_pub_len + 2 + server_pub_len;
    uint8_t *key_context = (uint8_t *)malloc(key_context_len);
    if (!key_context) return ESP_FAIL;
    size_t ci = 0;
    memcpy(key_context + ci, "P-256", 6); ci += 6;  // includes null terminator
    key_context[ci++] = (uint8_t)((s_client_pub_len >> 8) & 0xFF);
    key_context[ci++] = (uint8_t)(s_client_pub_len & 0xFF);
    memcpy(key_context + ci, s_client_pub, s_client_pub_len);
    ci += s_client_pub_len;
    key_context[ci++] = (uint8_t)((server_pub_len >> 8) & 0xFF);
    key_context[ci++] = (uint8_t)(server_pub_len & 0xFF);
    memcpy(key_context + ci, server_pub, server_pub_len);
    ci += server_pub_len;

    // 6. CEK: HKDF-Expand(prk2, "Content-Encoding: aesgcm\0" + key_context, 16)
    size_t cek_info_len = 25 + key_context_len;
    uint8_t *cek_info = (uint8_t *)malloc(cek_info_len);
    memcpy(cek_info, "Content-Encoding: aesgcm", 25);  // 24 chars + \0
    memcpy(cek_info + 25, key_context, key_context_len);

    uint8_t cek[16];
    ret = hkdf_expand(prk2, 32, cek_info, cek_info_len, cek, 16);
    free(cek_info);
    if (ret != 0) {
        free(key_context);
        printf("[FCM] ERROR: HKDF expand CEK failed\n");
        return ESP_FAIL;
    }

    // 7. Nonce: HKDF-Expand(prk2, "Content-Encoding: nonce\0" + key_context, 12)
    size_t nonce_info_len = 24 + key_context_len;
    uint8_t *nonce_info = (uint8_t *)malloc(nonce_info_len);
    memcpy(nonce_info, "Content-Encoding: nonce", 24);  // 23 chars + \0
    memcpy(nonce_info + 24, key_context, key_context_len);

    uint8_t nonce[12];
    ret = hkdf_expand(prk2, 32, nonce_info, nonce_info_len, nonce, 12);
    free(nonce_info);
    free(key_context);
    if (ret != 0) {
        printf("[FCM] ERROR: HKDF expand nonce failed\n");
        return ESP_FAIL;
    }

    // 8. AES-128-GCM decrypt
    size_t ciphertext_len = raw_data_len - 16;
    const uint8_t *ciphertext = raw_data;
    const uint8_t *gcm_tag = raw_data + ciphertext_len;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, cek, 128);
    if (ret != 0) {
        printf("[FCM] ERROR: GCM setkey failed\n");
        mbedtls_gcm_free(&gcm);
        return ESP_FAIL;
    }

    ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len,
                                    nonce, 12,
                                    NULL, 0,
                                    gcm_tag, 16,
                                    ciphertext, out);
    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        printf("[FCM] ERROR: GCM decrypt failed: -0x%04x\n", (unsigned)-ret);
        return ESP_FAIL;
    }

    // Remove padding: first 2 bytes are padding length (big endian), then padding bytes
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

    // printf("[FCM] Decrypted %d bytes\n", (int)*out_len);
    return ESP_OK;
}
