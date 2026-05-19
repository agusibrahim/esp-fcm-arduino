#include "fcm_proto.h"
#include <stdlib.h>
#include <string.h>

static void pb_encoder_grow(pb_encoder_t *e, size_t extra) {
    size_t needed = e->len + extra;
    if (needed <= e->cap) return;
    size_t new_cap = e->cap ? e->cap * 2 : 64;
    while (new_cap < needed) new_cap *= 2;
    e->buf = (uint8_t *)realloc(e->buf, new_cap);
    e->cap = new_cap;
}

static void pb_encoder_push(pb_encoder_t *e, uint8_t byte) {
    pb_encoder_grow(e, 1);
    e->buf[e->len++] = byte;
}

static void pb_encoder_append(pb_encoder_t *e, const uint8_t *data, size_t n) {
    pb_encoder_grow(e, n);
    memcpy(e->buf + e->len, data, n);
    e->len += n;
}

void pb_encoder_init(pb_encoder_t *e) {
    e->buf = NULL; e->len = 0; e->cap = 0;
}

void pb_encoder_free(pb_encoder_t *e) {
    free(e->buf); e->buf = NULL; e->len = 0; e->cap = 0;
}

uint8_t *pb_encoder_detach(pb_encoder_t *e, size_t *out_len) {
    uint8_t *buf = e->buf; *out_len = e->len;
    e->buf = NULL; e->len = 0; e->cap = 0;
    return buf;
}

void pb_encode_varint(pb_encoder_t *e, uint64_t value) {
    while (value >= 0x80) { pb_encoder_push(e, ((uint8_t)(value & 0x7F)) | 0x80); value >>= 7; }
    pb_encoder_push(e, (uint8_t)value);
}

static void pb_encode_field_number(pb_encoder_t *e, uint32_t field, uint8_t wire_type) {
    pb_encode_varint(e, ((uint64_t)field << 3) | wire_type);
}

void pb_encode_string(pb_encoder_t *e, uint32_t field, const char *value) {
    size_t slen = strlen(value);
    pb_encode_field_number(e, field, PB_WIRE_LENGTH_DELIMITED);
    pb_encode_varint(e, (uint64_t)slen);
    pb_encoder_append(e, (const uint8_t *)value, slen);
}

void pb_encode_bytes(pb_encoder_t *e, uint32_t field, const uint8_t *data, size_t len) {
    pb_encode_field_number(e, field, PB_WIRE_LENGTH_DELIMITED);
    pb_encode_varint(e, (uint64_t)len);
    pb_encoder_append(e, data, len);
}

void pb_encode_bool(pb_encoder_t *e, uint32_t field, bool value) {
    pb_encode_field_number(e, field, PB_WIRE_VARINT);
    pb_encode_varint(e, value ? 1 : 0);
}

void pb_encode_int32(pb_encoder_t *e, uint32_t field, int32_t value) {
    pb_encode_field_number(e, field, PB_WIRE_VARINT);
    pb_encode_varint(e, (uint64_t)(uint32_t)value);
}

void pb_encode_int64(pb_encoder_t *e, uint32_t field, int64_t value) {
    pb_encode_field_number(e, field, PB_WIRE_VARINT);
    pb_encode_varint(e, (uint64_t)value);
}

// ── Decoder ──

void pb_decoder_init(pb_decoder_t *d, const uint8_t *buf, size_t len) {
    d->buf = buf; d->len = len; d->pos = 0;
}

size_t pb_decoder_remaining(const pb_decoder_t *d) {
    return (d->len > d->pos) ? (d->len - d->pos) : 0;
}

int pb_decode_varint(pb_decoder_t *d, uint64_t *value) {
    uint64_t x = 0; uint32_t s = 0;
    for (size_t i = 0; d->pos + i < d->len; i++) {
        if (i >= 10) return -1; // varint max 10 bytes for 64-bit
        uint8_t b = d->buf[d->pos + i];
        x |= ((uint64_t)(b & 0x7F)) << s;
        if (b < 0x80) { *value = x; d->pos += i + 1; return 0; }
        s += 7; if (s >= 64) return -1;
    }
    return -1;
}

int pb_decode_field(pb_decoder_t *d, uint32_t *field_number, uint8_t *wire_type) {
    uint64_t key;
    if (pb_decode_varint(d, &key) != 0) return -1;
    *field_number = (uint32_t)(key >> 3); *wire_type = (uint8_t)(key & 0x7);
    return 0;
}

int pb_decode_int32(pb_decoder_t *d, int32_t *value) {
    uint64_t v; if (pb_decode_varint(d, &v) != 0) return -1;
    *value = (int32_t)v; return 0;
}

int pb_decode_bool(pb_decoder_t *d, bool *value) {
    uint64_t v; if (pb_decode_varint(d, &v) != 0) return -1;
    *value = (v != 0); return 0;
}

int pb_decode_string(pb_decoder_t *d, char *out, size_t out_cap, size_t *out_len) {
    uint64_t slen;
    if (pb_decode_varint(d, &slen) != 0) return -1;
    if (d->pos + (size_t)slen > d->len) return -1;
    size_t copy_len = (size_t)slen;
    if (out && out_cap > 0) {
        size_t to_copy = copy_len < (out_cap - 1) ? copy_len : (out_cap - 1);
        memcpy(out, d->buf + d->pos, to_copy); out[to_copy] = '\0';
    }
    if (out_len) *out_len = copy_len;
    d->pos += copy_len;
    return 0;
}

int pb_decode_bytes(pb_decoder_t *d, const uint8_t **out, size_t *out_len) {
    uint64_t blen;
    if (pb_decode_varint(d, &blen) != 0) return -1;
    if (d->pos + (size_t)blen > d->len) return -1;
    *out = d->buf + d->pos; *out_len = (size_t)blen;
    d->pos += (size_t)blen;
    return 0;
}

int pb_skip_field(pb_decoder_t *d, uint8_t wire_type) {
    switch (wire_type) {
        case PB_WIRE_VARINT: { uint64_t dummy; return pb_decode_varint(d, &dummy); }
        case PB_WIRE_BIT64: if (d->pos + 8 > d->len) return -1; d->pos += 8; return 0;
        case PB_WIRE_LENGTH_DELIMITED: { uint64_t slen; if (pb_decode_varint(d, &slen) != 0) return -1; if (d->pos + (size_t)slen > d->len) return -1; d->pos += (size_t)slen; return 0; }
        case PB_WIRE_BIT32: if (d->pos + 4 > d->len) return -1; d->pos += 4; return 0;
        default: return -1;
    }
}

int pb_decode_uint64(pb_decoder_t *d, uint64_t *value) {
    return pb_decode_varint(d, value);
}

int pb_decode_fixed64(pb_decoder_t *d, uint64_t *value) {
    if (d->pos + 8 > d->len) return -1;
    *value = 0;
    for (int i = 0; i < 8; i++)
        *value |= ((uint64_t)d->buf[d->pos + i]) << (i * 8);
    d->pos += 8;
    return 0;
}

int pb_put_uvarint(uint8_t *buf, size_t buf_cap, uint64_t value) {
    int i = 0;
    while (value >= 0x80) {
        if ((size_t)i >= buf_cap) return -1;
        buf[i++] = ((uint8_t)(value & 0x7F)) | 0x80; value >>= 7;
    }
    if ((size_t)i >= buf_cap) return -1;
    buf[i++] = (uint8_t)value;
    return i;
}

int pb_try_read_varint(const uint8_t *buf, size_t len, size_t *value, size_t *consumed) {
    size_t result = 0, shift = 0;
    for (size_t i = 0; i < len && i < 5; i++) {
        result |= ((size_t)(buf[i] & 0x7F)) << shift;
        if ((buf[i] & 0x80) == 0) { *value = result; *consumed = i + 1; return 1; }
        shift += 7;
    }
    if (len >= 5) return -1;
    return 0;
}
