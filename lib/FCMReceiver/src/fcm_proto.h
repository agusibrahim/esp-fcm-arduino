#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define PB_WIRE_VARINT           0
#define PB_WIRE_BIT64            1
#define PB_WIRE_LENGTH_DELIMITED 2
#define PB_WIRE_BIT32            5

typedef struct {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
} pb_encoder_t;

void pb_encoder_init(pb_encoder_t *e);
void pb_encoder_free(pb_encoder_t *e);
uint8_t *pb_encoder_detach(pb_encoder_t *e, size_t *out_len);

void pb_encode_varint(pb_encoder_t *e, uint64_t value);
void pb_encode_string(pb_encoder_t *e, uint32_t field, const char *value);
void pb_encode_bytes(pb_encoder_t *e, uint32_t field, const uint8_t *data, size_t len);
void pb_encode_bool(pb_encoder_t *e, uint32_t field, bool value);
void pb_encode_int32(pb_encoder_t *e, uint32_t field, int32_t value);
void pb_encode_int64(pb_encoder_t *e, uint32_t field, int64_t value);

typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
} pb_decoder_t;

void   pb_decoder_init(pb_decoder_t *d, const uint8_t *buf, size_t len);
size_t pb_decoder_remaining(const pb_decoder_t *d);
int pb_decode_field(pb_decoder_t *d, uint32_t *field_number, uint8_t *wire_type);
int pb_decode_varint(pb_decoder_t *d, uint64_t *value);
int pb_decode_int32(pb_decoder_t *d, int32_t *value);
int pb_decode_bool(pb_decoder_t *d, bool *value);
int pb_decode_string(pb_decoder_t *d, char *out, size_t out_cap, size_t *out_len);
int pb_decode_bytes(pb_decoder_t *d, const uint8_t **out, size_t *out_len);
int pb_skip_field(pb_decoder_t *d, uint8_t wire_type);

int pb_decode_uint64(pb_decoder_t *d, uint64_t *value);
int pb_decode_fixed64(pb_decoder_t *d, uint64_t *value);

int pb_put_uvarint(uint8_t *buf, size_t buf_cap, uint64_t value);
int pb_try_read_varint(const uint8_t *buf, size_t len, size_t *value, size_t *consumed);
