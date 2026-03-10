#pragma once
#include <stddef.h>
#include <stdint.h>

#define FF_OK 0
#define FF_ERR -1

void ff_die(const char *fmt, ...);

int ff_mkdir_p(const char *path);
int ff_read_file(const char *path, uint8_t **out, size_t *out_len);
int ff_write_file_atomic(const char *path, const uint8_t *buf, size_t len, int mode);

int ff_b64enc(const uint8_t *bin, size_t bin_len, char **out);
int ff_b64dec(const char *b64, uint8_t **out, size_t *out_len);

int ff_b64u_enc(const uint8_t *bin, size_t bin_len, char **out);
int ff_b64u_dec(const char *b64u, uint8_t **out, size_t *out_len);

int ff_json_escape(const char *in, char **out);
void ff_strlcpy(char *dst, const char *src, size_t dst_len);

void ff_u16be(uint16_t x, uint8_t out[2]);
void ff_u32be(uint32_t x, uint8_t out[4]);
void ff_u64be(uint64_t x, uint8_t out[8]);

void ff_hmac_sha512(uint8_t out64[64], const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len);
