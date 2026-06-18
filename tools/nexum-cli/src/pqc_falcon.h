#pragma once
#include <stddef.h>
#include <stdint.h>

// FREE Falcon ternary (N=1536, q=18433, logn=10) wrapper.

#define FF_FALCON_LOGN       10
#define FF_FALCON_TERNARY     1
#define FF_FALCON_SIG_MAX  4096
#define FF_FALCON_PK_MAX   4096
#define FF_FALCON_SK_MAX  16384

int ff_falcon_keygen(uint8_t *sk, size_t *sk_len, uint8_t *pk, size_t *pk_len);

int ff_falcon_sign_ct(const uint8_t *sk, size_t sk_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t *sig, size_t *sig_len);

int ff_falcon_verify(const uint8_t *pk, size_t pk_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *sig, size_t sig_len);

void ff_shake256_kdf(const uint8_t *in, size_t in_len,
                     const uint8_t *ctx, size_t ctx_len,
                     uint8_t *out, size_t out_len);
