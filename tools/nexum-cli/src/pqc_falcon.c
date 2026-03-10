#include "pqc_falcon.h"
#include "util.h"

#include <string.h>
#include <stdlib.h>
#include <sodium.h>

// Vendor headers
#include "../vendor/falcon/falcon.h"

static int init_rng(shake256_context *rng) {
    int r = shake256_init_prng_from_system(rng);
    if (r < 0) return r;
    shake256_flip(rng);
    return 0;
}

int ff_falcon_keygen(uint8_t *sk, size_t *sk_len, uint8_t *pk, size_t *pk_len) {
    shake256_context rng;
    if (init_rng(&rng) != 0) return -1;

    size_t skmax = FALCON_PRIVKEY_SIZE(FF_FALCON_LOGN);
    size_t pkmax = FALCON_PUBKEY_SIZE(FF_FALCON_LOGN);

    void *tmp = malloc(FALCON_TMPSIZE_KEYGEN(FF_FALCON_LOGN));
    if (!tmp) return -1;

    int r = falcon_keygen_make(&rng, FF_FALCON_LOGN,
                              sk, skmax,
                              pk, pkmax,
                              tmp, FALCON_TMPSIZE_KEYGEN(FF_FALCON_LOGN));
    sodium_memzero(tmp, FALCON_TMPSIZE_KEYGEN(FF_FALCON_LOGN));
    free(tmp);
    if (r != 0) return -1;

    *sk_len = skmax;
    *pk_len = pkmax;
    return 0;
}

int ff_falcon_sign_ct(const uint8_t *sk, size_t sk_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t *sig, size_t *sig_len) {
    shake256_context rng;
    if (init_rng(&rng) != 0) return -1;

    int logn = falcon_get_logn((void*)sk, sk_len);
    if (logn != FF_FALCON_LOGN) return -1;

    size_t tmpsz = FALCON_TMPSIZE_SIGNDYN(FF_FALCON_LOGN);
    void *tmp = malloc(tmpsz);
    if (!tmp) return -1;

    int r = falcon_sign_dyn(&rng,
                           sig, sig_len, FALCON_SIG_CT,
                           sk, sk_len,
                           msg, msg_len,
                           tmp, tmpsz);
    sodium_memzero(tmp, tmpsz);
    free(tmp);
    return (r == 0) ? 0 : -1;
}

int ff_falcon_verify(const uint8_t *pk, size_t pk_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *sig, size_t sig_len) {
    int logn = falcon_get_logn((void*)pk, pk_len);
    if (logn != FF_FALCON_LOGN) return -1;

    size_t tmpsz = FALCON_TMPSIZE_VERIFY(FF_FALCON_LOGN);
    void *tmp = malloc(tmpsz);
    if (!tmp) return -1;

    int r = falcon_verify(sig, sig_len, FALCON_SIG_CT,
                          pk, pk_len,
                          msg, msg_len,
                          tmp, tmpsz);
    sodium_memzero(tmp, tmpsz);
    free(tmp);
    return (r == 0) ? 0 : -1;
}

void ff_shake256_kdf(const uint8_t *in, size_t in_len,
                     const uint8_t *ctx, size_t ctx_len,
                     uint8_t *out, size_t out_len) {
    shake256_context sc;
    shake256_init(&sc);
    if (ctx && ctx_len) {
        shake256_inject(&sc, ctx, ctx_len);
    }
    shake256_inject(&sc, in, in_len);
    shake256_flip(&sc);
    shake256_extract(&sc, out, out_len);
    sodium_memzero(&sc, sizeof(sc));
}
