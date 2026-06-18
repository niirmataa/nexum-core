#include "pqc_falcon.h"
#include "util.h"

#include <string.h>
#include <stdlib.h>
#include <sodium.h>

#include "../vendor/falcon/falcon.h"
#include "../vendor/falcon/shake.h"

int ff_falcon_keygen(uint8_t *sk, size_t *sk_len, uint8_t *pk, size_t *pk_len) {
    falcon_keygen *fk = falcon_keygen_new(FF_FALCON_LOGN, FF_FALCON_TERNARY);
    if (!fk) return -1;

    size_t sk_max = falcon_keygen_max_privkey_size(fk);
    size_t pk_max = falcon_keygen_max_pubkey_size(fk);

    if (sk_max > FF_FALCON_SK_MAX || pk_max > FF_FALCON_PK_MAX) {
        falcon_keygen_free(fk);
        return -1;
    }

    size_t sk_out_len = sk_max;
    size_t pk_out_len = pk_max;

    int r = falcon_keygen_make(fk, FALCON_COMP_STATIC,
                               sk, &sk_out_len,
                               pk, &pk_out_len);
    falcon_keygen_free(fk);
    if (r != 1) return -1;

    *sk_len = sk_out_len;
    *pk_len = pk_out_len;
    return 0;
}

int ff_falcon_sign_ct(const uint8_t *sk, size_t sk_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t *sig, size_t *sig_len) {
    falcon_sign *fs = falcon_sign_new();
    if (!fs) return -1;

    if (falcon_sign_set_private_key(fs, sk, sk_len) != 1) {
        falcon_sign_free(fs);
        return -1;
    }

    uint8_t nonce[40];
    randombytes_buf(nonce, sizeof(nonce));

    falcon_sign_start_external_nonce(fs, nonce, sizeof(nonce));
    falcon_sign_update(fs, msg, msg_len);

    // sig blob = nonce(40) || encoded_signature
    size_t sig_max = *sig_len;
    if (sig_max < 41) {
        falcon_sign_free(fs);
        return -1;
    }

    size_t out_len = falcon_sign_generate(fs, sig + 40, sig_max - 40, FALCON_COMP_STATIC);
    falcon_sign_free(fs);

    if (out_len == 0) return -1;

    // Prepend nonce to signature
    memcpy(sig, nonce, 40);
    *sig_len = 40 + out_len;
    return 0;
}

int ff_falcon_verify(const uint8_t *pk, size_t pk_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *sig, size_t sig_len) {
    if (sig_len < 41) return -1;

    falcon_vrfy *fv = falcon_vrfy_new();
    if (!fv) return -1;

    if (falcon_vrfy_set_public_key(fv, pk, pk_len) != 1) {
        falcon_vrfy_free(fv);
        return -1;
    }

    // Extract nonce from first 40 bytes of sig blob
    falcon_vrfy_start(fv, sig, 40);
    falcon_vrfy_update(fv, msg, msg_len);

    int rc = falcon_vrfy_verify(fv, sig + 40, sig_len - 40);
    falcon_vrfy_free(fv);

    return (rc == 1) ? 0 : -1;
}

void ff_shake256_kdf(const uint8_t *in, size_t in_len,
                     const uint8_t *ctx, size_t ctx_len,
                     uint8_t *out, size_t out_len) {
    shake_context sc;
    shake_init(&sc, 512);
    if (ctx && ctx_len) {
        shake_inject(&sc, ctx, ctx_len);
    }
    shake_inject(&sc, in, in_len);
    shake_flip(&sc);
    shake_extract(&sc, out, out_len);
    sodium_memzero(&sc, sizeof(sc));
}
