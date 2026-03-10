#include "pow.h"
#include "util.h"

#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int leading_zero_bits(const uint8_t d[32]) {
    int n = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t b = d[i];
        if (b == 0) { n += 8; continue; }
        for (int bit = 7; bit >= 0; bit--) {
            if (((b >> bit) & 1) == 0) n++;
            else return n;
        }
    }
    return n;
}

int ff_pow_solve(const char *token_b64u, const char *purpose, const char *nick,
                 int difficulty, uint64_t start_nonce, uint64_t *found_nonce) {
    if (!token_b64u || !purpose || !nick || !found_nonce) return -1;

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (ff_b64u_dec(token_b64u, &raw, &raw_len) != 0) return -1;
    if (raw_len != 64) { free(raw); return -1; }

    const uint8_t *payload = raw; /* first 32 bytes: ts|exp|rnd */

    crypto_hash_sha256_state st;
    uint8_t digest[32];
    uint8_t nb[8];

    for (uint64_t nonce = start_nonce; ; nonce++) {
        ff_u64be(nonce, nb);

        crypto_hash_sha256_init(&st);
        crypto_hash_sha256_update(&st, payload, 32);

        crypto_hash_sha256_update(&st, (const unsigned char*)"\0", 1);
        crypto_hash_sha256_update(&st, (const unsigned char*)purpose, strlen(purpose));

        crypto_hash_sha256_update(&st, (const unsigned char*)"\0", 1);
        crypto_hash_sha256_update(&st, (const unsigned char*)nick, strlen(nick));

        crypto_hash_sha256_update(&st, (const unsigned char*)"\0", 1);
        crypto_hash_sha256_update(&st, nb, 8);

        crypto_hash_sha256_final(&st, digest);

        if (leading_zero_bits(digest) >= difficulty) {
            *found_nonce = nonce;
            sodium_memzero(digest, sizeof(digest));
            sodium_memzero(nb, sizeof(nb));
            sodium_memzero(raw, raw_len);
            free(raw);
            return 0;
        }
    }
}
