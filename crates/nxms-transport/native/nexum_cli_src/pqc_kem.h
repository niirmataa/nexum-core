#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char alg[32];
    uint8_t *pk;
    size_t pk_len;
    uint8_t *sk;
    size_t sk_len;
} ff_kem_keys_t;

int ff_kem_keygen(const char *alg, ff_kem_keys_t *out);
int ff_kem_encaps(const char *alg, const uint8_t *pk, size_t pk_len,
                  uint8_t **ct, size_t *ct_len,
                  uint8_t **ss, size_t *ss_len);
int ff_kem_decaps(const char *alg, const uint8_t *sk, size_t sk_len,
                  const uint8_t *ct, size_t ct_len,
                  uint8_t **ss, size_t *ss_len);
void ff_kem_free(ff_kem_keys_t *k);

#ifdef FF_TEST_HOOKS
void ff_test_kem_hooks_reset(void);
void ff_test_kem_force_failures(int keypair_fail, int encaps_fail, int decaps_fail);
size_t ff_test_kem_cleanse_calls(void);
size_t ff_test_kem_cleanse_total(void);
size_t ff_test_kem_last_cleanse_len(void);
#endif
