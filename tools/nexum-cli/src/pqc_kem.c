#include "pqc_kem.h"
#include "util.h"

#include <oqs/oqs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef FF_TEST_HOOKS
static size_t g_test_cleanse_calls = 0;
static size_t g_test_cleanse_total = 0;
static size_t g_test_last_cleanse_len = 0;
static int g_test_force_keypair_fail = 0;
static int g_test_force_encaps_fail = 0;
static int g_test_force_decaps_fail = 0;

void ff_test_kem_hooks_reset(void) {
    g_test_cleanse_calls = 0;
    g_test_cleanse_total = 0;
    g_test_last_cleanse_len = 0;
    g_test_force_keypair_fail = 0;
    g_test_force_encaps_fail = 0;
    g_test_force_decaps_fail = 0;
}

void ff_test_kem_force_failures(int keypair_fail, int encaps_fail, int decaps_fail) {
    g_test_force_keypair_fail = keypair_fail ? 1 : 0;
    g_test_force_encaps_fail = encaps_fail ? 1 : 0;
    g_test_force_decaps_fail = decaps_fail ? 1 : 0;
}

size_t ff_test_kem_cleanse_calls(void) { return g_test_cleanse_calls; }
size_t ff_test_kem_cleanse_total(void) { return g_test_cleanse_total; }
size_t ff_test_kem_last_cleanse_len(void) { return g_test_last_cleanse_len; }
#endif

static void kem_secret_free(uint8_t **p, size_t *len) {
    if (!p || !*p) {
        if (len) *len = 0;
        return;
    }
    size_t n = len ? *len : 0;
#ifdef FF_TEST_HOOKS
    g_test_cleanse_calls++;
    g_test_cleanse_total += n;
    g_test_last_cleanse_len = n;
#endif
    if (n > 0) OQS_MEM_cleanse(*p, n);
    free(*p);
    *p = NULL;
    if (len) *len = 0;
}

static int kem_check(const OQS_KEM *kem, const uint8_t *pk, size_t pk_len, const uint8_t *sk, size_t sk_len) {
    if (!kem) return -1;
    if (pk && pk_len != kem->length_public_key) return -1;
    if (sk && sk_len != kem->length_secret_key) return -1;
    return 0;
}

int ff_kem_keygen(const char *alg, ff_kem_keys_t *out) {
    memset(out, 0, sizeof(*out));
    ff_strlcpy(out->alg, alg, sizeof(out->alg));

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) return -1;

    out->pk_len = kem->length_public_key;
    out->sk_len = kem->length_secret_key;
    out->pk = (uint8_t*)malloc(out->pk_len);
    out->sk = (uint8_t*)malloc(out->sk_len);
    if (!out->pk || !out->sk) {
        OQS_KEM_free(kem);
        free(out->pk);
        out->pk = NULL;
        out->pk_len = 0;
        kem_secret_free(&out->sk, &out->sk_len);
        memset(out, 0, sizeof(*out));
        return -1;
    }

    int force_keypair_fail = 0;
#ifdef FF_TEST_HOOKS
    if (g_test_force_keypair_fail) {
        force_keypair_fail = 1;
        g_test_force_keypair_fail = 0;
    }
#endif
    if (force_keypair_fail || OQS_KEM_keypair(kem, out->pk, out->sk) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        free(out->pk);
        out->pk = NULL;
        out->pk_len = 0;
        kem_secret_free(&out->sk, &out->sk_len);
        memset(out, 0, sizeof(*out));
        return -1;
    }

    OQS_KEM_free(kem);
    return 0;
}

int ff_kem_encaps(const char *alg, const uint8_t *pk, size_t pk_len,
                  uint8_t **ct, size_t *ct_len,
                  uint8_t **ss, size_t *ss_len) {
    *ct = NULL; *ss = NULL; *ct_len = 0; *ss_len = 0;
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) return -1;
    if (kem_check(kem, pk, pk_len, NULL, 0) != 0) { OQS_KEM_free(kem); return -1; }

    *ct_len = kem->length_ciphertext;
    *ss_len = kem->length_shared_secret;
    *ct = (uint8_t*)malloc(*ct_len);
    *ss = (uint8_t*)malloc(*ss_len);
    if (!*ct || !*ss) {
        OQS_KEM_free(kem);
        free(*ct);
        *ct = NULL;
        *ct_len = 0;
        kem_secret_free(ss, ss_len);
        return -1;
    }

    int force_encaps_fail = 0;
#ifdef FF_TEST_HOOKS
    if (g_test_force_encaps_fail) {
        force_encaps_fail = 1;
        g_test_force_encaps_fail = 0;
    }
#endif
    if (force_encaps_fail || OQS_KEM_encaps(kem, *ct, *ss, pk) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        free(*ct);
        *ct = NULL;
        *ct_len = 0;
        kem_secret_free(ss, ss_len);
        return -1;
    }

    OQS_KEM_free(kem);
    return 0;
}

int ff_kem_decaps(const char *alg, const uint8_t *sk, size_t sk_len,
                  const uint8_t *ct, size_t ct_len,
                  uint8_t **ss, size_t *ss_len) {
    *ss = NULL; *ss_len = 0;
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) return -1;
    if (kem_check(kem, NULL, 0, sk, sk_len) != 0) { OQS_KEM_free(kem); return -1; }
    if (ct_len != kem->length_ciphertext) { OQS_KEM_free(kem); return -1; }

    *ss_len = kem->length_shared_secret;
    *ss = (uint8_t*)malloc(*ss_len);
    if (!*ss) { OQS_KEM_free(kem); return -1; }

    int force_decaps_fail = 0;
#ifdef FF_TEST_HOOKS
    if (g_test_force_decaps_fail) {
        force_decaps_fail = 1;
        g_test_force_decaps_fail = 0;
    }
#endif
    if (force_decaps_fail || OQS_KEM_decaps(kem, *ss, ct, sk) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        kem_secret_free(ss, ss_len);
        return -1;
    }

    OQS_KEM_free(kem);
    return 0;
}

void ff_kem_free(ff_kem_keys_t *k) {
    if (!k) return;
    kem_secret_free(&k->sk, &k->sk_len);
    if (k->pk) {
        free(k->pk);
        k->pk = NULL;
        k->pk_len = 0;
    }
    memset(k, 0, sizeof(*k));
}
