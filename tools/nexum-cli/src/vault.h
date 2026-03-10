#pragma once
#include <stddef.h>
#include <stdint.h>

// Simple encrypted vault storing PQ keys.

typedef struct {
    uint8_t falcon_sk[2305]; // FALCON_PRIVKEY_SIZE(10)
    uint8_t falcon_pk[1793]; // FALCON_PUBKEY_SIZE(10)
    size_t falcon_sk_len;
    size_t falcon_pk_len;

    uint8_t *kem_sk;
    size_t kem_sk_len;
    uint8_t *kem_pk;
    size_t kem_pk_len;

    char nick[64];
    char kem_alg[32];

    char *token; // optional, malloc
    char *session_id; // optional, malloc (Bearer)
    char *csrf; // optional, malloc
} ff_vault_t;

int ff_vault_init(const char *dir, const char *pass);
int ff_vault_load(const char *dir, const char *pass, ff_vault_t *out);
int ff_vault_save(const char *dir, const char *pass, const ff_vault_t *v);
void ff_vault_free(ff_vault_t *v);
