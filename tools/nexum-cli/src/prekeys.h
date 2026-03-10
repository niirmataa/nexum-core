#pragma once
#include <stddef.h>
#include <stdint.h>

#define FF_PREKEY_ID_LEN 16
#define FF_PREKEY_FLAG_UPLOADED 0x01
#define FF_PREKEY_FLAG_USED     0x02

typedef struct {
    uint8_t prekey_id[FF_PREKEY_ID_LEN];
    char kem_id[64];

    uint8_t *pk;
    size_t pk_len;
    uint8_t *sk;
    size_t sk_len;

    uint64_t created_at;
    uint64_t expires_at;
    uint8_t flags;
} ff_prekey_entry;

typedef struct {
    ff_prekey_entry *items;
    size_t count;
} ff_prekeys_t;

int ff_prekeys_load(const char *dir, const char *pass, ff_prekeys_t *out);
int ff_prekeys_save(const char *dir, const char *pass, const ff_prekeys_t *st);
void ff_prekeys_free(ff_prekeys_t *st);
