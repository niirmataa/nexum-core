#include "prekeys.h"
#include "util.h"

#include <sodium.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PREKEYS_MAGIC "FFP1"
#define SALT_LEN 16
#define NONCE_LEN crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

#define FF_PWHASH_OPSLIMIT crypto_pwhash_OPSLIMIT_INTERACTIVE
#define FF_PWHASH_MEMLIMIT crypto_pwhash_MEMLIMIT_INTERACTIVE
/* Defensive cap against local file-header tampering / OOM attempts. */
#define FF_PREKEYS_MAX_CT_LEN (128U * 1024U * 1024U)

typedef struct __attribute__((packed)) {
    char magic[4];
    uint8_t salt[SALT_LEN];
    uint64_t opslimit;
    uint64_t memlimit;
    uint8_t nonce[NONCE_LEN];
    uint32_t ct_len;
} prekeys_hdr_t;

static int prekeys_path(const char *dir, char *out, size_t n) {
    if (snprintf(out, n, "%s/prekeys.bin", dir) >= (int)n) return -1;
    return 0;
}

static int read_u16(const uint8_t *p, size_t left, uint16_t *out) {
    if (left < 2) return -1;
    *out = (uint16_t)p[0] << 8 | (uint16_t)p[1];
    return 0;
}

static int read_u32(const uint8_t *p, size_t left, uint32_t *out) {
    if (left < 4) return -1;
    *out = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
    return 0;
}

static int read_u64(const uint8_t *p, size_t left, uint64_t *out) {
    if (left < 8) return -1;
    *out = (uint64_t)p[0] << 56 | (uint64_t)p[1] << 48 | (uint64_t)p[2] << 40 | (uint64_t)p[3] << 32 |
           (uint64_t)p[4] << 24 | (uint64_t)p[5] << 16 | (uint64_t)p[6] << 8 | (uint64_t)p[7];
    return 0;
}

static int derive_key(uint8_t *key, const prekeys_hdr_t *h, const char *pass) {
    if (pass == NULL) return -1;
    size_t pass_len = strlen(pass);
    if (pass_len < 12) return -1;

    if (crypto_pwhash(
            key,
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
            pass,
            pass_len,
            h->salt,
            (unsigned long long)h->opslimit,
            (size_t)h->memlimit,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        fprintf(stderr, "prekeys: crypto_pwhash failed (bad passphrase or OOM)\n");
        return -1;
    }
    return 0;
}

void ff_prekeys_free(ff_prekeys_t *st) {
    if (!st || !st->items) return;
    for (size_t i = 0; i < st->count; i++) {
        ff_prekey_entry *e = &st->items[i];
        if (e->sk) {
            sodium_memzero(e->sk, e->sk_len);
            free(e->sk);
        }
        if (e->pk) {
            free(e->pk);
        }
        memset(e, 0, sizeof(*e));
    }
    free(st->items);
    st->items = NULL;
    st->count = 0;
}

int ff_prekeys_load(const char *dir, const char *pass, ff_prekeys_t *out) {
    if (!dir || !pass || !out) return -1;
    if (sodium_init() < 0) return -1;

    out->items = NULL;
    out->count = 0;

    char path[4096];
    if (prekeys_path(dir, path, sizeof(path)) != 0) return -1;

    if (access(path, F_OK) != 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (ff_read_file(path, &blob, &blob_len) != 0) return -1;
    if (blob_len < sizeof(prekeys_hdr_t)) {
        free(blob);
        return -1;
    }

    prekeys_hdr_t h;
    memcpy(&h, blob, sizeof(h));
    if (memcmp(h.magic, PREKEYS_MAGIC, 4) != 0) {
        free(blob);
        return -1;
    }
    if (h.ct_len == 0 || h.ct_len > FF_PREKEYS_MAX_CT_LEN) {
        free(blob);
        return -1;
    }
    if (blob_len != sizeof(h) + (size_t)h.ct_len) {
        free(blob);
        return -1;
    }

    const uint8_t *ct = blob + sizeof(h);
    uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if (derive_key(key, &h, pass) != 0) {
        sodium_memzero(key, sizeof(key));
        free(blob);
        return -1;
    }

    uint8_t *pt = (uint8_t*)malloc((size_t)h.ct_len);
    if (!pt) {
        sodium_memzero(key, sizeof(key));
        free(blob);
        return -1;
    }

    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt, &pt_len,
            NULL,
            ct, (unsigned long long)h.ct_len,
            NULL, 0,
            h.nonce, key) != 0) {
        sodium_memzero(key, sizeof(key));
        sodium_memzero(pt, (size_t)h.ct_len);
        free(pt);
        free(blob);
        return -1;
    }
    sodium_memzero(key, sizeof(key));
    free(blob);

    const uint8_t *p = pt;
    size_t left = (size_t)pt_len;
    uint32_t count = 0;
    if (read_u32(p, left, &count) != 0) goto fail;
    p += 4; left -= 4;
    if (count > 10000) goto fail;

    ff_prekey_entry *items = (ff_prekey_entry*)calloc(count, sizeof(ff_prekey_entry));
    if (!items && count > 0) goto fail;

    uint32_t parsed = 0;
    uint64_t now = (uint64_t)time(NULL);
    ff_prekey_entry tmp;
    memset(&tmp, 0, sizeof(tmp));
    for (uint32_t i = 0; i < count; i++) {
        memset(&tmp, 0, sizeof(tmp));
        if (left < FF_PREKEY_ID_LEN) goto fail_items;
        memcpy(tmp.prekey_id, p, FF_PREKEY_ID_LEN);
        p += FF_PREKEY_ID_LEN; left -= FF_PREKEY_ID_LEN;

        uint16_t kem_len = 0;
        if (read_u16(p, left, &kem_len) != 0) goto fail_items;
        p += 2; left -= 2;
        if (kem_len == 0 || kem_len >= sizeof(tmp.kem_id) || left < kem_len) goto fail_items;
        memcpy(tmp.kem_id, p, kem_len);
        tmp.kem_id[kem_len] = 0;
        p += kem_len; left -= kem_len;

        uint32_t pk_len = 0;
        if (read_u32(p, left, &pk_len) != 0) goto fail_items;
        p += 4; left -= 4;
        if (left < pk_len) goto fail_items;
        tmp.pk = (uint8_t*)malloc(pk_len ? pk_len : 1);
        if (!tmp.pk) goto fail_items;
        memcpy(tmp.pk, p, pk_len);
        tmp.pk_len = pk_len;
        p += pk_len; left -= pk_len;

        uint32_t sk_len = 0;
        if (read_u32(p, left, &sk_len) != 0) goto fail_items;
        p += 4; left -= 4;
        if (left < sk_len) goto fail_items;
        tmp.sk = (uint8_t*)malloc(sk_len ? sk_len : 1);
        if (!tmp.sk) goto fail_items;
        memcpy(tmp.sk, p, sk_len);
        tmp.sk_len = sk_len;
        p += sk_len; left -= sk_len;

        uint64_t created_at = 0;
        if (read_u64(p, left, &created_at) != 0) goto fail_items;
        p += 8; left -= 8;
        uint64_t expires_at = 0;
        if (read_u64(p, left, &expires_at) != 0) goto fail_items;
        p += 8; left -= 8;
        if (left < 1) goto fail_items;
        tmp.created_at = created_at;
        tmp.expires_at = expires_at;
        tmp.flags = p[0];
        p += 1; left -= 1;

        if (tmp.expires_at && tmp.expires_at <= now) {
            if (tmp.sk) {
                sodium_memzero(tmp.sk, tmp.sk_len);
                free(tmp.sk);
            }
            if (tmp.pk) free(tmp.pk);
            continue;
        }

        items[parsed++] = tmp;
    }

    if (parsed != count) {
        ff_prekey_entry *shrunk = (ff_prekey_entry*)realloc(items, parsed * sizeof(*items));
        if (shrunk || parsed == 0) items = shrunk;
    }

    out->items = items;
    out->count = parsed;
    sodium_memzero(pt, (size_t)pt_len);
    free(pt);
    return 0;

fail_items:
    if (tmp.sk) {
        sodium_memzero(tmp.sk, tmp.sk_len);
        free(tmp.sk);
    }
    if (tmp.pk) free(tmp.pk);
    if (items) {
        ff_prekeys_t tmp2 = { .items = items, .count = parsed };
        ff_prekeys_free(&tmp2);
    }
fail:
    sodium_memzero(pt, (size_t)pt_len);
    free(pt);
    return -1;
}

int ff_prekeys_save(const char *dir, const char *pass, const ff_prekeys_t *st) {
    if (!dir || !pass || !st) return -1;
    if (sodium_init() < 0) return -1;
    if (strlen(pass) < 12) return -1;
    if (ff_mkdir_p(dir) != 0) return -1;

    char path[4096];
    if (prekeys_path(dir, path, sizeof(path)) != 0) return -1;

    prekeys_hdr_t h;
    memset(&h, 0, sizeof(h));
    memcpy(h.magic, PREKEYS_MAGIC, 4);
    h.opslimit = (uint64_t)FF_PWHASH_OPSLIMIT;
    h.memlimit = (uint64_t)FF_PWHASH_MEMLIMIT;
    randombytes_buf(h.salt, sizeof(h.salt));
    randombytes_buf(h.nonce, sizeof(h.nonce));

    uint8_t *old = NULL;
    size_t old_len = 0;
    if (ff_read_file(path, &old, &old_len) == 0 && old_len >= sizeof(prekeys_hdr_t)) {
        prekeys_hdr_t oh;
        memcpy(&oh, old, sizeof(oh));
        if (memcmp(oh.magic, PREKEYS_MAGIC, 4) == 0) {
            memcpy(h.salt, oh.salt, sizeof(h.salt));
            if (oh.opslimit > 0 && oh.opslimit <= (uint64_t)FF_PWHASH_OPSLIMIT) h.opslimit = oh.opslimit;
            if (oh.memlimit > 0 && oh.memlimit <= (uint64_t)FF_PWHASH_MEMLIMIT) h.memlimit = oh.memlimit;
        }
        free(old);
    }

    size_t pt_len = 4;
    for (size_t i = 0; i < st->count; i++) {
        const ff_prekey_entry *e = &st->items[i];
        size_t kem_len = strnlen(e->kem_id, sizeof(e->kem_id));
        pt_len += FF_PREKEY_ID_LEN + 2 + kem_len + 4 + e->pk_len + 4 + e->sk_len + 8 + 8 + 1;
    }

    uint8_t *pt = (uint8_t*)malloc(pt_len ? pt_len : 1);
    if (!pt) return -1;

    uint8_t *p = pt;
    size_t left = pt_len;
    if (left < 4) { free(pt); return -1; }
    ff_u32be((uint32_t)st->count, p);
    p += 4; left -= 4;

    for (size_t i = 0; i < st->count; i++) {
        const ff_prekey_entry *e = &st->items[i];
        size_t kem_len = strnlen(e->kem_id, sizeof(e->kem_id));
        if (left < FF_PREKEY_ID_LEN + 2 + kem_len + 4 + e->pk_len + 4 + e->sk_len + 8 + 8 + 1) {
            sodium_memzero(pt, pt_len);
            free(pt);
            return -1;
        }
        memcpy(p, e->prekey_id, FF_PREKEY_ID_LEN);
        p += FF_PREKEY_ID_LEN; left -= FF_PREKEY_ID_LEN;

        ff_u16be((uint16_t)kem_len, p);
        p += 2; left -= 2;
        memcpy(p, e->kem_id, kem_len);
        p += kem_len; left -= kem_len;

        ff_u32be((uint32_t)e->pk_len, p);
        p += 4; left -= 4;
        memcpy(p, e->pk, e->pk_len);
        p += e->pk_len; left -= e->pk_len;

        ff_u32be((uint32_t)e->sk_len, p);
        p += 4; left -= 4;
        memcpy(p, e->sk, e->sk_len);
        p += e->sk_len; left -= e->sk_len;

        ff_u64be(e->created_at, p);
        p += 8; left -= 8;
        ff_u64be(e->expires_at, p);
        p += 8; left -= 8;

        *p++ = e->flags;
        left -= 1;
    }

    uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if (derive_key(key, &h, pass) != 0) {
        sodium_memzero(pt, pt_len);
        free(pt);
        sodium_memzero(key, sizeof(key));
        return -1;
    }

    size_t ct_cap = pt_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    uint8_t *ct = (uint8_t*)malloc(ct_cap);
    if (!ct) {
        sodium_memzero(pt, pt_len);
        free(pt);
        sodium_memzero(key, sizeof(key));
        return -1;
    }

    unsigned long long ct_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, &ct_len,
            pt, (unsigned long long)pt_len,
            NULL, 0,
            NULL,
            h.nonce, key) != 0) {
        sodium_memzero(pt, pt_len);
        free(pt);
        sodium_memzero(ct, ct_cap);
        free(ct);
        sodium_memzero(key, sizeof(key));
        return -1;
    }
    sodium_memzero(pt, pt_len);
    free(pt);
    sodium_memzero(key, sizeof(key));

    h.ct_len = (uint32_t)ct_len;
    size_t blob_len = sizeof(h) + (size_t)ct_len;
    uint8_t *blob = (uint8_t*)malloc(blob_len);
    if (!blob) {
        sodium_memzero(ct, ct_len);
        free(ct);
        return -1;
    }
    memcpy(blob, &h, sizeof(h));
    memcpy(blob + sizeof(h), ct, (size_t)ct_len);
    sodium_memzero(ct, ct_len);
    free(ct);

    int rc = ff_write_file_atomic(path, blob, blob_len, 0600);
    sodium_memzero(blob, blob_len);
    free(blob);
    return rc;
}
