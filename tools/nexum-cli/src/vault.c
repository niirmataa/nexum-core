#include "vault.h"
#include "util.h"
#include "pqc_falcon.h"

#include <sodium.h>

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

#define VAULT_MAGIC "FFV1"
#define SALT_LEN 16
#define NONCE_LEN crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

/* Produkcyjne, rozsądne defaulty dla kontenera.
   Z mocnym passphrase nadal jest OK.
   Jak chcesz mocniej na gołym metal, zrób opcję konfig. */
#define FF_PWHASH_OPSLIMIT crypto_pwhash_OPSLIMIT_INTERACTIVE
#define FF_PWHASH_MEMLIMIT crypto_pwhash_MEMLIMIT_INTERACTIVE
/* Defensive cap against local file-header tampering / OOM attempts. */
#define FF_VAULT_MAX_CT_LEN (16U * 1024U * 1024U)

typedef struct __attribute__((packed)) {
    char magic[4];
    uint8_t salt[SALT_LEN];
    uint64_t opslimit;
    uint64_t memlimit;
    uint8_t nonce[NONCE_LEN];
    uint32_t ct_len;
} vault_hdr_t;

/* TLV types */
#define T_MANIFEST_JSON 1
#define T_MANIFEST_SIG  2
#define T_FALCON_SK     3
#define T_FALCON_PK     4
#define T_KEM_SK        5
#define T_KEM_PK        6
#define T_TOKEN_JSON    7
#define T_SESSION_ID    8
#define T_CSRF_TOKEN    9

static int write_tlv(uint8_t **p, size_t *left, uint16_t t, const uint8_t *v, uint32_t n) {
    if (*left < 6U + (size_t)n) return -1;
    (*p)[0] = (uint8_t)(t & 0xFF);
    (*p)[1] = (uint8_t)((t >> 8) & 0xFF);
    (*p)[2] = (uint8_t)(n & 0xFF);
    (*p)[3] = (uint8_t)((n >> 8) & 0xFF);
    (*p)[4] = (uint8_t)((n >> 16) & 0xFF);
    (*p)[5] = (uint8_t)((n >> 24) & 0xFF);
    memcpy((*p) + 6, v, n);
    *p += 6 + (size_t)n;
    *left -= 6 + (size_t)n;
    return 0;
}

static int read_u16(const uint8_t *p, size_t left, uint16_t *out) {
    if (left < 2) return -1;
    *out = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    return 0;
}

static int read_u32(const uint8_t *p, size_t left, uint32_t *out) {
    if (left < 4) return -1;
    *out = (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
    return 0;
}

static void vault_zero(ff_vault_t *v) {
    memset(v, 0, sizeof(*v));
}

static int vault_paths(const char *dir, char *p_vault, size_t n1) {
    if (snprintf(p_vault, n1, "%s/vault.bin", dir) >= (int)n1) return -1;
    return 0;
}

static int derive_key(uint8_t *key, const vault_hdr_t *h, const char *pass) {
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
        fprintf(stderr, "vault: crypto_pwhash failed (bad passphrase or OOM)\n");
        return -1;
    }
    return 0;
}

int ff_vault_init(const char *dir, const char *pass) {
    if (sodium_init() < 0) return -1;
    if (dir == NULL || pass == NULL) return -1;
    if (strlen(pass) < 12) return -1;

    if (ff_mkdir_p(dir) != 0) return -1;

    char path[4096];
    if (vault_paths(dir, path, sizeof(path)) != 0) return -1;

    vault_hdr_t h;
    memcpy(h.magic, VAULT_MAGIC, 4);
    randombytes_buf(h.salt, sizeof(h.salt));
    h.opslimit = (uint64_t)FF_PWHASH_OPSLIMIT;
    h.memlimit = (uint64_t)FF_PWHASH_MEMLIMIT;
    randombytes_buf(h.nonce, sizeof(h.nonce));

    /* Pusty vault = minimalny plaintext 1 bajt, zaszyfrowany */
    const uint8_t empty = 0;
    uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    if (derive_key(key, &h, pass) != 0) {
        sodium_memzero(key, sizeof(key));
        return -1;
    }

    uint8_t ct[crypto_aead_xchacha20poly1305_ietf_ABYTES + 1];
    unsigned long long ct_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, &ct_len,
            &empty, 1,
            NULL, 0,
            NULL,
            h.nonce, key) != 0) {
        sodium_memzero(key, sizeof(key));
        return -1;
    }
    sodium_memzero(key, sizeof(key));

    h.ct_len = (uint32_t)ct_len;

    size_t blob_len = sizeof(h) + (size_t)ct_len;
    uint8_t *blob = (uint8_t *)malloc(blob_len);
    if (!blob) return -1;

    memcpy(blob, &h, sizeof(h));
    memcpy(blob + sizeof(h), ct, (size_t)ct_len);

    int rc = ff_write_file_atomic(path, blob, blob_len, 0600);
    sodium_memzero(blob, blob_len);
    free(blob);

    return rc;
}

int ff_vault_load(const char *dir, const char *pass, ff_vault_t *out) {
    vault_zero(out);
    if (sodium_init() < 0) return -1;
    if (dir == NULL || pass == NULL || out == NULL) return -1;

    char path[4096];
    if (vault_paths(dir, path, sizeof(path)) != 0) return -1;

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (ff_read_file(path, &blob, &blob_len) != 0) return -1;
    if (blob_len < sizeof(vault_hdr_t)) {
        free(blob);
        return -1;
    }

    vault_hdr_t h;
    memcpy(&h, blob, sizeof(h));

    if (memcmp(h.magic, VAULT_MAGIC, 4) != 0) {
        free(blob);
        return -1;
    }
    if (h.ct_len == 0 || h.ct_len > FF_VAULT_MAX_CT_LEN) {
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

    uint8_t *pt = (uint8_t *)malloc((size_t)h.ct_len);
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
        free(blob);
        free(pt);
        return -1;
    }

    sodium_memzero(key, sizeof(key));
    free(blob);

    /* Parse TLV */
    const uint8_t *p = pt;
    size_t left = (size_t)pt_len;

    char nick[64] = {0};
    char kem_alg[32] = {0};

    uint8_t *manifest_json = NULL;
    uint32_t manifest_json_len = 0;

    while (left > 0) {
        if (left < 6) break;

        uint16_t t;
        uint32_t n;
        if (read_u16(p, left, &t) != 0) break;
        if (read_u32(p + 2, left - 2, &n) != 0) break;
        if (left < 6U + (size_t)n) break;

        const uint8_t *v = p + 6;

        switch (t) {
            case T_MANIFEST_JSON:
                free(manifest_json);
                manifest_json = (uint8_t*)malloc((size_t)n + 1);
                if (manifest_json) {
                    memcpy(manifest_json, v, n);
                    manifest_json[n] = 0;
                    manifest_json_len = n;
                }
                break;

            case T_FALCON_SK:
                if (n <= sizeof(out->falcon_sk)) {
                    memcpy(out->falcon_sk, v, n);
                    out->falcon_sk_len = n;
                }
                break;

            case T_FALCON_PK:
                if (n <= sizeof(out->falcon_pk)) {
                    memcpy(out->falcon_pk, v, n);
                    out->falcon_pk_len = n;
                }
                break;

            case T_KEM_SK:
                if (out->kem_sk) {
                    sodium_memzero(out->kem_sk, out->kem_sk_len);
                    free(out->kem_sk);
                }
                out->kem_sk = (uint8_t*)malloc(n);
                if (out->kem_sk) {
                    memcpy(out->kem_sk, v, n);
                    out->kem_sk_len = n;
                }
                break;

            case T_KEM_PK:
                if (out->kem_pk) free(out->kem_pk);
                out->kem_pk = (uint8_t*)malloc(n);
                if (out->kem_pk) {
                    memcpy(out->kem_pk, v, n);
                    out->kem_pk_len = n;
                }
                break;

            case T_TOKEN_JSON:
                if (out->token) {
                    sodium_memzero(out->token, strlen(out->token));
                    free(out->token);
                }
                out->token = (char*)malloc((size_t)n + 1);
                if (out->token) {
                    memcpy(out->token, v, n);
                    out->token[n] = 0;
                }
                break;

            case T_SESSION_ID:
                if (out->session_id) {
                    sodium_memzero(out->session_id, strlen(out->session_id));
                    free(out->session_id);
                }
                out->session_id = (char*)malloc((size_t)n + 1);
                if (out->session_id) {
                    memcpy(out->session_id, v, n);
                    out->session_id[n] = 0;
                }
                break;

            case T_CSRF_TOKEN:
                if (out->csrf) {
                    sodium_memzero(out->csrf, strlen(out->csrf));
                    free(out->csrf);
                }
                out->csrf = (char*)malloc((size_t)n + 1);
                if (out->csrf) {
                    memcpy(out->csrf, v, n);
                    out->csrf[n] = 0;
                }
                break;

            default:
                break;
        }

        p += 6 + (size_t)n;
        left -= 6 + (size_t)n;
    }

    /* Manifest extraction: nick + kem_alg from JSON parser (jansson) */
    if (manifest_json && manifest_json_len > 0) {
        json_error_t err;
        json_t *root = json_loadb((const char *)manifest_json, (size_t)manifest_json_len, 0, &err);
        if (root && json_is_object(root)) {
            json_t *j_nick = json_object_get(root, "nick");
            if (json_is_string(j_nick)) {
                ff_strlcpy(nick, json_string_value(j_nick), sizeof(nick));
            }

            json_t *j_kem = json_object_get(root, "kem_alg");
            if (json_is_string(j_kem)) {
                ff_strlcpy(kem_alg, json_string_value(j_kem), sizeof(kem_alg));
            }
        }
        if (root) {
            json_decref(root);
        }
    }

    ff_strlcpy(out->nick, nick, sizeof(out->nick));
    ff_strlcpy(out->kem_alg, kem_alg, sizeof(out->kem_alg));

    if (manifest_json) free(manifest_json);

    sodium_memzero(pt, (size_t)pt_len);
    free(pt);

    return 0;
}

int ff_vault_save(const char *dir, const char *pass, const ff_vault_t *v) {
    if (sodium_init() < 0) return -1;
    if (dir == NULL || pass == NULL || v == NULL) return -1;
    if (strlen(pass) < 12) return -1;

    char path[4096];
    if (vault_paths(dir, path, sizeof(path)) != 0) return -1;

    vault_hdr_t h;
    memset(&h, 0, sizeof(h));
    memcpy(h.magic, VAULT_MAGIC, 4);

    /* domyślne, bezpieczne i przewidywalne */
    h.opslimit = (uint64_t)FF_PWHASH_OPSLIMIT;
    h.memlimit = (uint64_t)FF_PWHASH_MEMLIMIT;
    randombytes_buf(h.salt, sizeof(h.salt));
    randombytes_buf(h.nonce, sizeof(h.nonce));

    /* Jeśli vault istnieje, zachowaj salt (żeby pass działał), ale NIE podnoś memlimit/opslimit ponad politykę */
    uint8_t *old = NULL;
    size_t old_len = 0;
    if (ff_read_file(path, &old, &old_len) == 0 && old_len >= sizeof(vault_hdr_t)) {
        vault_hdr_t oh;
        memcpy(&oh, old, sizeof(oh));
        if (memcmp(oh.magic, VAULT_MAGIC, 4) == 0) {
            memcpy(h.salt, oh.salt, sizeof(h.salt));

            if (oh.opslimit > 0 && oh.opslimit <= (uint64_t)FF_PWHASH_OPSLIMIT) {
                h.opslimit = oh.opslimit;
            }
            if (oh.memlimit > 0 && oh.memlimit <= (uint64_t)FF_PWHASH_MEMLIMIT) {
                h.memlimit = oh.memlimit;
            }
        }
        free(old);
    }

    /* Manifest JSON */
    char manifest[512];
    snprintf(manifest, sizeof(manifest),
             "{\"v\":1,\"nick\":\"%s\",\"sig_alg\":\"falcon1024-ct\",\"kem_alg\":\"%s\"}",
             v->nick,
             v->kem_alg[0] ? v->kem_alg : "ntru-hrss701");

    uint8_t sig_buf[2048];
    size_t sig_len = sizeof(sig_buf);
    int have_sig = 0;

    if (v->falcon_sk_len > 0) {
        if (ff_falcon_sign_ct(
                v->falcon_sk, v->falcon_sk_len,
                (const uint8_t*)manifest, strlen(manifest),
                sig_buf, &sig_len) == 0) {
            have_sig = 1;
        }
    }
    if (!have_sig) {
        sig_buf[0] = 0;
        sig_len = 1;
    }

    /* TLV size upper bound */
    size_t pt_cap = 4096
              + v->falcon_sk_len + v->falcon_pk_len
              + v->kem_sk_len + v->kem_pk_len;
    if (v->token) pt_cap += strlen(v->token) + 64;
    if (v->session_id) pt_cap += strlen(v->session_id) + 64;
    if (v->csrf) pt_cap += strlen(v->csrf) + 64;

    uint8_t *pt = (uint8_t*)malloc(pt_cap);
    if (!pt) return -1;

    uint8_t *p = pt;
    size_t left = pt_cap;

    if (write_tlv(&p, &left, T_MANIFEST_JSON, (const uint8_t*)manifest, (uint32_t)strlen(manifest)) != 0) {
        free(pt);
        return -1;
    }
    if (write_tlv(&p, &left, T_MANIFEST_SIG, sig_buf, (uint32_t)sig_len) != 0) {
        free(pt);
        return -1;
    }
    if (v->falcon_sk_len) {
        if (write_tlv(&p, &left, T_FALCON_SK, v->falcon_sk, (uint32_t)v->falcon_sk_len) != 0) {
            free(pt);
            return -1;
        }
    }
    if (v->falcon_pk_len) {
        if (write_tlv(&p, &left, T_FALCON_PK, v->falcon_pk, (uint32_t)v->falcon_pk_len) != 0) {
            free(pt);
            return -1;
        }
    }
    if (v->kem_sk && v->kem_sk_len) {
        if (write_tlv(&p, &left, T_KEM_SK, v->kem_sk, (uint32_t)v->kem_sk_len) != 0) {
            free(pt);
            return -1;
        }
    }
    if (v->kem_pk && v->kem_pk_len) {
        if (write_tlv(&p, &left, T_KEM_PK, v->kem_pk, (uint32_t)v->kem_pk_len) != 0) {
            free(pt);
            return -1;
        }
    }
    if (v->token) {
        if (write_tlv(&p, &left, T_TOKEN_JSON, (const uint8_t*)v->token, (uint32_t)strlen(v->token)) != 0) {
            free(pt);
            return -1;
        }
    }
    if (v->session_id) {
        if (write_tlv(&p, &left, T_SESSION_ID, (const uint8_t*)v->session_id, (uint32_t)strlen(v->session_id)) != 0) {
            free(pt);
            return -1;
        }
    }
    if (v->csrf) {
        if (write_tlv(&p, &left, T_CSRF_TOKEN, (const uint8_t*)v->csrf, (uint32_t)strlen(v->csrf)) != 0) {
            free(pt);
            return -1;
        }
    }

    size_t pt_len = pt_cap - left;

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
    randombytes_buf(h.nonce, sizeof(h.nonce));

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, &ct_len,
            pt, (unsigned long long)pt_len,
            NULL, 0,
            NULL,
            h.nonce, key) != 0) {
        sodium_memzero(pt, pt_len);
        free(pt);
        sodium_memzero(key, sizeof(key));
        sodium_memzero(ct, ct_cap);
        free(ct);
        return -1;
    }

    sodium_memzero(key, sizeof(key));
    sodium_memzero(pt, pt_len);
    free(pt);

    h.ct_len = (uint32_t)ct_len;

    size_t blob_len = sizeof(h) + (size_t)ct_len;
    uint8_t *blob = (uint8_t*)malloc(blob_len);
    if (!blob) {
        sodium_memzero(ct, ct_cap);
        free(ct);
        return -1;
    }

    memcpy(blob, &h, sizeof(h));
    memcpy(blob + sizeof(h), ct, (size_t)ct_len);

    sodium_memzero(ct, ct_cap);
    free(ct);

    int rc = ff_write_file_atomic(path, blob, blob_len, 0600);
    sodium_memzero(blob, blob_len);
    free(blob);

    return rc;
}

void ff_vault_free(ff_vault_t *v) {
    if (!v) return;

    if (v->kem_sk) {
        sodium_memzero(v->kem_sk, v->kem_sk_len);
        free(v->kem_sk);
        v->kem_sk = NULL;
        v->kem_sk_len = 0;
    }
    if (v->kem_pk) {
        free(v->kem_pk);
        v->kem_pk = NULL;
        v->kem_pk_len = 0;
    }
    if (v->token) {
        sodium_memzero(v->token, strlen(v->token));
        free(v->token);
        v->token = NULL;
    }
    if (v->session_id) {
        sodium_memzero(v->session_id, strlen(v->session_id));
        free(v->session_id);
        v->session_id = NULL;
    }
    if (v->csrf) {
        sodium_memzero(v->csrf, strlen(v->csrf));
        free(v->csrf);
        v->csrf = NULL;
    }

    sodium_memzero(v->falcon_sk, sizeof(v->falcon_sk));
    sodium_memzero(v->falcon_pk, sizeof(v->falcon_pk));
    memset(v, 0, sizeof(*v));
}
