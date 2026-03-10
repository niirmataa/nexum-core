#include "dm.h"
#include "pqc_kem.h"
#include "pqc_falcon.h"
#include "util.h"

#include <sodium.h>

#include <stdlib.h>
#include <string.h>

static const uint8_t DM_AAD_PREFIX[] = "FF-DM-v1";
static const uint8_t DM_SIG_PREFIX[] = "FF-DM-SIG-v1";

static void xor_bytes(uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) a[i] ^= b[i];
}

static int build_aad(const char *sender_nick, const char *to_nick, const char *kem_id,
                     const uint8_t *prekey_id_raw, size_t prekey_id_len,
                     const uint8_t *ct, size_t ct_len,
                     uint8_t **out, size_t *out_len) {
    if (!sender_nick || !to_nick || !kem_id || !prekey_id_raw || prekey_id_len != 16 || !ct) return -1;
    uint8_t ct_hash[32];
    crypto_hash_sha256(ct_hash, ct, (unsigned long long)ct_len);

    size_t sender_len = strlen(sender_nick);
    size_t to_len = strlen(to_nick);
    size_t kem_len = strlen(kem_id);
    size_t prefix_len = sizeof(DM_AAD_PREFIX) - 1;
    size_t len = prefix_len + 1 + sender_len + 1 + to_len + 1 + prekey_id_len + 1 + kem_len + 1 + sizeof(ct_hash);

    uint8_t *buf = (uint8_t*)malloc(len);
    if (!buf) return -1;

    uint8_t *p = buf;
    memcpy(p, DM_AAD_PREFIX, prefix_len); p += prefix_len;
    *p++ = 0;
    memcpy(p, sender_nick, sender_len); p += sender_len;
    *p++ = 0;
    memcpy(p, to_nick, to_len); p += to_len;
    *p++ = 0;
    memcpy(p, prekey_id_raw, prekey_id_len); p += prekey_id_len;
    *p++ = 0;
    memcpy(p, kem_id, kem_len); p += kem_len;
    *p++ = 0;
    memcpy(p, ct_hash, sizeof(ct_hash)); p += sizeof(ct_hash);

    sodium_memzero(ct_hash, sizeof(ct_hash));
    *out = buf;
    *out_len = len;
    return 0;
}

int ff_dm_encrypt_packet(const char *sender_nick,
                         const char *to_nick,
                         const char *kem_id,
                         const uint8_t *prekey_id_raw, size_t prekey_id_len,
                         const uint8_t *pk_ot, size_t pk_ot_len,
                         const uint8_t *sender_sk_sig, size_t sender_sk_sig_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t **ct, size_t *ct_len,
                         uint8_t **dm_nonce, size_t *dm_nonce_len,
                         uint8_t **ciphertext, size_t *ciphertext_len,
                         uint8_t **tag, size_t *tag_len,
                         uint8_t **sig, size_t *sig_len) {
    if (!sender_nick || !to_nick || !kem_id || !prekey_id_raw || prekey_id_len != 16 ||
        !pk_ot || !sender_sk_sig || !ct || !ct_len || !dm_nonce || !dm_nonce_len ||
        !ciphertext || !ciphertext_len || !tag || !tag_len || !sig || !sig_len) {
        return -1;
    }

    *ct = NULL; *ct_len = 0;
    *dm_nonce = NULL; *dm_nonce_len = 0;
    *ciphertext = NULL; *ciphertext_len = 0;
    *tag = NULL; *tag_len = 0;
    *sig = NULL; *sig_len = 0;

    uint8_t *ct_loc = NULL;
    uint8_t *ss = NULL;
    size_t ct_loc_len = 0, ss_len = 0;
    if (ff_kem_encaps(kem_id, pk_ot, pk_ot_len, &ct_loc, &ct_loc_len, &ss, &ss_len) != 0) return -1;

    uint8_t ke[32], km[32];
    size_t tmp_len = ss_len + prekey_id_len + 5;
    uint8_t *tmp = (uint8_t*)malloc(tmp_len);
    if (!tmp) { free(ct_loc); free(ss); return -1; }
    memcpy(tmp, ss, ss_len);
    memcpy(tmp + ss_len, prekey_id_raw, prekey_id_len);
    memcpy(tmp + ss_len + prekey_id_len, "dm-ke", 5);
    ff_shake256_kdf(tmp, ss_len + prekey_id_len + 5, NULL, 0, ke, sizeof(ke));
    memcpy(tmp + ss_len + prekey_id_len, "dm-km", 5);
    ff_shake256_kdf(tmp, ss_len + prekey_id_len + 5, NULL, 0, km, sizeof(km));
    sodium_memzero(tmp, tmp_len);
    free(tmp);

    int enc_ret = -1;
    uint8_t *nonce = NULL, *ctext = NULL, *aad = NULL;
    uint8_t *tag_loc = NULL, *sig_msg = NULL, *sig_loc = NULL;

    nonce = (uint8_t*)malloc(16);
    if (!nonce) { free(ct_loc); sodium_memzero(ss, ss_len); free(ss); goto encrypt_out; }
    randombytes_buf(nonce, 16);

    ctext = (uint8_t*)malloc(plaintext_len ? plaintext_len : 1);
    if (!ctext) { free(nonce); nonce = NULL; free(ct_loc); sodium_memzero(ss, ss_len); free(ss); goto encrypt_out; }
    memcpy(ctext, plaintext, plaintext_len);

    {
        uint8_t *stream = (uint8_t*)malloc(plaintext_len ? plaintext_len : 1);
        if (!stream) {
            free(ctext); ctext = NULL; free(nonce); nonce = NULL; free(ct_loc); sodium_memzero(ss, ss_len); free(ss);
            goto encrypt_out;
        }
        uint8_t *kestream = (uint8_t*)malloc(sizeof(ke) + 16);
        if (!kestream) {
            free(stream); free(ctext); ctext = NULL; free(nonce); nonce = NULL; free(ct_loc); sodium_memzero(ss, ss_len); free(ss);
            goto encrypt_out;
        }
        memcpy(kestream, ke, sizeof(ke));
        memcpy(kestream + sizeof(ke), nonce, 16);
        ff_shake256_kdf(kestream, sizeof(ke) + 16, NULL, 0, stream, plaintext_len);
        xor_bytes(ctext, stream, plaintext_len);
        sodium_memzero(kestream, sizeof(ke) + 16);
        free(kestream);
        sodium_memzero(stream, plaintext_len);
        free(stream);
    }

    size_t aad_len = 0;
    if (build_aad(sender_nick, to_nick, kem_id, prekey_id_raw, prekey_id_len, ct_loc, ct_loc_len, &aad, &aad_len) != 0) {
        free(ctext); ctext = NULL; free(nonce); nonce = NULL; free(ct_loc); sodium_memzero(ss, ss_len); free(ss);
        goto encrypt_out;
    }

    size_t mac_len = aad_len + 16 + plaintext_len;
    uint8_t *mac_in = (uint8_t*)malloc(mac_len ? mac_len : 1);
    if (!mac_in) {
        free(aad); aad = NULL; free(ctext); ctext = NULL; free(nonce); nonce = NULL; free(ct_loc); sodium_memzero(ss, ss_len); free(ss);
        goto encrypt_out;
    }
    uint8_t *mp = mac_in;
    memcpy(mp, aad, aad_len); mp += aad_len;
    memcpy(mp, nonce, 16); mp += 16;
    if (plaintext_len) memcpy(mp, ctext, plaintext_len);

    uint8_t mac64[64];
    ff_hmac_sha512(mac64, km, sizeof(km), mac_in, mac_len);
    sodium_memzero(mac_in, mac_len);
    free(mac_in);

    tag_loc = (uint8_t*)malloc(32);
    if (!tag_loc) {
        free(aad); aad = NULL; free(ctext); ctext = NULL; free(nonce); nonce = NULL; free(ct_loc); sodium_memzero(ss, ss_len); free(ss);
        goto encrypt_out;
    }
    memcpy(tag_loc, mac64, 32);
    sodium_memzero(mac64, sizeof(mac64));

    size_t sig_msg_len = (sizeof(DM_SIG_PREFIX) - 1) + 1 + aad_len + 1 + 16 + 1 + plaintext_len + 1 + 32;
    sig_msg = (uint8_t*)malloc(sig_msg_len);
    if (!sig_msg) {
        free(tag_loc); tag_loc = NULL; free(aad); aad = NULL; free(ctext); ctext = NULL; free(nonce); nonce = NULL; free(ct_loc); sodium_memzero(ss, ss_len); free(ss);
        goto encrypt_out;
    }
    uint8_t *sp = sig_msg;
    memcpy(sp, DM_SIG_PREFIX, sizeof(DM_SIG_PREFIX) - 1); sp += sizeof(DM_SIG_PREFIX) - 1;
    *sp++ = 0;
    memcpy(sp, aad, aad_len); sp += aad_len;
    *sp++ = 0;
    memcpy(sp, nonce, 16); sp += 16;
    *sp++ = 0;
    if (plaintext_len) { memcpy(sp, ctext, plaintext_len); sp += plaintext_len; }
    *sp++ = 0;
    memcpy(sp, tag_loc, 32); sp += 32;

    sig_loc = (uint8_t*)malloc(FF_FALCON_SIG_MAX);
    if (!sig_loc) {
        free(sig_msg); sig_msg = NULL; free(tag_loc); tag_loc = NULL; free(aad); aad = NULL; free(ctext); ctext = NULL; free(nonce); nonce = NULL; free(ct_loc); sodium_memzero(ss, ss_len); free(ss);
        goto encrypt_out;
    }
    size_t sig_loc_len = FF_FALCON_SIG_MAX;
    if (ff_falcon_sign_ct(sender_sk_sig, sender_sk_sig_len, sig_msg, sig_msg_len, sig_loc, &sig_loc_len) != 0) {
        free(sig_loc); sig_loc = NULL; free(sig_msg); sig_msg = NULL; free(tag_loc); tag_loc = NULL; free(aad); aad = NULL; free(ctext); ctext = NULL; free(nonce); nonce = NULL; free(ct_loc); sodium_memzero(ss, ss_len); free(ss);
        goto encrypt_out;
    }

    free(sig_msg);
    free(aad);
    sodium_memzero(ss, ss_len);
    free(ss);

    *ct = ct_loc; *ct_len = ct_loc_len;
    *dm_nonce = nonce; *dm_nonce_len = 16;
    *ciphertext = ctext; *ciphertext_len = plaintext_len;
    *tag = tag_loc; *tag_len = 32;
    *sig = sig_loc; *sig_len = sig_loc_len;
    enc_ret = 0;

encrypt_out:
    sodium_memzero(ke, sizeof(ke));
    sodium_memzero(km, sizeof(km));
    return enc_ret;
}

int ff_dm_verify_decrypt(const char *sender_nick,
                         const char *to_nick,
                         const char *kem_id,
                         const uint8_t *prekey_id_raw, size_t prekey_id_len,
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t *dm_nonce, size_t dm_nonce_len,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         const uint8_t *tag, size_t tag_len,
                         const uint8_t *sig, size_t sig_len,
                         const uint8_t *recipient_sk_ot, size_t recipient_sk_ot_len,
                         const uint8_t *sender_pk_sig, size_t sender_pk_sig_len,
                         uint8_t **out_plain, size_t *out_plain_len) {
    if (!sender_nick || !to_nick || !kem_id || !prekey_id_raw || prekey_id_len != 16 ||
        !ct || !dm_nonce || dm_nonce_len != 16 || !ciphertext || !tag || tag_len != 32 ||
        !sig || !recipient_sk_ot || !sender_pk_sig || !out_plain || !out_plain_len) return -1;

    *out_plain = NULL; *out_plain_len = 0;

    uint8_t *ss = NULL;
    size_t ss_len = 0;
    if (ff_kem_decaps(kem_id, recipient_sk_ot, recipient_sk_ot_len, ct, ct_len, &ss, &ss_len) != 0) return -1;

    uint8_t ke[32], km[32];
    size_t tmp_len = ss_len + prekey_id_len + 5;
    uint8_t *tmp = (uint8_t*)malloc(tmp_len);
    if (!tmp) { sodium_memzero(ss, ss_len); free(ss); return -1; }
    memcpy(tmp, ss, ss_len);
    memcpy(tmp + ss_len, prekey_id_raw, prekey_id_len);
    memcpy(tmp + ss_len + prekey_id_len, "dm-ke", 5);
    ff_shake256_kdf(tmp, ss_len + prekey_id_len + 5, NULL, 0, ke, sizeof(ke));
    memcpy(tmp + ss_len + prekey_id_len, "dm-km", 5);
    ff_shake256_kdf(tmp, ss_len + prekey_id_len + 5, NULL, 0, km, sizeof(km));
    sodium_memzero(tmp, tmp_len);
    free(tmp);
    sodium_memzero(ss, ss_len);
    free(ss);

    int ret = -1;
    uint8_t *aad = NULL;
    size_t aad_len = 0;
    if (build_aad(sender_nick, to_nick, kem_id, prekey_id_raw, prekey_id_len, ct, ct_len, &aad, &aad_len) != 0) {
        goto decrypt_out;
    }

    size_t mac_len = aad_len + dm_nonce_len + ciphertext_len;
    uint8_t *mac_in = (uint8_t*)malloc(mac_len ? mac_len : 1);
    if (!mac_in) { free(aad); aad = NULL; goto decrypt_out; }
    uint8_t *mp = mac_in;
    memcpy(mp, aad, aad_len); mp += aad_len;
    memcpy(mp, dm_nonce, dm_nonce_len); mp += dm_nonce_len;
    if (ciphertext_len) memcpy(mp, ciphertext, ciphertext_len);

    uint8_t mac64[64];
    ff_hmac_sha512(mac64, km, sizeof(km), mac_in, mac_len);
    sodium_memzero(mac_in, mac_len);
    free(mac_in);

    if (sodium_memcmp(tag, mac64, 32) != 0) {
        sodium_memzero(mac64, sizeof(mac64));
        free(aad); aad = NULL;
        goto decrypt_out;
    }
    sodium_memzero(mac64, sizeof(mac64));

    size_t sig_msg_len = (sizeof(DM_SIG_PREFIX) - 1) + 1 + aad_len + 1 + dm_nonce_len + 1 + ciphertext_len + 1 + 32;
    uint8_t *sig_msg = (uint8_t*)malloc(sig_msg_len);
    if (!sig_msg) { free(aad); aad = NULL; goto decrypt_out; }
    uint8_t *sp = sig_msg;
    memcpy(sp, DM_SIG_PREFIX, sizeof(DM_SIG_PREFIX) - 1); sp += sizeof(DM_SIG_PREFIX) - 1;
    *sp++ = 0;
    memcpy(sp, aad, aad_len); sp += aad_len;
    *sp++ = 0;
    memcpy(sp, dm_nonce, dm_nonce_len); sp += dm_nonce_len;
    *sp++ = 0;
    if (ciphertext_len) { memcpy(sp, ciphertext, ciphertext_len); sp += ciphertext_len; }
    *sp++ = 0;
    memcpy(sp, tag, 32); sp += 32;

    int ok = ff_falcon_verify(sender_pk_sig, sender_pk_sig_len, sig_msg, sig_msg_len, sig, sig_len);
    sodium_memzero(sig_msg, sig_msg_len);
    free(sig_msg);
    free(aad); aad = NULL;
    if (ok != 0) {
        goto decrypt_out;
    }

    uint8_t *plain = (uint8_t*)malloc(ciphertext_len ? ciphertext_len : 1);
    if (!plain) goto decrypt_out;
    memcpy(plain, ciphertext, ciphertext_len);

    uint8_t *stream = (uint8_t*)malloc(ciphertext_len ? ciphertext_len : 1);
    if (!stream) { free(plain); goto decrypt_out; }
    uint8_t *kestream = (uint8_t*)malloc(sizeof(ke) + dm_nonce_len);
    if (!kestream) { free(stream); free(plain); goto decrypt_out; }
    memcpy(kestream, ke, sizeof(ke));
    memcpy(kestream + sizeof(ke), dm_nonce, dm_nonce_len);
    ff_shake256_kdf(kestream, sizeof(ke) + dm_nonce_len, NULL, 0, stream, ciphertext_len);
    xor_bytes(plain, stream, ciphertext_len);
    sodium_memzero(kestream, sizeof(ke) + dm_nonce_len);
    free(kestream);
    sodium_memzero(stream, ciphertext_len);
    free(stream);

    *out_plain = plain;
    *out_plain_len = ciphertext_len;
    ret = 0;

decrypt_out:
    sodium_memzero(ke, sizeof(ke));
    sodium_memzero(km, sizeof(km));
    return ret;
}
