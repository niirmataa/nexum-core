#include "nxms_ms_transport.h"

#include "pqc_kem.h"
#include "pqc_falcon.h"

// vendor/falcon provides SHAKE256 primitives + system seed helper
#include "falcon.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t AAD_PREFIX[] = "NXMS-AAD-v1";
static const uint8_t SIG_PREFIX[] = "NXMS-SIG-v1";
static const uint8_t CTHASH_PREFIX[] = "NXMS-CTHASH-v1";
static const uint8_t KDF_PREFIX[] = "NXMS-KDF-v1";

static void memzero(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;
}

static int rand_bytes(uint8_t *out, size_t out_len) {
    shake256_context rng;
    if (shake256_init_prng_from_system(&rng) != 0) {
        memzero(&rng, sizeof(rng));
        return -1;
    }
    shake256_flip(&rng); // IMPORTANT: init_prng_from_system() injects seed but does NOT flip.
    shake256_extract(&rng, out, out_len);
    memzero(&rng, sizeof(rng));
    return 0;
}

static void xor_bytes(uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) a[i] ^= b[i];
}

static void u64be(uint64_t x, uint8_t out[8]) {
    out[0] = (uint8_t)(x >> 56);
    out[1] = (uint8_t)(x >> 48);
    out[2] = (uint8_t)(x >> 40);
    out[3] = (uint8_t)(x >> 32);
    out[4] = (uint8_t)(x >> 24);
    out[5] = (uint8_t)(x >> 16);
    out[6] = (uint8_t)(x >> 8);
    out[7] = (uint8_t)(x);
}

static size_t nxms_strnlen(const char *s, size_t max) {
    size_t n = 0;
    if (!s) return 0;
    while (n < max && s[n] != 0) n++;
    return n;
}

static int add_sz(size_t *acc, size_t x) {
    if (!acc) return -1;
    if (*acc > SIZE_MAX - x) return -1;
    *acc += x;
    return 0;
}

static void secure_free(void *p, size_t n) {
    if (p) {
        memzero(p, n);
        free(p);
    }
}

/*
 * XOR-in-place a SHAKE256 keystream derived from (ke || nonce).
 * Streaming implementation: avoids allocating len bytes of keystream in memory.
 *
 * NOTE: This intentionally matches the previous ff_shake256_kdf(ke||nonce) behavior.
 */
static int xor_shake_keystream(uint8_t *buf, size_t len,
                               const uint8_t ke[32],
                               const uint8_t nonce[NXMS_NONCE_LEN]) {
    if (!buf || (!len)) return 0;
    if (!ke || !nonce) return -1;

    shake256_context sc;
    shake256_init(&sc);
    shake256_inject(&sc, ke, 32);
    shake256_inject(&sc, nonce, NXMS_NONCE_LEN);
    shake256_flip(&sc);

    uint8_t block[4096];
    size_t off = 0;
    while (off < len) {
        size_t n = len - off;
        if (n > sizeof(block)) n = sizeof(block);
        shake256_extract(&sc, block, n);
        xor_bytes(buf + off, block, n);
        off += n;
    }
    memzero(block, sizeof(block));
    memzero(&sc, sizeof(sc));
    return 0;
}


/*
 * Hash `ct` to fixed 32 bytes using SHAKE256 (no SHA2 dependency).
 * This mirrors the role of ct_hash in dm.c but avoids sha256/hmac.
 */
static void shake_hash32(uint8_t out32[32], const uint8_t *ct, size_t ct_len) {
    shake256_context sc;
    shake256_init(&sc);
    shake256_inject(&sc, CTHASH_PREFIX, sizeof(CTHASH_PREFIX) - 1);
    shake256_inject(&sc, ct, ct_len);
    shake256_flip(&sc);
    shake256_extract(&sc, out32, 32);
}

/*
 * Canonical AAD for multisig packets.
 *
 * Layout:
 *   "NXMS-AAD-v1" 0
 *   sender_id 0
 *   to_id 0
 *   kem_id 0
 *   sig_id 0
 *   msg_type 0
 *   escrow_id_raw (16 bytes) 0
 *   seq_be (8 bytes) 0
 *   ct_hash32
 */
static int build_aad(const char *sender_id, const char *to_id, const char *msg_type,
                     const uint8_t escrow_id_raw[NXMS_ESCROW_ID_LEN],
                     uint64_t seq,
                     const uint8_t *ct, size_t ct_len,
                     uint8_t **out, size_t *out_len) {
    if (!sender_id || !to_id || !msg_type || !escrow_id_raw || !ct || !out || !out_len) return -1;
    if (ct_len < NXMS_MIN_KEM_BYTES || ct_len > NXMS_MAX_KEM_CT_LEN) return -1;

    size_t sender_len = nxms_strnlen(sender_id, NXMS_MAX_ID_LEN + 1);
    size_t to_len     = nxms_strnlen(to_id, NXMS_MAX_ID_LEN + 1);
    size_t msg_len    = nxms_strnlen(msg_type, NXMS_MAX_ID_LEN + 1);
    if (sender_len == 0 || to_len == 0 || msg_len == 0) return -1;
    if (sender_len > NXMS_MAX_ID_LEN || to_len > NXMS_MAX_ID_LEN || msg_len > NXMS_MAX_ID_LEN) return -1;

    uint8_t ct_hash[32];
    shake_hash32(ct_hash, ct, ct_len);

    size_t kem_len = strlen(NXMS_KEM_ID);
    size_t sig_len = strlen(NXMS_SIG_ID);
    size_t prefix_len = sizeof(AAD_PREFIX) - 1;

    uint8_t seq_be[8];
    u64be(seq, seq_be);

    size_t len = 0;
    if (add_sz(&len, prefix_len + 1) != 0) goto fail;
    if (add_sz(&len, sender_len + 1) != 0) goto fail;
    if (add_sz(&len, to_len + 1) != 0) goto fail;
    if (add_sz(&len, kem_len + 1) != 0) goto fail;
    if (add_sz(&len, sig_len + 1) != 0) goto fail;
    if (add_sz(&len, msg_len + 1) != 0) goto fail;
    if (add_sz(&len, NXMS_ESCROW_ID_LEN + 1) != 0) goto fail;
    if (add_sz(&len, sizeof(seq_be) + 1) != 0) goto fail;
    if (add_sz(&len, sizeof(ct_hash)) != 0) goto fail;

    uint8_t *buf = (uint8_t*)malloc(len ? len : 1);
    if (!buf) goto fail;

    uint8_t *p = buf;
    memcpy(p, AAD_PREFIX, prefix_len); p += prefix_len; *p++ = 0;
    memcpy(p, sender_id, sender_len); p += sender_len; *p++ = 0;
    memcpy(p, to_id, to_len); p += to_len; *p++ = 0;
    memcpy(p, NXMS_KEM_ID, kem_len); p += kem_len; *p++ = 0;
    memcpy(p, NXMS_SIG_ID, sig_len); p += sig_len; *p++ = 0;
    memcpy(p, msg_type, msg_len); p += msg_len; *p++ = 0;
    memcpy(p, escrow_id_raw, NXMS_ESCROW_ID_LEN); p += NXMS_ESCROW_ID_LEN; *p++ = 0;
    memcpy(p, seq_be, sizeof(seq_be)); p += sizeof(seq_be); *p++ = 0;
    memcpy(p, ct_hash, sizeof(ct_hash)); p += sizeof(ct_hash);

    memzero(ct_hash, sizeof(ct_hash));
    *out = buf;
    *out_len = len;
    return 0;

fail:
    memzero(ct_hash, sizeof(ct_hash));
    return -1;
}

/*
 * Derive ke/km (32 bytes each) from shared secret using SHAKE256.
 * Input material:
 *   ss || escrow_id || "ms-ke"/"ms-km"
 * KDF context:
 *   "NXMS-KDF-v1"
 */
static int derive_keys(const uint8_t *ss, size_t ss_len,
                       const uint8_t escrow_id_raw[NXMS_ESCROW_ID_LEN],
                       uint8_t ke[32], uint8_t km[32]) {
    if (!ss || ss_len == 0 || !escrow_id_raw) return -1;

    const char *lbl_ke = "ms-ke";
    const char *lbl_km = "ms-km";
    const size_t lbl_len = 5;

    size_t tmp_len = 0;
    if (add_sz(&tmp_len, ss_len) != 0) return -1;
    if (add_sz(&tmp_len, NXMS_ESCROW_ID_LEN) != 0) return -1;
    if (add_sz(&tmp_len, lbl_len) != 0) return -1;
    uint8_t *tmp = (uint8_t*)malloc(tmp_len ? tmp_len : 1);
    if (!tmp) return -1;

    memcpy(tmp, ss, ss_len);
    memcpy(tmp + ss_len, escrow_id_raw, NXMS_ESCROW_ID_LEN);

    memcpy(tmp + ss_len + NXMS_ESCROW_ID_LEN, lbl_ke, lbl_len);
    ff_shake256_kdf(tmp, tmp_len, KDF_PREFIX, sizeof(KDF_PREFIX) - 1, ke, 32);

    memcpy(tmp + ss_len + NXMS_ESCROW_ID_LEN, lbl_km, lbl_len);
    ff_shake256_kdf(tmp, tmp_len, KDF_PREFIX, sizeof(KDF_PREFIX) - 1, km, 32);

    memzero(tmp, tmp_len);
    free(tmp);
    return 0;
}

/*
 * Keyed SHAKE tag (32 bytes) without SHA2/HMAC.
 *
 * tag = SHAKE256( "NXMS-TAG-v1" || km || 0 || aad || 0 || nonce || 0 || ciphertext )[0..32)
 */
static int compute_tag(uint8_t out32[NXMS_TAG_LEN],
                       const uint8_t km[32],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *ciphertext, size_t ciphertext_len) {
    if (!out32 || !km || !aad || !nonce || nonce_len != NXMS_NONCE_LEN) return -1;

    shake256_context sc;
    shake256_init(&sc);
    shake256_inject(&sc, "NXMS-TAG-v1", 11);
    shake256_inject(&sc, km, 32);
    uint8_t z = 0;
    shake256_inject(&sc, &z, 1);
    shake256_inject(&sc, aad, aad_len);
    shake256_inject(&sc, &z, 1);
    shake256_inject(&sc, nonce, nonce_len);
    shake256_inject(&sc, &z, 1);
    if (ciphertext_len) shake256_inject(&sc, ciphertext, ciphertext_len);
    shake256_flip(&sc);
    shake256_extract(&sc, out32, NXMS_TAG_LEN);
    memzero(&sc, sizeof(sc));
    return 0;
}

/*
 * Build signature message:
 *   "NXMS-SIG-v1" 0 aad 0 nonce 0 ciphertext 0 tag
 *
 * We sign the raw bytes (Falcon signs arbitrary message).
 */
static int build_sig_message(const uint8_t *aad, size_t aad_len,
                             const uint8_t *nonce, size_t nonce_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             const uint8_t tag32[NXMS_TAG_LEN],
                             uint8_t **out, size_t *out_len) {
    if (!aad || !nonce || !tag32 || !out || !out_len) return -1;
    if (nonce_len != NXMS_NONCE_LEN) return -1;
    if (ciphertext_len > 0 && !ciphertext) return -1;

    size_t prefix_len = sizeof(SIG_PREFIX) - 1;
    size_t len = 0;
    if (add_sz(&len, prefix_len + 1) != 0) return -1;
    if (add_sz(&len, aad_len + 1) != 0) return -1;
    if (add_sz(&len, nonce_len + 1) != 0) return -1;
    if (add_sz(&len, ciphertext_len + 1) != 0) return -1;
    if (add_sz(&len, NXMS_TAG_LEN) != 0) return -1;

    uint8_t *buf = (uint8_t*)malloc(len ? len : 1);
    if (!buf) return -1;

    uint8_t *p = buf;
    memcpy(p, SIG_PREFIX, prefix_len); p += prefix_len; *p++ = 0;
    memcpy(p, aad, aad_len); p += aad_len; *p++ = 0;
    memcpy(p, nonce, nonce_len); p += nonce_len; *p++ = 0;
    if (ciphertext_len) { memcpy(p, ciphertext, ciphertext_len); p += ciphertext_len; }
    *p++ = 0;
    memcpy(p, tag32, NXMS_TAG_LEN); p += NXMS_TAG_LEN;

    *out = buf;
    *out_len = len;
    return 0;
}

int nxms_ms_encrypt_packet(const char *sender_id,
                           const char *to_id,
                           const char *msg_type,
                           const uint8_t escrow_id_raw[NXMS_ESCROW_ID_LEN],
                           uint64_t seq,
                           const uint8_t *recipient_pk_kem, size_t recipient_pk_kem_len,
                           const uint8_t *sender_sk_sig, size_t sender_sk_sig_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t **kem_ct, size_t *kem_ct_len,
                           uint8_t **nonce, size_t *nonce_len,
                           uint8_t **ciphertext, size_t *ciphertext_len,
                           uint8_t **tag, size_t *tag_len,
                           uint8_t **sig, size_t *sig_len) {
    if (!kem_ct || !kem_ct_len || !nonce || !nonce_len ||
        !ciphertext || !ciphertext_len || !tag || !tag_len || !sig || !sig_len) return -1;

    // Fail-closed output contract: outputs are reset for every call.
    *kem_ct = NULL; *kem_ct_len = 0;
    *nonce = NULL; *nonce_len = 0;
    *ciphertext = NULL; *ciphertext_len = 0;
    *tag = NULL; *tag_len = 0;
    *sig = NULL; *sig_len = 0;

    if (!sender_id || !to_id || !msg_type || !escrow_id_raw ||
        !recipient_pk_kem || !sender_sk_sig) return -1;
    if (seq == 0) return -1;

    // hard limits to defend against memory/CPU DoS
    if (plaintext_len > NXMS_MAX_PAYLOAD) return -1;
    if (plaintext_len > 0 && !plaintext) return -1;
    if (recipient_pk_kem_len < NXMS_MIN_KEM_BYTES || recipient_pk_kem_len > NXMS_MAX_KEM_PK_LEN) return -1;
    if (sender_sk_sig_len == 0 || sender_sk_sig_len > NXMS_MAX_SIG_SK_LEN) return -1;

    size_t sid_len = nxms_strnlen(sender_id, NXMS_MAX_ID_LEN + 1);
    size_t tid_len = nxms_strnlen(to_id, NXMS_MAX_ID_LEN + 1);
    size_t mt_len  = nxms_strnlen(msg_type, NXMS_MAX_ID_LEN + 1);
    if (sid_len == 0 || tid_len == 0 || mt_len == 0) return -1;
    if (sid_len > NXMS_MAX_ID_LEN || tid_len > NXMS_MAX_ID_LEN || mt_len > NXMS_MAX_ID_LEN) return -1;

    // 1) KEM encaps (FrodoKEM-640-SHAKE)
    uint8_t *ct_loc = NULL;
    uint8_t *ss = NULL;
    size_t ct_loc_len = 0, ss_len = 0;
    if (ff_kem_encaps(NXMS_KEM_ID, recipient_pk_kem, recipient_pk_kem_len,
                      &ct_loc, &ct_loc_len, &ss, &ss_len) != 0) {
        return -1;
    }

    if (ct_loc_len < NXMS_MIN_KEM_BYTES || ct_loc_len > NXMS_MAX_KEM_CT_LEN) {
        memzero(ss, ss_len); free(ss);
        free(ct_loc);
        return -1;
    }
    if (ss_len == 0) { memzero(ss, ss_len); free(ss); free(ct_loc); return -1; }

    // 2) Derive keys ke/km
    uint8_t ke[32], km[32];
    if (derive_keys(ss, ss_len, escrow_id_raw, ke, km) != 0) {
        memzero(ss, ss_len); free(ss);
        free(ct_loc);
        return -1;
    }
    memzero(ss, ss_len); free(ss);

    // 3) Nonce
    uint8_t *nonce_loc = (uint8_t*)malloc(NXMS_NONCE_LEN);
    if (!nonce_loc) { free(ct_loc); memzero(ke,32); memzero(km,32); return -1; }
    if (rand_bytes(nonce_loc, NXMS_NONCE_LEN) != 0) {
        free(nonce_loc); free(ct_loc); memzero(ke,32); memzero(km,32); return -1;
    }

    // 4) Encrypt payload via XOR(SHAKE256(ke||nonce))
    uint8_t *ctext_loc = (uint8_t*)malloc(plaintext_len ? plaintext_len : 1);
    if (!ctext_loc) { free(nonce_loc); free(ct_loc); memzero(ke,32); memzero(km,32); return -1; }
    if (plaintext_len) memcpy(ctext_loc, plaintext, plaintext_len);
    if (plaintext_len) {
        if (xor_shake_keystream(ctext_loc, plaintext_len, ke, nonce_loc) != 0) {
            secure_free(ctext_loc, plaintext_len);
            secure_free(nonce_loc, NXMS_NONCE_LEN);
            free(ct_loc);
            memzero(ke,32); memzero(km,32);
            return -1;
        }
    }

    // 5) AAD
    uint8_t *aad = NULL;
    size_t aad_len = 0;
    if (build_aad(sender_id, to_id, msg_type, escrow_id_raw, seq, ct_loc, ct_loc_len, &aad, &aad_len) != 0) {
        free(ctext_loc); free(nonce_loc); free(ct_loc);
        memzero(ke,32); memzero(km,32);
        return -1;
    }

    // 6) Tag
    uint8_t tag32[NXMS_TAG_LEN];
    if (compute_tag(tag32, km, aad, aad_len, nonce_loc, NXMS_NONCE_LEN, ctext_loc, plaintext_len) != 0) {
        free(aad);
        free(ctext_loc); free(nonce_loc); free(ct_loc);
        memzero(ke,32); memzero(km,32);
        return -1;
    }

    uint8_t *tag_loc = (uint8_t*)malloc(NXMS_TAG_LEN);
    if (!tag_loc) {
        free(aad);
        free(ctext_loc); free(nonce_loc); free(ct_loc);
        memzero(ke,32); memzero(km,32);
        memzero(tag32, sizeof(tag32));
        return -1;
    }
    memcpy(tag_loc, tag32, NXMS_TAG_LEN);
    memzero(tag32, sizeof(tag32));

    // 7) Signature
    uint8_t *sig_msg = NULL;
    size_t sig_msg_len = 0;
    if (build_sig_message(aad, aad_len, nonce_loc, NXMS_NONCE_LEN, ctext_loc, plaintext_len, tag_loc, &sig_msg, &sig_msg_len) != 0) {
        free(tag_loc); free(aad);
        free(ctext_loc); free(nonce_loc); free(ct_loc);
        memzero(ke,32); memzero(km,32);
        return -1;
    }

    uint8_t *sig_loc = (uint8_t*)malloc(FF_FALCON_SIG_MAX);
    if (!sig_loc) {
        free(sig_msg); free(tag_loc); free(aad);
        free(ctext_loc); free(nonce_loc); free(ct_loc);
        memzero(ke,32); memzero(km,32);
        return -1;
    }
    size_t sig_loc_len = FF_FALCON_SIG_MAX;
    if (ff_falcon_sign_ct(sender_sk_sig, sender_sk_sig_len, sig_msg, sig_msg_len, sig_loc, &sig_loc_len) != 0) {
        free(sig_loc);
        free(sig_msg); free(tag_loc); free(aad);
        free(ctext_loc); free(nonce_loc); free(ct_loc);
        memzero(ke,32); memzero(km,32);
        return -1;
    }

    free(sig_msg);
    free(aad);
    memzero(ke,32);
    memzero(km,32);

    *kem_ct = ct_loc; *kem_ct_len = ct_loc_len;
    *nonce = nonce_loc; *nonce_len = NXMS_NONCE_LEN;
    *ciphertext = ctext_loc; *ciphertext_len = plaintext_len;
    *tag = tag_loc; *tag_len = NXMS_TAG_LEN;
    *sig = sig_loc; *sig_len = sig_loc_len;
    return 0;
}

int nxms_ms_verify_decrypt(const char *sender_id,
                           const char *to_id,
                           const char *msg_type,
                           const uint8_t escrow_id_raw[NXMS_ESCROW_ID_LEN],
                           uint64_t seq,
                           const uint8_t *kem_ct, size_t kem_ct_len,
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           const uint8_t *tag, size_t tag_len,
                           const uint8_t *sig, size_t sig_len,
                           const uint8_t *recipient_sk_kem, size_t recipient_sk_kem_len,
                           const uint8_t *sender_pk_sig, size_t sender_pk_sig_len,
                           uint8_t **out_plain, size_t *out_plain_len) {
    if (!out_plain || !out_plain_len) return -1;
    // Fail-closed output contract: output reset on call entry.
    *out_plain = NULL;
    *out_plain_len = 0;

    if (!sender_id || !to_id || !msg_type || !escrow_id_raw ||
        !kem_ct || !nonce || !ciphertext || !tag || !sig ||
        !recipient_sk_kem || !sender_pk_sig) return -1;
    if (seq == 0) return -1;

    if (nonce_len != NXMS_NONCE_LEN) return -1;
    if (tag_len != NXMS_TAG_LEN) return -1;

    if (ciphertext_len > NXMS_MAX_PAYLOAD) return -1;
    if (ciphertext_len > 0 && !ciphertext) return -1;
    if (kem_ct_len < NXMS_MIN_KEM_BYTES || kem_ct_len > NXMS_MAX_KEM_CT_LEN) return -1;
    if (sig_len == 0 || sig_len > FF_FALCON_SIG_MAX) return -1;
    if (recipient_sk_kem_len < NXMS_MIN_KEM_BYTES || recipient_sk_kem_len > NXMS_MAX_KEM_SK_LEN) return -1;
    if (sender_pk_sig_len == 0 || sender_pk_sig_len > NXMS_MAX_SIG_PK_LEN) return -1;

    size_t sid_len = nxms_strnlen(sender_id, NXMS_MAX_ID_LEN + 1);
    size_t tid_len = nxms_strnlen(to_id, NXMS_MAX_ID_LEN + 1);
    size_t mt_len  = nxms_strnlen(msg_type, NXMS_MAX_ID_LEN + 1);
    if (sid_len == 0 || tid_len == 0 || mt_len == 0) return -1;
    if (sid_len > NXMS_MAX_ID_LEN || tid_len > NXMS_MAX_ID_LEN || mt_len > NXMS_MAX_ID_LEN) return -1;

    // 1) KEM decaps
    uint8_t *ss = NULL;
    size_t ss_len = 0;
    if (ff_kem_decaps(NXMS_KEM_ID, recipient_sk_kem, recipient_sk_kem_len, kem_ct, kem_ct_len, &ss, &ss_len) != 0) {
        return -1;
    }

    if (ss_len == 0) { memzero(ss, ss_len); free(ss); return -1; }

    // 2) Derive keys
    uint8_t ke[32], km[32];
    if (derive_keys(ss, ss_len, escrow_id_raw, ke, km) != 0) {
        memzero(ss, ss_len); free(ss);
        return -1;
    }
    memzero(ss, ss_len); free(ss);

    // 3) Rebuild AAD
    uint8_t *aad = NULL;
    size_t aad_len = 0;
    if (build_aad(sender_id, to_id, msg_type, escrow_id_raw, seq, kem_ct, kem_ct_len, &aad, &aad_len) != 0) {
        memzero(ke,32); memzero(km,32);
        return -1;
    }

    // 4) Tag verify
    uint8_t tag_exp[NXMS_TAG_LEN];
    if (compute_tag(tag_exp, km, aad, aad_len, nonce, nonce_len, ciphertext, ciphertext_len) != 0) {
        free(aad);
        memzero(ke,32); memzero(km,32);
        return -1;
    }
    // constant-time compare (simple; caller can wrap with stronger if desired)
    uint8_t diff = 0;
    for (size_t i = 0; i < NXMS_TAG_LEN; i++) diff |= (tag_exp[i] ^ tag[i]);
    memzero(tag_exp, sizeof(tag_exp));
    if (diff != 0) {
        free(aad);
        memzero(ke,32); memzero(km,32);
        return -1; // tag mismatch
    }

    // 5) Signature verify
    uint8_t *sig_msg = NULL;
    size_t sig_msg_len = 0;
    if (build_sig_message(aad, aad_len, nonce, nonce_len, ciphertext, ciphertext_len, tag, &sig_msg, &sig_msg_len) != 0) {
        free(aad);
        memzero(ke,32); memzero(km,32);
        return -1;
    }
    int sig_ok = ff_falcon_verify(sender_pk_sig, sender_pk_sig_len, sig_msg, sig_msg_len, sig, sig_len);
    free(sig_msg);
    free(aad);
    if (sig_ok != 0) {
        memzero(ke,32); memzero(km,32);
        return -1;
    }

    // 6) Decrypt
    uint8_t *plain = (uint8_t*)malloc(ciphertext_len ? ciphertext_len : 1);
    if (!plain) { memzero(ke,32); memzero(km,32); return -1; }
    if (ciphertext_len) memcpy(plain, ciphertext, ciphertext_len);
    if (ciphertext_len) {
        if (xor_shake_keystream(plain, ciphertext_len, ke, nonce) != 0) {
            secure_free(plain, ciphertext_len);
            memzero(ke,32); memzero(km,32);
            return -1;
        }
    }

    memzero(ke,32);
    memzero(km,32);

    *out_plain = plain;
    *out_plain_len = ciphertext_len;
    return 0;
}

void nxms_ms_free(void *ptr) {
    free(ptr);
}

void nxms_ms_free_secure(void *ptr, size_t len) {
    secure_free(ptr, len);
}
