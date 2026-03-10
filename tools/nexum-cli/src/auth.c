#include "auth.h"
#include "util.h"
#include "pqc_falcon.h"
#include "pqc_kem.h"
#include "json_min.h"

#include <sodium.h>
#include <jansson.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* hard limits for JSON fields to prevent oversized allocations */
#define FF_MAX_FLOW_LEN        32
#define FF_MAX_NICK_LEN        64
#define FF_MAX_KEM_ID_LEN      64
#define FF_MAX_CT_LEN          16384
#define FF_MAX_CT_B64_LEN      24000
#define FF_MAX_PAYLOAD_LEN     1024
#define FF_MAX_PAYLOAD_B64_LEN 2048
#define FF_MAX_TAG_B64_LEN     512
#define FF_MAX_SID_B64_LEN     64

static const uint8_t CTX_AAD_V2[]  = "nexum-aad-v2\0";
static const uint8_t CTX_AUTH_V1[] = "FF-AUTH-v1";

static int raw_append(uint8_t **buf, size_t *len, const uint8_t *data, size_t data_len) {
    uint8_t *p = (uint8_t *)realloc(*buf, *len + data_len);
    if (!p) return -1;
    memcpy(p + *len, data, data_len);
    *buf = p;
    *len += data_len;
    return 0;
}

static int enc_field_append(uint8_t **buf, size_t *len, const uint8_t *field, size_t field_len) {
    uint8_t l4[4];
    ff_u32be((uint32_t)field_len, l4);
    uint8_t *p = (uint8_t *)realloc(*buf, *len + 4 + field_len);
    if (!p) return -1;
    memcpy(p + *len, l4, 4);
    memcpy(p + *len + 4, field, field_len);
    *buf = p;
    *len += 4 + field_len;
    return 0;
}

/* mask = shake256(ss || sid || "mask", 32)
   kmac = shake256(ss || sid || "mac", 32)
*/
static int derive_mask_kmac(const uint8_t *ss, size_t ss_len, const uint8_t *sid, size_t sid_len,
                            uint8_t mask[FF_CHALLENGE_LEN], uint8_t kmac[32]) {
    uint8_t *tmp = (uint8_t *)malloc(ss_len + sid_len + 4);
    if (!tmp) return -1;

    memcpy(tmp, ss, ss_len);
    memcpy(tmp + ss_len, sid, sid_len);

    memcpy(tmp + ss_len + sid_len, "mask", 4);
    ff_shake256_kdf(tmp, ss_len + sid_len + 4, NULL, 0, mask, FF_CHALLENGE_LEN);

    /* overwrite suffix and use correct length (3) */
    tmp[ss_len + sid_len + 0] = (uint8_t)'m';
    tmp[ss_len + sid_len + 1] = (uint8_t)'a';
    tmp[ss_len + sid_len + 2] = (uint8_t)'c';
    ff_shake256_kdf(tmp, ss_len + sid_len + 3, NULL, 0, kmac, 32);

    sodium_memzero(tmp, ss_len + sid_len + 4);
    free(tmp);
    return 0;
}

static int aad_v1_legacy(const ff_challenge_pkt *pkt, uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;

    size_t nick_len = strlen(pkt->nick);
    size_t kem_len  = strlen(pkt->kem_id);
    size_t flow_len = strlen(pkt->flow);

    size_t n = pkt->sid_len + 8 + nick_len + kem_len + flow_len + pkt->ct_len + pkt->payload_len;
    uint8_t *b = (uint8_t *)malloc(n);
    if (!b) return -1;

    size_t off = 0;
    memcpy(b + off, pkt->sid_raw, pkt->sid_len); off += pkt->sid_len;

    uint8_t t8[8];
    ff_u64be(pkt->ts, t8);
    memcpy(b + off, t8, 8); off += 8;

    memcpy(b + off, pkt->nick, nick_len); off += nick_len;
    memcpy(b + off, pkt->kem_id, kem_len); off += kem_len;
    memcpy(b + off, pkt->flow, flow_len); off += flow_len;
    memcpy(b + off, pkt->ct, pkt->ct_len); off += pkt->ct_len;
    memcpy(b + off, pkt->payload, pkt->payload_len); off += pkt->payload_len;

    *out = b;
    *out_len = off;
    return 0;
}

/* Python v2:
   out = CTX_AAD_V2 (RAW) || enc_field(sid) || enc_field(ts) || enc_field(nick) || enc_field(kem_id) ||
         enc_field(flow) || enc_field(ct) || enc_field(payload)
*/
static int aad_v2(const ff_challenge_pkt *pkt, uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;

    uint8_t *b = NULL;
    size_t bl = 0;

    if (raw_append(&b, &bl, CTX_AAD_V2, sizeof(CTX_AAD_V2) - 1) != 0) goto fail;
    if (enc_field_append(&b, &bl, pkt->sid_raw, pkt->sid_len) != 0) goto fail;

    uint8_t t8[8];
    ff_u64be(pkt->ts, t8);
    if (enc_field_append(&b, &bl, t8, 8) != 0) goto fail;

    if (enc_field_append(&b, &bl, (const uint8_t *)pkt->nick, strlen(pkt->nick)) != 0) goto fail;
    if (enc_field_append(&b, &bl, (const uint8_t *)pkt->kem_id, strlen(pkt->kem_id)) != 0) goto fail;
    if (enc_field_append(&b, &bl, (const uint8_t *)pkt->flow, strlen(pkt->flow)) != 0) goto fail;
    if (enc_field_append(&b, &bl, pkt->ct, pkt->ct_len) != 0) goto fail;
    if (enc_field_append(&b, &bl, pkt->payload, pkt->payload_len) != 0) goto fail;

    *out = b;
    *out_len = bl;
    return 0;

fail:
    free(b);
    return -1;
}

int ff_recover_challenge(const ff_challenge_pkt *pkt,
                         const uint8_t *sk_kem, size_t sk_kem_len,
                         uint8_t out_challenge[FF_CHALLENGE_LEN]) {
    if (!pkt || !sk_kem || !out_challenge) return -1;
    if (!pkt->flow || !pkt->nick || !pkt->kem_id) return -1;
    if (pkt->sid_len != FF_SID_LEN) return -1;
    if (pkt->payload_len != FF_CHALLENGE_LEN) return -1;

    uint8_t *ss = NULL;
    size_t ss_len = 0;
    if (ff_kem_decaps(pkt->kem_id, sk_kem, sk_kem_len, pkt->ct, pkt->ct_len, &ss, &ss_len) != 0) return -1;

    uint8_t mask[FF_CHALLENGE_LEN];
    uint8_t kmac[32];
    if (derive_mask_kmac(ss, ss_len, pkt->sid_raw, pkt->sid_len, mask, kmac) != 0) {
        sodium_memzero(ss, ss_len);
        free(ss);
        return -1;
    }

    uint8_t tag_calc64[64];
    uint8_t *aad = NULL;
    size_t aad_len = 0;

    if (pkt->aad_ver == FF_AAD_VER_V2 && pkt->tag2 && pkt->tag2_len == FF_TAG_LEN) {
        if (aad_v2(pkt, &aad, &aad_len) != 0) goto out;
        ff_hmac_sha512(tag_calc64, kmac, sizeof(kmac), aad, aad_len);
        if (sodium_memcmp(pkt->tag2, tag_calc64, FF_TAG_LEN) != 0) goto out;
    } else {
        if (!pkt->tag1 || pkt->tag1_len != FF_TAG_LEN) goto out;
        if (aad_v1_legacy(pkt, &aad, &aad_len) != 0) goto out;
        ff_hmac_sha512(tag_calc64, kmac, sizeof(kmac), aad, aad_len);
        if (sodium_memcmp(pkt->tag1, tag_calc64, FF_TAG_LEN) != 0) goto out;
    }

    for (size_t i = 0; i < FF_CHALLENGE_LEN; i++) out_challenge[i] = (uint8_t)(pkt->payload[i] ^ mask[i]);

    if (aad) { sodium_memzero(aad, aad_len); free(aad); }
    sodium_memzero(tag_calc64, sizeof(tag_calc64));
    sodium_memzero(kmac, sizeof(kmac));
    sodium_memzero(mask, sizeof(mask));
    sodium_memzero(ss, ss_len);
    free(ss);
    return 0;

out:
    if (aad) { sodium_memzero(aad, aad_len); free(aad); }
    sodium_memzero(tag_calc64, sizeof(tag_calc64));
    sodium_memzero(kmac, sizeof(kmac));
    sodium_memzero(mask, sizeof(mask));
    sodium_memzero(ss, ss_len);
    free(ss);
    return -1;
}

/* Python transcript:
   out = CTX_AUTH_V1 (RAW)
       + enc_field(flow)
       + enc_field(nick)
       + enc_field(u64be(ts))
       + enc_field(sid)
       + enc_field(kem_id)
       + enc_field(sha256(ct))
       + enc_field(challenge)
*/
int ff_build_transcript(const ff_challenge_pkt *pkt,
                        const uint8_t *challenge, size_t challenge_len,
                        uint8_t **out, size_t *out_len) {
    if (!pkt || !challenge || !out || !out_len) return -1;
    if (!pkt->flow || !pkt->nick || !pkt->kem_id) return -1;
    if (challenge_len != FF_CHALLENGE_LEN) return -1;

    uint8_t ct_hash[32];
    crypto_hash_sha256(ct_hash, pkt->ct, (unsigned long long)pkt->ct_len);

    uint8_t *b = NULL;
    size_t bl = 0;

    if (raw_append(&b, &bl, CTX_AUTH_V1, sizeof(CTX_AUTH_V1) - 1) != 0) goto fail;
    if (enc_field_append(&b, &bl, (const uint8_t *)pkt->flow, strlen(pkt->flow)) != 0) goto fail;
    if (enc_field_append(&b, &bl, (const uint8_t *)pkt->nick, strlen(pkt->nick)) != 0) goto fail;

    uint8_t t8[8];
    ff_u64be(pkt->ts, t8);
    if (enc_field_append(&b, &bl, t8, 8) != 0) goto fail;

    if (enc_field_append(&b, &bl, pkt->sid_raw, pkt->sid_len) != 0) goto fail;
    if (enc_field_append(&b, &bl, (const uint8_t *)pkt->kem_id, strlen(pkt->kem_id)) != 0) goto fail;
    if (enc_field_append(&b, &bl, ct_hash, sizeof(ct_hash)) != 0) goto fail;
    if (enc_field_append(&b, &bl, challenge, challenge_len) != 0) goto fail;

    sodium_memzero(ct_hash, sizeof(ct_hash));
    *out = b;
    *out_len = bl;
    return 0;

fail:
    sodium_memzero(ct_hash, sizeof(ct_hash));
    free(b);
    return -1;
}

static const char *json_get_str2(json_t *primary, json_t *fallback, const char *key) {
    json_t *v = NULL;
    if (primary && json_is_object(primary)) v = json_object_get(primary, key);
    if (!v && fallback && fallback != primary && json_is_object(fallback)) v = json_object_get(fallback, key);
    if (!v || !json_is_string(v)) return NULL;
    return json_string_value(v);
}

static json_t *json_get_i642(json_t *primary, json_t *fallback, const char *key) {
    json_t *v = NULL;
    if (primary && json_is_object(primary)) v = json_object_get(primary, key);
    if (!v && fallback && fallback != primary && json_is_object(fallback)) v = json_object_get(fallback, key);
    if (!v || !json_is_integer(v)) return NULL;
    return v;
}

static int pkt_parse_json_owned(char *json, size_t len, ff_challenge_pkt *pkt) {
    json_t *root = NULL;
    if (!json || !pkt) return -1;

    json_error_t jerr;
    root = json_loadb(json, len, 0, &jerr);
    if (!root || !json_is_object(root)) goto fail;

    json_t *src = root;
    json_t *pkt_obj = json_object_get(root, "pkt");
    if (pkt_obj) {
        if (!json_is_object(pkt_obj)) goto fail;
        src = pkt_obj;
    }

    const char *flow = json_get_str2(src, root, "flow");
    if (!flow) goto fail;
    pkt->flow = strdup(flow);
    if (!pkt->flow || strlen(pkt->flow) > FF_MAX_FLOW_LEN) goto fail;

    /* nick bywa pominięty w JSON -> uzupełnimy w cmd_respond z vaultu */
    const char *nick = json_get_str2(src, root, "nick");
    if (nick) {
        pkt->nick = strdup(nick);
        if (!pkt->nick || strlen(pkt->nick) > FF_MAX_NICK_LEN) goto fail;
    }

    const char *kem_id = json_get_str2(src, root, "kem_id");
    if (!kem_id) goto fail;
    pkt->kem_id = strdup(kem_id);
    if (!pkt->kem_id || strlen(pkt->kem_id) > FF_MAX_KEM_ID_LEN) goto fail;

    const char *sid = json_get_str2(src, root, "sid");
    if (!sid) goto fail;
    if (strlen(sid) > FF_MAX_SID_B64_LEN) goto fail;
    if (ff_b64u_dec(sid, &pkt->sid_raw, &pkt->sid_len) != 0) goto fail;
    if (pkt->sid_len != FF_SID_LEN) goto fail;

    json_t *tsv = json_get_i642(src, root, "ts");
    if (!tsv) goto fail;
    int64_t ts = json_integer_value(tsv);
    if (ts < 0) goto fail;
    pkt->ts = (uint64_t)ts;

    const char *ct_b64 = json_get_str2(src, root, "ct_b64");
    if (!ct_b64) goto fail;
    if (strlen(ct_b64) > FF_MAX_CT_B64_LEN) goto fail;
    if (ff_b64dec(ct_b64, &pkt->ct, &pkt->ct_len) != 0) goto fail;
    if (pkt->ct_len == 0 || pkt->ct_len > FF_MAX_CT_LEN) goto fail;

    const char *payload_b64 = json_get_str2(src, root, "payload_b64");
    if (!payload_b64) goto fail;
    if (strlen(payload_b64) > FF_MAX_PAYLOAD_B64_LEN) goto fail;
    if (ff_b64dec(payload_b64, &pkt->payload, &pkt->payload_len) != 0) goto fail;
    if (pkt->payload_len > FF_MAX_PAYLOAD_LEN) goto fail;

    const char *tag_b64 = json_get_str2(src, root, "tag_b64");
    if (tag_b64) {
        if (strlen(tag_b64) > FF_MAX_TAG_B64_LEN) goto fail;
        if (ff_b64dec(tag_b64, &pkt->tag1, &pkt->tag1_len) != 0) goto fail;
        if (pkt->tag1_len != FF_TAG_LEN) goto fail;
    }

    pkt->aad_ver = FF_AAD_VER_V1;
    json_t *aadv = json_get_i642(src, root, "aad_ver");
    if (aadv) pkt->aad_ver = (int)json_integer_value(aadv);

    const char *tag2_b64 = json_get_str2(src, root, "tag2_b64");
    if (tag2_b64) {
        if (strlen(tag2_b64) > FF_MAX_TAG_B64_LEN) goto fail;
        if (ff_b64dec(tag2_b64, &pkt->tag2, &pkt->tag2_len) != 0) goto fail;
        if (pkt->tag2_len != FF_TAG_LEN) goto fail;
    }

    json_decref(root);
    sodium_memzero(json, len);
    free(json);
    return 0;

fail:
    if (root) json_decref(root);
    sodium_memzero(json, len);
    free(json);
    ff_pkt_free(pkt);
    return -1;
}

int ff_pkt_load_json(const char *path, ff_challenge_pkt *pkt) {
    memset(pkt, 0, sizeof(*pkt));

    uint8_t *buf = NULL;
    size_t len = 0;
    if (ff_read_file(path, &buf, &len) != 0) return -1;

    char *json = (char *)malloc(len + 1);
    if (!json) { free(buf); return -1; }
    memcpy(json, buf, len);
    json[len] = 0;
    sodium_memzero(buf, len);
    free(buf);

    return pkt_parse_json_owned(json, len, pkt);
}

int ff_pkt_load_json_buf(const char *json_in, size_t len, ff_challenge_pkt *pkt) {
    memset(pkt, 0, sizeof(*pkt));
    if (!json_in) return -1;
    if (len == 0) len = strlen(json_in);
    char *json = (char *)malloc(len + 1);
    if (!json) return -1;
    memcpy(json, json_in, len);
    json[len] = 0;
    return pkt_parse_json_owned(json, len, pkt);
}

void ff_pkt_free(ff_challenge_pkt *pkt) {
    if (!pkt) return;

    free(pkt->flow);
    free(pkt->nick);
    free(pkt->kem_id);

    if (pkt->sid_raw) { sodium_memzero(pkt->sid_raw, pkt->sid_len); free(pkt->sid_raw); }
    if (pkt->ct) { sodium_memzero(pkt->ct, pkt->ct_len); free(pkt->ct); }
    if (pkt->payload) { sodium_memzero(pkt->payload, pkt->payload_len); free(pkt->payload); }
    if (pkt->tag1) { sodium_memzero(pkt->tag1, pkt->tag1_len); free(pkt->tag1); }
    if (pkt->tag2) { sodium_memzero(pkt->tag2, pkt->tag2_len); free(pkt->tag2); }

    memset(pkt, 0, sizeof(*pkt));
}
