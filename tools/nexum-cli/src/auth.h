#pragma once
#include <stddef.h>
#include <stdint.h>

#define FF_CHALLENGE_LEN 32
#define FF_SID_LEN 16
#define FF_TAG_LEN 32

#define FF_AAD_VER_V1 1
#define FF_AAD_VER_V2 2

typedef struct {
    char *flow;
    char *nick;
    char *kem_id;
    uint8_t *sid_raw;
    size_t sid_len;
    uint64_t ts;

    uint8_t *ct;
    size_t ct_len;

    uint8_t *payload;
    size_t payload_len;

    uint8_t *tag1;
    size_t tag1_len;

    int aad_ver;
    uint8_t *tag2;
    size_t tag2_len;
} ff_challenge_pkt;

int ff_pkt_load_json(const char *path, ff_challenge_pkt *pkt);
int ff_pkt_load_json_buf(const char *json, size_t len, ff_challenge_pkt *pkt);
void ff_pkt_free(ff_challenge_pkt *pkt);

int ff_recover_challenge(const ff_challenge_pkt *pkt,
                         const uint8_t *sk_kem, size_t sk_kem_len,
                         uint8_t out_challenge[FF_CHALLENGE_LEN]);

int ff_build_transcript(const ff_challenge_pkt *pkt,
                        const uint8_t *challenge, size_t challenge_len,
                        uint8_t **out, size_t *out_len);
