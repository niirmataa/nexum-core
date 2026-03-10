#pragma once
#include <stddef.h>

// Very small HTTP helper.

typedef struct {
    char *data;
    size_t len;
} ff_http_resp_t;

int ff_http_post_json(const char *url, const char *socks5_proxy,
                     const char *json_body,
                     ff_http_resp_t *out);

int ff_http_post_json_idempotent(const char *url, const char *socks5_proxy,
                                 const char *json_body,
                                 const char *idempotency_key,
                                 ff_http_resp_t *out);

int ff_http_post_json_auth(const char *url, const char *socks5_proxy,
                           const char *json_body,
                           const char *bearer,
                           const char *csrf,
                           ff_http_resp_t *out);

int ff_http_get_json_auth(const char *url, const char *socks5_proxy,
                          const char *bearer,
                          const char *csrf,
                          ff_http_resp_t *out);

void ff_http_resp_free(ff_http_resp_t *r);
const char *ff_http_last_error(void);
long ff_http_last_status(void);

// naive json field extractor for "field":"value"
// returns malloc'ed string or NULL
char *ff_json_get_str(const char *json, const char *field);

// json field extractor for numbers (int64)
int ff_json_get_i64(const char *json, const char *field, long long *out);
