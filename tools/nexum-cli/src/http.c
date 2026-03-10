#include "http.h"

#include <curl/curl.h>

#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "json_min.h"

static long g_last_http_status = 0;
static char g_last_http_error[768];
static const size_t FF_HTTP_MAX_RESPONSE_BYTES = 4U * 1024U * 1024U;

static void set_last_http_error(const char *msg) {
    if (!msg) msg = "http error";
    snprintf(g_last_http_error, sizeof(g_last_http_error), "%s", msg);
}

static void set_last_http_errorf(const char *prefix, long status, const char *detail) {
    const char *p = prefix ? prefix : "http error";
    const char *d = detail ? detail : "";
    if (status > 0) {
        snprintf(g_last_http_error, sizeof(g_last_http_error), "%s (status=%ld): %s", p, status, d);
    } else {
        snprintf(g_last_http_error, sizeof(g_last_http_error), "%s: %s", p, d);
    }
}

static void set_last_http_error_from_body(long status, const ff_http_resp_t *out) {
    char *detail = NULL;
    if (out && out->data) {
        if (ff_json_get_string(out->data, "detail", &detail) != 0) {
            if (ff_json_get_string(out->data, "error", &detail) != 0) {
                (void)ff_json_get_string(out->data, "message", &detail);
            }
        }
    }
    if (detail && detail[0]) {
        set_last_http_errorf("http request failed", status, detail);
        free(detail);
        return;
    }
    if (detail) free(detail);

    if (out && out->data && out->len > 0) {
        char snippet[320];
        size_t n = out->len;
        if (n > sizeof(snippet) - 1) n = sizeof(snippet) - 1;
        memcpy(snippet, out->data, n);
        snippet[n] = 0;
        set_last_http_errorf("http request failed", status, snippet);
        return;
    }
    set_last_http_errorf("http request failed", status, "empty response");
}

static int ff_http_has_ctl_newline(const char *s) {
    if (!s) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '\r' || *p == '\n') return 1;
    }
    return 0;
}

static int ff_http_cookie_value_safe(const char *s) {
    if (!s) return 1;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (c == '\r' || c == '\n' || c == ';' || c == ',') return 0;
        if (c < 0x20 || c == 0x7f) return 0;
    }
    return 1;
}

static int ff_http_starts_with_ci(const char *s, const char *prefix) {
    if (!s || !prefix) return 0;
    size_t n = strlen(prefix);
    return strncasecmp(s, prefix, n) == 0;
}

static int ff_http_url_host_is_onion(const char *url) {
    if (!url || !url[0]) return 0;
    const char *p = strstr(url, "://");
    const char *host = p ? (p + 3) : url;
    if (!host[0]) return 0;
    size_t host_len = strcspn(host, "/?#");
    if (host_len == 0) return 0;
    const char *host_end = host + host_len;
    const char *colon = memchr(host, ':', host_len);
    if (colon) host_end = colon;
    size_t bare_len = (size_t)(host_end - host);
    if (bare_len < 6) return 0;
    return strncasecmp(host_end - 6, ".onion", 6) == 0;
}

static int ff_http_validate_transport_policy(const char *url, const char *socks5_proxy) {
    if (!url || !url[0]) {
        set_last_http_error("http request failed: missing URL");
        return -1;
    }
    if (ff_http_url_host_is_onion(url)) {
        if (!socks5_proxy || !socks5_proxy[0]) {
            set_last_http_error("http request blocked: .onion requires SOCKS5H proxy");
            return -1;
        }
        if (!ff_http_starts_with_ci(socks5_proxy, "socks5h://")) {
            set_last_http_error("http request blocked: .onion requires socks5h:// proxy");
            return -1;
        }
    }
    if (socks5_proxy && socks5_proxy[0] &&
        !ff_http_starts_with_ci(socks5_proxy, "socks5h://")) {
        set_last_http_error("http request blocked: proxy must use socks5h://");
        return -1;
    }
    /* non-onion http:// hard-fail belongs at command/policy layer; local runtime probes use http://127.0.0.1 */
    return 0;
}

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    if (size != 0 && nmemb > (SIZE_MAX / size)) {
        set_last_http_error("http response too large (size overflow)");
        return 0;
    }
    size_t n = size * nmemb;
    ff_http_resp_t *r = (ff_http_resp_t*)userdata;
    if (n > (SIZE_MAX - r->len - 1)) {
        set_last_http_error("http response too large");
        return 0;
    }
    if (r->len + n > FF_HTTP_MAX_RESPONSE_BYTES) {
        set_last_http_error("http response exceeds max size");
        return 0;
    }
    char *p = (char*)realloc(r->data, r->len + n + 1);
    if (!p) return 0;
    r->data = p;
    memcpy(r->data + r->len, ptr, n);
    r->len += n;
    r->data[r->len] = 0;
    return n;
}

static int http_request(const char *url, const char *socks5_proxy,
                        const char *method,
                        const char *json_body,
                        const char *idempotency_key,
                        const char *bearer,
                        const char *csrf,
                        ff_http_resp_t *out) {
    g_last_http_status = 0;
    g_last_http_error[0] = 0;
    memset(out, 0, sizeof(*out));
    if (ff_http_validate_transport_policy(url, socks5_proxy) != 0) {
        return -1;
    }
    CURL *c = curl_easy_init();
    if (!c) {
        set_last_http_error("curl init failed");
        return -1;
    }

    struct curl_slist *hdr = NULL;
    if (json_body) hdr = curl_slist_append(hdr, "Content-Type: application/json");
    hdr = curl_slist_append(hdr, "Accept: application/json");
    if (bearer && bearer[0]) {
        if (ff_http_has_ctl_newline(bearer)) {
            curl_slist_free_all(hdr);
            set_last_http_error("http request blocked: Authorization token contains CR/LF");
            curl_easy_cleanup(c);
            return -1;
        }
        char hbuf[512];
        int n = snprintf(hbuf, sizeof(hbuf), "Authorization: Bearer %s", bearer);
        if (n < 0 || (size_t)n >= sizeof(hbuf)) {
            curl_slist_free_all(hdr);
            set_last_http_error("http request blocked: Authorization header too long");
            curl_easy_cleanup(c);
            return -1;
        }
        hdr = curl_slist_append(hdr, hbuf);
    }
    if (csrf && csrf[0]) {
        if (ff_http_has_ctl_newline(csrf)) {
            curl_slist_free_all(hdr);
            set_last_http_error("http request blocked: X-CSRF token contains CR/LF");
            curl_easy_cleanup(c);
            return -1;
        }
        char hbuf[256];
        int n = snprintf(hbuf, sizeof(hbuf), "X-CSRF: %s", csrf);
        if (n < 0 || (size_t)n >= sizeof(hbuf)) {
            curl_slist_free_all(hdr);
            set_last_http_error("http request blocked: X-CSRF header too long");
            curl_easy_cleanup(c);
            return -1;
        }
        hdr = curl_slist_append(hdr, hbuf);
    }
    if (idempotency_key && idempotency_key[0]) {
        if (ff_http_has_ctl_newline(idempotency_key)) {
            curl_slist_free_all(hdr);
            set_last_http_error("http request blocked: idempotency key contains CR/LF");
            curl_easy_cleanup(c);
            return -1;
        }
        char hbuf[256];
        int n = snprintf(hbuf, sizeof(hbuf), "x-idempotency-key: %s", idempotency_key);
        if (n < 0 || (size_t)n >= sizeof(hbuf)) {
            curl_slist_free_all(hdr);
            set_last_http_error("http request blocked: idempotency header too long");
            curl_easy_cleanup(c);
            return -1;
        }
        hdr = curl_slist_append(hdr, hbuf);
    }
    {
        const char *gate = getenv("FF_GATE_OK");
        const char *scid = getenv("FF_SCAPTCHA_CID");
        if ((gate && gate[0]) || (scid && scid[0])) {
            if ((gate && !ff_http_cookie_value_safe(gate)) ||
                (scid && !ff_http_cookie_value_safe(scid))) {
                curl_slist_free_all(hdr);
                set_last_http_error("http request blocked: cookie env contains unsafe characters");
                curl_easy_cleanup(c);
                return -1;
            }
            char hbuf[1024];
            int n = 0;
            if (gate && gate[0] && scid && scid[0]) {
                n = snprintf(hbuf, sizeof(hbuf), "Cookie: gate_ok=%s; scaptcha_cid=%s", gate, scid);
            } else if (gate && gate[0]) {
                n = snprintf(hbuf, sizeof(hbuf), "Cookie: gate_ok=%s", gate);
            } else {
                n = snprintf(hbuf, sizeof(hbuf), "Cookie: scaptcha_cid=%s", scid);
            }
            if (n < 0 || (size_t)n >= sizeof(hbuf)) {
                curl_slist_free_all(hdr);
                set_last_http_error("http request blocked: Cookie header too long");
                curl_easy_cleanup(c);
                return -1;
            }
            hdr = curl_slist_append(hdr, hbuf);
        }
    }

    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
#ifdef CURLOPT_PROTOCOLS_STR
    curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "http,https");
#else
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    curl_easy_setopt(c, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#endif
#ifdef CURLOPT_REDIR_PROTOCOLS_STR
    curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#endif
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
    if (method && strcmp(method, "POST") == 0) {
        curl_easy_setopt(c, CURLOPT_POST, 1L);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, json_body ? json_body : "");
    } else {
        curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
    }
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, out);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "nexum-cli/1.0");
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 40L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 20L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);

    if (socks5_proxy && socks5_proxy[0]) {
        curl_easy_setopt(c, CURLOPT_PROXY, socks5_proxy);
        curl_easy_setopt(c, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5_HOSTNAME);
    }

    CURLcode rc = curl_easy_perform(c);
    long http_code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http_code);
    g_last_http_status = http_code;

    curl_slist_free_all(hdr);
    curl_easy_cleanup(c);

    if (rc != CURLE_OK) {
        if (!g_last_http_error[0]) {
            set_last_http_errorf("transport error", 0, curl_easy_strerror(rc));
        }
        return -1;
    }
    if (http_code < 200 || http_code >= 300) {
        set_last_http_error_from_body(http_code, out);
        return -1;
    }
    return 0;
}

int ff_http_post_json(const char *url, const char *socks5_proxy,
                     const char *json_body,
                     ff_http_resp_t *out) {
    return http_request(url, socks5_proxy, "POST", json_body, NULL, NULL, NULL, out);
}

int ff_http_post_json_idempotent(const char *url, const char *socks5_proxy,
                                 const char *json_body,
                                 const char *idempotency_key,
                                 ff_http_resp_t *out) {
    return http_request(
        url,
        socks5_proxy,
        "POST",
        json_body,
        idempotency_key,
        NULL,
        NULL,
        out
    );
}

int ff_http_post_json_auth(const char *url, const char *socks5_proxy,
                           const char *json_body,
                           const char *bearer,
                           const char *csrf,
                           ff_http_resp_t *out) {
    return http_request(
        url,
        socks5_proxy,
        "POST",
        json_body,
        NULL,
        bearer,
        csrf,
        out
    );
}

int ff_http_get_json_auth(const char *url, const char *socks5_proxy,
                          const char *bearer,
                          const char *csrf,
                          ff_http_resp_t *out) {
    return http_request(url, socks5_proxy, "GET", NULL, NULL, bearer, csrf, out);
}

void ff_http_resp_free(ff_http_resp_t *r) {
    if (!r) return;
    if (r->data && r->len) sodium_memzero(r->data, r->len);
    free(r->data);
    r->data = NULL;
    r->len = 0;
}

const char *ff_http_last_error(void) {
    if (!g_last_http_error[0]) return "http request failed";
    return g_last_http_error;
}

long ff_http_last_status(void) {
    return g_last_http_status;
}

char *ff_json_get_str(const char *json, const char *field) {
    char *out = NULL;
    if (ff_json_get_string(json, field, &out) != 0) return NULL;
    return out;
}

int ff_json_get_i64(const char *json, const char *field, long long *out) {
    if (!out) return -1;
    *out = 0;
    int64_t v = 0;
    if (ff_json_get_int64(json, field, &v) != 0) return -1;
    *out = (long long)v;
    return 0;
}
