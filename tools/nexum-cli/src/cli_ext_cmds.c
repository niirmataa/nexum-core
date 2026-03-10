#include "util.h"
#include "vault.h"
#include "pqc_falcon.h"
#include "pqc_kem.h"
#include "http.h"
#include "prekeys.h"
#include "dm.h"
#include "cli_common.h"
#include "cli_ext_cmds.h"

#include <sodium.h>
#include <curl/curl.h>
#include <jansson.h>
#include <sqlite3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>
#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/wait.h>

static const char *resolve_orch_bin(const char *orch_bin_opt);
static int pf_parse_http_url_host_port(const char *url, char *host_out, size_t host_cap, int *port_out);
static int pf_is_true(const char *s);
static int pf_http_host_is_loopback(const char *host);
static void pf_require_escrow_base_url_policy(const char *base, int allow_remote_http_override, const char *ctx);
static char *url_encode_component(const char *in);
typedef struct {
    const char *key;
    const char *value;
} pf_env_kv_t;
static int pf_run_orch_capture(const char *orch_bin,
                               char *const argv[],
                               char *out_buf,
                               size_t out_cap,
                               int *exit_code);
static int pf_run_orch_capture_env(const char *orch_bin,
                                   char *const argv[],
                                   const pf_env_kv_t *envs,
                                   size_t env_count,
                                   char *out_buf,
                                   size_t out_cap,
                                   int *exit_code);
static int orch_validate_bin_path(const char *orch_bin, char *err, size_t err_cap);
static int orch_pipe_cloexec(int pipefd[2]);
static void orch_exec_child_sanitized(const char *orch_bin,
                                      char *const argv[],
                                      const pf_env_kv_t *envs,
                                      size_t env_count);

static int prekeys_append(ff_prekeys_t *st, const ff_prekey_entry *e) {
    ff_prekey_entry *p = (ff_prekey_entry*)realloc(st->items, (st->count + 1) * sizeof(*p));
    if (!p) return -1;
    st->items = p;
    st->items[st->count] = *e;
    st->count++;
    return 0;
}

static size_t prekeys_count_available(const ff_prekeys_t *st, uint64_t now) {
    size_t n = 0;
    for (size_t i = 0; i < st->count; i++) {
        const ff_prekey_entry *e = &st->items[i];
        if (e->flags & FF_PREKEY_FLAG_USED) continue;
        if (e->expires_at && e->expires_at <= now) continue;
        n++;
    }
    return n;
}

static size_t prekeys_collect_unuploaded(const ff_prekeys_t *st, uint64_t now, size_t limit,
                                         size_t **out_idx, const char **out_kem_id) {
    *out_idx = NULL;
    *out_kem_id = NULL;
    if (!st || st->count == 0) return 0;

    size_t *idx = (size_t*)malloc(st->count * sizeof(size_t));
    if (!idx) return 0;

    size_t n = 0;
    const char *kem_id = NULL;
    for (size_t i = 0; i < st->count; i++) {
        const ff_prekey_entry *e = &st->items[i];
        if (e->flags & FF_PREKEY_FLAG_USED) continue;
        if (e->flags & FF_PREKEY_FLAG_UPLOADED) continue;
        if (e->expires_at && e->expires_at <= now) continue;
        if (!kem_id) kem_id = e->kem_id;
        if (strcmp(e->kem_id, kem_id) != 0) continue;
        idx[n++] = i;
        if (limit && n >= limit) break;
    }

    if (n == 0) {
        free(idx);
        return 0;
    }
    *out_idx = idx;
    *out_kem_id = kem_id;
    return n;
}

static int prekeys_find_mixed_unuploaded_kems(const ff_prekeys_t *st, uint64_t now,
                                              char *first_out, size_t first_cap,
                                              char *other_out, size_t other_cap) {
    if (!st) return 0;
    const char *first = NULL;
    for (size_t i = 0; i < st->count; i++) {
        const ff_prekey_entry *e = &st->items[i];
        if (e->flags & FF_PREKEY_FLAG_USED) continue;
        if (e->flags & FF_PREKEY_FLAG_UPLOADED) continue;
        if (e->expires_at && e->expires_at <= now) continue;
        if (!first) {
            first = e->kem_id;
            continue;
        }
        if (strcmp(e->kem_id, first) != 0) {
            if (first_out && first_cap > 0) ff_strlcpy(first_out, first, first_cap);
            if (other_out && other_cap > 0) ff_strlcpy(other_out, e->kem_id, other_cap);
            return 1;
        }
    }
    return 0;
}

static const uint8_t PREKEYS_SIG_PREFIX[] = "FF-PREKEYS-v1";

static int build_prekeys_sig_msg(const char *nick, const char *kem_id,
                                 const ff_prekeys_t *st, const size_t *idx, size_t n,
                                 uint8_t **out, size_t *out_len) {
    if (!nick || !kem_id || !st || !idx || !out || !out_len) return -1;
    size_t nick_len = strlen(nick);
    size_t kem_len = strlen(kem_id);
    size_t prefix_len = sizeof(PREKEYS_SIG_PREFIX) - 1;

    size_t len = prefix_len + 1 + nick_len + 1 + kem_len + 1 + 4 + n * (FF_PREKEY_ID_LEN + 32);
    uint8_t *buf = (uint8_t*)malloc(len);
    if (!buf) return -1;

    uint8_t *p = buf;
    memcpy(p, PREKEYS_SIG_PREFIX, prefix_len);
    p += prefix_len;
    *p++ = 0;
    memcpy(p, nick, nick_len);
    p += nick_len;
    *p++ = 0;
    memcpy(p, kem_id, kem_len);
    p += kem_len;
    *p++ = 0;

    uint8_t cnt[4];
    ff_u32be((uint32_t)n, cnt);
    memcpy(p, cnt, 4);
    p += 4;

    for (size_t i = 0; i < n; i++) {
        const ff_prekey_entry *e = &st->items[idx[i]];
        memcpy(p, e->prekey_id, FF_PREKEY_ID_LEN);
        p += FF_PREKEY_ID_LEN;
        uint8_t h[32];
        crypto_hash_sha256(h, e->pk, (unsigned long long)e->pk_len);
        memcpy(p, h, sizeof(h));
        p += sizeof(h);
    }

    *out = buf;
    *out_len = len;
    return 0;
}

static int prekeys_generate_into_store(ff_prekeys_t *st, const char *kem_id, int count, int ttl_days) {
    if (!st || !kem_id || count <= 0 || ttl_days <= 0) return -1;
    uint64_t now = (uint64_t)time(NULL);
    uint64_t ttl = (uint64_t)ttl_days * 86400ULL;

    for (int i = 0; i < count; i++) {
        ff_kem_keys_t k;
        if (ff_kem_keygen(kem_id, &k) != 0) return -1;

        ff_prekey_entry e;
        memset(&e, 0, sizeof(e));
        int tries = 0;
        int collision = 0;
        do {
            collision = 0;
            randombytes_buf(e.prekey_id, FF_PREKEY_ID_LEN);
            for (size_t j = 0; j < st->count; j++) {
                if (memcmp(st->items[j].prekey_id, e.prekey_id, FF_PREKEY_ID_LEN) == 0) {
                    collision = 1;
                    break;
                }
            }
        } while (collision && ++tries < 5);
        if (collision) {
            if (k.sk) { sodium_memzero(k.sk, k.sk_len); free(k.sk); }
            if (k.pk) free(k.pk);
            return -1;
        }
        ff_strlcpy(e.kem_id, kem_id, sizeof(e.kem_id));
        e.pk = k.pk; e.pk_len = k.pk_len;
        e.sk = k.sk; e.sk_len = k.sk_len;
        k.pk = NULL; k.sk = NULL;
        e.created_at = now;
        e.expires_at = now + ttl;
        e.flags = 0;

        if (prekeys_append(st, &e) != 0) {
            if (e.sk) { sodium_memzero(e.sk, e.sk_len); free(e.sk); }
            if (e.pk) free(e.pk);
            return -1;
        }
    }
    return 0;
}

static int prekeys_upload_with_loaded(const char *base, const char *socks5,
                                      ff_vault_t *v, ff_prekeys_t *st, int limit) {
    if (!v || !st) return -1;
    if (!v->session_id || !v->csrf) ff_die("login required (no session/csrf in vault)");
    if (!v->nick[0]) ff_die("vault missing nick (login first)");

    uint64_t now = (uint64_t)time(NULL);
    {
        char kem_a[64] = {0};
        char kem_b[64] = {0};
        if (prekeys_find_mixed_unuploaded_kems(st, now, kem_a, sizeof(kem_a), kem_b, sizeof(kem_b))) {
            ff_die("prekeys upload blocked: multiple pending kem_id values detected (%s, %s); upload/rotate one KEM family at a time",
                   kem_a[0] ? kem_a : "?",
                   kem_b[0] ? kem_b : "?");
        }
    }
    size_t *idx = NULL;
    const char *kem_id = NULL;
    size_t n = prekeys_collect_unuploaded(st, now, (limit > 0) ? (size_t)limit : 0, &idx, &kem_id);
    if (n == 0) {
        printf("No prekeys to upload.\n");
        return 0;
    }
    if (!kem_id || !kem_id[0]) {
        free(idx);
        return -1;
    }
    if (v->kem_alg[0] && strcmp(kem_id, v->kem_alg) != 0) {
        free(idx);
        ff_die("kem_id mismatch between prekeys and vault");
    }

    uint8_t *msg = NULL;
    size_t msg_len = 0;
    if (build_prekeys_sig_msg(v->nick, kem_id, st, idx, n, &msg, &msg_len) != 0) {
        free(idx);
        return -1;
    }

    uint8_t sig[FF_FALCON_SIG_MAX];
    size_t sig_len = sizeof(sig);
    if (ff_falcon_sign_ct(v->falcon_sk, v->falcon_sk_len, msg, msg_len, sig, &sig_len) != 0) {
        sodium_memzero(msg, msg_len);
        free(msg);
        free(idx);
        ff_die("falcon sign failed");
    }
    sodium_memzero(msg, msg_len);
    free(msg);

    char *sig_b64 = NULL;
    if (ff_b64enc(sig, sig_len, &sig_b64) != 0) {
        free(idx);
        ff_die("b64 encode failed");
    }

    char *json = NULL;
    size_t json_len = 0;
    append_or_die(&json, &json_len, "{\"kem_id\":\"");
    append_json_escaped_or_die(&json, &json_len, kem_id);
    append_or_die(&json, &json_len, "\",\"keys\":[");

    for (size_t i = 0; i < n; i++) {
        ff_prekey_entry *e = &st->items[idx[i]];
        char *prekey_id_b64u = NULL;
        char *pk_b64 = NULL;
        if (ff_b64u_enc(e->prekey_id, FF_PREKEY_ID_LEN, &prekey_id_b64u) != 0 ||
            ff_b64enc(e->pk, e->pk_len, &pk_b64) != 0) {
            free(prekey_id_b64u);
            free(pk_b64);
            free(sig_b64);
            free(idx);
            free(json);
            ff_die("b64 encode failed");
        }

        if (i > 0) append_or_die(&json, &json_len, ",");
        append_or_die(&json, &json_len, "{\"prekey_id\":\"");
        append_json_escaped_or_die(&json, &json_len, prekey_id_b64u);
        append_or_die(&json, &json_len, "\",\"kem_id\":\"");
        append_json_escaped_or_die(&json, &json_len, kem_id);
        append_or_die(&json, &json_len, "\",\"pk_b64\":\"");
        append_json_escaped_or_die(&json, &json_len, pk_b64);
        append_or_die(&json, &json_len, "\"}");

        free(prekey_id_b64u);
        free(pk_b64);
    }
    append_or_die(&json, &json_len, "],\"sig_b64\":\"");
    append_json_escaped_or_die(&json, &json_len, sig_b64);
    append_or_die(&json, &json_len, "\"}");

    char url[512];
    snprintf(url, sizeof(url), "%s/api/prekeys/upload", base);

    ff_http_resp_t r;
    if (ff_http_post_json_auth(url, socks5, json, v->session_id, v->csrf, &r) != 0) {
        free(sig_b64);
        free(idx);
        free(json);
        ff_die("prekeys upload failed: %s", ff_http_last_error());
    }
    ff_http_resp_free(&r);

    for (size_t i = 0; i < n; i++) {
        st->items[idx[i]].flags |= FF_PREKEY_FLAG_UPLOADED;
    }

    free(sig_b64);
    free(idx);
    free(json);
    return 0;
}

int cmd_prekeys_gen(const char *dir, const char *kem_id_opt, int count, int ttl_days) {
    if (count <= 0 || ttl_days <= 0) ff_die("prekeys-gen requires --count > 0 and --ttl-days > 0");
    char *pass = prompt_pass("Vault passphrase: ");
    if (!pass) ff_die("no passphrase");

    ff_vault_t v;
    if (ff_vault_load(dir, pass, &v) != 0) {
        secure_free_str(&pass);
        ff_die("vault load failed");
    }

    const char *kem_id = kem_id_opt;
    if (!kem_id || !*kem_id) {
        kem_id = v.kem_alg[0] ? v.kem_alg : "ntru-hrss701";
    }

    ff_prekeys_t st;
    if (ff_prekeys_load(dir, pass, &st) != 0) {
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("prekeys load failed");
    }

    if (prekeys_generate_into_store(&st, kem_id, count, ttl_days) != 0) {
        ff_prekeys_free(&st);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("prekeys generate failed");
    }

    if (ff_prekeys_save(dir, pass, &st) != 0) {
        ff_prekeys_free(&st);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("prekeys save failed");
    }

    printf("OK: generated %d prekeys (ttl %d days)\n", count, ttl_days);

    ff_prekeys_free(&st);
    ff_vault_free(&v);
    secure_free_str(&pass);
    return 0;
}

int cmd_prekeys_upload(const char *dir, const char *base, const char *socks5, int limit) {
    require_tor(base, socks5);
    char *pass = prompt_pass("Vault passphrase: ");
    if (!pass) ff_die("no passphrase");

    ff_vault_t v;
    if (ff_vault_load(dir, pass, &v) != 0) {
        secure_free_str(&pass);
        ff_die("vault load failed");
    }

    ff_prekeys_t st;
    if (ff_prekeys_load(dir, pass, &st) != 0) {
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("prekeys load failed");
    }

    if (prekeys_upload_with_loaded(base, socks5, &v, &st, limit) != 0) {
        ff_prekeys_free(&st);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("prekeys upload failed");
    }

    if (ff_prekeys_save(dir, pass, &st) != 0) {
        ff_prekeys_free(&st);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("prekeys save failed");
    }

    printf("OK: prekeys uploaded\n");

    ff_prekeys_free(&st);
    ff_vault_free(&v);
    secure_free_str(&pass);
    return 0;
}

int cmd_prekeys_rotate(const char *dir, const char *base, const char *socks5,
                              const char *kem_id_opt, int count, int min, int ttl_days) {
    require_tor(base, socks5);
    if (count <= 0 || min < 0 || ttl_days <= 0) ff_die("prekeys-rotate requires --count > 0 and --ttl-days > 0");
    char *pass = prompt_pass("Vault passphrase: ");
    if (!pass) ff_die("no passphrase");

    ff_vault_t v;
    if (ff_vault_load(dir, pass, &v) != 0) {
        secure_free_str(&pass);
        ff_die("vault load failed");
    }

    const char *kem_id = kem_id_opt;
    if (!kem_id || !*kem_id) {
        kem_id = v.kem_alg[0] ? v.kem_alg : "ntru-hrss701";
    }

    ff_prekeys_t st;
    if (ff_prekeys_load(dir, pass, &st) != 0) {
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("prekeys load failed");
    }

    uint64_t now = (uint64_t)time(NULL);
    size_t avail = prekeys_count_available(&st, now);
    int need = 0;
    if ((int)avail < min) {
        need = count - (int)avail;
        if (need < 0) need = 0;
    }

    if (need > 0) {
        if (prekeys_generate_into_store(&st, kem_id, need, ttl_days) != 0) {
            ff_prekeys_free(&st);
            ff_vault_free(&v); secure_free_str(&pass);
            ff_die("prekeys generate failed");
        }
    }

    if (prekeys_upload_with_loaded(base, socks5, &v, &st, count) != 0) {
        ff_prekeys_free(&st);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("prekeys upload failed");
    }

    if (ff_prekeys_save(dir, pass, &st) != 0) {
        ff_prekeys_free(&st);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("prekeys save failed");
    }

    printf("OK: prekeys rotated (avail=%zu, target=%d, min=%d)\n", avail, count, min);

    ff_prekeys_free(&st);
    ff_vault_free(&v);
    secure_free_str(&pass);
    return 0;
}

int cmd_tor_check(const char *base, const char *socks5_in) {
    const char *socks5 = socks5_in && socks5_in[0] ? socks5_in : "socks5h://127.0.0.1:9050";

    if (strncmp(socks5, "socks5h://", 10) != 0) {
        ff_die("Tor required: use socks5h:// (DNS over Tor)");
    }
    if (base && base[0] && !url_host_is_onion_suffix(base)) {
        ff_die("Tor required: --base must be a .onion address");
    }
    if (tor_proxy_reachable(socks5) != 0) {
        ff_die("Tor not reachable at %s (is Tor running? socks5h on 127.0.0.1:9050)", socks5);
    }
    printf("OK: Tor proxy reachable at %s\n", socks5);
    if (base && base[0]) {
        printf("OK: base looks like onion: %s\n", base);
    }
    return 0;
}

typedef struct {
    char *nick;
    uint8_t *pk;
    size_t pk_len;
} pk_cache_entry;

static void pk_cache_free(pk_cache_entry *arr, size_t n) {
    if (!arr) return;
    for (size_t i = 0; i < n; i++) {
        free(arr[i].nick);
        free(arr[i].pk);
    }
    free(arr);
}

static int fetch_pk_sig(const char *base, const char *socks5,
                        const char *bearer, const char *csrf,
                        const char *nick, uint8_t **out, size_t *out_len,
                        char *err, size_t err_cap) {
    *out = NULL; *out_len = 0;
    if (err && err_cap > 0) err[0] = 0;
    char *nick_e = url_encode_component(nick);
    if (!nick_e) {
        if (err && err_cap > 0) snprintf(err, err_cap, "invalid/oom nick");
        return -1;
    }
    char url[512];
    if (snprintf(url, sizeof(url), "%s/api/users/pk_sig/%s", base, nick_e) >= (int)sizeof(url)) {
        free(nick_e);
        if (err && err_cap > 0) snprintf(err, err_cap, "pk_sig url too long");
        return -1;
    }
    free(nick_e);
    ff_http_resp_t r;
    if (ff_http_get_json_auth(url, socks5, bearer, csrf, &r) != 0) {
        if (err && err_cap > 0) {
            snprintf(err, err_cap, "%s", ff_http_last_error());
        }
        return -1;
    }
    char *pk_b64 = ff_json_get_str(r.data, "pk_sig_b64");
    if (!pk_b64) {
        if (err && err_cap > 0) {
            snprintf(err, err_cap, "missing pk_sig_b64 in response");
        }
        ff_http_resp_free(&r);
        return -1;
    }
    if (ff_b64dec(pk_b64, out, out_len) != 0) {
        if (err && err_cap > 0) {
            snprintf(err, err_cap, "invalid pk_sig_b64 in response");
        }
        free(pk_b64);
        ff_http_resp_free(&r);
        return -1;
    }
    free(pk_b64);
    ff_http_resp_free(&r);
    return 0;
}

int cmd_dm_send(const char *dir, const char *base, const char *socks5,
                       const char *to_nick, const char *msg, const char *file_path) {
    require_tor(base, socks5);
    if (!to_nick || (!msg && !file_path)) ff_die("dm-send requires --to and (--msg or --file)");
    char *pass = prompt_pass("Vault passphrase: ");
    if (!pass) ff_die("no passphrase");

    ff_vault_t v;
    if (ff_vault_load(dir, pass, &v) != 0) {
        secure_free_str(&pass);
        ff_die("vault load failed");
    }
    if (!v.session_id || !v.csrf) {
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("login required (no session/csrf)");
    }
    if (!v.nick[0]) {
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("vault missing nick");
    }

    char *msg_buf = NULL;
    size_t msg_len = 0;
    if (file_path) {
        msg_buf = read_file_str(file_path, &msg_len);
        if (!msg_buf) { ff_vault_free(&v); secure_free_str(&pass); ff_die("failed to read file"); }
    } else {
        msg_len = strlen(msg);
        msg_buf = strdup(msg);
        if (!msg_buf) { ff_vault_free(&v); secure_free_str(&pass); ff_die("oom"); }
    }

    char *to_nick_e = url_encode_component(to_nick);
    if (!to_nick_e) {
        secure_free_mem(msg_buf, msg_len);
        msg_buf = NULL;
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("invalid recipient nick");
    }
    char url[512];
    if (snprintf(url, sizeof(url), "%s/api/prekeys/fetch/%s", base, to_nick_e) >= (int)sizeof(url)) {
        free(to_nick_e);
        secure_free_mem(msg_buf, msg_len);
        msg_buf = NULL;
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("prekeys fetch url too long");
    }
    free(to_nick_e);
    ff_http_resp_t rpk;
    if (ff_http_get_json_auth(url, socks5, v.session_id, v.csrf, &rpk) != 0) {
        secure_free_mem(msg_buf, msg_len);
        msg_buf = NULL;
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("prekeys fetch failed: %s", ff_http_last_error());
    }
    char *prekey_id_b64u = ff_json_get_str(rpk.data, "prekey_id");
    char *kem_id = ff_json_get_str(rpk.data, "kem_id");
    char *pk_b64 = ff_json_get_str(rpk.data, "pk_b64");
    if (!prekey_id_b64u || !kem_id || !pk_b64) {
        free(prekey_id_b64u); free(kem_id); free(pk_b64);
        ff_http_resp_free(&rpk);
        secure_free_mem(msg_buf, msg_len);
        msg_buf = NULL;
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("bad prekeys fetch response");
    }

    uint8_t *prekey_id_raw = NULL; size_t prekey_id_len = 0;
    uint8_t *pk_ot = NULL; size_t pk_ot_len = 0;
    if (ff_b64u_dec(prekey_id_b64u, &prekey_id_raw, &prekey_id_len) != 0 ||
        ff_b64dec(pk_b64, &pk_ot, &pk_ot_len) != 0) {
        free(prekey_id_b64u); free(kem_id); free(pk_b64);
        ff_http_resp_free(&rpk);
        secure_free_mem(msg_buf, msg_len);
        msg_buf = NULL;
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("b64 decode failed");
    }
    ff_http_resp_free(&rpk);

    uint8_t *ct = NULL, *dm_nonce = NULL, *ciphertext = NULL, *tag = NULL, *sig = NULL;
    size_t ct_len = 0, dm_nonce_len = 0, ciphertext_len = 0, tag_len = 0, sig_len = 0;
    if (ff_dm_encrypt_packet(v.nick, to_nick, kem_id,
                             prekey_id_raw, prekey_id_len,
                             pk_ot, pk_ot_len,
                             v.falcon_sk, v.falcon_sk_len,
                             (uint8_t*)msg_buf, msg_len,
                             &ct, &ct_len, &dm_nonce, &dm_nonce_len,
                             &ciphertext, &ciphertext_len, &tag, &tag_len,
                             &sig, &sig_len) != 0) {
        free(prekey_id_b64u); free(kem_id); free(pk_b64);
        free(prekey_id_raw); free(pk_ot);
        secure_free_mem(msg_buf, msg_len);
        msg_buf = NULL;
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("dm encrypt failed");
    }

    char *ct_b64 = NULL, *nonce_b64 = NULL, *cipher_b64 = NULL, *tag_b64 = NULL, *sig_b64 = NULL;
    if (ff_b64enc(ct, ct_len, &ct_b64) != 0 ||
        ff_b64enc(dm_nonce, dm_nonce_len, &nonce_b64) != 0 ||
        ff_b64enc(ciphertext, ciphertext_len, &cipher_b64) != 0 ||
        ff_b64enc(tag, tag_len, &tag_b64) != 0 ||
        ff_b64enc(sig, sig_len, &sig_b64) != 0) {
        free(ct_b64); free(nonce_b64); free(cipher_b64); free(tag_b64); free(sig_b64);
        free(ct); free(dm_nonce); free(ciphertext); free(tag); free(sig);
        free(prekey_id_raw); free(pk_ot);
        free(prekey_id_b64u); free(kem_id); free(pk_b64);
        secure_free_mem(msg_buf, msg_len);
        msg_buf = NULL;
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("b64 encode failed");
    }

    char *json = NULL;
    size_t json_len = 0;
    append_or_die(&json, &json_len, "{\"v\":1,\"from\":\"");
    append_json_escaped_or_die(&json, &json_len, v.nick);
    append_or_die(&json, &json_len, "\",\"to\":\"");
    append_json_escaped_or_die(&json, &json_len, to_nick);
    append_or_die(&json, &json_len, "\",\"kem_id\":\"");
    append_json_escaped_or_die(&json, &json_len, kem_id);
    append_or_die(&json, &json_len, "\",\"prekey_id\":\"");
    append_json_escaped_or_die(&json, &json_len, prekey_id_b64u);
    append_or_die(&json, &json_len, "\",\"ct_b64\":\"");
    append_json_escaped_or_die(&json, &json_len, ct_b64 ? ct_b64 : "");
    append_or_die(&json, &json_len, "\",\"dm_nonce_b64\":\"");
    append_json_escaped_or_die(&json, &json_len, nonce_b64 ? nonce_b64 : "");
    append_or_die(&json, &json_len, "\",\"ciphertext_b64\":\"");
    append_json_escaped_or_die(&json, &json_len, cipher_b64 ? cipher_b64 : "");
    append_or_die(&json, &json_len, "\",\"tag_b64\":\"");
    append_json_escaped_or_die(&json, &json_len, tag_b64 ? tag_b64 : "");
    append_or_die(&json, &json_len, "\",\"sig_b64\":\"");
    append_json_escaped_or_die(&json, &json_len, sig_b64 ? sig_b64 : "");
    append_or_die(&json, &json_len, "\"}");

    char url_send[512];
    snprintf(url_send, sizeof(url_send), "%s/api/dm/send", base);
    ff_http_resp_t rsend;
    if (ff_http_post_json_auth(url_send, socks5, json, v.session_id, v.csrf, &rsend) != 0) {
        ff_http_resp_free(&rsend);
        free(json);
        free(ct_b64); free(nonce_b64); free(cipher_b64); free(tag_b64); free(sig_b64);
        free(ct); free(dm_nonce); free(ciphertext); free(tag); free(sig);
        free(prekey_id_raw); free(pk_ot);
        free(prekey_id_b64u); free(kem_id); free(pk_b64);
        secure_free_mem(msg_buf, msg_len);
        msg_buf = NULL;
        ff_vault_free(&v);
        secure_free_str(&pass);
        ff_die("dm send failed: %s", ff_http_last_error());
    }
    ff_http_resp_free(&rsend);

    printf("OK: DM sent to %s\n", to_nick);

    free(json);
    free(ct_b64); free(nonce_b64); free(cipher_b64); free(tag_b64); free(sig_b64);
    free(ct); free(dm_nonce); free(ciphertext); free(tag); free(sig);
    free(prekey_id_raw); free(pk_ot);
    free(prekey_id_b64u); free(kem_id); free(pk_b64);
    secure_free_mem(msg_buf, msg_len);
    msg_buf = NULL;
    ff_vault_free(&v);
    secure_free_str(&pass);
    return 0;
}

int cmd_dm_inbox(const char *dir, const char *base, const char *socks5,
                        int limit, int keep) {
    require_tor(base, socks5);
    char *pass = prompt_pass("Vault passphrase: ");
    if (!pass) ff_die("no passphrase");

    ff_vault_t v;
    if (ff_vault_load(dir, pass, &v) != 0) {
        secure_free_str(&pass);
        ff_die("vault load failed");
    }
    if (!v.session_id || !v.csrf) {
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("login required (no session/csrf)");
    }

    ff_prekeys_t st;
    if (ff_prekeys_load(dir, pass, &st) != 0) {
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("prekeys load failed");
    }

    char url[512];
    snprintf(url, sizeof(url), "%s/api/dm/inbox?limit=%d&mark_delivered=%d", base, limit, keep ? 0 : 1);
    ff_http_resp_t r;
    if (ff_http_get_json_auth(url, socks5, v.session_id, v.csrf, &r) != 0) {
        ff_prekeys_free(&st);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("dm inbox failed: %s", ff_http_last_error());
    }

    char **msgs = NULL;
    size_t msg_count = 0;
    if (json_split_messages(r.data, &msgs, &msg_count) != 0) {
        ff_http_resp_free(&r);
        ff_prekeys_free(&st);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("failed to parse inbox");
    }
    ff_http_resp_free(&r);

    pk_cache_entry *cache = NULL;
    size_t cache_n = 0;

    for (size_t i = 0; i < msg_count; i++) {
        char *mjson = msgs[i];
        char *from = ff_json_get_str(mjson, "from");
        char *to = ff_json_get_str(mjson, "to");
        char *kem_id = ff_json_get_str(mjson, "kem_id");
        char *prekey_id_b64u = ff_json_get_str(mjson, "prekey_id");
        char *ct_b64 = ff_json_get_str(mjson, "ct_b64");
        char *nonce_b64 = ff_json_get_str(mjson, "dm_nonce_b64");
        char *cipher_b64 = ff_json_get_str(mjson, "ciphertext_b64");
        char *tag_b64 = ff_json_get_str(mjson, "tag_b64");
        char *sig_b64 = ff_json_get_str(mjson, "sig_b64");

        if (!from || !to || !kem_id || !prekey_id_b64u || !ct_b64 || !nonce_b64 || !cipher_b64 || !tag_b64 || !sig_b64) {
            fprintf(stderr, "WARN: malformed DM packet\n");
            free(from); free(to); free(kem_id); free(prekey_id_b64u);
            free(ct_b64); free(nonce_b64); free(cipher_b64); free(tag_b64); free(sig_b64);
            continue;
        }

        uint8_t *prekey_id_raw = NULL; size_t prekey_id_len = 0;
        uint8_t *ct = NULL; size_t ct_len = 0;
        uint8_t *nonce = NULL; size_t nonce_len = 0;
        uint8_t *cipher = NULL; size_t cipher_len = 0;
        uint8_t *tag = NULL; size_t tag_len = 0;
        uint8_t *sig = NULL; size_t sig_len = 0;

        if (ff_b64u_dec(prekey_id_b64u, &prekey_id_raw, &prekey_id_len) != 0 ||
            ff_b64dec(ct_b64, &ct, &ct_len) != 0 ||
            ff_b64dec(nonce_b64, &nonce, &nonce_len) != 0 ||
            ff_b64dec(cipher_b64, &cipher, &cipher_len) != 0 ||
            ff_b64dec(tag_b64, &tag, &tag_len) != 0 ||
            ff_b64dec(sig_b64, &sig, &sig_len) != 0) {
            fprintf(stderr, "WARN: b64 decode failed\n");
            free(prekey_id_raw); free(ct); free(nonce); free(cipher); free(tag); free(sig);
            free(from); free(to); free(kem_id); free(prekey_id_b64u);
            free(ct_b64); free(nonce_b64); free(cipher_b64); free(tag_b64); free(sig_b64);
            continue;
        }

        ff_prekey_entry *pk = NULL;
        for (size_t j = 0; j < st.count; j++) {
            if (memcmp(st.items[j].prekey_id, prekey_id_raw, FF_PREKEY_ID_LEN) == 0) {
                pk = &st.items[j];
                break;
            }
        }
        if (!pk || !pk->sk || pk->sk_len == 0) {
            fprintf(stderr, "WARN: missing local prekey for message from %s\n", from);
            free(prekey_id_raw); free(ct); free(nonce); free(cipher); free(tag); free(sig);
            free(from); free(to); free(kem_id); free(prekey_id_b64u);
            free(ct_b64); free(nonce_b64); free(cipher_b64); free(tag_b64); free(sig_b64);
            continue;
        }
        if (pk->flags & FF_PREKEY_FLAG_USED) {
            fprintf(stderr, "WARN: replay/duplicate DM rejected for used prekey (from %s)\n", from);
            free(prekey_id_raw); free(ct); free(nonce); free(cipher); free(tag); free(sig);
            free(from); free(to); free(kem_id); free(prekey_id_b64u);
            free(ct_b64); free(nonce_b64); free(cipher_b64); free(tag_b64); free(sig_b64);
            continue;
        }

        uint8_t *sender_pk = NULL; size_t sender_pk_len = 0;
        for (size_t j = 0; j < cache_n; j++) {
            if (strcmp(cache[j].nick, from) == 0) {
                sender_pk = cache[j].pk;
                sender_pk_len = cache[j].pk_len;
                break;
            }
        }
        if (!sender_pk) {
            char fetch_err[256];
            if (fetch_pk_sig(base, socks5, v.session_id, v.csrf, from,
                             &sender_pk, &sender_pk_len, fetch_err, sizeof(fetch_err)) != 0) {
                if (fetch_err[0]) {
                    fprintf(stderr, "WARN: cannot fetch pk_sig for %s: %s\n", from, fetch_err);
                } else {
                    fprintf(stderr, "WARN: cannot fetch pk_sig for %s\n", from);
                }
                free(prekey_id_raw); free(ct); free(nonce); free(cipher); free(tag); free(sig);
                free(from); free(to); free(kem_id); free(prekey_id_b64u);
                free(ct_b64); free(nonce_b64); free(cipher_b64); free(tag_b64); free(sig_b64);
                continue;
            }
            pk_cache_entry *tmp = (pk_cache_entry*)realloc(cache, (cache_n + 1) * sizeof(*tmp));
            if (!tmp) {
                free(sender_pk);
                free(prekey_id_raw); free(ct); free(nonce); free(cipher); free(tag); free(sig);
                free(from); free(to); free(kem_id); free(prekey_id_b64u);
                free(ct_b64); free(nonce_b64); free(cipher_b64); free(tag_b64); free(sig_b64);
                continue;
            }
            cache = tmp;
            cache[cache_n].nick = strdup(from);
            cache[cache_n].pk = sender_pk;
            cache[cache_n].pk_len = sender_pk_len;
            cache_n++;
        }

        uint8_t *plain = NULL; size_t plain_len = 0;
        if (ff_dm_verify_decrypt(from, to, kem_id, prekey_id_raw, prekey_id_len,
                                 ct, ct_len, nonce, nonce_len, cipher, cipher_len,
                                 tag, tag_len, sig, sig_len,
                                 pk->sk, pk->sk_len,
                                 sender_pk, sender_pk_len,
                                 &plain, &plain_len) != 0) {
            fprintf(stderr, "WARN: failed to verify/decrypt DM from %s\n", from);
        } else {
            printf("DM from %s: ", from);
            fwrite(plain, 1, plain_len, stdout);
            printf("\n");
            pk->flags |= FF_PREKEY_FLAG_USED;
        }

        if (plain) { sodium_memzero(plain, plain_len); free(plain); }
        free(prekey_id_raw); free(ct); free(nonce); free(cipher); free(tag); free(sig);
        free(from); free(to); free(kem_id); free(prekey_id_b64u);
        free(ct_b64); free(nonce_b64); free(cipher_b64); free(tag_b64); free(sig_b64);
    }

    for (size_t i = 0; i < msg_count; i++) free(msgs[i]);
    free(msgs);

    if (ff_prekeys_save(dir, pass, &st) != 0) {
        pk_cache_free(cache, cache_n);
        ff_prekeys_free(&st);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("prekeys save failed");
    }

    pk_cache_free(cache, cache_n);
    ff_prekeys_free(&st);
    ff_vault_free(&v);
    secure_free_str(&pass);
    return 0;
}

int cmd_prekeys_list(const char *dir, int verbose) {
    char *pass = prompt_pass("Vault passphrase: ");
    if (!pass) ff_die("no passphrase");

    ff_prekeys_t st;
    if (ff_prekeys_load(dir, pass, &st) != 0) {
        secure_free_str(&pass);
        ff_die("prekeys load failed");
    }

    uint64_t now = (uint64_t)time(NULL);
    size_t total = st.count, used = 0, uploaded = 0, expired = 0, available = 0;
    for (size_t i = 0; i < st.count; i++) {
        ff_prekey_entry *e = &st.items[i];
        if (e->flags & FF_PREKEY_FLAG_USED) used++;
        if (e->flags & FF_PREKEY_FLAG_UPLOADED) uploaded++;
        if (e->expires_at && e->expires_at <= now) expired++;
        if (!(e->flags & FF_PREKEY_FLAG_USED) && (!e->expires_at || e->expires_at > now)) available++;
    }

    printf("prekeys: total=%zu available=%zu uploaded=%zu used=%zu expired=%zu\n",
           total, available, uploaded, used, expired);

    if (verbose) {
        for (size_t i = 0; i < st.count; i++) {
            ff_prekey_entry *e = &st.items[i];
            char *id_b64u = NULL;
            if (ff_b64u_enc(e->prekey_id, FF_PREKEY_ID_LEN, &id_b64u) != 0) {
                id_b64u = NULL;
            }
            printf("  %s kem=%s created=%llu expires=%llu flags=%u\n",
                   id_b64u ? id_b64u : "",
                   e->kem_id,
                   (unsigned long long)e->created_at,
                   (unsigned long long)e->expires_at,
                   (unsigned)e->flags);
            free(id_b64u);
        }
    }

    ff_prekeys_free(&st);
    secure_free_str(&pass);
    return 0;
}

int cmd_prekeys_prune(const char *dir, int prune_used, int prune_expired) {
    if (!prune_used && !prune_expired) ff_die("prekeys-prune: nothing to prune (use --used/--expired)");
    char *pass = prompt_pass("Vault passphrase: ");
    if (!pass) ff_die("no passphrase");

    ff_prekeys_t st;
    if (ff_prekeys_load(dir, pass, &st) != 0) {
        secure_free_str(&pass);
        ff_die("prekeys load failed");
    }

    uint64_t now = (uint64_t)time(NULL);
    ff_prekey_entry *new_items = (ff_prekey_entry*)calloc(st.count, sizeof(ff_prekey_entry));
    if (!new_items && st.count > 0) {
        ff_prekeys_free(&st);
        secure_free_str(&pass);
        ff_die("oom");
    }
    size_t kept = 0;
    for (size_t i = 0; i < st.count; i++) {
        ff_prekey_entry *e = &st.items[i];
        int drop = 0;
        if (prune_used && (e->flags & FF_PREKEY_FLAG_USED)) drop = 1;
        if (prune_expired && e->expires_at && e->expires_at <= now) drop = 1;
        if (drop) {
            if (e->sk) { sodium_memzero(e->sk, e->sk_len); free(e->sk); }
            if (e->pk) free(e->pk);
            continue;
        }
        new_items[kept++] = *e;
    }

    free(st.items);
    st.items = new_items;
    st.count = kept;

    if (ff_prekeys_save(dir, pass, &st) != 0) {
        ff_prekeys_free(&st);
        secure_free_str(&pass);
        ff_die("prekeys save failed");
    }

    printf("OK: prekeys pruned, kept=%zu\n", kept);

    ff_prekeys_free(&st);
    secure_free_str(&pass);
    return 0;
}

static char *dup_trimmed_copy(const char *in) {
    if (!in) return NULL;
    const unsigned char *s = (const unsigned char *)in;
    while (*s && isspace(*s)) s++;
    const unsigned char *e = s + strlen((const char *)s);
    while (e > s && isspace(*(e - 1))) e--;
    size_t n = (size_t)(e - s);
    char *out = (char *)malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, s, n);
    out[n] = 0;
    return out;
}

static char *url_encode_component(const char *in) {
    if (!in) return NULL;
    size_t len = strlen(in);
    size_t cap = len * 3 + 1;
    char *out = (char *)malloc(cap);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)in[i];
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out[j++] = (char)c;
        } else {
            snprintf(out + j, 4, "%%%02X", (unsigned)c);
            j += 3;
        }
    }
    out[j] = 0;
    return out;
}

static char *resolve_optional_token(const char *inline_token,
                                    const char *file_path,
                                    const char *env_name,
                                    const char *label,
                                    const char *source_hint) {
    int sources = 0;
    if (inline_token && inline_token[0]) sources++;
    if (file_path && file_path[0]) sources++;
    if (env_name && env_name[0]) sources++;
    if (sources > 1) {
        ff_die("%s: use only one source (%s)", label, source_hint);
    }

    char *raw = NULL;
    if (inline_token && inline_token[0]) {
        raw = strdup(inline_token);
    } else if (file_path && file_path[0]) {
        raw = read_file_str(file_path, NULL);
        if (!raw) ff_die("%s: failed to read token file: %s", label, file_path);
    } else if (env_name && env_name[0]) {
        const char *v = getenv(env_name);
        if (!v || !v[0]) ff_die("%s: env var %s is empty or missing", label, env_name);
        raw = strdup(v);
    }
    if (!raw) return NULL;

    char *trim = dup_trimmed_copy(raw);
    free(raw);
    if (!trim) ff_die("oom");
    if (!trim[0]) {
        free(trim);
        return NULL;
    }
    return trim;
}

static int contains_ascii_case_insensitive(const char *haystack, const char *needle) {
    if (!haystack || !needle || !needle[0]) return 0;
    size_t needle_len = strlen(needle);
    if (needle_len == 0) return 0;
    for (size_t i = 0; haystack[i]; i++) {
        size_t j = 0;
        while (j < needle_len && haystack[i + j] &&
               tolower((unsigned char)haystack[i + j]) == tolower((unsigned char)needle[j])) {
            j++;
        }
        if (j == needle_len) return 1;
    }
    return 0;
}

static char *http_error_detail_from_response(const ff_http_resp_t *resp) {
    if (!resp || !resp->data || !resp->data[0]) return NULL;

    char *detail = ff_json_get_str(resp->data, "detail");
    if (!detail) detail = ff_json_get_str(resp->data, "error");
    if (!detail) detail = ff_json_get_str(resp->data, "message");

    if (detail) {
        char *trim = dup_trimmed_copy(detail);
        free(detail);
        if (trim && trim[0]) return trim;
        free(trim);
    }
    return dup_trimmed_copy(resp->data);
}

static int is_missing_capability_token_error(long status, const char *detail) {
    const char *d = detail ? detail : "";
    if (contains_ascii_case_insensitive(d, "action token required")) return 1;
    if (contains_ascii_case_insensitive(d, "invalid action token")) return 1;
    if (contains_ascii_case_insensitive(d, "action token mismatch")) return 1;
    if (contains_ascii_case_insensitive(d, "missing seller quorum proof in action token")) return 1;
    if (contains_ascii_case_insensitive(d, "missing seller req_id quorum proof in action token")) return 1;
    if (contains_ascii_case_insensitive(d, "authorization scheme must be bearer")) return 1;
    if (contains_ascii_case_insensitive(d, "empty bearer token")) return 1;
    if (contains_ascii_case_insensitive(d, "bad authorization header format")) return 1;
    if ((status == 401 || status == 403) &&
        (contains_ascii_case_insensitive(d, "action token") ||
         contains_ascii_case_insensitive(d, "signer_action_token") ||
         contains_ascii_case_insensitive(d, "signer_sign_action_token") ||
         contains_ascii_case_insensitive(d, "signer_submit_action_token"))) {
        return 1;
    }
    return 0;
}

static int is_policy_reject_error(long status, const char *detail) {
    const char *d = detail ? detail : "";
    if (contains_ascii_case_insensitive(d, "policy reject")) return 1;
    if (contains_ascii_case_insensitive(d, "policy violation")) return 1;
    if (contains_ascii_case_insensitive(d, "describe_transfer")) return 1;
    if (contains_ascii_case_insensitive(d, "tx_sign_rejected")) return 1;
    if (contains_ascii_case_insensitive(d, "snapshot_hash mismatch")) return 1;
    if (contains_ascii_case_insensitive(d, "txset_hash mismatch")) return 1;
    if (contains_ascii_case_insensitive(d, "unexpected recipient")) return 1;
    if (contains_ascii_case_insensitive(d, "unlock_time")) return 1;
    if (contains_ascii_case_insensitive(d, "fee") &&
        contains_ascii_case_insensitive(d, "policy")) {
        return 1;
    }
    if (status == 400 &&
        (contains_ascii_case_insensitive(d, "policy") ||
         contains_ascii_case_insensitive(d, "snapshot") ||
         contains_ascii_case_insensitive(d, "txset"))) {
        return 1;
    }
    return 0;
}

static void die_escrow_confirm_http_error(const char *label, const ff_http_resp_t *resp) {
    long status = ff_http_last_status();
    const char *fallback = ff_http_last_error();
    char *detail_owned = http_error_detail_from_response(resp);
    const char *detail = (detail_owned && detail_owned[0]) ? detail_owned : fallback;

    if (is_missing_capability_token_error(status, detail)) {
        ff_die(
            "%s failed: missing/invalid signer capability token. Use one of "
            "--signer-action-token | --signer-action-token-file | --signer-action-token-env. "
            "server_detail=%s",
            label,
            detail
        );
    }
    if (is_policy_reject_error(status, detail)) {
        ff_die(
            "%s failed: signer policy rejected this txset (snapshot/recipient/fee/unlock checks). "
            "server_detail=%s",
            label,
            detail
        );
    }
    ff_die("%s failed: %s", label, fallback);
}

static char *normalize_idempotency_key(const char *raw_key, const char *label) {
    char *key = dup_trimmed_copy(raw_key);
    if (!key) return NULL;
    if (!key[0]) {
        free(key);
        return NULL;
    }
    size_t n = strlen(key);
    if (n > 128) {
        ff_die("%s: --idempotency-key too long (max 128 chars)", label);
    }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)key[i];
        int ok = ((c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') ||
                  c == '-' || c == '_' || c == '.' || c == ':');
        if (!ok) {
            ff_die(
                "%s: --idempotency-key has invalid chars; allowed [A-Za-z0-9-_.:]",
                label
            );
        }
    }
    return key;
}

static int should_retry_escrow_http_error(
    long status,
    const char *detail,
    int attempt,
    int retry_max,
    const char *idempotency_key
) {
    if (!idempotency_key || !idempotency_key[0]) return 0;
    if (retry_max <= 0 || attempt >= retry_max) return 0;

    const char *d = detail ? detail : "";
    if (status == 409 && contains_ascii_case_insensitive(d, "already in progress")) return 1;
    if (status == 408 || status == 429 || status == 502 || status == 503 || status == 504) return 1;
    if (status <= 0 && contains_ascii_case_insensitive(d, "transport error")) return 1;
    return 0;
}

static char *build_confirm_json_body(const char *nick,
                                     const char *token,
                                     const char *tx_data_hex,
                                     const char *txid,
                                     const char *signer_wallet_password,
                                     const char *signer_action_token,
                                     const char *signer_sign_action_token,
                                     const char *signer_submit_action_token) {
    char *json = NULL;
    size_t len = 0;
    int first = 1;

    append_or_die(&json, &len, "{");

#define APPEND_FIELD_STR(key, val)                          \
    do {                                                    \
        if ((val) && (val)[0]) {                            \
            if (!first) append_or_die(&json, &len, ",");    \
            append_or_die(&json, &len, "\"" key "\":\"");   \
            append_json_escaped_or_die(&json, &len, (val)); \
            append_or_die(&json, &len, "\"");               \
            first = 0;                                      \
        }                                                   \
    } while (0)

    APPEND_FIELD_STR("nick", nick);
    APPEND_FIELD_STR("token", token);
    APPEND_FIELD_STR("txid", txid);
    APPEND_FIELD_STR("tx_data_hex", tx_data_hex);
    APPEND_FIELD_STR("signer_wallet_password", signer_wallet_password);
    APPEND_FIELD_STR("signer_action_token", signer_action_token);
    APPEND_FIELD_STR("signer_sign_action_token", signer_sign_action_token);
    APPEND_FIELD_STR("signer_submit_action_token", signer_submit_action_token);

#undef APPEND_FIELD_STR

    append_or_die(&json, &len, "}");
    return json;
}

int cmd_escrow_proposal_show(const char *base, const char *socks5,
                             unsigned long long escrow_id,
                             const char *nick, const char *token) {
    pf_require_escrow_base_url_policy(base, 0, "escrow-proposal");
    require_tor(base, socks5);
    if (!nick || !nick[0] || !token || !token[0]) {
        ff_die("escrow-proposal requires --nick and --token");
    }

    char *nick_e = url_encode_component(nick);
    char *token_e = url_encode_component(token);
    if (!nick_e || !token_e) {
        free(nick_e);
        secure_free_str(&token_e);
        ff_die("oom");
    }

    char url[1024];
    snprintf(
        url,
        sizeof(url),
        "%s/escrows/%llu/xmr/proposal?nick=%s&token=%s",
        base,
        escrow_id,
        nick_e,
        token_e
    );

    ff_http_resp_t r;
    if (ff_http_get_json_auth(url, socks5, NULL, NULL, &r) != 0) {
        free(nick_e);
        secure_free_str(&token_e);
        ff_die("escrow-proposal failed: %s", ff_http_last_error());
    }
    printf("%s\n", r.data ? r.data : "{}");
    ff_http_resp_free(&r);
    free(nick_e);
    secure_free_str(&token_e);
    return 0;
}

static int fetch_proposal_response(
    const char *base,
    const char *socks5,
    unsigned long long escrow_id,
    const char *nick,
    const char *token,
    ff_http_resp_t *out
) {
    pf_require_escrow_base_url_policy(base, 0, "escrow-proposal");
    require_tor(base, socks5);
    if (!nick || !nick[0] || !token || !token[0]) {
        ff_die("escrow-proposal requires --nick and --token");
    }

    char *nick_e = url_encode_component(nick);
    char *token_e = url_encode_component(token);
    if (!nick_e || !token_e) {
        free(nick_e);
        secure_free_str(&token_e);
        ff_die("oom");
    }

    char url[1024];
    snprintf(
        url,
        sizeof(url),
        "%s/escrows/%llu/xmr/proposal?nick=%s&token=%s",
        base,
        escrow_id,
        nick_e,
        token_e
    );
    int rc = ff_http_get_json_auth(url, socks5, NULL, NULL, out);
    free(nick_e);
    secure_free_str(&token_e);
    return rc;
}

static char *fetch_proposal_tx_data_hex(
    const char *base,
    const char *socks5,
    unsigned long long escrow_id,
    const char *nick,
    const char *token
) {
    ff_http_resp_t r;
    if (fetch_proposal_response(base, socks5, escrow_id, nick, token, &r) != 0) {
        ff_die("escrow-proposal failed: %s", ff_http_last_error());
    }
    char *tx_data_hex = ff_json_get_str(r.data, "tx_data_hex");
    if (!tx_data_hex || !tx_data_hex[0]) {
        secure_free_str(&tx_data_hex);
        ff_http_resp_free(&r);
        ff_die("escrow-proposal returned missing tx_data_hex");
    }
    ff_http_resp_free(&r);
    return tx_data_hex;
}

int cmd_escrow_release(const char *base, const char *socks5,
                       unsigned long long escrow_id,
                       const char *nick, const char *token,
                       const char *tx_data_hex, const char *txid,
                       const char *signer_wallet_password,
                       const char *signer_action_token,
                       const char *signer_action_token_file,
                       const char *signer_action_token_env,
                       const char *signer_sign_action_token,
                       const char *signer_sign_action_token_file,
                       const char *signer_sign_action_token_env,
                       const char *signer_submit_action_token,
                       const char *signer_submit_action_token_file,
                       const char *signer_submit_action_token_env,
                       const char *idempotency_key,
                       int retry_max,
                       unsigned retry_backoff_ms) {
    pf_require_escrow_base_url_policy(base, 0, "escrow-release");
    require_tor(base, socks5);
    if (!nick || !nick[0] || !token || !token[0]) {
        ff_die("escrow-release requires --nick and --token");
    }
    if (retry_max < 0) ff_die("escrow-release: --retry-max must be >= 0");

    char *tx_data_trim = dup_trimmed_copy(tx_data_hex);
    char *txid_trim = dup_trimmed_copy(txid);
    char *wallet_pw_trim = dup_trimmed_copy(signer_wallet_password);
    char *token_legacy_inline_trim = dup_trimmed_copy(signer_action_token);
    char *token_sign_inline_trim = dup_trimmed_copy(signer_sign_action_token);
    char *token_submit_inline_trim = dup_trimmed_copy(signer_submit_action_token);
    char *idem_key_trim = normalize_idempotency_key(idempotency_key, "escrow-release");
    if ((tx_data_hex && !tx_data_trim) || (txid && !txid_trim) ||
        (signer_wallet_password && !wallet_pw_trim) ||
        (signer_action_token && !token_legacy_inline_trim) ||
        (signer_sign_action_token && !token_sign_inline_trim) ||
        (signer_submit_action_token && !token_submit_inline_trim)) {
        free(tx_data_trim);
        free(txid_trim);
        secure_free_str(&wallet_pw_trim);
        secure_free_str(&token_legacy_inline_trim);
        secure_free_str(&token_sign_inline_trim);
        secure_free_str(&token_submit_inline_trim);
        free(idem_key_trim);
        ff_die("oom");
    }
    if (tx_data_trim && !tx_data_trim[0]) {
        free(tx_data_trim);
        tx_data_trim = NULL;
    }
    if (txid_trim && !txid_trim[0]) {
        free(txid_trim);
        txid_trim = NULL;
    }
    if (!tx_data_trim && !txid_trim) {
        secure_free_str(&wallet_pw_trim);
        secure_free_str(&token_legacy_inline_trim);
        secure_free_str(&token_sign_inline_trim);
        secure_free_str(&token_submit_inline_trim);
        free(idem_key_trim);
        ff_die("escrow-release requires at least one of --tx-data-hex or --txid");
    }
    if (retry_max > 0 && (!idem_key_trim || !idem_key_trim[0])) {
        free(tx_data_trim);
        free(txid_trim);
        secure_free_str(&wallet_pw_trim);
        secure_free_str(&token_legacy_inline_trim);
        secure_free_str(&token_sign_inline_trim);
        secure_free_str(&token_submit_inline_trim);
        free(idem_key_trim);
        ff_die("escrow-release: retry requires --idempotency-key");
    }

    char *resolved_legacy_action_token = resolve_optional_token(
        token_legacy_inline_trim,
        signer_action_token_file,
        signer_action_token_env,
        "escrow-release",
        "--signer-action-token | --signer-action-token-file | --signer-action-token-env"
    );
    char *resolved_sign_action_token = resolve_optional_token(
        token_sign_inline_trim,
        signer_sign_action_token_file,
        signer_sign_action_token_env,
        "escrow-release",
        "--signer-sign-action-token | --signer-sign-action-token-file | --signer-sign-action-token-env"
    );
    char *resolved_submit_action_token = resolve_optional_token(
        token_submit_inline_trim,
        signer_submit_action_token_file,
        signer_submit_action_token_env,
        "escrow-release",
        "--signer-submit-action-token | --signer-submit-action-token-file | --signer-submit-action-token-env"
    );
    secure_free_str(&token_legacy_inline_trim);
    secure_free_str(&token_sign_inline_trim);
    secure_free_str(&token_submit_inline_trim);

    if (resolved_sign_action_token &&
        resolved_submit_action_token &&
        strcmp(resolved_sign_action_token, resolved_submit_action_token) == 0) {
        free(tx_data_trim);
        free(txid_trim);
        secure_free_str(&wallet_pw_trim);
        secure_free_str(&resolved_legacy_action_token);
        secure_free_str(&resolved_sign_action_token);
        secure_free_str(&resolved_submit_action_token);
        free(idem_key_trim);
        ff_die(
            "escrow-release: split tokens must be distinct (--signer-sign-action-token != --signer-submit-action-token)"
        );
    }

    const char *effective_sign_action_token =
        resolved_sign_action_token ? resolved_sign_action_token : resolved_legacy_action_token;
    const char *effective_submit_action_token =
        resolved_submit_action_token ? resolved_submit_action_token : resolved_legacy_action_token;

    char *body = build_confirm_json_body(
        nick,
        token,
        tx_data_trim,
        txid_trim,
        wallet_pw_trim,
        resolved_legacy_action_token,
        effective_sign_action_token,
        effective_submit_action_token
    );

    char url[512];
    snprintf(url, sizeof(url), "%s/escrows/%llu/xmr/release", base, escrow_id);

    int attempt = 0;
    for (;;) {
        ff_http_resp_t r;
        if (ff_http_post_json_idempotent(url, socks5, body, idem_key_trim, &r) == 0) {
            printf("%s\n", r.data ? r.data : "{}");
            ff_http_resp_free(&r);
            break;
        }
        long status = ff_http_last_status();
        char *detail_owned = http_error_detail_from_response(&r);
        const char *detail = (detail_owned && detail_owned[0]) ? detail_owned : ff_http_last_error();
        int retry = should_retry_escrow_http_error(
            status,
            detail,
            attempt,
            retry_max,
            idem_key_trim
        );
        free(detail_owned);
        if (retry) {
            attempt++;
            fprintf(
                stderr,
                "escrow-release retry %d/%d after transient error (status=%ld)\n",
                attempt,
                retry_max,
                status
            );
            ff_http_resp_free(&r);
            if (retry_backoff_ms > 0) usleep((useconds_t)retry_backoff_ms * 1000U);
            continue;
        }
        secure_free_str(&body);
        die_escrow_confirm_http_error("escrow-release", &r);
    }

    free(tx_data_trim);
    free(txid_trim);
    secure_free_str(&wallet_pw_trim);
    secure_free_str(&resolved_legacy_action_token);
    secure_free_str(&resolved_sign_action_token);
    secure_free_str(&resolved_submit_action_token);
    free(idem_key_trim);
    secure_free_str(&body);
    return 0;
}

int cmd_escrow_refund(const char *base, const char *socks5,
                      unsigned long long escrow_id,
                      const char *nick, const char *token,
                      const char *tx_data_hex, const char *txid,
                      const char *signer_action_token,
                      const char *signer_action_token_file,
                      const char *signer_action_token_env,
                      const char *idempotency_key,
                      int retry_max,
                      unsigned retry_backoff_ms) {
    pf_require_escrow_base_url_policy(base, 0, "escrow-refund");
    require_tor(base, socks5);
    if (!nick || !nick[0] || !token || !token[0]) {
        ff_die("escrow-refund requires --nick and --token");
    }
    if (retry_max < 0) ff_die("escrow-refund: --retry-max must be >= 0");

    char *tx_data_trim = dup_trimmed_copy(tx_data_hex);
    char *txid_trim = dup_trimmed_copy(txid);
    char *token_inline_trim = dup_trimmed_copy(signer_action_token);
    char *idem_key_trim = normalize_idempotency_key(idempotency_key, "escrow-refund");
    if ((tx_data_hex && !tx_data_trim) || (txid && !txid_trim) ||
        (signer_action_token && !token_inline_trim)) {
        free(tx_data_trim);
        free(txid_trim);
        secure_free_str(&token_inline_trim);
        free(idem_key_trim);
        ff_die("oom");
    }
    if (tx_data_trim && !tx_data_trim[0]) {
        free(tx_data_trim);
        tx_data_trim = NULL;
    }
    if (txid_trim && !txid_trim[0]) {
        free(txid_trim);
        txid_trim = NULL;
    }
    if (!tx_data_trim && !txid_trim) {
        secure_free_str(&token_inline_trim);
        free(idem_key_trim);
        ff_die("escrow-refund requires at least one of --tx-data-hex or --txid");
    }
    if (retry_max > 0 && (!idem_key_trim || !idem_key_trim[0])) {
        free(tx_data_trim);
        free(txid_trim);
        secure_free_str(&token_inline_trim);
        free(idem_key_trim);
        ff_die("escrow-refund: retry requires --idempotency-key");
    }

    char *resolved_action_token = resolve_optional_token(
        token_inline_trim,
        signer_action_token_file,
        signer_action_token_env,
        "escrow-refund",
        "--signer-action-token | --signer-action-token-file | --signer-action-token-env"
    );
    secure_free_str(&token_inline_trim);

    char *body = build_confirm_json_body(
        nick,
        token,
        tx_data_trim,
        txid_trim,
        NULL,
        resolved_action_token,
        NULL,
        NULL
    );

    char url[512];
    snprintf(url, sizeof(url), "%s/escrows/%llu/xmr/refund", base, escrow_id);

    int attempt = 0;
    for (;;) {
        ff_http_resp_t r;
        if (ff_http_post_json_idempotent(url, socks5, body, idem_key_trim, &r) == 0) {
            printf("%s\n", r.data ? r.data : "{}");
            ff_http_resp_free(&r);
            break;
        }
        long status = ff_http_last_status();
        char *detail_owned = http_error_detail_from_response(&r);
        const char *detail = (detail_owned && detail_owned[0]) ? detail_owned : ff_http_last_error();
        int retry = should_retry_escrow_http_error(
            status,
            detail,
            attempt,
            retry_max,
            idem_key_trim
        );
        free(detail_owned);
        if (retry) {
            attempt++;
            fprintf(
                stderr,
                "escrow-refund retry %d/%d after transient error (status=%ld)\n",
                attempt,
                retry_max,
                status
            );
            ff_http_resp_free(&r);
            if (retry_backoff_ms > 0) usleep((useconds_t)retry_backoff_ms * 1000U);
            continue;
        }
        secure_free_str(&body);
        die_escrow_confirm_http_error("escrow-refund", &r);
    }

    free(tx_data_trim);
    free(txid_trim);
    secure_free_str(&resolved_action_token);
    free(idem_key_trim);
    secure_free_str(&body);
    return 0;
}

static void validate_txid_hex_or_die(const char *txid, const char *ctx_label) {
    if (!txid || !txid[0]) {
        ff_die("%s requires non-empty --txid", ctx_label);
    }
    if (strlen(txid) != 64) {
        ff_die("%s: --txid must be 64 hex chars", ctx_label);
    }
    for (size_t i = 0; txid[i]; i++) {
        unsigned char c = (unsigned char)txid[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            ff_die("%s: --txid must be 64 hex chars", ctx_label);
        }
    }
}

static char *build_legacy_confirm_idempotency_key_or_die(const char *ctx_label,
                                                         const char *prefix,
                                                         unsigned long long escrow_id,
                                                         const char *nick,
                                                         const char *scope,
                                                         const char *txid) {
    const char *effective_prefix = (prefix && prefix[0]) ? prefix : "stagenet-live";
    char *prefix_trim = normalize_idempotency_key(effective_prefix, ctx_label);
    char *nick_trim = dup_trimmed_copy(nick);
    char *txid_trim = dup_trimmed_copy(txid);
    if (!prefix_trim || !nick_trim || !txid_trim) {
        free(prefix_trim);
        free(nick_trim);
        free(txid_trim);
        ff_die("oom");
    }
    if (!nick_trim[0] || !txid_trim[0]) {
        free(prefix_trim);
        free(nick_trim);
        free(txid_trim);
        ff_die("%s requires non-empty --nick and --txid", ctx_label);
    }
    validate_txid_hex_or_die(txid_trim, ctx_label);

    size_t cap = strlen(prefix_trim) + strlen(nick_trim) + strlen(scope) + strlen(txid_trim) + 96;
    char *out = (char *)malloc(cap);
    if (!out) {
        free(prefix_trim);
        free(nick_trim);
        free(txid_trim);
        ff_die("oom");
    }
    snprintf(out, cap, "%s:%llu:%s:%s:%s", prefix_trim, escrow_id, nick_trim, scope, txid_trim);
    free(prefix_trim);
    free(nick_trim);
    free(txid_trim);
    return out;
}

int cmd_escrow_confirm_release(const char *base,
                               const char *socks5,
                               unsigned long long escrow_id,
                               const char *nick,
                               const char *token,
                               const char *txid,
                               const char *idempotency_prefix,
                               int retry_max,
                               unsigned retry_backoff_ms) {
    char *idem_key = build_legacy_confirm_idempotency_key_or_die(
        "escrow-confirm-release",
        idempotency_prefix,
        escrow_id,
        nick,
        "release",
        txid
    );
    int rc = cmd_escrow_release(
        base,
        socks5,
        escrow_id,
        nick,
        token,
        NULL,
        txid,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        idem_key,
        retry_max,
        retry_backoff_ms
    );
    free(idem_key);
    return rc;
}

int cmd_escrow_confirm_refund(const char *base,
                              const char *socks5,
                              unsigned long long escrow_id,
                              const char *nick,
                              const char *token,
                              const char *txid,
                              const char *idempotency_prefix,
                              int retry_max,
                              unsigned retry_backoff_ms) {
    char *idem_key = build_legacy_confirm_idempotency_key_or_die(
        "escrow-confirm-refund",
        idempotency_prefix,
        escrow_id,
        nick,
        "refund",
        txid
    );
    int rc = cmd_escrow_refund(
        base,
        socks5,
        escrow_id,
        nick,
        token,
        NULL,
        txid,
        NULL,
        NULL,
        NULL,
        idem_key,
        retry_max,
        retry_backoff_ms
    );
    free(idem_key);
    return rc;
}

int cmd_escrow_release_pipeline(
    const char *base,
    const char *socks5,
    unsigned long long escrow_id,
    const char *seller_nick,
    const char *seller_token,
    const char *arbiter_nick,
    const char *arbiter_token,
    const char *seller_wallet_password,
    const char *seller_signer_action_token,
    const char *seller_signer_action_token_file,
    const char *seller_signer_action_token_env,
    const char *seller_signer_sign_action_token,
    const char *seller_signer_sign_action_token_file,
    const char *seller_signer_sign_action_token_env,
    const char *seller_signer_submit_action_token,
    const char *seller_signer_submit_action_token_file,
    const char *seller_signer_submit_action_token_env,
    const char *arbiter_signer_action_token,
    const char *arbiter_signer_action_token_file,
    const char *arbiter_signer_action_token_env,
    const char *arbiter_signer_submit_action_token,
    const char *arbiter_signer_submit_action_token_file,
    const char *arbiter_signer_submit_action_token_env,
    const char *idempotency_prefix,
    int retry_max,
    unsigned retry_backoff_ms
) {
    if (!seller_nick || !seller_nick[0] || !seller_token || !seller_token[0]) {
        ff_die("escrow-release-pipeline requires --seller-nick --seller-token");
    }
    if (!arbiter_nick || !arbiter_nick[0] || !arbiter_token || !arbiter_token[0]) {
        ff_die("escrow-release-pipeline requires --arbiter-nick --arbiter-token");
    }
    if (retry_max < 0) {
        ff_die("escrow-release-pipeline: --retry-max must be >= 0");
    }
    pf_require_escrow_base_url_policy(base, 0, "escrow-release-pipeline");

    char *idem_prefix_trim = normalize_idempotency_key(
        idempotency_prefix,
        "escrow-release-pipeline"
    );
    if (retry_max > 0 && (!idem_prefix_trim || !idem_prefix_trim[0])) {
        free(idem_prefix_trim);
        ff_die("escrow-release-pipeline: retry requires --idempotency-prefix");
    }

    char *seller_idem = NULL;
    char *arbiter_idem = NULL;
    if (idem_prefix_trim && idem_prefix_trim[0]) {
        size_t n = strlen(idem_prefix_trim);
        size_t seller_cap = n + 32;
        size_t arbiter_cap = n + 32;
        seller_idem = (char *)malloc(seller_cap);
        arbiter_idem = (char *)malloc(arbiter_cap);
        if (!seller_idem || !arbiter_idem) {
            free(idem_prefix_trim);
            free(seller_idem);
            free(arbiter_idem);
            ff_die("oom");
        }
        snprintf(seller_idem, seller_cap, "%s:seller_release", idem_prefix_trim);
        snprintf(arbiter_idem, arbiter_cap, "%s:arbiter_release", idem_prefix_trim);
    }

    fprintf(stderr, "pipeline: fetching proposal tx_data_hex (arbiter auth)\n");
    char *tx_data_hex =
        fetch_proposal_tx_data_hex(base, socks5, escrow_id, arbiter_nick, arbiter_token);

    fprintf(stderr, "pipeline: seller release step\n");
    cmd_escrow_release(
        base,
        socks5,
        escrow_id,
        seller_nick,
        seller_token,
        tx_data_hex,
        NULL,
        seller_wallet_password,
        seller_signer_action_token,
        seller_signer_action_token_file,
        seller_signer_action_token_env,
        seller_signer_sign_action_token,
        seller_signer_sign_action_token_file,
        seller_signer_sign_action_token_env,
        seller_signer_submit_action_token,
        seller_signer_submit_action_token_file,
        seller_signer_submit_action_token_env,
        seller_idem,
        retry_max,
        retry_backoff_ms
    );

    fprintf(stderr, "pipeline: arbiter release step\n");
    cmd_escrow_release(
        base,
        socks5,
        escrow_id,
        arbiter_nick,
        arbiter_token,
        tx_data_hex,
        NULL,
        NULL,
        arbiter_signer_action_token,
        arbiter_signer_action_token_file,
        arbiter_signer_action_token_env,
        NULL,
        NULL,
        NULL,
        arbiter_signer_submit_action_token,
        arbiter_signer_submit_action_token_file,
        arbiter_signer_submit_action_token_env,
        arbiter_idem,
        retry_max,
        retry_backoff_ms
    );

    secure_free_str(&tx_data_hex);
    free(idem_prefix_trim);
    free(seller_idem);
    free(arbiter_idem);
    return 0;
}

static const char *resolve_orch_bin(const char *orch_bin_opt) {
    if (orch_bin_opt && orch_bin_opt[0]) return orch_bin_opt;
    const char *env_bin = getenv("NXMS_ORCH_BIN");
    if (env_bin && env_bin[0]) return env_bin;
    return "nxms-escrow-orchestrator";
}

static const char *resolve_orch_db_path(const char *orch_db_path_opt) {
    if (orch_db_path_opt && orch_db_path_opt[0]) return orch_db_path_opt;
    const char *env_db = getenv("NXMS_ORCH_DB_PATH");
    if (env_db && env_db[0]) return env_db;
    return "nxms_orchestrator.db";
}

static int orch_has_forbidden_ctl(const char *s) {
    if (!s) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '\r' || *p == '\n') return 1;
    }
    return 0;
}

static int orch_env_key_is_safe(const char *key) {
    if (!key || !key[0]) return 0;
    if (!(key[0] == '_' || isalpha((unsigned char)key[0]))) return 0;
    for (size_t i = 1; key[i]; i++) {
        unsigned char c = (unsigned char)key[i];
        if (c == '=') return 0;
        if (!(c == '_' || isalnum(c))) return 0;
    }
    return 1;
}

static char *orch_env_join_kv_dup(const char *key, const char *value) {
    if (!key || !value) return NULL;
    size_t klen = strlen(key);
    size_t vlen = strlen(value);
    char *out = (char *)malloc(klen + 1 + vlen + 1);
    if (!out) return NULL;
    memcpy(out, key, klen);
    out[klen] = '=';
    memcpy(out + klen + 1, value, vlen);
    out[klen + 1 + vlen] = 0;
    return out;
}

static void orch_free_envp_secure(char **envp, size_t n) {
    if (!envp) return;
    for (size_t i = 0; i < n; i++) {
        if (!envp[i]) continue;
        sodium_memzero(envp[i], strlen(envp[i]));
        free(envp[i]);
        envp[i] = NULL;
    }
    free(envp);
}

static int orch_validate_bin_path(const char *orch_bin, char *err, size_t err_cap) {
    if (err && err_cap > 0) err[0] = 0;
    if (!orch_bin || !orch_bin[0]) {
        if (err && err_cap > 0) snprintf(err, err_cap, "missing orchestrator binary path");
        return -1;
    }
    if (orch_has_forbidden_ctl(orch_bin)) {
        if (err && err_cap > 0) snprintf(err, err_cap, "orchestrator path contains forbidden control characters");
        return -1;
    }
    if (orch_bin[0] != '/') {
        if (err && err_cap > 0) {
            snprintf(err, err_cap,
                     "orchestrator path must be absolute (use --orch-bin or NXMS_ORCH_BIN); PATH lookup disabled");
        }
        return -1;
    }

    struct stat st;
    if (lstat(orch_bin, &st) != 0) {
        if (err && err_cap > 0) snprintf(err, err_cap, "lstat(%s) failed: %s", orch_bin, strerror(errno));
        return -1;
    }
    if (S_ISLNK(st.st_mode)) {
        if (err && err_cap > 0) snprintf(err, err_cap, "orchestrator path must not be a symlink: %s", orch_bin);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        if (err && err_cap > 0) snprintf(err, err_cap, "orchestrator path is not a regular file: %s", orch_bin);
        return -1;
    }
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        if (err && err_cap > 0) snprintf(err, err_cap, "orchestrator binary is group/world-writable: %s", orch_bin);
        return -1;
    }
    {
        uid_t me = geteuid();
        if (st.st_uid != 0 && st.st_uid != me) {
            if (err && err_cap > 0) {
                snprintf(err, err_cap,
                         "orchestrator binary owner uid=%lu is not trusted (expected root or euid=%lu): %s",
                         (unsigned long)st.st_uid, (unsigned long)me, orch_bin);
            }
            return -1;
        }
    }
    if (access(orch_bin, X_OK) != 0) {
        if (err && err_cap > 0) snprintf(err, err_cap, "orchestrator binary is not executable: %s", orch_bin);
        return -1;
    }
    return 0;
}

static int orch_pipe_cloexec(int pipefd[2]) {
#if defined(__linux__) && defined(O_CLOEXEC)
    if (pipe2(pipefd, O_CLOEXEC) == 0) return 0;
    if (errno != ENOSYS && errno != EINVAL) return -1;
#endif
    if (pipe(pipefd) != 0) return -1;
    int flags0 = fcntl(pipefd[0], F_GETFD);
    int flags1 = fcntl(pipefd[1], F_GETFD);
    if (flags0 < 0 || flags1 < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (fcntl(pipefd[0], F_SETFD, flags0 | FD_CLOEXEC) != 0 ||
        fcntl(pipefd[1], F_SETFD, flags1 | FD_CLOEXEC) != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    return 0;
}

static void orch_exec_child_sanitized(const char *orch_bin,
                                      char *const argv[],
                                      const pf_env_kv_t *envs,
                                      size_t env_count) {
    umask(077);

    size_t base_envs = 3;
    size_t cap = base_envs + env_count + 1;
    char **envp = (char **)calloc(cap, sizeof(char *));
    if (!envp) {
        perror("calloc");
        _exit(127);
    }

    size_t n = 0;
    envp[n++] = orch_env_join_kv_dup("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    envp[n++] = orch_env_join_kv_dup("LANG", "C");
    envp[n++] = orch_env_join_kv_dup("LC_ALL", "C");
    if (!envp[0] || !envp[1] || !envp[2]) {
        orch_free_envp_secure(envp, n);
        perror("malloc");
        _exit(127);
    }

    for (size_t i = 0; i < env_count; i++) {
        const char *k = (envs && envs[i].key) ? envs[i].key : NULL;
        const char *v = (envs && envs[i].value) ? envs[i].value : "";
        if (!k || !k[0]) continue;
        if (!orch_env_key_is_safe(k)) {
            fprintf(stderr, "invalid orchestrator env key: %s\n", k);
            orch_free_envp_secure(envp, n);
            _exit(127);
        }
        if (orch_has_forbidden_ctl(v)) {
            fprintf(stderr, "invalid orchestrator env value (control chars) for key: %s\n", k);
            orch_free_envp_secure(envp, n);
            _exit(127);
        }
        envp[n] = orch_env_join_kv_dup(k, v);
        if (!envp[n]) {
            orch_free_envp_secure(envp, n);
            perror("malloc");
            _exit(127);
        }
        n++;
    }
    envp[n] = NULL;

    execve(orch_bin, argv, envp);
    perror("execve");
    orch_free_envp_secure(envp, n);
    _exit(127);
}

static void require_escrow_id_hex_32(const char *escrow_id_hex) {
    if (!escrow_id_hex || !escrow_id_hex[0]) {
        ff_die("worker-route requires --escrow-id-hex");
    }
    size_t n = strlen(escrow_id_hex);
    if (n != 32) {
        ff_die("--escrow-id-hex must be exactly 32 hex chars");
    }
    for (size_t i = 0; i < n; i++) {
        if (!isxdigit((unsigned char)escrow_id_hex[i])) {
            ff_die("--escrow-id-hex must be hex");
        }
    }
}

static void require_worker_role(const char *role) {
    if (!role || !role[0]) ff_die("worker-route requires --role");
    if (strcmp(role, "buyer") != 0 &&
        strcmp(role, "seller") != 0 &&
        strcmp(role, "arbiter") != 0) {
        ff_die("--role must be one of: buyer|seller|arbiter");
    }
}

static int run_orchestrator_passthrough(const char *orch_bin, char *const argv[]) {
    char err[512];
    if (orch_validate_bin_path(orch_bin, err, sizeof(err)) != 0) {
        ff_die("orchestrator command blocked: %s", err[0] ? err : "invalid orchestrator path");
    }

    pid_t pid = fork();
    if (pid < 0) ff_die("fork failed for orchestrator command");

    if (pid == 0) {
        orch_exec_child_sanitized(orch_bin, argv, NULL, 0);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        ff_die("waitpid failed for orchestrator command");
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
    if (WIFEXITED(status)) {
        ff_die("orchestrator command failed (exit=%d)", WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
        ff_die("orchestrator command failed (signal=%d)", WTERMSIG(status));
    }
    ff_die("orchestrator command failed");
    return -1;
}

int cmd_worker_route_set(const char *orch_bin_opt,
                         const char *orch_db_path_opt,
                         const char *escrow_id_hex,
                         const char *role,
                         const char *endpoint) {
    require_escrow_id_hex_32(escrow_id_hex);
    require_worker_role(role);
    if (!endpoint || !endpoint[0]) ff_die("worker-route set requires --endpoint");

    const char *orch_bin = resolve_orch_bin(orch_bin_opt);
    const char *db_path = resolve_orch_db_path(orch_db_path_opt);
    char *const argv[] = {
        (char *)orch_bin,
        "worker-route",
        "set",
        "--db-path",
        (char *)db_path,
        "--escrow-id-hex",
        (char *)escrow_id_hex,
        "--role",
        (char *)role,
        "--endpoint",
        (char *)endpoint,
        NULL
    };
    return run_orchestrator_passthrough(orch_bin, argv);
}

int cmd_worker_route_show(const char *orch_bin_opt,
                          const char *orch_db_path_opt,
                          const char *escrow_id_hex,
                          const char *role) {
    require_escrow_id_hex_32(escrow_id_hex);
    require_worker_role(role);

    const char *orch_bin = resolve_orch_bin(orch_bin_opt);
    const char *db_path = resolve_orch_db_path(orch_db_path_opt);
    char *const argv[] = {
        (char *)orch_bin,
        "worker-route",
        "show",
        "--db-path",
        (char *)db_path,
        "--escrow-id-hex",
        (char *)escrow_id_hex,
        "--role",
        (char *)role,
        NULL
    };
    return run_orchestrator_passthrough(orch_bin, argv);
}

int cmd_worker_route_reconcile(const char *orch_bin_opt,
                               const char *orch_db_path_opt,
                               unsigned long long stale_after_ms,
                               int include_terminal,
                               unsigned limit,
                               int fail_on_findings) {
    const char *orch_bin = resolve_orch_bin(orch_bin_opt);
    const char *db_path = resolve_orch_db_path(orch_db_path_opt);

    char stale_buf[32];
    char limit_buf[16];
    snprintf(stale_buf, sizeof(stale_buf), "%llu", stale_after_ms);
    snprintf(limit_buf, sizeof(limit_buf), "%u", limit);

    char *argv[18];
    int i = 0;
    argv[i++] = (char *)orch_bin;
    argv[i++] = "worker-route";
    argv[i++] = "reconcile";
    argv[i++] = "--db-path";
    argv[i++] = (char *)db_path;
    argv[i++] = "--stale-after-ms";
    argv[i++] = stale_buf;
    argv[i++] = "--limit";
    argv[i++] = limit_buf;
    if (include_terminal) {
        argv[i++] = "--include-terminal";
    }
    if (fail_on_findings) {
        argv[i++] = "--fail-on-findings";
    }
    argv[i] = NULL;
    return run_orchestrator_passthrough(orch_bin, argv);
}

typedef enum {
    PF_ST_PASS = 0,
    PF_ST_WARN = 1,
    PF_ST_FAIL = 2,
    PF_ST_SKIP = 3
} pf_status_t;

typedef struct {
    int pass_count;
    int warn_count;
    int fail_count;
    int skip_count;
    int verbose;
    int json_mode;
    char *summary_buf;
    size_t summary_len;
    char *checks_tsv;
    size_t checks_tsv_len;
    char *checks_json;
    size_t checks_json_len;
    int checks_json_count;
} pf_ctx_t;

static const char *pf_status_str(pf_status_t st) {
    switch (st) {
        case PF_ST_PASS: return "PASS";
        case PF_ST_WARN: return "WARN";
        case PF_ST_FAIL: return "FAIL";
        case PF_ST_SKIP: return "SKIP";
        default: return "UNK";
    }
}

static int pf_is_true(const char *s) {
    if (!s || !s[0]) return 0;
    return strcmp(s, "1") == 0 ||
           strcmp(s, "true") == 0 ||
           strcmp(s, "TRUE") == 0 ||
           strcmp(s, "True") == 0 ||
           strcmp(s, "yes") == 0 ||
           strcmp(s, "YES") == 0 ||
           strcmp(s, "on") == 0 ||
           strcmp(s, "ON") == 0;
}

static const char *pf_getenv_nonempty(const char *name) {
    const char *v = getenv(name);
    if (!v || !v[0]) return NULL;
    return v;
}

static void pf_utc_now(char out[32]) {
    time_t now = time(NULL);
    struct tm tmv;
    memset(&tmv, 0, sizeof(tmv));
    gmtime_r(&now, &tmv);
    strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

static void pf_append_line(pf_ctx_t *ctx, const char *line) {
    if (!ctx || !line) return;
    if (!ctx->json_mode) {
        fputs(line, stdout);
    }
    append_or_die(&ctx->summary_buf, &ctx->summary_len, line);
}

static void pf_tsv_sanitize(const char *in, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    if (!in) {
        out[0] = 0;
        return;
    }
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < out_cap; i++) {
        char c = in[i];
        if (c == '\t' || c == '\r' || c == '\n') c = ' ';
        out[j++] = c;
    }
    out[j] = 0;
}

static void pf_record(pf_ctx_t *ctx,
                      pf_status_t st,
                      const char *check_id,
                      const char *reason_code,
                      const char *message,
                      const char *hint,
                      int verbose_only) {
    if (!ctx) return;
    switch (st) {
        case PF_ST_PASS: ctx->pass_count++; break;
        case PF_ST_WARN: ctx->warn_count++; break;
        case PF_ST_FAIL: ctx->fail_count++; break;
        case PF_ST_SKIP: ctx->skip_count++; break;
        default: break;
    }

    char reason_s[256];
    char msg_s[1024];
    char hint_s[512];
    pf_tsv_sanitize(reason_code ? reason_code : "", reason_s, sizeof(reason_s));
    pf_tsv_sanitize(message ? message : "", msg_s, sizeof(msg_s));
    pf_tsv_sanitize(hint ? hint : "", hint_s, sizeof(hint_s));

    char tsv_line[2048];
    snprintf(tsv_line, sizeof(tsv_line), "%s\t%s\t%s\t%s\t%s\n",
             pf_status_str(st),
             check_id ? check_id : "",
             reason_s,
             msg_s,
             hint_s);
    append_or_die(&ctx->checks_tsv, &ctx->checks_tsv_len, tsv_line);

    {
        char *check_esc = json_escape_or_die(check_id ? check_id : "");
        char *reason_esc = json_escape_or_die(reason_code ? reason_code : "");
        char *msg_esc = json_escape_or_die(message ? message : "");
        char *hint_esc = json_escape_or_die(hint ? hint : "");
        char obj[12288];
        snprintf(obj, sizeof(obj),
                 "%s{\"status\":\"%s\",\"check_id\":\"%s\",\"reason_code\":\"%s\",\"message\":\"%s\",\"hint\":\"%s\"}",
                 (ctx->checks_json_count > 0) ? "," : "",
                 pf_status_str(st),
                 check_esc,
                 reason_esc,
                 msg_esc,
                 hint_esc);
        append_or_die(&ctx->checks_json, &ctx->checks_json_len, obj);
        ctx->checks_json_count++;
        free(check_esc);
        free(reason_esc);
        free(msg_esc);
        free(hint_esc);
    }

    if (verbose_only && !ctx->verbose) {
        return;
    }

    char line[2300];
    if (hint && hint[0]) {
        snprintf(line, sizeof(line), "%-4s  %-24s %s (hint: %s)\n",
                 pf_status_str(st), check_id ? check_id : "-", message ? message : "", hint);
    } else {
        snprintf(line, sizeof(line), "%-4s  %-24s %s\n",
                 pf_status_str(st), check_id ? check_id : "-", message ? message : "");
    }
    pf_append_line(ctx, line);
}

static void pf_emit_json(const pf_ctx_t *ctx,
                         const char *base,
                         const char *ui_base,
                         const char *socks5,
                         const char *verdict) {
    if (!ctx) return;
    char now_s[32];
    pf_utc_now(now_s);
    char *base_esc = json_escape_or_die(base ? base : "");
    char *ui_esc = json_escape_or_die(ui_base ? ui_base : "");
    char *socks_esc = json_escape_or_die(socks5 ? socks5 : "");
    char *verdict_esc = json_escape_or_die(verdict ? verdict : "");

    printf("{\n");
    printf("  \"format\": \"nexum_cli_preflight_output_v1\",\n");
    printf("  \"generated_at_utc\": \"%s\",\n", now_s);
    printf("  \"command\": \"nexum preflight escrow\",\n");
    printf("  \"targets\": {\n");
    printf("    \"escrow_http_base\": \"%s\",\n", base_esc);
    printf("    \"nxms_serv_base\": \"%s\",\n", ui_esc);
    printf("    \"socks5\": \"%s\"\n", socks_esc);
    printf("  },\n");
    printf("  \"counts\": {\n");
    printf("    \"pass\": %d,\n", ctx->pass_count);
    printf("    \"warn\": %d,\n", ctx->warn_count);
    printf("    \"fail\": %d,\n", ctx->fail_count);
    printf("    \"skip\": %d\n", ctx->skip_count);
    printf("  },\n");
    printf("  \"verdict\": \"%s\",\n", verdict_esc);
    printf("  \"checks\": [%s]\n", ctx->checks_json ? ctx->checks_json : "");
    printf("}\n");

    free(base_esc);
    free(ui_esc);
    free(socks_esc);
    free(verdict_esc);
}

static int pf_write_text(const char *path, const char *txt) {
    if (!path || !txt) return -1;
    return ff_write_file_atomic(path, (const uint8_t *)txt, strlen(txt), 0600);
}

static int pf_join_url(char *out, size_t out_cap, const char *base, const char *suffix) {
    if (!out || out_cap == 0 || !base || !base[0] || !suffix || !suffix[0]) return -1;
    size_t bl = strlen(base);
    int base_has_slash = (bl > 0 && base[bl - 1] == '/');
    int suf_has_slash = (suffix[0] == '/');
    if (base_has_slash && suf_has_slash) {
        return snprintf(out, out_cap, "%s%s", base, suffix + 1) < (int)out_cap ? 0 : -1;
    }
    if (!base_has_slash && !suf_has_slash) {
        return snprintf(out, out_cap, "%s/%s", base, suffix) < (int)out_cap ? 0 : -1;
    }
    return snprintf(out, out_cap, "%s%s", base, suffix) < (int)out_cap ? 0 : -1;
}

static int pf_http_get_2xx(const char *url, const char *socks5, char *err, size_t err_cap, char **out_body) {
    if (err && err_cap > 0) err[0] = 0;
    if (out_body) *out_body = NULL;
    ff_http_resp_t r;
    memset(&r, 0, sizeof(r));
    if (ff_http_get_json_auth(url, socks5, NULL, NULL, &r) != 0) {
        if (err && err_cap > 0) snprintf(err, err_cap, "%s", ff_http_last_error());
        ff_http_resp_free(&r);
        return -1;
    }
    if (out_body && r.data) {
        *out_body = strdup(r.data);
    }
    ff_http_resp_free(&r);
    return 0;
}

static int pf_http_post_json_expect_auth_challenge_or_ok(const char *url,
                                                         const char *json,
                                                         char *detail,
                                                         size_t detail_cap) {
    if (detail && detail_cap > 0) detail[0] = 0;
    ff_http_resp_t r;
    memset(&r, 0, sizeof(r));
    int rc = ff_http_post_json(url, NULL, json, &r);
    long st = ff_http_last_status();
    if (rc == 0) {
        if (detail && detail_cap > 0) snprintf(detail, detail_cap, "HTTP %ld (no auth challenge)", st);
        ff_http_resp_free(&r);
        return 0;
    }
    if (st == 401) {
        if (detail && detail_cap > 0) snprintf(detail, detail_cap, "HTTP 401 auth challenge observed");
        ff_http_resp_free(&r);
        return 1;
    }
    if (detail && detail_cap > 0) snprintf(detail, detail_cap, "%s", ff_http_last_error());
    ff_http_resp_free(&r);
    return -1;
}

typedef struct {
    ff_http_resp_t *resp;
    int too_large;
    int overflow;
} pf_curl_write_ctx_t;

static int pf_ascii_streq_ci(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static int pf_http_host_is_loopback(const char *host) {
    if (!host || !host[0]) return 0;
    if (strcmp(host, "::1") == 0) return 1;
    if (strncmp(host, "127.", 4) == 0) return 1;
    if (strncmp(host, "::ffff:127.", 10) == 0) return 1;
    if (pf_ascii_streq_ci(host, "localhost")) return 1;
    return 0;
}

static int pf_http_host_is_onion_suffix(const char *host) {
    if (!host || !host[0]) return 0;
    size_t n = strlen(host);
    if (n < 6) return 0;
    return strncasecmp(host + n - 6, ".onion", 6) == 0;
}

static void pf_require_escrow_base_url_policy(const char *base,
                                              int allow_remote_http_override,
                                              const char *ctx) {
    if (!base || !base[0]) return;
    if (strncasecmp(base, "http://", 7) != 0 &&
        strncasecmp(base, "https://", 8) != 0) {
        return;
    }

    char host[256];
    int port = 0;
    (void)port;
    if (pf_parse_http_url_host_port(base, host, sizeof(host), &port) != 0) {
        ff_die("%s: invalid --base URL", ctx ? ctx : "escrow");
    }

    if (strncasecmp(base, "http://", 7) != 0) return;
    if (pf_http_host_is_onion_suffix(host)) return;
    if (pf_http_host_is_loopback(host)) return;
    if (allow_remote_http_override) return;

    if (pf_is_true(getenv("NEXUM_ESCROW_ALLOW_REMOTE_HTTP"))) return;

    ff_die(
        "%s: non-onion remote http:// base blocked (use .onion+socks5h, https://, loopback, or set NEXUM_ESCROW_ALLOW_REMOTE_HTTP=true)",
        ctx ? ctx : "escrow"
    );
}

static int pf_wallet_rpc_validate_url_policy(const char *url,
                                             int *allow_basic_out,
                                             char *err,
                                             size_t err_cap) {
    if (allow_basic_out) *allow_basic_out = 0;
    if (err && err_cap > 0) err[0] = 0;
    if (!url || !url[0]) {
        if (err && err_cap > 0) snprintf(err, err_cap, "missing wallet-rpc url");
        return -1;
    }
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) {
        if (err && err_cap > 0) snprintf(err, err_cap, "wallet-rpc url must use http:// or https://");
        return -1;
    }

    char host[256];
    int port = 0;
    (void)port;
    if (pf_parse_http_url_host_port(url, host, sizeof(host), &port) != 0) {
        if (err && err_cap > 0) snprintf(err, err_cap, "invalid wallet-rpc url");
        return -1;
    }

    int is_loopback = pf_http_host_is_loopback(host);
    if (strncmp(url, "http://", 7) == 0 && !is_loopback) {
        const char *allow_remote_http = getenv("NXMS_WALLET_RPC_ALLOW_REMOTE_HTTP");
        if (!pf_is_true(allow_remote_http)) {
            if (err && err_cap > 0) {
                snprintf(err, err_cap,
                         "wallet-rpc remote http:// blocked (use https:// or set NXMS_WALLET_RPC_ALLOW_REMOTE_HTTP=true)");
            }
            return -1;
        }
    }

    if (allow_basic_out) {
        *allow_basic_out = is_loopback ? 1 : 0;
        if (!*allow_basic_out) {
            const char *allow_remote_basic = getenv("NXMS_WALLET_RPC_ALLOW_BASIC_REMOTE");
            if (pf_is_true(allow_remote_basic)) *allow_basic_out = 1;
        }
    }

    return 0;
}

static size_t pf_curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    static const size_t PF_HTTP_MAX_RESPONSE_BYTES = 4U * 1024U * 1024U;
    pf_curl_write_ctx_t *ctx = (pf_curl_write_ctx_t *)userdata;
    if (!ctx || !ctx->resp) return 0;
    if (size != 0 && nmemb > (SIZE_MAX / size)) {
        ctx->overflow = 1;
        return 0;
    }
    size_t n = size * nmemb;
    ff_http_resp_t *r = ctx->resp;
    if (n > (SIZE_MAX - r->len - 1)) {
        ctx->overflow = 1;
        return 0;
    }
    if (r->len + n > PF_HTTP_MAX_RESPONSE_BYTES) {
        ctx->too_large = 1;
        return 0;
    }
    char *p = (char *)realloc(r->data, r->len + n + 1);
    if (!p) return 0;
    r->data = p;
    memcpy(r->data + r->len, ptr, n);
    r->len += n;
    r->data[r->len] = 0;
    return n;
}

static int pf_http_post_json_auth_digest(const char *url,
                                         const char *json_body,
                                         const char *user,
                                         const char *pass,
                                         long timeout_secs,
                                         ff_http_resp_t *out,
                                         char *err,
                                         size_t err_cap) {
    if (err && err_cap > 0) err[0] = 0;
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!url || !user || !pass) {
        if (err && err_cap > 0) snprintf(err, err_cap, "missing url/user/pass");
        return -1;
    }
    int allow_basic = 0;
    if (pf_wallet_rpc_validate_url_policy(url, &allow_basic, err, err_cap) != 0) {
        return -1;
    }

    CURL *c = curl_easy_init();
    if (!c) {
        if (err && err_cap > 0) snprintf(err, err_cap, "curl init failed");
        return -1;
    }

    struct curl_slist *hdr = NULL;
    hdr = curl_slist_append(hdr, "Content-Type: application/json");
    hdr = curl_slist_append(hdr, "Accept: application/json");

    pf_curl_write_ctx_t wctx;
    memset(&wctx, 0, sizeof(wctx));
    wctx.resp = out;

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
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, json_body ? json_body : "{}");
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, pf_curl_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &wctx);
    curl_easy_setopt(c, CURLOPT_USERNAME, user);
    curl_easy_setopt(c, CURLOPT_PASSWORD, pass);
    curl_easy_setopt(c, CURLOPT_HTTPAUTH, allow_basic ? (CURLAUTH_DIGEST | CURLAUTH_BASIC) : CURLAUTH_DIGEST);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "nexum-cli/1.0");
    curl_easy_setopt(c, CURLOPT_TIMEOUT, timeout_secs > 0 ? timeout_secs : 40L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode rc = curl_easy_perform(c);
    long http_code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(hdr);
    curl_easy_cleanup(c);

    if (rc != CURLE_OK) {
        if (err && err_cap > 0) {
            if (wctx.too_large) {
                snprintf(err, err_cap, "wallet-rpc response exceeds max size");
            } else if (wctx.overflow) {
                snprintf(err, err_cap, "wallet-rpc response too large (size overflow)");
            } else {
                snprintf(err, err_cap, "transport error: %s", curl_easy_strerror(rc));
            }
        }
        ff_http_resp_free(out);
        return -1;
    }
    if (http_code < 200 || http_code >= 300) {
        if (err && err_cap > 0) {
            if (out->data && out->data[0]) {
                snprintf(err, err_cap, "http %ld: %s", http_code, out->data);
            } else {
                snprintf(err, err_cap, "http %ld", http_code);
            }
        }
        ff_http_resp_free(out);
        return -1;
    }
    return 0;
}

static const char *pf_first_nonempty3(const char *a, const char *b, const char *c) {
    if (a && a[0]) return a;
    if (b && b[0]) return b;
    if (c && c[0]) return c;
    return NULL;
}

static const char *pf_first_nonempty4(const char *a, const char *b, const char *c, const char *d) {
    if (a && a[0]) return a;
    if (b && b[0]) return b;
    if (c && c[0]) return c;
    if (d && d[0]) return d;
    return NULL;
}

static int pf_wallet_rpc_post_authed(const char *url,
                                     const char *user,
                                     const char *pass,
                                     const char *json_body,
                                     unsigned timeout_ms,
                                     ff_http_resp_t *out,
                                     char *err,
                                     size_t err_cap) {
    long timeout_secs = 40L;
    if (timeout_ms > 0) {
        timeout_secs = (long)((timeout_ms + 999U) / 1000U);
        if (timeout_secs < 1L) timeout_secs = 1L;
    }
    return pf_http_post_json_auth_digest(url, json_body, user, pass, timeout_secs, out, err, err_cap);
}

static int pf_wallet_rpc_contains_error(const ff_http_resp_t *r) {
    if (!r || !r->data) return 1;
    return strstr(r->data, "\"error\"") != NULL;
}

static int pf_wallet_rpc_is_multisig_true(const ff_http_resp_t *r) {
    if (!r || !r->data) return 0;
    const char *p = r->data;
    while ((p = strstr(p, "\"multisig\"")) != NULL) {
        p += 10; /* strlen("\"multisig\"") */
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p != ':') continue;
        p++;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (strncmp(p, "true", 4) == 0) return 1;
    }
    return 0;
}

static int pf_wallet_rpc_result_has_address(const ff_http_resp_t *r, char *addr_out, size_t addr_cap) {
    if (!r || !r->data || !addr_out || addr_cap == 0) return -1;
    char *addr = ff_json_get_str(r->data, "address");
    if (!addr || !addr[0]) {
        free(addr);
        addr = NULL;
        const char *p = r->data;
        while ((p = strstr(p, "\"address\"")) != NULL) {
            p += 9;
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
            if (*p != ':') continue;
            p++;
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
            if (*p != '"') continue;
            p++;
            const char *start = p;
            while (*p && *p != '"') {
                if (*p == '\\' && p[1]) p++;
                p++;
            }
            if (*p != '"') break;
            size_t n = (size_t)(p - start);
            if (n > 0) {
                if (n >= addr_cap) n = addr_cap - 1;
                memcpy(addr_out, start, n);
                addr_out[n] = 0;
                return 0;
            }
        }
        free(addr);
        return -1;
    }
    ff_strlcpy(addr_out, addr, addr_cap);
    free(addr);
    return 0;
}

static int pf_wallet_rpc_transfer_dry_run_ok(const ff_http_resp_t *r) {
    if (!r || !r->data) return 0;
    if (pf_wallet_rpc_contains_error(r)) return 0;
    return strstr(r->data, "\"tx_hash\"") != NULL ||
           strstr(r->data, "\"tx_hash_list\"") != NULL ||
           strstr(r->data, "\"tx_blob\"") != NULL;
}

static int pf_run_orch_capture(const char *orch_bin,
                               char *const argv[],
                               char *out_buf,
                               size_t out_cap,
                               int *exit_code) {
    return pf_run_orch_capture_env(orch_bin, argv, NULL, 0, out_buf, out_cap, exit_code);
}

static int pf_run_orch_capture_env(const char *orch_bin,
                                   char *const argv[],
                                   const pf_env_kv_t *envs,
                                   size_t env_count,
                                   char *out_buf,
                                   size_t out_cap,
                                   int *exit_code) {
    if (!orch_bin || !argv) return -1;
    if (out_buf && out_cap > 0) out_buf[0] = 0;
    if (exit_code) *exit_code = -1;

    int pipefd[2];
    if (orch_pipe_cloexec(pipefd) != 0) return -1;

    char orch_err[512];
    if (orch_validate_bin_path(orch_bin, orch_err, sizeof(orch_err)) != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        if (out_buf && out_cap > 0) {
            snprintf(out_buf, out_cap, "{\"ok\":false,\"error\":\"%s\"}",
                     orch_err[0] ? orch_err : "invalid orchestrator path");
        }
        if (exit_code) *exit_code = 127;
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        (void)dup2(pipefd[1], STDOUT_FILENO);
        (void)dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        orch_exec_child_sanitized(orch_bin, argv, envs, env_count);
    }

    close(pipefd[1]);
    size_t off = 0;
    if (out_buf && out_cap > 0) out_buf[0] = 0;
    char tmp[512];
    for (;;) {
        ssize_t n = read(pipefd[0], tmp, sizeof(tmp));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        if (out_buf && out_cap > 1 && off < out_cap - 1) {
            size_t cpy = (size_t)n;
            if (cpy > (out_cap - 1 - off)) cpy = out_cap - 1 - off;
            memcpy(out_buf + off, tmp, cpy);
            off += cpy;
            out_buf[off] = 0;
        }
    }
    close(pipefd[0]);

    int st = 0;
    if (waitpid(pid, &st, 0) < 0) return -1;
    if (WIFEXITED(st)) {
        if (exit_code) *exit_code = WEXITSTATUS(st);
        return WEXITSTATUS(st) == 0 ? 0 : -1;
    }
    if (WIFSIGNALED(st)) {
        if (exit_code) *exit_code = 128 + WTERMSIG(st);
    }
    return -1;
}

static void pf_probe_arbiter_wallet_multisig(pf_ctx_t *ctx, const char *wallet_rpc_url, unsigned timeout_ms) {
    const char *user = pf_getenv_nonempty("XMR_WALLET_RPC_USER");
    const char *pass = pf_getenv_nonempty("XMR_WALLET_RPC_PASS");
    if (!user || !pass) {
        pf_record(ctx, PF_ST_FAIL, "wallet-rpc-arbiter.multisig_probe", "WALLET_RPC_ARBITER_AUTH_FAILED",
                  "arbiter wallet-rpc credentials missing for strict multisig probe",
                  "set XMR_WALLET_RPC_USER and XMR_WALLET_RPC_PASS", 0);
        return;
    }

    const char *wallet_name = pf_first_nonempty4(
        pf_getenv_nonempty("NXMS_PREFLIGHT_ARBITER_WALLET_NAME"),
        pf_getenv_nonempty("XMR_ARBITER_WALLET_NAME"),
        pf_getenv_nonempty("XMR_WALLET_NAME"),
        pf_getenv_nonempty("WALLET_NAME")
    );
    const char *wallet_pass = pf_first_nonempty4(
        pf_getenv_nonempty("XMR_ARBITER_WALLET_PASS"),
        pf_getenv_nonempty("XMR_ARBITER_WALLET_PASSWORD"),
        pf_getenv_nonempty("XMR_WALLET_RPC_WALLET_PASSWORD"),
        pf_getenv_nonempty("WALLET_PASSWORD")
    );

    ff_http_resp_t r;
    char err[1024];
    memset(&r, 0, sizeof(r));
    if (pf_wallet_rpc_post_authed(wallet_rpc_url, user, pass,
                                  "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_version\"}",
                                  timeout_ms, &r, err, sizeof(err)) != 0) {
        pf_record(ctx, PF_ST_FAIL, "wallet-rpc-arbiter.multisig_probe", "WALLET_RPC_ARBITER_AUTH_FAILED",
                  err[0] ? err : "authenticated arbiter wallet-rpc probe failed", NULL, 0);
        ff_http_resp_free(&r);
        return;
    }
    ff_http_resp_free(&r);
    pf_record(ctx, PF_ST_PASS, "wallet-rpc-arbiter.auth_rpc", "", "authenticated arbiter wallet-rpc RPC call OK", NULL, 0);

    if (wallet_name && wallet_pass) {
        char *wn = json_escape_or_die(wallet_name);
        char *wp = json_escape_or_die(wallet_pass);
        char body[2048];
        snprintf(body, sizeof(body),
                 "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"open_wallet\",\"params\":{\"filename\":\"%s\",\"password\":\"%s\"}}",
                 wn, wp);
        free(wn);
        free(wp);
        memset(&r, 0, sizeof(r));
        if (pf_wallet_rpc_post_authed(wallet_rpc_url, user, pass, body, timeout_ms, &r, err, sizeof(err)) != 0) {
            pf_record(ctx, PF_ST_FAIL, "wallet-rpc-arbiter.open_wallet", "WALLET_RPC_ARBITER_OPEN_WALLET_FAILED",
                      err[0] ? err : "open_wallet failed for arbiter probe", NULL, 0);
            ff_http_resp_free(&r);
            return;
        }
        ff_http_resp_free(&r);
        pf_record(ctx, PF_ST_PASS, "wallet-rpc-arbiter.open_wallet", "", "arbiter wallet open_wallet OK", NULL, 0);
    } else {
        pf_record(ctx, PF_ST_SKIP, "wallet-rpc-arbiter.open_wallet", "WALLET_RPC_OPEN_WALLET_ENV_NOT_SET",
                  "open_wallet skipped (no arbiter wallet name/password env provided)", NULL, 1);
    }

    memset(&r, 0, sizeof(r));
    if (pf_wallet_rpc_post_authed(wallet_rpc_url, user, pass,
                                  "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"is_multisig\"}",
                                  timeout_ms, &r, err, sizeof(err)) != 0) {
        pf_record(ctx, PF_ST_FAIL, "wallet-rpc-arbiter.is_multisig", "WALLET_RPC_ARBITER_MULTISIG_PROBE_FAILED",
                  err[0] ? err : "is_multisig probe failed", "ensure arbiter wallet is opened and multisig-ready", 0);
        ff_http_resp_free(&r);
        return;
    }
    if (!pf_wallet_rpc_is_multisig_true(&r)) {
        pf_record(ctx, PF_ST_FAIL, "wallet-rpc-arbiter.is_multisig", "WALLET_RPC_ARBITER_NOT_MULTISIG",
                  "is_multisig returned but wallet is not multisig=true", NULL, 0);
        ff_http_resp_free(&r);
        return;
    }
    ff_http_resp_free(&r);
    pf_record(ctx, PF_ST_PASS, "wallet-rpc-arbiter.is_multisig", "", "arbiter wallet reports multisig=true", NULL, 0);

    memset(&r, 0, sizeof(r));
    if (pf_wallet_rpc_post_authed(wallet_rpc_url, user, pass,
                                  "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"refresh\"}",
                                  timeout_ms, &r, err, sizeof(err)) != 0) {
        pf_record(ctx, PF_ST_FAIL, "wallet-rpc-arbiter.refresh", "WALLET_RPC_ARBITER_MULTISIG_PROBE_FAILED",
                  err[0] ? err : "refresh failed during strict multisig probe", NULL, 0);
        ff_http_resp_free(&r);
        return;
    }
    ff_http_resp_free(&r);
    pf_record(ctx, PF_ST_PASS, "wallet-rpc-arbiter.refresh", "", "arbiter wallet refresh OK", NULL, 0);
}

static void pf_probe_party_wallet_transfer_dry_run(pf_ctx_t *ctx, const char *wallet_rpc_url, unsigned timeout_ms) {
    const char *user = pf_first_nonempty3(
        pf_getenv_nonempty("XMR_PARTY_WALLET_RPC_USER"),
        pf_getenv_nonempty("BUYER_FUNDING_WALLET_RPC_USER"),
        pf_getenv_nonempty("XMR_WALLET_RPC_USER")
    );
    const char *pass = pf_first_nonempty3(
        pf_getenv_nonempty("XMR_PARTY_WALLET_RPC_PASS"),
        pf_getenv_nonempty("BUYER_FUNDING_WALLET_RPC_PASS"),
        pf_getenv_nonempty("XMR_WALLET_RPC_PASS")
    );
    if (!user || !pass) {
        pf_record(ctx, PF_ST_FAIL, "wallet-rpc-party.transfer_dry_run", "WALLET_RPC_PARTY_AUTH_FAILED",
                  "party wallet-rpc credentials missing for transfer dry-run probe",
                  "set XMR_PARTY_WALLET_RPC_USER/PASS (or buyer funding fallback creds)", 0);
        return;
    }

    const char *wallet_name = pf_first_nonempty4(
        pf_getenv_nonempty("NXMS_PREFLIGHT_PARTY_WALLET_NAME"),
        pf_getenv_nonempty("XMR_PARTY_WALLET_NAME"),
        pf_getenv_nonempty("BUYER_FUNDING_WALLET_NAME"),
        pf_getenv_nonempty("XMR_WALLET_NAME")
    );
    const char *wallet_pass = pf_first_nonempty4(
        pf_getenv_nonempty("XMR_PARTY_WALLET_PASS"),
        pf_getenv_nonempty("XMR_PARTY_WALLET_PASSWORD"),
        pf_getenv_nonempty("BUYER_FUNDING_WALLET_RPC_PASS"),
        pf_getenv_nonempty("XMR_WALLET_RPC_WALLET_PASSWORD")
    );

    ff_http_resp_t r;
    char err[2048];
    memset(&r, 0, sizeof(r));
    if (pf_wallet_rpc_post_authed(wallet_rpc_url, user, pass,
                                  "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_version\"}",
                                  timeout_ms, &r, err, sizeof(err)) != 0) {
        pf_record(ctx, PF_ST_FAIL, "wallet-rpc-party.transfer_dry_run", "WALLET_RPC_PARTY_AUTH_FAILED",
                  err[0] ? err : "authenticated party wallet-rpc probe failed", NULL, 0);
        ff_http_resp_free(&r);
        return;
    }
    ff_http_resp_free(&r);
    pf_record(ctx, PF_ST_PASS, "wallet-rpc-party.auth_rpc", "", "authenticated party wallet-rpc RPC call OK", NULL, 0);

    if (wallet_name && wallet_pass) {
        char *wn = json_escape_or_die(wallet_name);
        char *wp = json_escape_or_die(wallet_pass);
        char body[2048];
        snprintf(body, sizeof(body),
                 "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"open_wallet\",\"params\":{\"filename\":\"%s\",\"password\":\"%s\"}}",
                 wn, wp);
        free(wn);
        free(wp);
        memset(&r, 0, sizeof(r));
        if (pf_wallet_rpc_post_authed(wallet_rpc_url, user, pass, body, timeout_ms, &r, err, sizeof(err)) != 0) {
            pf_record(ctx, PF_ST_FAIL, "wallet-rpc-party.open_wallet", "WALLET_RPC_PARTY_OPEN_WALLET_FAILED",
                      err[0] ? err : "open_wallet failed for party probe", NULL, 0);
            ff_http_resp_free(&r);
            return;
        }
        ff_http_resp_free(&r);
        pf_record(ctx, PF_ST_PASS, "wallet-rpc-party.open_wallet", "", "party wallet open_wallet OK", NULL, 0);
    } else {
        pf_record(ctx, PF_ST_SKIP, "wallet-rpc-party.open_wallet", "WALLET_RPC_OPEN_WALLET_ENV_NOT_SET",
                  "open_wallet skipped (no party wallet name/password env provided)", NULL, 1);
    }

    memset(&r, 0, sizeof(r));
    if (pf_wallet_rpc_post_authed(wallet_rpc_url, user, pass,
                                  "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"refresh\"}",
                                  timeout_ms, &r, err, sizeof(err)) != 0) {
        pf_record(ctx, PF_ST_FAIL, "wallet-rpc-party.refresh", "WALLET_RPC_PARTY_TRANSFER_PROBE_FAILED",
                  err[0] ? err : "party wallet refresh failed", NULL, 0);
        ff_http_resp_free(&r);
        return;
    }
    ff_http_resp_free(&r);
    pf_record(ctx, PF_ST_PASS, "wallet-rpc-party.refresh", "", "party wallet refresh OK", NULL, 0);

    memset(&r, 0, sizeof(r));
    if (pf_wallet_rpc_post_authed(wallet_rpc_url, user, pass,
                                  "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_address\"}",
                                  timeout_ms, &r, err, sizeof(err)) != 0) {
        pf_record(ctx, PF_ST_FAIL, "wallet-rpc-party.get_address", "WALLET_RPC_PARTY_TRANSFER_PROBE_FAILED",
                  err[0] ? err : "party wallet get_address failed", NULL, 0);
        ff_http_resp_free(&r);
        return;
    }
    char self_addr[256];
    if (pf_wallet_rpc_result_has_address(&r, self_addr, sizeof(self_addr)) != 0) {
        pf_record(ctx, PF_ST_FAIL, "wallet-rpc-party.get_address", "WALLET_RPC_PARTY_TRANSFER_PROBE_FAILED",
                  "party wallet get_address response missing address", NULL, 0);
        ff_http_resp_free(&r);
        return;
    }
    ff_http_resp_free(&r);
    pf_record(ctx, PF_ST_PASS, "wallet-rpc-party.get_address", "", "party wallet self-address fetched", NULL, 0);

    char *addr_esc = json_escape_or_die(self_addr);
    char tx_body[4096];
    snprintf(tx_body, sizeof(tx_body),
             "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"transfer\",\"params\":{\"destinations\":[{\"amount\":1,\"address\":\"%s\"}],\"do_not_relay\":true}}",
             addr_esc);
    free(addr_esc);

    unsigned tx_timeout_ms = timeout_ms > 0 ? timeout_ms : 90000U;
    memset(&r, 0, sizeof(r));
    if (pf_wallet_rpc_post_authed(wallet_rpc_url, user, pass, tx_body, tx_timeout_ms, &r, err, sizeof(err)) != 0) {
        pf_record(ctx, PF_ST_FAIL, "wallet-rpc-party.transfer_dry_run", "WALLET_RPC_PARTY_TRANSFER_PROBE_FAILED",
                  err[0] ? err : "party wallet transfer dry-run failed", NULL, 0);
        ff_http_resp_free(&r);
        return;
    }
    if (!pf_wallet_rpc_transfer_dry_run_ok(&r)) {
        pf_record(ctx, PF_ST_FAIL, "wallet-rpc-party.transfer_dry_run", "WALLET_RPC_PARTY_TRANSFER_PROBE_FAILED",
                  "transfer dry-run returned 2xx but result markers not found", NULL, 0);
        ff_http_resp_free(&r);
        return;
    }
    ff_http_resp_free(&r);
    pf_record(ctx, PF_ST_PASS, "wallet-rpc-party.transfer_dry_run", "", "party wallet transfer dry-run (do_not_relay=true) OK", NULL, 0);
}

static void pf_probe_worker_routes_for_escrow(pf_ctx_t *ctx,
                                              const char *orch_bin,
                                              const char *orch_db,
                                              const char *escrow_id_hex) {
    if (!ctx || !orch_bin || !orch_db || !escrow_id_hex || !escrow_id_hex[0]) return;
    const char *roles[] = {"seller", "arbiter"};
    for (size_t i = 0; i < sizeof(roles)/sizeof(roles[0]); i++) {
        const char *role = roles[i];
        char *argv[] = {
            (char *)orch_bin,
            "worker-route",
            "show",
            "--db-path",
            (char *)orch_db,
            "--escrow-id-hex",
            (char *)escrow_id_hex,
            "--role",
            (char *)role,
            NULL
        };
        char out[4096];
        int ec = -1;
        if (pf_run_orch_capture(orch_bin, argv, out, sizeof(out), &ec) == 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "worker-route show %s OK", role);
            pf_record(ctx, PF_ST_PASS,
                      strcmp(role, "seller") == 0 ? "worker-route.seller" : "worker-route.arbiter",
                      "", msg, NULL, 0);
        } else {
            char sanitized[768];
            pf_tsv_sanitize(out, sanitized, sizeof(sanitized));
            char msg[1024];
            snprintf(msg, sizeof(msg), "worker-route show %s failed (exit=%d)", role, ec);
            pf_record(ctx, PF_ST_FAIL,
                      strcmp(role, "seller") == 0 ? "worker-route.seller" : "worker-route.arbiter",
                      "WORKER_ROUTE_MISSING",
                      msg,
                      sanitized[0] ? sanitized : "set worker route via nexum worker-route-set",
                      0);
        }
    }
}

static int pf_parse_host_port_pair(const char *host_in, const char *port_in,
                                   const char *def_host, int def_port,
                                   char *host_out, size_t host_cap, int *port_out) {
    const char *h = (host_in && host_in[0]) ? host_in : def_host;
    const char *p = (port_in && port_in[0]) ? port_in : NULL;
    if (!h || !host_out || host_cap == 0 || !port_out) return -1;
    ff_strlcpy(host_out, h, host_cap);
    if (!p) {
        *port_out = def_port;
        return 0;
    }
    char *endp = NULL;
    long pv = strtol(p, &endp, 10);
    if (endp == p || (endp && *endp) || pv <= 0 || pv > 65535) return -1;
    *port_out = (int)pv;
    return 0;
}

static int pf_parse_bind_host_port(const char *bind, char *host_out, size_t host_cap, int *port_out) {
    if (!bind || !bind[0] || !host_out || host_cap == 0 || !port_out) return -1;
    const char *colon = strrchr(bind, ':');
    if (!colon || colon == bind) return -1;
    size_t hlen = (size_t)(colon - bind);
    if (hlen + 1 > host_cap) return -1;
    memcpy(host_out, bind, hlen);
    host_out[hlen] = 0;
    if (strcmp(host_out, "0.0.0.0") == 0 || strcmp(host_out, "::") == 0 || host_out[0] == 0) {
        ff_strlcpy(host_out, "127.0.0.1", host_cap);
    }
    char *endp = NULL;
    long pv = strtol(colon + 1, &endp, 10);
    if (endp == colon + 1 || (endp && *endp) || pv <= 0 || pv > 65535) return -1;
    *port_out = (int)pv;
    return 0;
}

static int pf_parse_http_url_host_port(const char *url, char *host_out, size_t host_cap, int *port_out) {
    if (!url || !url[0] || !host_out || host_cap == 0 || !port_out) return -1;
    const char *p = url;
    int def_port = 80;
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
        def_port = 80;
    } else if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        def_port = 443;
    }
    const char *host_start = p;
    const char *host_end = NULL;
    if (*p == '[') {
        const char *end = strchr(p, ']');
        if (!end) return -1;
        host_start = p + 1;
        host_end = end;
        p = end + 1;
        if (*p == ':') p++;
        else p = NULL;
    } else {
        while (*p && *p != ':' && *p != '/') p++;
        host_end = p;
        if (*p == ':') p++;
        else p = NULL;
    }
    size_t hlen = (size_t)(host_end - host_start);
    if (hlen == 0 || hlen + 1 > host_cap) return -1;
    memcpy(host_out, host_start, hlen);
    host_out[hlen] = 0;

    if (!p) {
        *port_out = def_port;
        return 0;
    }
    char portbuf[16];
    size_t pi = 0;
    while (*p && *p != '/' && pi + 1 < sizeof(portbuf)) {
        portbuf[pi++] = *p++;
    }
    portbuf[pi] = 0;
    if (pi == 0) {
        *port_out = def_port;
        return 0;
    }
    char *endp = NULL;
    long pv = strtol(portbuf, &endp, 10);
    if (endp == portbuf || (endp && *endp) || pv <= 0 || pv > 65535) return -1;
    *port_out = (int)pv;
    return 0;
}

static int pf_parse_redis_url_host_port(const char *url, char *host_out, size_t host_cap, int *port_out) {
    if (!url || !url[0]) return -1;
    const char *p = url;
    if (strncmp(p, "redis://", 8) == 0) p += 8;
    else if (strncmp(p, "rediss://", 9) == 0) p += 9;

    const char *at = strchr(p, '@');
    const char *slash = strchr(p, '/');
    if (at && (!slash || at < slash)) p = at + 1;

    const char *host_start = p;
    const char *host_end = NULL;
    int port = 6379;
    if (*p == '[') {
        const char *end = strchr(p, ']');
        if (!end) return -1;
        host_start = p + 1;
        host_end = end;
        p = end + 1;
        if (*p == ':') {
            p++;
            char *endp = NULL;
            long pv = strtol(p, &endp, 10);
            if (endp == p || pv <= 0 || pv > 65535) return -1;
            port = (int)pv;
        }
    } else {
        while (*p && *p != ':' && *p != '/') p++;
        host_end = p;
        if (*p == ':') {
            p++;
            char *endp = NULL;
            long pv = strtol(p, &endp, 10);
            if (endp == p || pv <= 0 || pv > 65535) return -1;
            port = (int)pv;
        }
    }
    size_t hlen = (size_t)(host_end - host_start);
    if (hlen == 0 || hlen + 1 > host_cap) return -1;
    memcpy(host_out, host_start, hlen);
    host_out[hlen] = 0;
    *port_out = port;
    return 0;
}

static int pf_tcp_reachable(const char *host, int port) {
    if (!host || !host[0] || port <= 0) return -1;
    char port_s[16];
    snprintf(port_s, sizeof(port_s), "%d", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_s, &hints, &res) != 0) return -1;
    int ok = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            ok = 0;
            close(fd);
            break;
        }
        if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            for (;;) {
                int pr = poll(&pfd, 1, 3000);
                if (pr < 0 && errno == EINTR) continue;
                if (pr <= 0) break;
                if (pfd.revents & (POLLOUT | POLLERR | POLLHUP)) {
                    int so_err = 0;
                    socklen_t so_len = (socklen_t)sizeof(so_err);
                    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len) == 0 && so_err == 0) {
                        ok = 0;
                    }
                }
                break;
            }
            if (ok == 0) {
                close(fd);
                break;
            }
        }
        close(fd);
    }
    freeaddrinfo(res);
    return ok;
}

static int pf_file_exists_executable_or_path_cmd(const char *cmd, char *resolved, size_t resolved_cap) {
    if (!cmd || !cmd[0]) return -1;
    if (strchr(cmd, '/')) {
        if (access(cmd, X_OK) == 0) {
            if (resolved && resolved_cap > 0) ff_strlcpy(resolved, cmd, resolved_cap);
            return 0;
        }
        return -1;
    }
    const char *path = getenv("PATH");
    if (!path || !path[0]) return -1;
    char *dup = strdup(path);
    if (!dup) return -1;
    int rc = -1;
    char *save = NULL;
    for (char *seg = strtok_r(dup, ":", &save); seg; seg = strtok_r(NULL, ":", &save)) {
        char cand[4096];
        if (snprintf(cand, sizeof(cand), "%s/%s", seg[0] ? seg : ".", cmd) >= (int)sizeof(cand)) continue;
        if (access(cand, X_OK) == 0) {
            if (resolved && resolved_cap > 0) ff_strlcpy(resolved, cand, resolved_cap);
            rc = 0;
            break;
        }
    }
    free(dup);
    return rc;
}

static int pf_parent_dir_writable(const char *path, char *detail, size_t detail_cap) {
    if (!path || !path[0]) return -1;
    struct stat st;
    if (stat(path, &st) == 0) {
        if (access(path, R_OK | W_OK) == 0) {
            if (detail && detail_cap > 0) snprintf(detail, detail_cap, "DB file exists and is readable/writable");
            return 0;
        }
        if (detail && detail_cap > 0) snprintf(detail, detail_cap, "DB file exists but not writable");
        return -1;
    }
    char parent[4096];
    ff_strlcpy(parent, path, sizeof(parent));
    char *slash = strrchr(parent, '/');
    if (!slash) {
        ff_strlcpy(parent, ".", sizeof(parent));
    } else if (slash == parent) {
        slash[1] = 0;
    } else {
        *slash = 0;
    }
    if (access(parent, W_OK | X_OK) == 0) {
        if (detail && detail_cap > 0) snprintf(detail, detail_cap, "parent dir writable: %s", parent);
        return 0;
    }
    if (detail && detail_cap > 0) snprintf(detail, detail_cap, "parent dir not writable: %s", parent);
    return -1;
}

static int pf_write_artifacts(const char *run_dir,
                              const pf_ctx_t *ctx,
                              const char *base,
                              const char *ui_base,
                              const char *socks5,
                              const char *verdict) {
    if (!run_dir || !run_dir[0] || !ctx) return 0;
    char preflight_dir[4096];
    if (snprintf(preflight_dir, sizeof(preflight_dir), "%s/preflight", run_dir) >= (int)sizeof(preflight_dir)) {
        fprintf(stderr, "WARN: run_dir path too long, skipping artifacts\n");
        return -1;
    }
    if (ff_mkdir_p(preflight_dir) != 0) {
        perror("preflight artifacts mkdir");
        fprintf(stderr, "WARN: failed to create run_dir/preflight, skipping artifacts\n");
        return -1;
    }

    char path_summary[4096];
    char path_checks[4096];
    char path_manifest[4096];
    snprintf(path_summary, sizeof(path_summary), "%s/summary.txt", preflight_dir);
    snprintf(path_checks, sizeof(path_checks), "%s/checks.tsv", preflight_dir);
    snprintf(path_manifest, sizeof(path_manifest), "%s/manifest.json", preflight_dir);

    if (pf_write_text(path_summary, ctx->summary_buf ? ctx->summary_buf : "") != 0) {
        perror("preflight summary write");
    }
    if (pf_write_text(path_checks, ctx->checks_tsv ? ctx->checks_tsv : "") != 0) {
        perror("preflight checks write");
    }

    char now_s[32];
    pf_utc_now(now_s);
    char *base_esc = json_escape_or_die(base ? base : "");
    char *ui_esc = json_escape_or_die(ui_base ? ui_base : "");
    char *socks_esc = json_escape_or_die(socks5 ? socks5 : "");
    char *verdict_esc = json_escape_or_die(verdict ? verdict : "");
    char manifest[4096];
    snprintf(
        manifest, sizeof(manifest),
        "{\n"
        "  \"format\": \"nexum_cli_preflight_manifest_v1\",\n"
        "  \"generated_at_utc\": \"%s\",\n"
        "  \"command\": \"nexum preflight escrow\",\n"
        "  \"targets\": {\n"
        "    \"escrow_http_base\": \"%s\",\n"
        "    \"nxms_serv_base\": \"%s\",\n"
        "    \"socks5\": \"%s\"\n"
        "  },\n"
        "  \"counts\": {\n"
        "    \"pass\": %d,\n"
        "    \"warn\": %d,\n"
        "    \"fail\": %d,\n"
        "    \"skip\": %d\n"
        "  },\n"
        "  \"verdict\": \"%s\"\n"
        "}\n",
        now_s,
        base_esc,
        ui_esc,
        socks_esc,
        ctx->pass_count,
        ctx->warn_count,
        ctx->fail_count,
        ctx->skip_count,
        verdict_esc
    );
    free(base_esc);
    free(ui_esc);
    free(socks_esc);
    free(verdict_esc);

    if (pf_write_text(path_manifest, manifest) != 0) {
        perror("preflight manifest write");
    }
    return 0;
}

static char *build_escrow_create_json_body(const char *buyer_nick,
                                           const char *seller_nick,
                                           unsigned long long amount_atomic,
                                           const char *memo,
                                           const char *buyer_refund_address) {
    char *json = NULL;
    size_t len = 0;
    int first = 1;

    append_or_die(&json, &len, "{");
#define APPEND_CREATE_STR(key, val)                        \
    do {                                                   \
        if ((val) && (val)[0]) {                           \
            if (!first) append_or_die(&json, &len, ",");   \
            append_or_die(&json, &len, "\"" key "\":\"");  \
            append_json_escaped_or_die(&json, &len, (val));\
            append_or_die(&json, &len, "\"");              \
            first = 0;                                     \
        }                                                  \
    } while (0)

    APPEND_CREATE_STR("asset", "XMR");
    APPEND_CREATE_STR("buyer_nick", buyer_nick);
    APPEND_CREATE_STR("seller_nick", seller_nick);
    if (!first) append_or_die(&json, &len, ",");
    {
        char numbuf[64];
        snprintf(numbuf, sizeof(numbuf), "\"amount_atomic\":%llu", amount_atomic);
        append_or_die(&json, &len, numbuf);
        first = 0;
    }
    APPEND_CREATE_STR("memo", memo);
    APPEND_CREATE_STR("buyer_refund_address", buyer_refund_address);
#undef APPEND_CREATE_STR
    append_or_die(&json, &len, "}");
    return json;
}

static void op_write_warn(const char *msg) {
    if (!msg || !msg[0]) return;
    fprintf(stderr, "WARN: %s\n", msg);
}

static int op_prepare_flow_run_dir(const char *run_dir, char *flow_dir, size_t flow_dir_cap) {
    if (!run_dir || !run_dir[0]) return 0;
    if (snprintf(flow_dir, flow_dir_cap, "%s/flow", run_dir) >= (int)flow_dir_cap) {
        op_write_warn("run_dir path too long, skipping flow artifacts");
        return -1;
    }
    if (ff_mkdir_p(run_dir) != 0) {
        op_write_warn("failed to create run_dir, skipping flow artifacts");
        return -1;
    }
    if (ff_mkdir_p(flow_dir) != 0) {
        op_write_warn("failed to create run_dir/flow, skipping flow artifacts");
        return -1;
    }
    return 0;
}

static void op_write_run_meta_manifest_basic(const char *run_dir,
                                             const char *command_name,
                                             const char *base,
                                             const char *socks5,
                                             long long escrow_id_or_neg1,
                                             const char *outcome,
                                             const char *artifact_rel_a,
                                             const char *artifact_rel_b,
                                             const char *artifact_rel_c) {
    if (!run_dir || !run_dir[0]) return;
    char meta_path[4096];
    char manifest_path[4096];
    if (snprintf(meta_path, sizeof(meta_path), "%s/meta.txt", run_dir) >= (int)sizeof(meta_path) ||
        snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", run_dir) >= (int)sizeof(manifest_path)) {
        op_write_warn("run_dir path too long, skipping meta/manifest");
        return;
    }

    char now_s[32];
    pf_utc_now(now_s);

    char meta[4096];
    snprintf(meta, sizeof(meta),
             "created_at_utc=%s\n"
             "run_kind=operator_flow\n"
             "tool=nexum-cli\n"
             "command=%s\n"
             "escrow_http_base=%s\n"
             "socks5=%s\n"
             "escrow_id=%s\n"
             "outcome=%s\n",
             now_s,
             command_name ? command_name : "nexum escrow",
             base ? base : "",
             socks5 ? socks5 : "",
             (escrow_id_or_neg1 >= 0) ? "set" : "unknown",
             outcome ? outcome : "unknown");

    if (escrow_id_or_neg1 >= 0) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "escrow_id_value=%lld\n", escrow_id_or_neg1);
        if (strlen(meta) + strlen(tmp) + 1 < sizeof(meta)) strcat(meta, tmp);
    }
    if (artifact_rel_a && artifact_rel_a[0]) {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "artifact=%s\n", artifact_rel_a);
        if (strlen(meta) + strlen(tmp) + 1 < sizeof(meta)) strcat(meta, tmp);
    }
    if (artifact_rel_b && artifact_rel_b[0]) {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "artifact=%s\n", artifact_rel_b);
        if (strlen(meta) + strlen(tmp) + 1 < sizeof(meta)) strcat(meta, tmp);
    }
    if (artifact_rel_c && artifact_rel_c[0]) {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "artifact=%s\n", artifact_rel_c);
        if (strlen(meta) + strlen(tmp) + 1 < sizeof(meta)) strcat(meta, tmp);
    }

    if (pf_write_text(meta_path, meta) != 0) {
        op_write_warn("failed to write run_dir/meta.txt");
    }

    char *cmd_esc = json_escape_or_die(command_name ? command_name : "nexum escrow");
    char *base_esc = json_escape_or_die(base ? base : "");
    char *socks_esc = json_escape_or_die(socks5 ? socks5 : "");
    char *outcome_esc = json_escape_or_die(outcome ? outcome : "unknown");

    char artifacts_json[2048];
    artifacts_json[0] = 0;
    size_t aj_len = 0;
    const char *arts[3] = { artifact_rel_a, artifact_rel_b, artifact_rel_c };
    for (int i = 0; i < 3; i++) {
        if (!arts[i] || !arts[i][0]) continue;
        char *path_esc = json_escape_or_die(arts[i]);
        char part[768];
        snprintf(part, sizeof(part),
                 "%s{\"path\":\"%s\",\"stage\":\"flow\"}",
                 (aj_len > 0) ? "," : "",
                 path_esc);
        free(path_esc);
        if (aj_len + strlen(part) + 1 >= sizeof(artifacts_json)) break;
        memcpy(artifacts_json + aj_len, part, strlen(part));
        aj_len += strlen(part);
        artifacts_json[aj_len] = 0;
    }

    char manifest[8192];
    snprintf(manifest, sizeof(manifest),
             "{\n"
             "  \"format\": \"nexum_cli_run_manifest_v1\",\n"
             "  \"created_at_utc\": \"%s\",\n"
             "  \"updated_at_utc\": \"%s\",\n"
             "  \"run_kind\": \"operator_flow\",\n"
             "  \"tool\": \"nexum-cli\",\n"
             "  \"command\": \"%s\",\n"
             "  \"escrow_id\": %s,\n"
             "  \"targets\": {\n"
             "    \"escrow_http_base\": \"%s\",\n"
             "    \"socks5\": \"%s\"\n"
             "  },\n"
             "  \"status\": \"completed\",\n"
             "  \"outcome\": \"%s\",\n"
             "  \"artifacts\": [%s]\n"
             "}\n",
             now_s,
             now_s,
             cmd_esc,
             (escrow_id_or_neg1 >= 0) ? "0" : "null",
             base_esc,
             socks_esc,
             outcome_esc,
             artifacts_json);

    if (escrow_id_or_neg1 >= 0) {
        char idbuf[64];
        snprintf(idbuf, sizeof(idbuf), "%lld", escrow_id_or_neg1);
        char *id_pos = strstr(manifest, "\"escrow_id\": 0");
        if (id_pos) {
            char rebuilt[8192];
            size_t prefix = (size_t)(id_pos - manifest);
            snprintf(rebuilt, sizeof(rebuilt), "%.*s\"escrow_id\": %s%s",
                     (int)prefix, manifest, idbuf, id_pos + strlen("\"escrow_id\": 0"));
            if (strlen(rebuilt) < sizeof(manifest)) {
                strcpy(manifest, rebuilt);
            }
        }
    }

    if (pf_write_text(manifest_path, manifest) != 0) {
        op_write_warn("failed to write run_dir/manifest.json");
    }

    free(cmd_esc);
    free(base_esc);
    free(socks_esc);
    free(outcome_esc);
}

static void op_print_escrow_create_summary(const char *resp_json, const char *run_dir) {
    long long id = -1;
    long long required = -1;
    long long amount = -1;
    (void)ff_json_get_i64(resp_json, "id", &id);
    (void)ff_json_get_i64(resp_json, "required_funding_atomic", &required);
    (void)ff_json_get_i64(resp_json, "amount_atomic", &amount);
    char *state = ff_json_get_str(resp_json, "state");
    char *buyer_token = ff_json_get_str(resp_json, "buyer_token");
    char *deposit = ff_json_get_str(resp_json, "deposit_address");
    char id_s[64];
    char amount_s[64];
    char required_s[64];
    if (id >= 0) snprintf(id_s, sizeof(id_s), "%lld", id);
    else ff_strlcpy(id_s, "?", sizeof(id_s));
    if (amount >= 0) snprintf(amount_s, sizeof(amount_s), "%lld", amount);
    else ff_strlcpy(amount_s, "?", sizeof(amount_s));
    if (required >= 0) snprintf(required_s, sizeof(required_s), "%lld", required);
    else ff_strlcpy(required_s, "?", sizeof(required_s));
    fprintf(stderr,
            "escrow-create OK: id=%s state=%s amount_atomic=%s required_funding_atomic=%s buyer_token=%s deposit_address=%s\n",
            id_s,
            (state && state[0]) ? state : "?",
            amount_s,
            required_s,
            (buyer_token && buyer_token[0]) ? "present" : "missing",
            (deposit && deposit[0]) ? deposit : "(not set)");
    if (run_dir && run_dir[0]) {
        fprintf(stderr, "  run_dir: %s\n", run_dir);
    }
    free(state);
    free(buyer_token);
    free(deposit);
}

static void op_print_escrow_status_summary(const char *resp_json, const char *run_dir) {
    long long id = -1;
    long long required = -1;
    (void)ff_json_get_i64(resp_json, "id", &id);
    (void)ff_json_get_i64(resp_json, "required_funding_atomic", &required);
    char *state = ff_json_get_str(resp_json, "state");
    char *deposit = ff_json_get_str(resp_json, "deposit_address");
    fprintf(stderr, "escrow-status OK: id=%lld state=%s deposit_address=%s required_funding_atomic=%lld\n",
            id,
            (state && state[0]) ? state : "?",
            (deposit && deposit[0]) ? deposit : "(not set)",
            required);
    if (run_dir && run_dir[0]) {
        fprintf(stderr, "  run_dir: %s\n", run_dir);
    }
    free(state);
    free(deposit);
}

static void op_write_escrow_create_artifacts(const char *run_dir,
                                             const char *base,
                                             const char *socks5,
                                             const char *req_json,
                                             const char *resp_json) {
    if (!run_dir || !run_dir[0]) return;
    char flow_dir[4096];
    if (op_prepare_flow_run_dir(run_dir, flow_dir, sizeof(flow_dir)) != 0) return;

    char p_req[4096];
    char p_resp[4096];
    char p_status[4096];
    if (snprintf(p_req, sizeof(p_req), "%s/create.request.json", flow_dir) >= (int)sizeof(p_req) ||
        snprintf(p_resp, sizeof(p_resp), "%s/create.response.json", flow_dir) >= (int)sizeof(p_resp) ||
        snprintf(p_status, sizeof(p_status), "%s/status.initial.json", flow_dir) >= (int)sizeof(p_status)) {
        op_write_warn("flow artifact path too long, skipping create artifacts");
        return;
    }
    if (pf_write_text(p_req, req_json ? req_json : "{}") != 0) op_write_warn("failed to write flow/create.request.json");
    if (pf_write_text(p_resp, resp_json ? resp_json : "{}") != 0) op_write_warn("failed to write flow/create.response.json");
    if (pf_write_text(p_status, resp_json ? resp_json : "{}") != 0) op_write_warn("failed to write flow/status.initial.json");

    long long escrow_id = -1;
    (void)ff_json_get_i64(resp_json, "id", &escrow_id);
    char *state = ff_json_get_str(resp_json, "state");
    op_write_run_meta_manifest_basic(
        run_dir,
        "nexum escrow-create",
        base,
        socks5,
        escrow_id,
        (state && state[0]) ? state : "ESCROW_CREATED",
        "flow/create.request.json",
        "flow/create.response.json",
        "flow/status.initial.json"
    );
    free(state);
}

static void op_write_escrow_status_artifacts(const char *run_dir,
                                             const char *base,
                                             const char *socks5,
                                             unsigned long long escrow_id,
                                             const char *resp_json) {
    if (!run_dir || !run_dir[0]) return;
    char flow_dir[4096];
    if (op_prepare_flow_run_dir(run_dir, flow_dir, sizeof(flow_dir)) != 0) return;

    char *state = ff_json_get_str(resp_json, "state");
    const char *rel = "flow/status.latest.json";
    if (state && strcmp(state, "FUNDED") == 0) rel = "flow/status.funded.json";
    else {
        char probe[4096];
        if (snprintf(probe, sizeof(probe), "%s/status.initial.json", flow_dir) < (int)sizeof(probe)) {
            if (access(probe, F_OK) != 0) rel = "flow/status.initial.json";
        }
    }

    char path_status[4096];
    if (snprintf(path_status, sizeof(path_status), "%s/%s", run_dir, rel) >= (int)sizeof(path_status)) {
        op_write_warn("flow artifact path too long, skipping status artifact");
        free(state);
        return;
    }
    if (pf_write_text(path_status, resp_json ? resp_json : "{}") != 0) {
        op_write_warn("failed to write flow status artifact");
    }
    op_write_run_meta_manifest_basic(
        run_dir,
        "nexum escrow-status",
        base,
        socks5,
        (long long)escrow_id,
        (state && state[0]) ? state : "STATUS_OK",
        rel,
        NULL,
        NULL
    );
    free(state);
}

int cmd_escrow_create(const char *base, const char *socks5,
                      const char *buyer_nick, const char *seller_nick,
                      unsigned long long amount_atomic,
                      const char *memo,
                      const char *buyer_refund_address,
                      const char *idempotency_key,
                      const char *run_dir) {
    pf_require_escrow_base_url_policy(base, 0, "escrow-create");
    require_tor(base, socks5);
    char *buyer = dup_trimmed_copy(buyer_nick);
    char *seller = dup_trimmed_copy(seller_nick);
    char *memo_trim = dup_trimmed_copy(memo);
    char *refund_trim = dup_trimmed_copy(buyer_refund_address);
    char *idem_key_trim = normalize_idempotency_key(idempotency_key, "escrow-create");
    if (!buyer || !seller) ff_die("oom");
    if (!buyer[0] || !seller[0]) ff_die("escrow-create requires non-empty --buyer-nick and --seller-nick");
    if (amount_atomic == 0ULL) ff_die("escrow-create requires --amount-atomic > 0");
    if (memo_trim && !memo_trim[0]) { free(memo_trim); memo_trim = NULL; }
    if (refund_trim && !refund_trim[0]) { free(refund_trim); refund_trim = NULL; }

    char url[1024];
    if (pf_join_url(url, sizeof(url), base, "/escrows") != 0) {
        ff_die("escrow-create: failed to build /escrows url");
    }
    char *body = build_escrow_create_json_body(buyer, seller, amount_atomic, memo_trim, refund_trim);
    if (!body) ff_die("oom");

    ff_http_resp_t r;
    memset(&r, 0, sizeof(r));
    if (ff_http_post_json_idempotent(url, socks5, body, idem_key_trim, &r) != 0) {
        long st = ff_http_last_status();
        char *detail = http_error_detail_from_response(&r);
        const char *msg = (detail && detail[0]) ? detail : ff_http_last_error();
        if (st > 0) ff_die("escrow-create failed (status=%ld): %s", st, msg);
        ff_die("escrow-create failed: %s", msg);
    }

    op_write_escrow_create_artifacts(run_dir, base, socks5, body, r.data ? r.data : "{}");
    op_print_escrow_create_summary(r.data ? r.data : "{}", run_dir);
    printf("%s\n", r.data ? r.data : "{}");

    ff_http_resp_free(&r);
    free(body);
    free(idem_key_trim);
    free(refund_trim);
    free(memo_trim);
    free(seller);
    free(buyer);
    return 0;
}

int cmd_escrow_status(const char *base, const char *socks5,
                      unsigned long long escrow_id,
                      const char *nick, const char *token,
                      const char *run_dir) {
    pf_require_escrow_base_url_policy(base, 0, "escrow-status");
    require_tor(base, socks5);
    if (!nick || !nick[0] || !token || !token[0]) {
        ff_die("escrow-status requires --nick and --token");
    }

    char *nick_e = url_encode_component(nick);
    char *token_e = url_encode_component(token);
    if (!nick_e || !token_e) {
        free(nick_e);
        secure_free_str(&token_e);
        ff_die("oom");
    }

    char url[1400];
    snprintf(url, sizeof(url), "%s/escrows/%llu?nick=%s&token=%s", base, escrow_id, nick_e, token_e);

    ff_http_resp_t r;
    memset(&r, 0, sizeof(r));
    if (ff_http_get_json_auth(url, socks5, NULL, NULL, &r) != 0) {
        long st = ff_http_last_status();
        char *detail = http_error_detail_from_response(&r);
        const char *msg = (detail && detail[0]) ? detail : ff_http_last_error();
        free(nick_e);
        secure_free_str(&token_e);
        if (st > 0) ff_die("escrow-status failed (status=%ld): %s", st, msg);
        ff_die("escrow-status failed: %s", msg);
    }

    op_write_escrow_status_artifacts(run_dir, base, socks5, escrow_id, r.data ? r.data : "{}");
    op_print_escrow_status_summary(r.data ? r.data : "{}", run_dir);
    printf("%s\n", r.data ? r.data : "{}");

    ff_http_resp_free(&r);
    free(nick_e);
    secure_free_str(&token_e);
    return 0;
}

typedef struct {
    const char *role_label; /* buyer / seller / arbiter */
    const char *nick;
    const char *token;
    const char *wallet_rpc_url;
    const char *wallet_rpc_user;
    const char *wallet_rpc_pass;
    const char *wallet_name;
    const char *wallet_password_env;
    const char *refund_address; /* used only for r1 */
} gate3_party_cfg_t;

static char *g3n_lookup_escrow_token_sqlite_or_die(const char *db_path,
                                                   unsigned long long escrow_id,
                                                   const char *role_label) {
    if (!db_path || !db_path[0]) {
        ff_die("gate3-ready: missing sqlite db path for %s token lookup", role_label ? role_label : "participant");
    }
    if (!role_label || !role_label[0]) {
        ff_die("gate3-ready: invalid role for sqlite token lookup");
    }

    const char *column = NULL;
    if (strcmp(role_label, "buyer") == 0) column = "buyer_token";
    else if (strcmp(role_label, "seller") == 0) column = "seller_token";
    else ff_die("gate3-ready: unsupported sqlite token lookup role: %s", role_label);

    char sql[128];
    if (snprintf(sql, sizeof(sql), "SELECT %s FROM escrows WHERE id = ?1", column) >= (int)sizeof(sql)) {
        ff_die("gate3-ready: sqlite query too long");
    }

    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char *token = NULL;
    int rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        const char *msg = (db ? sqlite3_errmsg(db) : "sqlite open failed");
        if (db) sqlite3_close(db);
        ff_die("gate3-ready: failed to open sqlite db (%s): %s", db_path, msg ? msg : "unknown error");
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        const char *msg = sqlite3_errmsg(db);
        sqlite3_close(db);
        ff_die("gate3-ready: sqlite prepare failed: %s", msg ? msg : "unknown error");
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)escrow_id);
    if (rc != SQLITE_OK) {
        const char *msg = sqlite3_errmsg(db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        ff_die("gate3-ready: sqlite bind failed: %s", msg ? msg : "unknown error");
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char *raw = sqlite3_column_text(stmt, 0);
        token = dup_trimmed_copy(raw ? (const char*)raw : NULL);
        if (!token || !token[0]) {
            secure_free_str(&token);
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            ff_die("gate3-ready: %s token not found in sqlite db for escrow %llu",
                   role_label, escrow_id);
        }
    } else if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        ff_die("gate3-ready: escrow %llu not found in sqlite db (%s)", escrow_id, db_path);
    } else {
        const char *msg = sqlite3_errmsg(db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        ff_die("gate3-ready: sqlite query failed: %s", msg ? msg : "unknown error");
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return token;
}

int cmd_escrow_token_from_db(const char *db_path,
                             unsigned long long escrow_id,
                             const char *role_label) {
    if (escrow_id == 0ULL) {
        ff_die("escrow-token-from-db: --escrow-id must be > 0");
    }
    char *token = g3n_lookup_escrow_token_sqlite_or_die(db_path, escrow_id, role_label);
    printf("%s\n", token);
    secure_free_str(&token);
    return 0;
}

int cmd_escrow_arbiter_token(unsigned long long escrow_id,
                             const char *master_token) {
    if (escrow_id == 0ULL) {
        ff_die("escrow-arbiter-token: --escrow-id must be > 0");
    }
    if (!master_token || !master_token[0]) {
        ff_die("escrow-arbiter-token: missing master token");
    }

    char payload[64];
    int payload_n = snprintf(payload, sizeof(payload), "escrow:%llu", escrow_id);
    if (payload_n <= 0 || (size_t)payload_n >= sizeof(payload)) {
        ff_die("escrow-arbiter-token: payload build failed");
    }

    unsigned char mac[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;
    if (crypto_auth_hmacsha256_init(
            &st,
            (const unsigned char *)master_token,
            strlen(master_token)) != 0) {
        ff_die("escrow-arbiter-token: hmac init failed");
    }
    crypto_auth_hmacsha256_update(
        &st,
        (const unsigned char *)payload,
        (unsigned long long)payload_n);
    crypto_auth_hmacsha256_final(&st, mac);
    sodium_memzero(&st, sizeof(st));

    char out_hex[crypto_auth_hmacsha256_BYTES * 2 + 1];
    sodium_bin2hex(out_hex, sizeof(out_hex), mac, sizeof(mac));
    sodium_memzero(mac, sizeof(mac));
    printf("%s\n", out_hex);
    sodium_memzero(out_hex, sizeof(out_hex));
    return 0;
}

static void visible_append_line_or_die(char **buf, size_t *len, const char *line) {
    append_or_die(buf, len, line ? line : "");
    append_or_die(buf, len, "\n");
}

static void visible_append_bytes_or_die(char **buf, size_t *len, const char *s, size_t n) {
    if (!buf || !len || !s) ff_die("visible export: invalid append");
    char *p = (char *)realloc(*buf, *len + n + 1);
    if (!p) ff_die("oom");
    memcpy(p + *len, s, n);
    *len += n;
    p[*len] = 0;
    *buf = p;
}

static void visible_trim_ws_slice(const char **p, size_t *n) {
    if (!p || !*p || !n) return;
    while (*n > 0 && isspace((unsigned char)(*p)[0])) {
        (*p)++;
        (*n)--;
    }
    while (*n > 0 && isspace((unsigned char)(*p)[*n - 1])) {
        (*n)--;
    }
}

static int visible_valid_env_key(const char *s, size_t n) {
    if (!s || n == 0) return 0;
    unsigned char c0 = (unsigned char)s[0];
    if (!(c0 == '_' || isalpha(c0))) return 0;
    for (size_t i = 1; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(c == '_' || isalnum(c))) return 0;
    }
    return 1;
}

static int visible_parse_env_assignment_line(const char *line,
                                             size_t line_len,
                                             int require_export,
                                             char *key_out,
                                             size_t key_cap,
                                             const char **val_out,
                                             size_t *val_len_out) {
    if (!line || !key_out || key_cap < 2 || !val_out || !val_len_out) return -1;
    *val_out = NULL;
    *val_len_out = 0;
    key_out[0] = 0;

    const char *p = line;
    size_t n = line_len;
    visible_trim_ws_slice(&p, &n);
    if (n == 0) return 0;
    if (p[0] == '#') return 0;

    int has_export = 0;
    if (n >= 6 && memcmp(p, "export", 6) == 0 && (n == 6 || isspace((unsigned char)p[6]))) {
        has_export = 1;
        p += 6;
        n -= 6;
        visible_trim_ws_slice(&p, &n);
    }
    if (require_export && !has_export) return 0;
    if (n == 0) return 0;

    size_t k = 0;
    while (k < n && (p[k] == '_' || isalnum((unsigned char)p[k]) || (k == 0 && isalpha((unsigned char)p[k])))) {
        k++;
    }
    if (k == 0 || !visible_valid_env_key(p, k)) return -1;

    const char *q = p + k;
    size_t qn = n - k;
    while (qn > 0 && isspace((unsigned char)q[0])) {
        q++;
        qn--;
    }
    if (qn == 0 || q[0] != '=') return -1;
    q++;
    qn--;
    while (qn > 0 && isspace((unsigned char)q[0])) {
        q++;
        qn--;
    }
    while (qn > 0 && (q[qn - 1] == '\r' || isspace((unsigned char)q[qn - 1]))) {
        qn--;
    }

    if (k >= key_cap) return -1;
    memcpy(key_out, p, k);
    key_out[k] = 0;

    if (qn >= 2 && ((q[0] == '\'' && q[qn - 1] == '\'') || (q[0] == '"' && q[qn - 1] == '"'))) {
        q++;
        qn -= 2;
    }

    *val_out = q;
    *val_len_out = qn;
    return 1;
}

static int visible_env_key_is_sensitive(const char *key) {
    if (!key || !key[0]) return 0;
    char up[256];
    size_t n = strlen(key);
    if (n >= sizeof(up)) n = sizeof(up) - 1;
    for (size_t i = 0; i < n; i++) {
        up[i] = (char)toupper((unsigned char)key[i]);
    }
    up[n] = 0;
    static const char *pats[] = {
        "TOKEN", "PASS", "SECRET", "KEY", "SEED", "AUTH", "COOKIE", "CRED"
    };
    for (size_t i = 0; i < sizeof(pats) / sizeof(pats[0]); i++) {
        if (strstr(up, pats[i]) != NULL) return 1;
    }
    return 0;
}

static void visible_append_shell_single_quoted_or_die(char **buf,
                                                      size_t *len,
                                                      const char *v,
                                                      size_t v_len) {
    append_or_die(buf, len, "'");
    for (size_t i = 0; i < v_len; i++) {
        unsigned char c = (unsigned char)v[i];
        if (c == '\'') {
            append_or_die(buf, len, "'\\''");
            continue;
        }
        if (c == '\r' || c == '\n' || c == 0 || (c < 0x20 && c != '\t')) {
            append_or_die(buf, len, " ");
            continue;
        }
        char ch = (char)c;
        visible_append_bytes_or_die(buf, len, &ch, 1);
    }
    append_or_die(buf, len, "'");
}

static void visible_append_env_kv_or_die(char **buf,
                                         size_t *len,
                                         const char *key,
                                         const char *value,
                                         size_t value_len) {
    if (!key || !key[0]) return;
    append_or_die(buf, len, key);
    append_or_die(buf, len, "=");
    visible_append_shell_single_quoted_or_die(buf, len, value ? value : "", value ? value_len : 0);
    append_or_die(buf, len, "\n");
}

static void visible_append_env_export_kv_or_die(char **buf,
                                                size_t *len,
                                                const char *key,
                                                const char *value,
                                                size_t value_len) {
    append_or_die(buf, len, "export ");
    visible_append_env_kv_or_die(buf, len, key, value, value_len);
}

static void visible_append_env_assignments_from_text_or_die(char **buf,
                                                            size_t *len,
                                                            const char *text,
                                                            int require_export_only,
                                                            int include_sensitive,
                                                            unsigned *kept_out,
                                                            unsigned *skipped_sensitive_out,
                                                            unsigned *skipped_unparsed_out) {
    unsigned kept = 0;
    unsigned skipped_sensitive = 0;
    unsigned skipped_unparsed = 0;
    if (kept_out) *kept_out = 0;
    if (skipped_sensitive_out) *skipped_sensitive_out = 0;
    if (skipped_unparsed_out) *skipped_unparsed_out = 0;
    if (!text) return;

    const char *p = text;
    while (*p) {
        const char *line_start = p;
        const char *line_end = strchr(p, '\n');
        size_t line_len = line_end ? (size_t)(line_end - line_start) : strlen(line_start);

        char key[256];
        const char *val = NULL;
        size_t val_len = 0;
        int pr = visible_parse_env_assignment_line(
            line_start,
            line_len,
            require_export_only,
            key,
            sizeof(key),
            &val,
            &val_len
        );
        if (pr > 0) {
            if (!include_sensitive && visible_env_key_is_sensitive(key)) {
                skipped_sensitive++;
            } else {
                visible_append_env_export_kv_or_die(buf, len, key, val ? val : "", val ? val_len : 0);
                kept++;
            }
        } else if (pr < 0) {
            skipped_unparsed++;
        }

        if (!line_end) break;
        p = line_end + 1;
    }

    if (kept_out) *kept_out = kept;
    if (skipped_sensitive_out) *skipped_sensitive_out = skipped_sensitive;
    if (skipped_unparsed_out) *skipped_unparsed_out = skipped_unparsed;
}

static void visible_verify_dir_nofollow_or_die(const char *path) {
    if (!path || !path[0]) ff_die("env-export-visible-flow: empty out dir");

    const char *p = path;
    int curfd = -1;
    if (path[0] == '/') {
        curfd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        p = path + 1;
    } else {
        curfd = open(".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    }
    if (curfd < 0) {
        ff_die("env-export-visible-flow: open(%s) failed: %s", path[0] == '/' ? "/" : ".", strerror(errno));
    }

    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *seg = p;
        while (*p && *p != '/') p++;
        size_t seg_len = (size_t)(p - seg);
        if (seg_len == 1 && seg[0] == '.') continue;
        if (seg_len == 2 && seg[0] == '.' && seg[1] == '.') {
            close(curfd);
            ff_die("env-export-visible-flow: --out-dir must not contain '..': %s", path);
        }
        if (seg_len == 0 || seg_len >= 256) {
            close(curfd);
            ff_die("env-export-visible-flow: invalid path segment in --out-dir: %s", path);
        }
        char name[256];
        memcpy(name, seg, seg_len);
        name[seg_len] = 0;
        int nextfd = openat(curfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (nextfd < 0) {
            int e = errno;
            close(curfd);
            ff_die("env-export-visible-flow: unsafe/non-dir path component '%s' in %s: %s", name, path, strerror(e));
        }
        close(curfd);
        curfd = nextfd;
    }

    struct stat st;
    if (fstat(curfd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        int e = errno;
        close(curfd);
        ff_die("env-export-visible-flow: out dir verify failed (%s): %s", path, strerror(e ? e : ENOTDIR));
    }
    close(curfd);
}
static void visible_json_set_text_or_null(json_t *obj,
                                          const char *key,
                                          sqlite3_stmt *stmt,
                                          int col) {
    if (sqlite3_column_type(stmt, col) == SQLITE_NULL) {
        json_object_set_new(obj, key, json_null());
        return;
    }
    const unsigned char *v = sqlite3_column_text(stmt, col);
    json_object_set_new(obj, key, json_string(v ? (const char *)v : ""));
}

static void visible_json_set_i64_or_null(json_t *obj,
                                         const char *key,
                                         sqlite3_stmt *stmt,
                                         int col) {
    if (sqlite3_column_type(stmt, col) == SQLITE_NULL) {
        json_object_set_new(obj, key, json_null());
        return;
    }
    sqlite3_int64 v = sqlite3_column_int64(stmt, col);
    json_object_set_new(obj, key, json_integer((json_int_t)v));
}

static json_t *visible_flow_row_to_json(sqlite3_stmt *stmt) {
    json_t *row = json_object();
    if (!row) ff_die("oom");
    visible_json_set_i64_or_null(row, "id", stmt, 0);
    visible_json_set_text_or_null(row, "state", stmt, 1);
    visible_json_set_text_or_null(row, "buyer_nick", stmt, 2);
    visible_json_set_text_or_null(row, "seller_nick", stmt, 3);
    visible_json_set_text_or_null(row, "arbiter_nick", stmt, 4);
    visible_json_set_i64_or_null(row, "amount_atomic", stmt, 5);
    visible_json_set_text_or_null(row, "buyer_token", stmt, 6);
    visible_json_set_text_or_null(row, "seller_token", stmt, 7);
    visible_json_set_text_or_null(row, "refund_address_buyer", stmt, 8);
    visible_json_set_text_or_null(row, "refund_address_seller", stmt, 9);
    visible_json_set_text_or_null(row, "deposit_address", stmt, 10);
    visible_json_set_text_or_null(row, "release_txid", stmt, 11);
    visible_json_set_text_or_null(row, "refund_txid", stmt, 12);
    return row;
}

static json_t *visible_flow_query_one(sqlite3 *db, const char *sql) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        if (stmt) sqlite3_finalize(stmt);
        return NULL;
    }
    rc = sqlite3_step(stmt);
    json_t *out = NULL;
    if (rc == SQLITE_ROW) {
        out = visible_flow_row_to_json(stmt);
    }
    sqlite3_finalize(stmt);
    return out;
}

static const char *visible_json_text_or_empty(json_t *obj, const char *key) {
    if (!obj || !json_is_object(obj)) return "";
    json_t *v = json_object_get(obj, key);
    if (!v || json_is_null(v)) return "";
    if (json_is_string(v)) return json_string_value(v);
    return "";
}

static long long visible_json_i64_or_neg1(json_t *obj, const char *key) {
    if (!obj || !json_is_object(obj)) return -1;
    json_t *v = json_object_get(obj, key);
    if (!v || json_is_null(v) || !json_is_integer(v)) return -1;
    return (long long)json_integer_value(v);
}

static void visible_append_escrow_env_snapshot_or_die(char **buf,
                                                      size_t *len,
                                                      json_t *active_row,
                                                      int include_tokens) {
    if (!active_row || !json_is_object(active_row)) return;
    visible_append_line_or_die(buf, len, "# --- escrow snapshot from sqlite ---");

    char num[64];
    long long id = visible_json_i64_or_neg1(active_row, "id");
    if (id >= 0) snprintf(num, sizeof(num), "%lld", id); else ff_strlcpy(num, "", sizeof(num));
    visible_append_env_kv_or_die(buf, len, "ESCROW_ID_ACTIVE", num, strlen(num));

    {
        const char *v = visible_json_text_or_empty(active_row, "state");
        visible_append_env_kv_or_die(buf, len, "ESCROW_STATE_ACTIVE", v, strlen(v));
    }
    {
        const char *v = visible_json_text_or_empty(active_row, "buyer_nick");
        visible_append_env_kv_or_die(buf, len, "BUYER_NICK", v, strlen(v));
    }
    {
        const char *v = visible_json_text_or_empty(active_row, "seller_nick");
        visible_append_env_kv_or_die(buf, len, "SELLER_NICK", v, strlen(v));
    }
    if (include_tokens) {
        const char *bt = visible_json_text_or_empty(active_row, "buyer_token");
        const char *st = visible_json_text_or_empty(active_row, "seller_token");
        visible_append_env_kv_or_die(buf, len, "BUYER_TOKEN", bt, strlen(bt));
        visible_append_env_kv_or_die(buf, len, "SELLER_TOKEN", st, strlen(st));
    } else {
        visible_append_line_or_die(buf, len, "# BUYER_TOKEN / SELLER_TOKEN omitted by default (break-glass: --include-tokens)");
    }
    {
        const char *v = visible_json_text_or_empty(active_row, "refund_address_buyer");
        visible_append_env_kv_or_die(buf, len, "BUYER_REFUND_ADDRESS", v, strlen(v));
    }
    {
        const char *v = visible_json_text_or_empty(active_row, "refund_address_seller");
        visible_append_env_kv_or_die(buf, len, "SELLER_REFUND_ADDRESS", v, strlen(v));
    }
    {
        const char *v = visible_json_text_or_empty(active_row, "deposit_address");
        visible_append_env_kv_or_die(buf, len, "DEPOSIT_ADDRESS", v, strlen(v));
    }

    long long amount = visible_json_i64_or_neg1(active_row, "amount_atomic");
    if (amount >= 0) snprintf(num, sizeof(num), "%lld", amount); else ff_strlcpy(num, "", sizeof(num));
    visible_append_env_kv_or_die(buf, len, "AMOUNT_ATOMIC", num, strlen(num));
    {
        const char *v = visible_json_text_or_empty(active_row, "release_txid");
        visible_append_env_kv_or_die(buf, len, "RELEASE_TXID", v, strlen(v));
    }
    {
        const char *v = visible_json_text_or_empty(active_row, "refund_txid");
        visible_append_env_kv_or_die(buf, len, "REFUND_TXID", v, strlen(v));
    }
    append_or_die(buf, len, "\n");
}

static void visible_build_escrow_query_or_die(char *out,
                                              size_t out_cap,
                                              const char *tail_sql,
                                              int include_tokens) {
    const char *token_cols = include_tokens
        ? "buyer_token, seller_token, "
        : "NULL AS buyer_token, NULL AS seller_token, ";
    int n = snprintf(
        out,
        out_cap,
        "SELECT id, state, buyer_nick, seller_nick, arbiter_nick, "
        "amount_atomic, %s"
        "refund_address_buyer, refund_address_seller, deposit_address, "
        "release_txid, refund_txid "
        "FROM escrows %s",
        token_cols,
        tail_sql ? tail_sql : ""
    );
    if (n <= 0 || (size_t)n >= out_cap) {
        ff_die("env-export-visible-flow: sql build failed");
    }
}

int cmd_env_export_visible_flow(const char *out_dir,
                                const char *base_url,
                                const char *db_path,
                                const char *nx_conf_path,
                                const char *real3p_env_path,
                                int include_real3p,
                                int include_tokens,
                                int include_config_secrets) {
    const char *out_dir_eff = (out_dir && out_dir[0]) ? out_dir : "VISIBLE_FLOW";
    const char *base_eff = (base_url && base_url[0]) ? base_url : "http://127.0.0.1:9000";
    const char *db_eff = (db_path && db_path[0]) ? db_path : "/var/lib/freeforum-escrow/escrow_rust.db";
    const char *nx_conf_eff = (nx_conf_path && nx_conf_path[0]) ? nx_conf_path : "/etc/conf.d/nx-escrow-rs";
    const char *real3p_eff = (real3p_env_path && real3p_env_path[0]) ? real3p_env_path : "/var/lib/monero/real3p_20260218_105633/credentials.env";

    if (include_tokens) {
        fprintf(stderr, "WARNING: env-export-visible-flow will write escrow tokens to disk (--include-tokens).\n");
    }
    if (include_config_secrets) {
        fprintf(stderr, "WARNING: env-export-visible-flow will write runtime/credential secrets to disk (--include-config-secrets).\n");
    }

    if (ff_mkdir_p(out_dir_eff) != 0) {
        ff_die("env-export-visible-flow: failed to create out dir: %s", out_dir_eff);
    }
    visible_verify_dir_nofollow_or_die(out_dir_eff);

    char out_env_path[4096];
    char out_json_path[4096];
    if (snprintf(out_env_path, sizeof(out_env_path), "%s/ACTIVE_FLOW.env", out_dir_eff) >= (int)sizeof(out_env_path) ||
        snprintf(out_json_path, sizeof(out_json_path), "%s/wallet_addresses.json", out_dir_eff) >= (int)sizeof(out_json_path)) {
        ff_die("env-export-visible-flow: output path too long");
    }

    char *env_txt = NULL;
    size_t env_len = 0;
    char now_s[32];
    pf_utc_now(now_s);
    char line[1024];

    snprintf(line, sizeof(line), "# Generated by nexum env-export-visible-flow on %s", now_s);
    visible_append_line_or_die(&env_txt, &env_len, line);
    visible_append_env_kv_or_die(&env_txt, &env_len, "BASE_URL", base_eff, strlen(base_eff));
    visible_append_env_kv_or_die(&env_txt, &env_len, "ESCROW_DB_PATH", db_eff, strlen(db_eff));
    append_or_die(&env_txt, &env_len, "\n");

    if (access(nx_conf_eff, F_OK) == 0) {
        snprintf(line, sizeof(line), "# --- nx-escrow-rs runtime (%s) ---", nx_conf_eff);
        visible_append_line_or_die(&env_txt, &env_len, line);
        char *nx_conf_raw = read_file_str(nx_conf_eff, NULL);
        if (nx_conf_raw) {
            unsigned kept = 0, skipped_sensitive = 0, skipped_unparsed = 0;
            visible_append_env_assignments_from_text_or_die(
                &env_txt,
                &env_len,
                nx_conf_raw,
                1,
                include_config_secrets,
                &kept,
                &skipped_sensitive,
                &skipped_unparsed
            );
            if (!include_config_secrets && skipped_sensitive > 0) {
                snprintf(line, sizeof(line),
                         "# redacted %u sensitive export(s) from nx-conf (pass --include-config-secrets for break-glass export)",
                         skipped_sensitive);
                visible_append_line_or_die(&env_txt, &env_len, line);
            }
            if (skipped_unparsed > 0) {
                snprintf(line, sizeof(line),
                         "# skipped %u non-assignment line(s) in nx-conf while exporting sanitized env",
                         skipped_unparsed);
                visible_append_line_or_die(&env_txt, &env_len, line);
            }
            if (kept == 0 && skipped_sensitive == 0 && skipped_unparsed == 0) {
                visible_append_line_or_die(&env_txt, &env_len, "# no export assignments found in nx-conf");
            }
            free(nx_conf_raw);
        }
        append_or_die(&env_txt, &env_len, "\n");
    } else {
        snprintf(line, sizeof(line), "# nx-escrow-rs runtime config not found: %s", nx_conf_eff);
        visible_append_line_or_die(&env_txt, &env_len, line);
        append_or_die(&env_txt, &env_len, "\n");
    }

    if (include_real3p) {
        if (!include_config_secrets) {
            visible_append_line_or_die(
                &env_txt,
                &env_len,
                "# legacy real3p credentials requested but suppressed (requires --include-config-secrets)"
            );
            snprintf(line, sizeof(line),
                     "# re-run with --include-real3p --include-config-secrets for break-glass export: %s",
                     real3p_eff);
            visible_append_line_or_die(&env_txt, &env_len, line);
            append_or_die(&env_txt, &env_len, "\n");
        } else if (access(real3p_eff, F_OK) == 0) {
            snprintf(line, sizeof(line), "# --- legacy real3p credentials (%s) ---", real3p_eff);
            visible_append_line_or_die(&env_txt, &env_len, line);
            char *real3p_raw = read_file_str(real3p_eff, NULL);
            if (real3p_raw) {
                unsigned kept = 0, skipped_sensitive = 0, skipped_unparsed = 0;
                visible_append_env_assignments_from_text_or_die(
                    &env_txt,
                    &env_len,
                    real3p_raw,
                    0,
                    1,
                    &kept,
                    &skipped_sensitive,
                    &skipped_unparsed
                );
                if (skipped_unparsed > 0) {
                    snprintf(line, sizeof(line),
                             "# skipped %u non-assignment line(s) in real3p credentials file",
                             skipped_unparsed);
                    visible_append_line_or_die(&env_txt, &env_len, line);
                }
                free(real3p_raw);
            }
            append_or_die(&env_txt, &env_len, "\n");
        } else {
            snprintf(line, sizeof(line), "# legacy real3p credentials not found: %s", real3p_eff);
            visible_append_line_or_die(&env_txt, &env_len, line);
            append_or_die(&env_txt, &env_len, "\n");
        }
    } else {
        visible_append_line_or_die(&env_txt, &env_len, "# legacy real3p credentials export disabled by default");
        snprintf(line, sizeof(line),
                 "# break-glass export requires both --include-real3p and --include-config-secrets: %s",
                 real3p_eff);
        visible_append_line_or_die(&env_txt, &env_len, line);
        append_or_die(&env_txt, &env_len, "\n");
    }

    json_t *payload = json_object();
    if (!payload) ff_die("oom");
    json_object_set_new(payload, "db_path", json_string(db_eff));
    json_object_set_new(payload, "tokens_included", json_boolean(include_tokens ? 1 : 0));
    json_object_set_new(payload, "config_secrets_included", json_boolean(include_config_secrets ? 1 : 0));
    json_object_set_new(payload, "latest", json_null());
    json_object_set_new(payload, "latest_funded", json_null());
    json_object_set_new(payload, "escrow_32", json_null());

    sqlite3 *db = NULL;
    if (access(db_eff, F_OK) == 0) {
        if (sqlite3_open_v2(db_eff, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
            char sql_latest[1024];
            char sql_latest_funded[1024];
            char sql_escrow_32[1024];
            visible_build_escrow_query_or_die(sql_latest, sizeof(sql_latest), "ORDER BY id DESC LIMIT 1", include_tokens);
            visible_build_escrow_query_or_die(
                sql_latest_funded,
                sizeof(sql_latest_funded),
                "WHERE state='FUNDED' ORDER BY id DESC LIMIT 1",
                include_tokens
            );
            visible_build_escrow_query_or_die(sql_escrow_32, sizeof(sql_escrow_32), "WHERE id=32", include_tokens);

            json_t *latest = visible_flow_query_one(db, sql_latest);
            json_t *latest_funded = visible_flow_query_one(db, sql_latest_funded);
            json_t *escrow_32 = visible_flow_query_one(db, sql_escrow_32);
            if (latest) json_object_set_new(payload, "latest", latest);
            if (latest_funded) json_object_set_new(payload, "latest_funded", latest_funded);
            if (escrow_32) json_object_set_new(payload, "escrow_32", escrow_32);

            json_t *active = json_object_get(payload, "latest_funded");
            if (!active || json_is_null(active)) active = json_object_get(payload, "latest");
            visible_append_escrow_env_snapshot_or_die(&env_txt, &env_len, active, include_tokens);
        } else {
            json_object_set_new(
                payload,
                "error",
                json_string("failed to open sqlite db")
            );
        }
    } else {
        snprintf(line, sizeof(line), "db not found: %s", db_eff);
        json_object_set_new(payload, "error", json_string(line));
    }
    if (db) sqlite3_close(db);

    char *payload_json = json_dumps(payload, JSON_INDENT(2));
    json_decref(payload);
    if (!payload_json) ff_die("env-export-visible-flow: json serialization failed");

    if (pf_write_text(out_env_path, env_txt ? env_txt : "") != 0) {
        free(payload_json);
        free(env_txt);
        ff_die("env-export-visible-flow: failed to write %s", out_env_path);
    }
    if (pf_write_text(out_json_path, payload_json) != 0) {
        free(payload_json);
        free(env_txt);
        ff_die("env-export-visible-flow: failed to write %s", out_json_path);
    }

    printf("wrote: %s\n", out_env_path);
    printf("wrote: %s\n", out_json_path);

    free(payload_json);
    free(env_txt);
    return 0;
}

static void op_write_escrow_gate3_ready_artifacts(const char *run_dir,
                                                  const char *base,
                                                  const char *socks5,
                                                  unsigned long long escrow_id) {
    if (!run_dir || !run_dir[0]) return;
    op_write_run_meta_manifest_basic(
        run_dir,
        "nexum escrow-gate3-ready",
        base,
        socks5,
        (long long)escrow_id,
        "READY",
        "flow/r1_buyer.json",
        "flow/status_ready.json",
        "flow/status_after_ready.json"
    );
}

typedef struct {
    char *buyer;
    char *seller;
    char *arbiter;
    char *state;
    char *deposit_address;
} g3n_round_fetch_t;

static void g3n_round_fetch_free(g3n_round_fetch_t *rf) {
    if (!rf) return;
    free(rf->buyer);
    free(rf->seller);
    free(rf->arbiter);
    free(rf->state);
    free(rf->deposit_address);
    memset(rf, 0, sizeof(*rf));
}

static char *g3n_json_dup_string(json_t *obj, const char *key) {
    if (!obj || !json_is_object(obj) || !key) return NULL;
    json_t *v = json_object_get(obj, key);
    if (!v || json_is_null(v) || !json_is_string(v)) return NULL;
    const char *s = json_string_value(v);
    if (!s) return NULL;
    return strdup(s);
}

static long long g3n_json_int_or_neg1(json_t *obj, const char *key) {
    if (!obj || !json_is_object(obj) || !key) return -1;
    json_t *v = json_object_get(obj, key);
    if (!v) return -1;
    if (json_is_integer(v)) return (long long)json_integer_value(v);
    if (json_is_string(v)) {
        const char *s = json_string_value(v);
        if (!s || !s[0]) return -1;
        char *endp = NULL;
        long long x = strtoll(s, &endp, 10);
        if (endp == s || (endp && *endp)) return -1;
        return x;
    }
    return -1;
}

static json_t *g3n_json_load_obj_or_die(const char *txt, const char *ctx) {
    if (!txt) ff_die("%s: empty json buffer", ctx ? ctx : "json");
    json_error_t err;
    json_t *root = json_loads(txt, 0, &err);
    if (!root) {
        ff_die("%s: invalid json (%s at line %d col %d)",
               ctx ? ctx : "json",
               err.text,
               err.line,
               err.column);
    }
    if (!json_is_object(root)) {
        json_decref(root);
        ff_die("%s: expected json object", ctx ? ctx : "json");
    }
    return root;
}

static char *g3n_json_dumps_compact_or_die(json_t *v, const char *ctx) {
    char *s = json_dumps(v, JSON_COMPACT);
    if (!s) ff_die("%s: json serialization failed", ctx ? ctx : "json");
    return s;
}

static char *g3n_trim_copy_or_die(const char *s, const char *label) {
    char *p = dup_trimmed_copy(s);
    if (!p) ff_die("oom");
    if (!p[0]) {
        free(p);
        ff_die("%s must not be empty", label ? label : "value");
    }
    return p;
}

static char *g3n_resolve_wallet_password_env_or_die(const char *env_name, const char *label) {
    if (!env_name || !env_name[0]) ff_die("%s requires wallet password env name", label ? label : "gate3");
    const char *raw = getenv(env_name);
    if (!raw || !raw[0]) {
        ff_die("%s: wallet password env '%s' is empty or not set",
               label ? label : "gate3", env_name);
    }
    char *pw = dup_trimmed_copy(raw);
    if (!pw) ff_die("oom");
    if (!pw[0]) {
        secure_free_str(&pw);
        ff_die("%s: wallet password env '%s' resolved to empty value",
               label ? label : "gate3", env_name);
    }
    return pw;
}

static char *g3n_build_auth_query_url_or_die(const char *base,
                                             unsigned long long escrow_id,
                                             const char *suffix,
                                             const char *nick,
                                             const char *token) {
    char *nick_e = url_encode_component(nick);
    char *token_e = url_encode_component(token);
    if (!nick_e || !token_e) {
        free(nick_e);
        secure_free_str(&token_e);
        ff_die("oom");
    }
    const char *sfx = suffix ? suffix : "";
    size_t cap = strlen(base) + strlen(sfx) + strlen(nick_e) + strlen(token_e) + 128;
    char *url = (char *)malloc(cap);
    if (!url) {
        free(nick_e);
        secure_free_str(&token_e);
        ff_die("oom");
    }
    snprintf(url, cap, "%s/escrows/%llu%s?nick=%s&token=%s",
             base, escrow_id, sfx, nick_e, token_e);
    free(nick_e);
    secure_free_str(&token_e);
    return url;
}

static char *g3n_http_error_msg_owned(ff_http_resp_t *r) {
    char *detail = http_error_detail_from_response(r);
    if (detail && detail[0]) return detail;
    free(detail);
    const char *fallback = ff_http_last_error();
    if (!fallback) fallback = "http request failed";
    return strdup(fallback);
}

static char *g3n_escrow_get_json_or_die(const char *base,
                                        const char *socks5,
                                        unsigned long long escrow_id,
                                        const char *suffix,
                                        const char *nick,
                                        const char *token,
                                        const char *ctx) {
    char *url = g3n_build_auth_query_url_or_die(base, escrow_id, suffix, nick, token);
    ff_http_resp_t r;
    memset(&r, 0, sizeof(r));
    if (ff_http_get_json_auth(url, socks5, token, NULL, &r) != 0) {
        long st = ff_http_last_status();
        char *msg = g3n_http_error_msg_owned(&r);
        free(url);
        ff_http_resp_free(&r);
        if (st > 0) ff_die("%s failed (status=%ld): %s", ctx, st, msg ? msg : "http error");
        ff_die("%s failed: %s", ctx, msg ? msg : "http error");
    }
    char *out = r.data ? strdup(r.data) : strdup("{}");
    ff_http_resp_free(&r);
    free(url);
    if (!out) ff_die("oom");
    return out;
}

static char *g3n_make_round_idem_key_or_die(const char *prefix,
                                            unsigned long long escrow_id,
                                            const char *nick,
                                            const char *scope) {
    if (!prefix || !prefix[0] || !nick || !nick[0] || !scope || !scope[0]) ff_die("gate3-ready: invalid idempotency inputs");
    size_t cap = strlen(prefix) + strlen(nick) + strlen(scope) + 64;
    char *k = (char *)malloc(cap);
    if (!k) ff_die("oom");
    snprintf(k, cap, "%s:%llu:%s:%s", prefix, escrow_id, nick, scope);
    return k;
}

static char *g3n_escrow_post_round_or_die(const char *base,
                                          const char *socks5,
                                          unsigned long long escrow_id,
                                          const char *round_scope,
                                          const char *nick,
                                          const char *token,
                                          const char *multisig_info,
                                          const char *refund_address,
                                          const char *idempotency_prefix,
                                          unsigned retry_max,
                                          unsigned poll_interval_s) {
    char path[64];
    snprintf(path, sizeof(path), "/escrows/%llu/xmr/%s", escrow_id, round_scope);
    char url[1024];
    if (pf_join_url(url, sizeof(url), base, path) != 0) {
        ff_die("gate3-ready: failed to build url for %s", round_scope);
    }

    json_t *body_j = json_object();
    if (!body_j) ff_die("oom");
    json_object_set_new(body_j, "nick", json_string(nick));
    json_object_set_new(body_j, "token", json_string(token));
    json_object_set_new(body_j, "multisig_info", json_string(multisig_info));
    if (refund_address && refund_address[0]) {
        json_object_set_new(body_j, "refund_address", json_string(refund_address));
    }
    char *body = g3n_json_dumps_compact_or_die(body_j, "gate3 round body");
    json_decref(body_j);

    char *idem = g3n_make_round_idem_key_or_die(idempotency_prefix, escrow_id, nick, round_scope);
    int attempt = 0;
    for (;;) {
        ff_http_resp_t r;
        memset(&r, 0, sizeof(r));
        if (ff_http_post_json_idempotent(url, socks5, body, idem, &r) == 0) {
            char *out = r.data ? strdup(r.data) : strdup("{}");
            ff_http_resp_free(&r);
            sodium_memzero(body, strlen(body));
            free(body);
            free(idem);
            if (!out) ff_die("oom");
            return out;
        }

        long st = ff_http_last_status();
        char *detail_owned = http_error_detail_from_response(&r);
        const char *detail = (detail_owned && detail_owned[0]) ? detail_owned : ff_http_last_error();
        int retry = should_retry_escrow_http_error(st, detail, attempt, (int)retry_max, idem);
        if (retry) {
            attempt++;
            fprintf(stderr, "WARN: %s %s retry %d/%u after transient error (status=%ld)\n",
                    round_scope, nick, attempt, retry_max, st);
            free(detail_owned);
            ff_http_resp_free(&r);
            if (poll_interval_s > 0) sleep(poll_interval_s);
            continue;
        }

        char *msg = g3n_http_error_msg_owned(&r);
        free(detail_owned);
        ff_http_resp_free(&r);
        sodium_memzero(body, strlen(body));
        free(body);
        free(idem);
        if (st > 0) ff_die("gate3-ready %s failed (status=%ld): %s", round_scope, st, msg ? msg : "http error");
        ff_die("gate3-ready %s failed: %s", round_scope, msg ? msg : "http error");
    }
}

static void g3n_parse_round_fetch_or_die(const char *json_txt,
                                         const char *round_key,
                                         g3n_round_fetch_t *out) {
    if (!out) ff_die("gate3-ready: internal parse error");
    memset(out, 0, sizeof(*out));
    json_t *root = g3n_json_load_obj_or_die(json_txt, round_key);
    out->state = g3n_json_dup_string(root, "state");
    out->deposit_address = g3n_json_dup_string(root, "deposit_address");

    json_t *round_obj = json_object_get(root, round_key);
    if (!round_obj || json_is_null(round_obj) || !json_is_object(round_obj)) {
        json_decref(root);
        ff_die("gate3-ready: response missing '%s' object", round_key);
    }
    out->buyer = g3n_json_dup_string(round_obj, "buyer");
    out->seller = g3n_json_dup_string(round_obj, "seller");
    out->arbiter = g3n_json_dup_string(round_obj, "arbiter");
    json_decref(root);
}

static char *g3n_detect_role_from_status_or_die(const char *status_json,
                                                const char *nick,
                                                const char *ctx_label) {
    if (!status_json || !nick || !nick[0]) {
        ff_die("%s: missing status json or nick",
               ctx_label ? ctx_label : "gate3-ready");
    }
    json_t *root = g3n_json_load_obj_or_die(status_json, ctx_label ? ctx_label : "escrow-status");
    char *buyer_nick = g3n_json_dup_string(root, "buyer_nick");
    char *seller_nick = g3n_json_dup_string(root, "seller_nick");
    char *arbiter_nick = g3n_json_dup_string(root, "arbiter_nick");
    json_decref(root);

    const char *role = NULL;
    if (buyer_nick && strcmp(nick, buyer_nick) == 0) role = "buyer";
    else if (seller_nick && strcmp(nick, seller_nick) == 0) role = "seller";
    else if (arbiter_nick && strcmp(nick, arbiter_nick) == 0) role = "arbiter";

    if (!role) {
        free(buyer_nick);
        free(seller_nick);
        free(arbiter_nick);
        ff_die("%s: nick '%s' does not match buyer_nick/seller_nick/arbiter_nick in escrow status",
               ctx_label ? ctx_label : "gate3-ready", nick);
    }

    char *out = strdup(role);
    free(buyer_nick);
    free(seller_nick);
    free(arbiter_nick);
    if (!out) ff_die("oom");
    return out;
}

static void g3n_collect_other_blobs_or_die(const g3n_round_fetch_t *rf,
                                           const char *self_role,
                                           char **out_a,
                                           char **out_b) {
    if (!rf || !self_role || !out_a || !out_b) ff_die("gate3-ready: internal blob selection error");
    *out_a = NULL;
    *out_b = NULL;

    const char *a = NULL;
    const char *b = NULL;
    if (strcmp(self_role, "buyer") == 0) {
        a = rf->seller;
        b = rf->arbiter;
    } else if (strcmp(self_role, "seller") == 0) {
        a = rf->buyer;
        b = rf->arbiter;
    } else if (strcmp(self_role, "arbiter") == 0) {
        a = rf->buyer;
        b = rf->seller;
    } else {
        ff_die("gate3-ready: unsupported role '%s'", self_role);
    }
    if (!a || !a[0] || !b || !b[0]) {
        ff_die("gate3-ready: missing %s round blobs for role %s (need two peers)",
               (rf->buyer || rf->seller || rf->arbiter) ? "peer" : "all", self_role);
    }

    *out_a = strdup(a);
    *out_b = strdup(b);
    if (!*out_a || !*out_b) {
        free(*out_a);
        free(*out_b);
        *out_a = NULL;
        *out_b = NULL;
        ff_die("oom");
    }
}

static int g3n_contains_multisig_disabled(const char *msg) {
    return msg && (contains_ascii_case_insensitive(msg, "multisig is disabled") ||
                   contains_ascii_case_insensitive(msg, "enable-multisig-experimental"));
}

static int g3n_contains_kex_already_complete(const char *msg) {
    return msg && contains_ascii_case_insensitive(msg, "kex is already complete");
}

static int g3n_wallet_missing_file_error(const char *msg) {
    if (!msg) return 0;
    return (contains_ascii_case_insensitive(msg, "wallet") &&
            contains_ascii_case_insensitive(msg, "not found")) ||
           contains_ascii_case_insensitive(msg, "file_not_found") ||
           contains_ascii_case_insensitive(msg, "file not found") ||
           contains_ascii_case_insensitive(msg, "doesn't exist") ||
           contains_ascii_case_insensitive(msg, "does not exist") ||
           contains_ascii_case_insensitive(msg, "no such file");
}

static char *g3n_wallet_error_text_from_json(json_t *err_obj, const char *method) {
    const char *message = NULL;
    json_t *msgv = err_obj ? json_object_get(err_obj, "message") : NULL;
    if (msgv && json_is_string(msgv)) message = json_string_value(msgv);
    long long code = g3n_json_int_or_neg1(err_obj, "code");
    char buf[1024];
    if (code >= 0 && message && message[0]) {
        snprintf(buf, sizeof(buf), "wallet-rpc %s error: code=%lld message=%s", method, code, message);
    } else if (message && message[0]) {
        snprintf(buf, sizeof(buf), "wallet-rpc %s error: %s", method, message);
    } else {
        snprintf(buf, sizeof(buf), "wallet-rpc %s error", method);
    }
    return strdup(buf);
}

static int g3n_wallet_rpc_call_ex(const char *url,
                                  const char *user,
                                  const char *pass,
                                  const char *method,
                                  json_t *params,
                                  unsigned timeout_s,
                                  json_t **out_result,
                                  char **out_err_text) {
    if (out_result) *out_result = NULL;
    if (out_err_text) *out_err_text = NULL;
    if (!url || !user || !pass || !method) return -1;

    json_t *req = json_object();
    if (!req) return -1;
    json_object_set_new(req, "jsonrpc", json_string("2.0"));
    json_object_set_new(req, "id", json_string("0"));
    json_object_set_new(req, "method", json_string(method));
    if (params) json_object_set(req, "params", params);

    char *body = json_dumps(req, JSON_COMPACT);
    json_decref(req);
    if (!body) return -1;

    ff_http_resp_t r;
    memset(&r, 0, sizeof(r));
    char errbuf[512];
    errbuf[0] = 0;
    unsigned timeout_ms = (timeout_s > 0U) ? (timeout_s * 1000U) : 20000U;
    int rc = pf_wallet_rpc_post_authed(url, user, pass, body, timeout_ms, &r, errbuf, sizeof(errbuf));
    sodium_memzero(body, strlen(body));
    free(body);
    if (rc != 0) {
        if (out_err_text) *out_err_text = strdup(errbuf[0] ? errbuf : ff_http_last_error());
        ff_http_resp_free(&r);
        return -1;
    }

    json_error_t jerr;
    json_t *root = json_loads(r.data ? r.data : "{}", 0, &jerr);
    if (!root || !json_is_object(root)) {
        if (out_err_text) {
            char buf[512];
            snprintf(buf, sizeof(buf), "wallet-rpc %s invalid json response", method);
            *out_err_text = strdup(buf);
        }
        if (root) json_decref(root);
        ff_http_resp_free(&r);
        return -1;
    }

    json_t *errv = json_object_get(root, "error");
    if (errv && !json_is_null(errv)) {
        if (out_err_text) *out_err_text = g3n_wallet_error_text_from_json(errv, method);
        json_decref(root);
        ff_http_resp_free(&r);
        return -1;
    }

    json_t *res = json_object_get(root, "result");
    if (!res || !json_is_object(res)) {
        if (out_err_text) {
            char buf[512];
            snprintf(buf, sizeof(buf), "wallet-rpc %s missing result object", method);
            *out_err_text = strdup(buf);
        }
        json_decref(root);
        ff_http_resp_free(&r);
        return -1;
    }

    if (out_result) {
        json_incref(res);
        *out_result = res;
    }
    json_decref(root);
    ff_http_resp_free(&r);
    return 0;
}

static json_t *g3n_wallet_rpc_call_or_die(const char *url,
                                          const char *user,
                                          const char *pass,
                                          const char *method,
                                          json_t *params,
                                          unsigned timeout_s) {
    json_t *res = NULL;
    char *err = NULL;
    if (g3n_wallet_rpc_call_ex(url, user, pass, method, params, timeout_s, &res, &err) != 0) {
        ff_die("%s", err ? err : "wallet-rpc call failed");
    }
    free(err);
    if (!res) ff_die("wallet-rpc %s returned no result", method);
    return res;
}

static void g3n_wallet_store_or_die(const char *url, const char *user, const char *pass, unsigned timeout_s) {
    json_t *params = json_object();
    json_t *res = g3n_wallet_rpc_call_or_die(url, user, pass, "store", params, timeout_s);
    json_decref(params);
    json_decref(res);
}

static void g3n_wallet_set_attr_multisig_or_die(const char *url,
                                                const char *user,
                                                const char *pass,
                                                unsigned timeout_s) {
    json_t *params = json_object();
    json_object_set_new(params, "key", json_string("enable-multisig-experimental"));
    json_object_set_new(params, "value", json_string("1"));
    json_t *res = g3n_wallet_rpc_call_or_die(url, user, pass, "set_attribute", params, timeout_s);
    json_decref(params);
    json_decref(res);
}

static void g3n_wallet_persist_settings_or_die(const char *url,
                                               const char *user,
                                               const char *pass,
                                               const char *wallet_password,
                                               unsigned timeout_s) {
    json_t *params = json_object();
    json_object_set_new(params, "old_password", json_string(wallet_password));
    json_object_set_new(params, "new_password", json_string(wallet_password));
    json_t *res = g3n_wallet_rpc_call_or_die(url, user, pass, "change_wallet_password", params, timeout_s);
    json_decref(params);
    json_decref(res);
    g3n_wallet_store_or_die(url, user, pass, timeout_s);
}

static long long g3n_wallet_get_version_or_neg1(const char *url,
                                                const char *user,
                                                const char *pass,
                                                unsigned timeout_s) {
    json_t *params = json_object();
    json_t *res = NULL;
    char *err = NULL;
    long long version = -1;
    if (g3n_wallet_rpc_call_ex(url, user, pass, "get_version", params, timeout_s, &res, &err) == 0 && res) {
        version = g3n_json_int_or_neg1(res, "version");
    }
    json_decref(params);
    if (res) json_decref(res);
    free(err);
    return version;
}

static int g3n_wallet_needs_exp_compat(long long version) {
    return (version >= 0 && version <= 65565LL);
}

static void g3n_wallet_open_or_create_or_die(const char *url,
                                             const char *user,
                                             const char *pass,
                                             const char *wallet_name,
                                             const char *wallet_password,
                                             unsigned timeout_s) {
    json_t *params = json_object();
    json_t *res = NULL;
    char *err = NULL;

    /* Best effort close. */
    if (params) {
        (void)g3n_wallet_rpc_call_ex(url, user, pass, "close_wallet", params, timeout_s, &res, &err);
        if (res) json_decref(res);
        free(err);
        err = NULL;
        params = NULL;
    }

    params = json_object();
    json_object_set_new(params, "filename", json_string(wallet_name));
    json_object_set_new(params, "password", json_string(wallet_password));
    if (g3n_wallet_rpc_call_ex(url, user, pass, "open_wallet", params, timeout_s, &res, &err) == 0) {
        json_decref(params);
        json_decref(res);
        free(err);
        return;
    }
    json_decref(params);
    if (!g3n_wallet_missing_file_error(err)) {
        ff_die("%s", err ? err : "wallet-rpc open_wallet failed");
    }
    free(err);
    err = NULL;

    params = json_object();
    json_object_set_new(params, "filename", json_string(wallet_name));
    json_object_set_new(params, "password", json_string(wallet_password));
    json_object_set_new(params, "language", json_string("English"));
    if (g3n_wallet_rpc_call_ex(url, user, pass, "create_wallet", params, timeout_s, &res, &err) != 0) {
        json_decref(params);
        ff_die("%s", err ? err : "wallet-rpc create_wallet failed");
    }
    json_decref(params);
    json_decref(res);
    free(err);
}

static char *g3n_wallet_extract_multisig_info_or_die(json_t *res, const char *ctx_label) {
    char *blob = g3n_json_dup_string(res, "multisig_info");
    if (!blob || !blob[0]) {
        free(blob);
        ff_die("%s returned empty multisig_info", ctx_label ? ctx_label : "wallet-rpc");
    }
    return blob;
}

static char *g3n_wallet_prepare_multisig_auto_or_die(const char *url,
                                                     const char *user,
                                                     const char *pass,
                                                     const char *wallet_password,
                                                     unsigned timeout_s) {
    int used_experimental = 0;
    long long version = g3n_wallet_get_version_or_neg1(url, user, pass, timeout_s);
    int force_compat = g3n_wallet_needs_exp_compat(version);
    json_t *res = NULL;
    char *err = NULL;

    json_t *params = json_object();
    if (force_compat) {
        used_experimental = 1;
        fprintf(stderr, "WARN: wallet-rpc version=%lld; forcing prepare_multisig compatibility rerun\n", version);
        json_object_set_new(params, "enable_multisig_experimental", json_true());
    }

    if (g3n_wallet_rpc_call_ex(url, user, pass, "prepare_multisig", params, timeout_s, &res, &err) != 0) {
        if (!g3n_contains_multisig_disabled(err)) {
            json_decref(params);
            ff_die("%s", err ? err : "wallet-rpc prepare_multisig failed");
        }
        fprintf(stderr,
                "WARN: prepare_multisig strict failed with multisig disabled; retrying with enable_multisig_experimental=true\n");
        free(err);
        err = NULL;
        used_experimental = 1;
        json_decref(params);
        params = json_object();
        json_object_set_new(params, "enable_multisig_experimental", json_true());
        if (g3n_wallet_rpc_call_ex(url, user, pass, "prepare_multisig", params, timeout_s, &res, &err) != 0) {
            if (!g3n_contains_multisig_disabled(err)) {
                json_decref(params);
                ff_die("%s", err ? err : "wallet-rpc prepare_multisig failed");
            }
            fprintf(stderr,
                    "WARN: prepare_multisig still reports multisig disabled; setting wallet attribute and retrying\n");
            g3n_wallet_set_attr_multisig_or_die(url, user, pass, timeout_s);
            free(err);
            err = NULL;
            if (g3n_wallet_rpc_call_ex(url, user, pass, "prepare_multisig", params, timeout_s, &res, &err) != 0) {
                json_decref(params);
                ff_die("%s", err ? err : "wallet-rpc prepare_multisig failed");
            }
        }
    }
    json_decref(params);
    free(err);

    char *blob = g3n_wallet_extract_multisig_info_or_die(res, "prepare_multisig");
    json_decref(res);

    if (used_experimental) {
        g3n_wallet_set_attr_multisig_or_die(url, user, pass, timeout_s);
        g3n_wallet_persist_settings_or_die(url, user, pass, wallet_password, timeout_s);
    } else {
        g3n_wallet_store_or_die(url, user, pass, timeout_s);
    }
    return blob;
}

static json_t *g3n_json_array_two_strings_or_die(const char *a, const char *b) {
    json_t *arr = json_array();
    if (!arr) ff_die("oom");
    if (json_array_append_new(arr, json_string(a)) != 0 ||
        json_array_append_new(arr, json_string(b)) != 0) {
        json_decref(arr);
        ff_die("oom");
    }
    return arr;
}

static char *g3n_wallet_make_multisig_auto_or_die(const char *url,
                                                  const char *user,
                                                  const char *pass,
                                                  const char *wallet_password,
                                                  const char *other_a,
                                                  const char *other_b,
                                                  int threshold,
                                                  unsigned timeout_s) {
    int used_experimental = 0;
    long long version = g3n_wallet_get_version_or_neg1(url, user, pass, timeout_s);
    int force_compat = g3n_wallet_needs_exp_compat(version);
    json_t *res = NULL;
    char *err = NULL;

    json_t *params = json_object();
    json_object_set_new(params, "multisig_info", g3n_json_array_two_strings_or_die(other_a, other_b));
    json_object_set_new(params, "threshold", json_integer(threshold));
    json_object_set_new(params, "password", json_string(wallet_password));
    if (force_compat) {
        used_experimental = 1;
        fprintf(stderr, "WARN: wallet-rpc version=%lld; forcing make_multisig compatibility params\n", version);
        json_object_set_new(params, "enable_multisig_experimental", json_true());
    }

    if (g3n_wallet_rpc_call_ex(url, user, pass, "make_multisig", params, timeout_s, &res, &err) != 0) {
        if (!g3n_contains_multisig_disabled(err)) {
            json_decref(params);
            ff_die("%s", err ? err : "wallet-rpc make_multisig failed");
        }
        fprintf(stderr,
                "WARN: make_multisig strict failed with multisig disabled; retrying with enable_multisig_experimental=true\n");
        free(err);
        err = NULL;
        used_experimental = 1;
        json_decref(params);
        params = json_object();
        json_object_set_new(params, "multisig_info", g3n_json_array_two_strings_or_die(other_a, other_b));
        json_object_set_new(params, "threshold", json_integer(threshold));
        json_object_set_new(params, "password", json_string(wallet_password));
        json_object_set_new(params, "enable_multisig_experimental", json_true());
        if (g3n_wallet_rpc_call_ex(url, user, pass, "make_multisig", params, timeout_s, &res, &err) != 0) {
            if (!g3n_contains_multisig_disabled(err)) {
                json_decref(params);
                ff_die("%s", err ? err : "wallet-rpc make_multisig failed");
            }
            fprintf(stderr,
                    "WARN: make_multisig still reports multisig disabled; setting wallet attribute and retrying\n");
            g3n_wallet_set_attr_multisig_or_die(url, user, pass, timeout_s);
            free(err);
            err = NULL;
            if (g3n_wallet_rpc_call_ex(url, user, pass, "make_multisig", params, timeout_s, &res, &err) != 0) {
                json_decref(params);
                ff_die("%s", err ? err : "wallet-rpc make_multisig failed");
            }
        }
    }
    json_decref(params);
    free(err);

    char *blob = g3n_wallet_extract_multisig_info_or_die(res, "make_multisig");
    json_decref(res);
    if (used_experimental) {
        g3n_wallet_set_attr_multisig_or_die(url, user, pass, timeout_s);
        g3n_wallet_persist_settings_or_die(url, user, pass, wallet_password, timeout_s);
    } else {
        g3n_wallet_store_or_die(url, user, pass, timeout_s);
    }
    return blob;
}

static json_t *g3n_wallet_exchange_multisig_auto_or_die(const char *url,
                                                        const char *user,
                                                        const char *pass,
                                                        const char *wallet_password,
                                                        const char *other_a,
                                                        const char *other_b,
                                                        const char *stage_label,
                                                        unsigned timeout_s,
                                                        int allow_kex_already_complete) {
    int used_experimental = 0;
    long long version = g3n_wallet_get_version_or_neg1(url, user, pass, timeout_s);
    int force_compat = g3n_wallet_needs_exp_compat(version);
    json_t *res = NULL;
    char *err = NULL;

    json_t *params = json_object();
    json_object_set_new(params, "multisig_info", g3n_json_array_two_strings_or_die(other_a, other_b));
    json_object_set_new(params, "password", json_string(wallet_password));
    if (force_compat) {
        used_experimental = 1;
        fprintf(stderr, "WARN: wallet-rpc version=%lld; forcing %s compatibility params\n",
                version, stage_label ? stage_label : "exchange_multisig_keys");
        json_object_set_new(params, "enable_multisig_experimental", json_true());
    }

    if (g3n_wallet_rpc_call_ex(url, user, pass, "exchange_multisig_keys", params, timeout_s, &res, &err) != 0) {
        if (allow_kex_already_complete && g3n_contains_kex_already_complete(err)) {
            fprintf(stderr, "WARN: %s already complete; continuing\n", stage_label ? stage_label : "exchange_multisig_keys");
            json_decref(params);
            free(err);
            return json_object();
        }
        if (!g3n_contains_multisig_disabled(err)) {
            json_decref(params);
            ff_die("%s", err ? err : "wallet-rpc exchange_multisig_keys failed");
        }
        fprintf(stderr,
                "WARN: %s strict failed with multisig disabled; retrying with enable_multisig_experimental=true\n",
                stage_label ? stage_label : "exchange_multisig_keys");
        free(err);
        err = NULL;
        used_experimental = 1;
        json_decref(params);
        params = json_object();
        json_object_set_new(params, "multisig_info", g3n_json_array_two_strings_or_die(other_a, other_b));
        json_object_set_new(params, "password", json_string(wallet_password));
        json_object_set_new(params, "enable_multisig_experimental", json_true());
        if (g3n_wallet_rpc_call_ex(url, user, pass, "exchange_multisig_keys", params, timeout_s, &res, &err) != 0) {
            if (allow_kex_already_complete && g3n_contains_kex_already_complete(err)) {
                fprintf(stderr, "WARN: %s already complete; continuing\n", stage_label ? stage_label : "exchange_multisig_keys");
                json_decref(params);
                free(err);
                return json_object();
            }
            if (!g3n_contains_multisig_disabled(err)) {
                json_decref(params);
                ff_die("%s", err ? err : "wallet-rpc exchange_multisig_keys failed");
            }
            fprintf(stderr,
                    "WARN: %s still reports multisig disabled; setting wallet attribute and retrying\n",
                    stage_label ? stage_label : "exchange_multisig_keys");
            g3n_wallet_set_attr_multisig_or_die(url, user, pass, timeout_s);
            free(err);
            err = NULL;
            if (g3n_wallet_rpc_call_ex(url, user, pass, "exchange_multisig_keys", params, timeout_s, &res, &err) != 0) {
                if (allow_kex_already_complete && g3n_contains_kex_already_complete(err)) {
                    fprintf(stderr, "WARN: %s already complete; continuing\n", stage_label ? stage_label : "exchange_multisig_keys");
                    json_decref(params);
                    free(err);
                    return json_object();
                }
                json_decref(params);
                ff_die("%s", err ? err : "wallet-rpc exchange_multisig_keys failed");
            }
        }
    }
    json_decref(params);
    free(err);

    if (used_experimental) {
        g3n_wallet_set_attr_multisig_or_die(url, user, pass, timeout_s);
        g3n_wallet_persist_settings_or_die(url, user, pass, wallet_password, timeout_s);
    } else {
        g3n_wallet_store_or_die(url, user, pass, timeout_s);
    }
    return res;
}

static json_t *g3n_wallet_is_multisig_or_die(const char *url,
                                             const char *user,
                                             const char *pass,
                                             unsigned timeout_s,
                                             int *ready_out) {
    json_t *params = json_object();
    json_t *res = g3n_wallet_rpc_call_or_die(url, user, pass, "is_multisig", params, timeout_s);
    json_decref(params);
    json_t *readyv = json_object_get(res, "ready");
    int ready = (readyv && json_is_true(readyv)) ? 1 : 0;
    if (ready_out) *ready_out = ready;
    return res;
}

static void g3n_write_artifact_or_die(const char *path, const char *txt) {
    if (!path || !path[0]) return;
    if (pf_write_text(path, txt ? txt : "{}") != 0) {
        ff_die("gate3-ready: failed to write artifact %s", path);
    }
}

static char *g3n_path_join3_or_die(const char *a, const char *b, const char *c) {
    if (!a || !b || !c) ff_die("gate3-ready: path join input missing");
    size_t cap = strlen(a) + strlen(b) + strlen(c) + 3;
    char *p = (char *)malloc(cap);
    if (!p) ff_die("oom");
    snprintf(p, cap, "%s/%s%s", a, b, c);
    return p;
}

static char *g3n_build_r4_local_output_or_die(json_t *exchange_res, json_t *is_multisig_res) {
    json_t *root = json_object();
    if (!root) ff_die("oom");
    json_object_set_new(root, "ok", json_true());
    if (exchange_res) json_object_set(root, "exchange", exchange_res);
    if (is_multisig_res) json_object_set(root, "is_multisig", is_multisig_res);
    char *out = json_dumps(root, JSON_INDENT(2) | JSON_SORT_KEYS);
    json_decref(root);
    if (!out) ff_die("gate3-ready: failed to serialize r4 output");
    return out;
}

static char *g3n_extract_state_from_escrow_json_or_die(const char *json_txt) {
    json_t *root = g3n_json_load_obj_or_die(json_txt, "escrow-status");
    char *state = g3n_json_dup_string(root, "state");
    json_decref(root);
    if (!state || !state[0]) {
        free(state);
        ff_die("gate3-ready: escrow status missing state");
    }
    return state;
}

static char *g3n_wait_ready_or_die(const char *base,
                                   const char *socks5,
                                   unsigned long long escrow_id,
                                   const char *buyer_nick,
                                   const char *buyer_token,
                                   unsigned wait_ready_timeout_s,
                                   unsigned poll_interval_s,
                                   const char *status_ready_artifact_path) {
    time_t deadline = time(NULL) + (time_t)wait_ready_timeout_s;
    char *last_state = NULL;
    for (;;) {
        char *status_json = g3n_escrow_get_json_or_die(base, socks5, escrow_id, "", buyer_nick, buyer_token, "gate3-ready status poll");
        char *state = g3n_extract_state_from_escrow_json_or_die(status_json);
        if (!last_state || strcmp(last_state, state) != 0) {
            fprintf(stderr, "gate3-ready: state=%s\n", state);
            free(last_state);
            last_state = strdup(state);
            if (!last_state) ff_die("oom");
        }
        if (strcmp(state, "READY") == 0) {
            g3n_write_artifact_or_die(status_ready_artifact_path, status_json);
            free(state);
            free(last_state);
            return status_json;
        }
        free(state);
        free(status_json);
        if (time(NULL) >= deadline) {
            char *ls_copy = last_state ? strdup(last_state) : strdup("");
            free(last_state);
            if (!ls_copy) ff_die("oom");
            ff_die("gate3-ready: timeout waiting for state=READY; last_state=%s", ls_copy);
        }
        if (poll_interval_s > 0) sleep(poll_interval_s);
    }
}

static char *g3n_status_after_ready_or_die(const char *base,
                                           const char *socks5,
                                           unsigned long long escrow_id,
                                           const char *buyer_nick,
                                           const char *buyer_token,
                                           unsigned poll_interval_s,
                                           const char *artifact_path) {
    for (int attempt = 1; attempt <= 3; attempt++) {
        ff_http_resp_t r;
        memset(&r, 0, sizeof(r));
        char *url = g3n_build_auth_query_url_or_die(base, escrow_id, "", buyer_nick, buyer_token);
        if (ff_http_get_json_auth(url, socks5, buyer_token, NULL, &r) == 0) {
            char *out = r.data ? strdup(r.data) : strdup("{}");
            ff_http_resp_free(&r);
            free(url);
            if (!out) ff_die("oom");
            g3n_write_artifact_or_die(artifact_path, out);
            return out;
        }
        long st = ff_http_last_status();
        char *msg = g3n_http_error_msg_owned(&r);
        ff_http_resp_free(&r);
        free(url);
        if (st == 429 && attempt < 3) {
            fprintf(stderr, "WARN: status after READY hit 429 (attempt %d/3), retrying after %us\n",
                    attempt, poll_interval_s);
            free(msg);
            if (poll_interval_s > 0) sleep(poll_interval_s);
            continue;
        }
        if (st > 0) ff_die("gate3-ready status after READY failed (status=%ld): %s", st, msg ? msg : "http error");
        ff_die("gate3-ready status after READY failed: %s", msg ? msg : "http error");
    }
    ff_die("gate3-ready status after READY failed");
    return NULL;
}

static void g3n_run_party_round_or_die(unsigned round_no,
                                       const gate3_party_cfg_t *cfg,
                                       const char *wallet_password,
                                       const char *base,
                                       const char *socks5,
                                       unsigned long long escrow_id,
                                       const char *idempotency_prefix,
                                       const char *flow_dir,
                                       unsigned timeout_s,
                                       unsigned round_retries,
                                       unsigned poll_interval_s) {
    if (!cfg || !cfg->role_label || !cfg->nick || !cfg->token || !wallet_password) {
        ff_die("gate3-ready: invalid party round config");
    }
    if (round_no < 1 || round_no > 4) ff_die("gate3-ready: invalid round number");

    fprintf(stderr, "gate3-ready: r%u %s\n", round_no, cfg->role_label);
    g3n_wallet_open_or_create_or_die(cfg->wallet_rpc_url,
                                     cfg->wallet_rpc_user,
                                     cfg->wallet_rpc_pass,
                                     cfg->wallet_name,
                                     wallet_password,
                                     timeout_s);

    char stem[64];
    snprintf(stem, sizeof(stem), "r%u_%s", round_no, cfg->role_label);
    char *artifact_path = g3n_path_join3_or_die(flow_dir, stem, ".json");

    if (round_no == 1) {
        char *blob = g3n_wallet_prepare_multisig_auto_or_die(cfg->wallet_rpc_url,
                                                             cfg->wallet_rpc_user,
                                                             cfg->wallet_rpc_pass,
                                                             wallet_password,
                                                             timeout_s);
        char *resp = g3n_escrow_post_round_or_die(base, socks5, escrow_id, "r1",
                                                  cfg->nick, cfg->token, blob, cfg->refund_address,
                                                  idempotency_prefix, round_retries, poll_interval_s);
        g3n_write_artifact_or_die(artifact_path, resp);
        secure_free_str(&blob);
        free(resp);
        free(artifact_path);
        return;
    }

    if (round_no == 2 || round_no == 3 || round_no == 4) {
        const char *fetch_suffix = (round_no == 2) ? "/xmr/r1" : (round_no == 3) ? "/xmr/r2" : "/xmr/r3";
        const char *round_key = (round_no == 2) ? "r1" : (round_no == 3) ? "r2" : "r3";
        char *fetch_json = g3n_escrow_get_json_or_die(base, socks5, escrow_id, fetch_suffix,
                                                      cfg->nick, cfg->token, "gate3-ready fetch round");
        g3n_round_fetch_t rf;
        g3n_parse_round_fetch_or_die(fetch_json, round_key, &rf);
        char *other_a = NULL;
        char *other_b = NULL;
        g3n_collect_other_blobs_or_die(&rf, cfg->role_label, &other_a, &other_b);

        if (round_no == 2) {
            char *blob = g3n_wallet_make_multisig_auto_or_die(cfg->wallet_rpc_url,
                                                              cfg->wallet_rpc_user,
                                                              cfg->wallet_rpc_pass,
                                                              wallet_password,
                                                              other_a,
                                                              other_b,
                                                              2,
                                                              timeout_s);
            char *resp = g3n_escrow_post_round_or_die(base, socks5, escrow_id, "r2",
                                                      cfg->nick, cfg->token, blob, NULL,
                                                      idempotency_prefix, round_retries, poll_interval_s);
            g3n_write_artifact_or_die(artifact_path, resp);
            secure_free_str(&blob);
            free(resp);
        } else if (round_no == 3) {
            json_t *ex = g3n_wallet_exchange_multisig_auto_or_die(cfg->wallet_rpc_url,
                                                                  cfg->wallet_rpc_user,
                                                                  cfg->wallet_rpc_pass,
                                                                  wallet_password,
                                                                  other_a,
                                                                  other_b,
                                                                  "r3 exchange_multisig_keys",
                                                                  timeout_s,
                                                                  0);
            char *blob = g3n_wallet_extract_multisig_info_or_die(ex, "exchange_multisig_keys (r3)");
            char *resp = g3n_escrow_post_round_or_die(base, socks5, escrow_id, "r3",
                                                      cfg->nick, cfg->token, blob, NULL,
                                                      idempotency_prefix, round_retries, poll_interval_s);
            g3n_write_artifact_or_die(artifact_path, resp);
            secure_free_str(&blob);
            free(resp);
            json_decref(ex);
        } else {
            json_t *ex = g3n_wallet_exchange_multisig_auto_or_die(cfg->wallet_rpc_url,
                                                                  cfg->wallet_rpc_user,
                                                                  cfg->wallet_rpc_pass,
                                                                  wallet_password,
                                                                  other_a,
                                                                  other_b,
                                                                  "r4 exchange_multisig_keys",
                                                                  timeout_s,
                                                                  1);
            int ready = 0;
            json_t *st = g3n_wallet_is_multisig_or_die(cfg->wallet_rpc_url,
                                                       cfg->wallet_rpc_user,
                                                       cfg->wallet_rpc_pass,
                                                       timeout_s,
                                                       &ready);
            if (!ready) {
                char *dump = g3n_json_dumps_compact_or_die(st, "is_multisig");
                ff_die("gate3-ready: wallet multisig not ready after r4 for %s: %s",
                       cfg->role_label, dump);
            }
            char *local_out = g3n_build_r4_local_output_or_die(ex, st);
            g3n_write_artifact_or_die(artifact_path, local_out);
            free(local_out);
            json_decref(st);
            json_decref(ex);
        }

        secure_free_str(&other_a);
        secure_free_str(&other_b);
        g3n_round_fetch_free(&rf);
        secure_free_str(&fetch_json);
        free(artifact_path);
        return;
    }

    free(artifact_path);
    ff_die("gate3-ready: unsupported round");
}

int cmd_escrow_r1(const char *base,
                  const char *socks5,
                  unsigned long long escrow_id,
                  const char *nick,
                  const char *token,
                  const char *wallet_rpc_url,
                  const char *wallet_rpc_user,
                  const char *wallet_rpc_pass,
                  const char *wallet_name,
                  const char *wallet_password_env,
                  const char *refund_address,
                  const char *idempotency_prefix,
                  unsigned timeout_s,
                  unsigned retry_max,
                  unsigned poll_interval_s) {
    pf_require_escrow_base_url_policy(base, 0, "escrow-r1");
    require_tor(base, socks5);
    if (!base || !base[0]) ff_die("escrow-r1 requires --base");
    if (!nick || !nick[0] || !token || !token[0]) ff_die("escrow-r1 requires --nick and --token");
    if (!wallet_rpc_url || !wallet_rpc_url[0] ||
        !wallet_rpc_user || !wallet_rpc_user[0] ||
        !wallet_rpc_pass || !wallet_rpc_pass[0] ||
        !wallet_name || !wallet_name[0] ||
        !wallet_password_env || !wallet_password_env[0]) {
        ff_die("escrow-r1: missing wallet-rpc arguments");
    }
    if (poll_interval_s > 600U) ff_die("escrow-r1: --poll-interval too large");
    if (timeout_s == 0U) timeout_s = 20U;

    char *token_trim = g3n_trim_copy_or_die(token, "token");
    char *wallet_password = g3n_resolve_wallet_password_env_or_die(wallet_password_env, "escrow-r1");
    char *idemp_prefix_trim = normalize_idempotency_key(idempotency_prefix, "escrow-r1");
    if (!idemp_prefix_trim) {
        idemp_prefix_trim = dup_trimmed_copy("gate3");
        if (!idemp_prefix_trim) {
            secure_free_str(&wallet_password);
            secure_free_str(&token_trim);
            ff_die("oom");
        }
    }

    char *status_json = g3n_escrow_get_json_or_die(base, socks5, escrow_id, "", nick, token_trim, "escrow-r1 status");
    char *role = g3n_detect_role_from_status_or_die(status_json, nick, "escrow-r1");
    char *state = g3n_extract_state_from_escrow_json_or_die(status_json);
    fprintf(stderr, "escrow-r1: role=%s state=%s\n", role, state);
    if (refund_address && refund_address[0] && strcmp(role, "arbiter") == 0) {
        fprintf(stderr, "WARN: escrow-r1 ignoring --refund-address for arbiter role\n");
    }

    g3n_wallet_open_or_create_or_die(wallet_rpc_url,
                                     wallet_rpc_user,
                                     wallet_rpc_pass,
                                     wallet_name,
                                     wallet_password,
                                     timeout_s);
    char *blob = g3n_wallet_prepare_multisig_auto_or_die(wallet_rpc_url,
                                                         wallet_rpc_user,
                                                         wallet_rpc_pass,
                                                         wallet_password,
                                                         timeout_s);
    const char *refund_eff = (strcmp(role, "buyer") == 0 || strcmp(role, "seller") == 0)
                                 ? refund_address
                                 : NULL;
    char *resp = g3n_escrow_post_round_or_die(base, socks5, escrow_id, "r1",
                                              nick, token_trim, blob, refund_eff,
                                              idemp_prefix_trim, retry_max, poll_interval_s);
    printf("%s", resp);
    if (!resp[0] || resp[strlen(resp) - 1] != '\n') printf("\n");

    free(resp);
    secure_free_str(&blob);
    free(state);
    free(role);
    free(status_json);
    free(idemp_prefix_trim);
    secure_free_str(&wallet_password);
    secure_free_str(&token_trim);
    return 0;
}

int cmd_escrow_r2(const char *base,
                  const char *socks5,
                  unsigned long long escrow_id,
                  const char *nick,
                  const char *token,
                  const char *wallet_rpc_url,
                  const char *wallet_rpc_user,
                  const char *wallet_rpc_pass,
                  const char *wallet_name,
                  const char *wallet_password_env,
                  int threshold,
                  const char *idempotency_prefix,
                  unsigned timeout_s,
                  unsigned retry_max,
                  unsigned poll_interval_s) {
    pf_require_escrow_base_url_policy(base, 0, "escrow-r2");
    require_tor(base, socks5);
    if (!base || !base[0]) ff_die("escrow-r2 requires --base");
    if (!nick || !nick[0] || !token || !token[0]) ff_die("escrow-r2 requires --nick and --token");
    if (!wallet_rpc_url || !wallet_rpc_url[0] ||
        !wallet_rpc_user || !wallet_rpc_user[0] ||
        !wallet_rpc_pass || !wallet_rpc_pass[0] ||
        !wallet_name || !wallet_name[0] ||
        !wallet_password_env || !wallet_password_env[0]) {
        ff_die("escrow-r2: missing wallet-rpc arguments");
    }
    if (threshold < 2 || threshold > 3) ff_die("escrow-r2: --threshold must be 2 or 3");
    if (poll_interval_s > 600U) ff_die("escrow-r2: --poll-interval too large");
    if (timeout_s == 0U) timeout_s = 20U;

    char *token_trim = g3n_trim_copy_or_die(token, "token");
    char *wallet_password = g3n_resolve_wallet_password_env_or_die(wallet_password_env, "escrow-r2");
    char *idemp_prefix_trim = normalize_idempotency_key(idempotency_prefix, "escrow-r2");
    if (!idemp_prefix_trim) {
        idemp_prefix_trim = dup_trimmed_copy("gate3");
        if (!idemp_prefix_trim) {
            secure_free_str(&wallet_password);
            secure_free_str(&token_trim);
            ff_die("oom");
        }
    }

    char *status_json = g3n_escrow_get_json_or_die(base, socks5, escrow_id, "", nick, token_trim, "escrow-r2 status");
    char *role = g3n_detect_role_from_status_or_die(status_json, nick, "escrow-r2");
    char *state = g3n_extract_state_from_escrow_json_or_die(status_json);
    fprintf(stderr, "escrow-r2: role=%s state=%s threshold=%d\n", role, state, threshold);

    g3n_wallet_open_or_create_or_die(wallet_rpc_url,
                                     wallet_rpc_user,
                                     wallet_rpc_pass,
                                     wallet_name,
                                     wallet_password,
                                     timeout_s);

    char *fetch_json = g3n_escrow_get_json_or_die(base, socks5, escrow_id, "/xmr/r1",
                                                  nick, token_trim, "escrow-r2 fetch r1");
    g3n_round_fetch_t rf;
    g3n_parse_round_fetch_or_die(fetch_json, "r1", &rf);
    char *other_a = NULL;
    char *other_b = NULL;
    g3n_collect_other_blobs_or_die(&rf, role, &other_a, &other_b);

    char *blob = g3n_wallet_make_multisig_auto_or_die(wallet_rpc_url,
                                                      wallet_rpc_user,
                                                      wallet_rpc_pass,
                                                      wallet_password,
                                                      other_a,
                                                      other_b,
                                                      threshold,
                                                      timeout_s);
    char *resp = g3n_escrow_post_round_or_die(base, socks5, escrow_id, "r2",
                                              nick, token_trim, blob, NULL,
                                              idemp_prefix_trim, retry_max, poll_interval_s);
    printf("%s", resp);
    if (!resp[0] || resp[strlen(resp) - 1] != '\n') printf("\n");

    free(resp);
    secure_free_str(&blob);
    secure_free_str(&other_a);
    secure_free_str(&other_b);
    g3n_round_fetch_free(&rf);
    secure_free_str(&fetch_json);
    free(state);
    free(role);
    free(status_json);
    free(idemp_prefix_trim);
    secure_free_str(&wallet_password);
    secure_free_str(&token_trim);
    return 0;
}

int cmd_escrow_r3(const char *base,
                  const char *socks5,
                  unsigned long long escrow_id,
                  const char *nick,
                  const char *token,
                  const char *wallet_rpc_url,
                  const char *wallet_rpc_user,
                  const char *wallet_rpc_pass,
                  const char *wallet_name,
                  const char *wallet_password_env,
                  const char *idempotency_prefix,
                  unsigned timeout_s,
                  unsigned retry_max,
                  unsigned poll_interval_s) {
    pf_require_escrow_base_url_policy(base, 0, "escrow-r3");
    require_tor(base, socks5);
    if (!base || !base[0]) ff_die("escrow-r3 requires --base");
    if (!nick || !nick[0] || !token || !token[0]) ff_die("escrow-r3 requires --nick and --token");
    if (!wallet_rpc_url || !wallet_rpc_url[0] ||
        !wallet_rpc_user || !wallet_rpc_user[0] ||
        !wallet_rpc_pass || !wallet_rpc_pass[0] ||
        !wallet_name || !wallet_name[0] ||
        !wallet_password_env || !wallet_password_env[0]) {
        ff_die("escrow-r3: missing wallet-rpc arguments");
    }
    if (poll_interval_s > 600U) ff_die("escrow-r3: --poll-interval too large");
    if (timeout_s == 0U) timeout_s = 20U;

    char *token_trim = g3n_trim_copy_or_die(token, "token");
    char *wallet_password = g3n_resolve_wallet_password_env_or_die(wallet_password_env, "escrow-r3");
    char *idemp_prefix_trim = normalize_idempotency_key(idempotency_prefix, "escrow-r3");
    if (!idemp_prefix_trim) {
        idemp_prefix_trim = dup_trimmed_copy("gate3");
        if (!idemp_prefix_trim) {
            secure_free_str(&wallet_password);
            secure_free_str(&token_trim);
            ff_die("oom");
        }
    }

    char *status_json = g3n_escrow_get_json_or_die(base, socks5, escrow_id, "", nick, token_trim, "escrow-r3 status");
    char *role = g3n_detect_role_from_status_or_die(status_json, nick, "escrow-r3");
    char *state = g3n_extract_state_from_escrow_json_or_die(status_json);
    fprintf(stderr, "escrow-r3: role=%s state=%s\n", role, state);

    g3n_wallet_open_or_create_or_die(wallet_rpc_url,
                                     wallet_rpc_user,
                                     wallet_rpc_pass,
                                     wallet_name,
                                     wallet_password,
                                     timeout_s);

    char *fetch_json = g3n_escrow_get_json_or_die(base, socks5, escrow_id, "/xmr/r2",
                                                  nick, token_trim, "escrow-r3 fetch r2");
    g3n_round_fetch_t rf;
    g3n_parse_round_fetch_or_die(fetch_json, "r2", &rf);
    char *other_a = NULL;
    char *other_b = NULL;
    g3n_collect_other_blobs_or_die(&rf, role, &other_a, &other_b);

    json_t *ex = g3n_wallet_exchange_multisig_auto_or_die(wallet_rpc_url,
                                                          wallet_rpc_user,
                                                          wallet_rpc_pass,
                                                          wallet_password,
                                                          other_a,
                                                          other_b,
                                                          "r3 exchange_multisig_keys",
                                                          timeout_s,
                                                          0);
    char *blob = g3n_wallet_extract_multisig_info_or_die(ex, "exchange_multisig_keys (r3)");
    char *resp = g3n_escrow_post_round_or_die(base, socks5, escrow_id, "r3",
                                              nick, token_trim, blob, NULL,
                                              idemp_prefix_trim, retry_max, poll_interval_s);
    printf("%s", resp);
    if (!resp[0] || resp[strlen(resp) - 1] != '\n') printf("\n");

    free(resp);
    secure_free_str(&blob);
    json_decref(ex);
    secure_free_str(&other_a);
    secure_free_str(&other_b);
    g3n_round_fetch_free(&rf);
    secure_free_str(&fetch_json);
    free(state);
    free(role);
    free(status_json);
    free(idemp_prefix_trim);
    secure_free_str(&wallet_password);
    secure_free_str(&token_trim);
    return 0;
}

int cmd_escrow_r4(const char *base,
                  const char *socks5,
                  unsigned long long escrow_id,
                  const char *nick,
                  const char *token,
                  const char *wallet_rpc_url,
                  const char *wallet_rpc_user,
                  const char *wallet_rpc_pass,
                  const char *wallet_name,
                  const char *wallet_password_env,
                  unsigned timeout_s) {
    pf_require_escrow_base_url_policy(base, 0, "escrow-r4");
    require_tor(base, socks5);
    if (!base || !base[0]) ff_die("escrow-r4 requires --base");
    if (!nick || !nick[0] || !token || !token[0]) ff_die("escrow-r4 requires --nick and --token");
    if (!wallet_rpc_url || !wallet_rpc_url[0] ||
        !wallet_rpc_user || !wallet_rpc_user[0] ||
        !wallet_rpc_pass || !wallet_rpc_pass[0] ||
        !wallet_name || !wallet_name[0] ||
        !wallet_password_env || !wallet_password_env[0]) {
        ff_die("escrow-r4: missing wallet-rpc arguments");
    }
    if (timeout_s == 0U) timeout_s = 20U;

    char *token_trim = g3n_trim_copy_or_die(token, "token");
    char *wallet_password = g3n_resolve_wallet_password_env_or_die(wallet_password_env, "escrow-r4");

    char *status_json = g3n_escrow_get_json_or_die(base, socks5, escrow_id, "", nick, token_trim, "escrow-r4 status");
    char *role = g3n_detect_role_from_status_or_die(status_json, nick, "escrow-r4");
    char *state = g3n_extract_state_from_escrow_json_or_die(status_json);
    fprintf(stderr, "escrow-r4: role=%s state=%s\n", role, state);

    g3n_wallet_open_or_create_or_die(wallet_rpc_url,
                                     wallet_rpc_user,
                                     wallet_rpc_pass,
                                     wallet_name,
                                     wallet_password,
                                     timeout_s);

    char *fetch_json = g3n_escrow_get_json_or_die(base, socks5, escrow_id, "/xmr/r3",
                                                  nick, token_trim, "escrow-r4 fetch r3");
    g3n_round_fetch_t rf;
    g3n_parse_round_fetch_or_die(fetch_json, "r3", &rf);
    char *other_a = NULL;
    char *other_b = NULL;
    g3n_collect_other_blobs_or_die(&rf, role, &other_a, &other_b);

    json_t *ex = g3n_wallet_exchange_multisig_auto_or_die(wallet_rpc_url,
                                                          wallet_rpc_user,
                                                          wallet_rpc_pass,
                                                          wallet_password,
                                                          other_a,
                                                          other_b,
                                                          "r4 exchange_multisig_keys",
                                                          timeout_s,
                                                          1);
    int ready = 0;
    json_t *st = g3n_wallet_is_multisig_or_die(wallet_rpc_url,
                                               wallet_rpc_user,
                                               wallet_rpc_pass,
                                               timeout_s,
                                               &ready);
    if (!ready) {
        char *dump = g3n_json_dumps_compact_or_die(st, "is_multisig");
        ff_die("escrow-r4: wallet multisig not ready for %s: %s", role, dump);
    }

    char *local_out = g3n_build_r4_local_output_or_die(ex, st);
    printf("%s", local_out);
    if (!local_out[0] || local_out[strlen(local_out) - 1] != '\n') printf("\n");

    free(local_out);
    json_decref(st);
    json_decref(ex);
    secure_free_str(&other_a);
    secure_free_str(&other_b);
    g3n_round_fetch_free(&rf);
    secure_free_str(&fetch_json);
    free(state);
    free(role);
    free(status_json);
    secure_free_str(&wallet_password);
    secure_free_str(&token_trim);
    return 0;
}

int cmd_escrow_gate3_ready(const char *base,
                           const char *socks5,
                           unsigned long long escrow_id,
                           const char *buyer_nick,
                           const char *buyer_token,
                           const char *seller_nick,
                           const char *seller_token,
                           const char *seller_token_db_path,
                           const char *buyer_wallet_rpc_url,
                           const char *buyer_wallet_rpc_user,
                           const char *buyer_wallet_rpc_pass,
                           const char *buyer_wallet_name,
                           const char *buyer_wallet_password_env,
                           const char *seller_wallet_rpc_url,
                           const char *seller_wallet_rpc_user,
                           const char *seller_wallet_rpc_pass,
                           const char *seller_wallet_name,
                           const char *seller_wallet_password_env,
                           const char *buyer_refund_address,
                           const char *seller_refund_address,
                           const char *idempotency_prefix,
                           const char *run_dir,
                           unsigned wait_ready_timeout_s,
                           unsigned poll_interval_s,
                           unsigned timeout_s,
                           unsigned round_retries) {
    pf_require_escrow_base_url_policy(base, 0, "escrow-gate3-ready");
    require_tor(base, socks5);
    if (!base || !base[0]) ff_die("escrow-gate3-ready requires --base");
    if (!buyer_nick || !buyer_nick[0]) ff_die("escrow-gate3-ready requires --buyer-nick");
    if (!buyer_token || !buyer_token[0]) ff_die("escrow-gate3-ready requires --buyer-token");
    if (!seller_nick || !seller_nick[0]) ff_die("escrow-gate3-ready requires --seller-nick");
    if (!buyer_wallet_rpc_url || !buyer_wallet_rpc_url[0] ||
        !buyer_wallet_rpc_user || !buyer_wallet_rpc_user[0] ||
        !buyer_wallet_rpc_pass || !buyer_wallet_rpc_pass[0] ||
        !buyer_wallet_name || !buyer_wallet_name[0] ||
        !buyer_wallet_password_env || !buyer_wallet_password_env[0]) {
        ff_die("escrow-gate3-ready: missing buyer wallet-rpc arguments");
    }
    if (!seller_wallet_rpc_url || !seller_wallet_rpc_url[0] ||
        !seller_wallet_rpc_user || !seller_wallet_rpc_user[0] ||
        !seller_wallet_rpc_pass || !seller_wallet_rpc_pass[0] ||
        !seller_wallet_name || !seller_wallet_name[0] ||
        !seller_wallet_password_env || !seller_wallet_password_env[0]) {
        ff_die("escrow-gate3-ready: missing seller wallet-rpc arguments");
    }
    if (poll_interval_s > 600U) ff_die("escrow-gate3-ready: --poll-interval too large");
    if (timeout_s == 0U) timeout_s = 20U;
    if (wait_ready_timeout_s == 0U) wait_ready_timeout_s = 900U;
    char *buyer_token_trim = g3n_trim_copy_or_die(buyer_token, "buyer token");

    char *seller_token_owned = dup_trimmed_copy(seller_token);
    if (seller_token_owned && !seller_token_owned[0]) {
        secure_free_str(&seller_token_owned);
    }
    if (!seller_token_owned) {
        if (!seller_token_db_path || !seller_token_db_path[0]) {
            secure_free_str(&buyer_token_trim);
            ff_die("escrow-gate3-ready requires --seller-token or --seller-token-db-path");
        }
        seller_token_owned = g3n_lookup_escrow_token_sqlite_or_die(seller_token_db_path, escrow_id, "seller");
        fprintf(stderr, "INFO: seller token resolved from sqlite db: %s\n", seller_token_db_path);
    }

    char *idemp_prefix_trim = normalize_idempotency_key(idempotency_prefix, "escrow-gate3-ready");
    if (!idemp_prefix_trim) {
        idemp_prefix_trim = dup_trimmed_copy("gate3");
        if (!idemp_prefix_trim) {
            secure_free_str(&seller_token_owned);
            secure_free_str(&buyer_token_trim);
            ff_die("oom");
        }
    }
    char *buyer_wallet_password = g3n_resolve_wallet_password_env_or_die(
        buyer_wallet_password_env, "escrow-gate3-ready buyer");
    char *seller_wallet_password = g3n_resolve_wallet_password_env_or_die(
        seller_wallet_password_env, "escrow-gate3-ready seller");

    char run_dir_auto[4096];
    const char *run_dir_eff = run_dir;
    if (!run_dir_eff || !run_dir_eff[0]) {
        char now_s[32];
        pf_utc_now(now_s);
        if (snprintf(run_dir_auto, sizeof(run_dir_auto), "/tmp/nexum-gate3-ready-%s", now_s) >= (int)sizeof(run_dir_auto)) {
            secure_free_str(&seller_wallet_password);
            secure_free_str(&buyer_wallet_password);
            free(idemp_prefix_trim);
            secure_free_str(&seller_token_owned);
            secure_free_str(&buyer_token_trim);
            ff_die("escrow-gate3-ready: generated run_dir path too long");
        }
        run_dir_eff = run_dir_auto;
        fprintf(stderr, "INFO: --run-dir not provided; using %s\n", run_dir_eff);
    }

    char flow_dir[4096];
    if (op_prepare_flow_run_dir(run_dir_eff, flow_dir, sizeof(flow_dir)) != 0) {
        secure_free_str(&seller_wallet_password);
        secure_free_str(&buyer_wallet_password);
        free(idemp_prefix_trim);
        secure_free_str(&seller_token_owned);
        secure_free_str(&buyer_token_trim);
        ff_die("escrow-gate3-ready: failed to initialize run_dir");
    }

    gate3_party_cfg_t buyer_cfg;
    memset(&buyer_cfg, 0, sizeof(buyer_cfg));
    buyer_cfg.role_label = "buyer";
    buyer_cfg.nick = buyer_nick;
    buyer_cfg.token = buyer_token_trim;
    buyer_cfg.wallet_rpc_url = buyer_wallet_rpc_url;
    buyer_cfg.wallet_rpc_user = buyer_wallet_rpc_user;
    buyer_cfg.wallet_rpc_pass = buyer_wallet_rpc_pass;
    buyer_cfg.wallet_name = buyer_wallet_name;
    buyer_cfg.wallet_password_env = buyer_wallet_password_env;
    buyer_cfg.refund_address = buyer_refund_address;

    gate3_party_cfg_t seller_cfg;
    memset(&seller_cfg, 0, sizeof(seller_cfg));
    seller_cfg.role_label = "seller";
    seller_cfg.nick = seller_nick;
    seller_cfg.token = seller_token_owned;
    seller_cfg.wallet_rpc_url = seller_wallet_rpc_url;
    seller_cfg.wallet_rpc_user = seller_wallet_rpc_user;
    seller_cfg.wallet_rpc_pass = seller_wallet_rpc_pass;
    seller_cfg.wallet_name = seller_wallet_name;
    seller_cfg.wallet_password_env = seller_wallet_password_env;
    seller_cfg.refund_address = seller_refund_address;

    fprintf(stderr, "gate3-ready: escrow_id=%llu base=%s\n", escrow_id, base);
    fprintf(stderr, "gate3-ready: native flow r1..r4 + wait READY\n");

    g3n_run_party_round_or_die(1, &buyer_cfg, buyer_wallet_password, base, socks5, escrow_id,
                               idemp_prefix_trim, flow_dir, timeout_s, round_retries, poll_interval_s);
    g3n_run_party_round_or_die(1, &seller_cfg, seller_wallet_password, base, socks5, escrow_id,
                               idemp_prefix_trim, flow_dir, timeout_s, round_retries, poll_interval_s);
    g3n_run_party_round_or_die(2, &buyer_cfg, buyer_wallet_password, base, socks5, escrow_id,
                               idemp_prefix_trim, flow_dir, timeout_s, round_retries, poll_interval_s);
    g3n_run_party_round_or_die(2, &seller_cfg, seller_wallet_password, base, socks5, escrow_id,
                               idemp_prefix_trim, flow_dir, timeout_s, round_retries, poll_interval_s);
    g3n_run_party_round_or_die(3, &buyer_cfg, buyer_wallet_password, base, socks5, escrow_id,
                               idemp_prefix_trim, flow_dir, timeout_s, round_retries, poll_interval_s);
    g3n_run_party_round_or_die(3, &seller_cfg, seller_wallet_password, base, socks5, escrow_id,
                               idemp_prefix_trim, flow_dir, timeout_s, round_retries, poll_interval_s);
    g3n_run_party_round_or_die(4, &buyer_cfg, buyer_wallet_password, base, socks5, escrow_id,
                               idemp_prefix_trim, flow_dir, timeout_s, round_retries, poll_interval_s);
    g3n_run_party_round_or_die(4, &seller_cfg, seller_wallet_password, base, socks5, escrow_id,
                               idemp_prefix_trim, flow_dir, timeout_s, round_retries, poll_interval_s);

    char *status_ready_path = g3n_path_join3_or_die(flow_dir, "status_ready", ".json");
    char *status_after_ready_path = g3n_path_join3_or_die(flow_dir, "status_after_ready", ".json");
    char *ready_json = g3n_wait_ready_or_die(base, socks5, escrow_id, buyer_nick, buyer_token_trim,
                                             wait_ready_timeout_s, poll_interval_s, status_ready_path);

    /* Avoid immediate post-ready 429 from local rate limiter (matches rehearsal behavior). */
    if (poll_interval_s > 0) sleep(poll_interval_s);

    char *final_json = g3n_status_after_ready_or_die(base, socks5, escrow_id, buyer_nick, buyer_token_trim,
                                                     poll_interval_s, status_after_ready_path);
    free(status_ready_path);
    free(status_after_ready_path);
    free(ready_json);

    op_write_escrow_gate3_ready_artifacts(run_dir_eff, base, socks5, escrow_id);
    fprintf(stderr, "escrow-gate3-ready OK: escrow_id=%llu reached READY\n", escrow_id);
    fprintf(stderr, "  run_dir: %s\n", run_dir_eff);
    op_print_escrow_status_summary(final_json, run_dir_eff);
    printf("%s", final_json);
    if (final_json[0]) {
        size_t n = strlen(final_json);
        if (n == 0 || final_json[n - 1] != '\n') printf("\n");
    }

    secure_free_str(&seller_wallet_password);
    secure_free_str(&buyer_wallet_password);
    free(final_json);
    free(idemp_prefix_trim);
    secure_free_str(&seller_token_owned);
    secure_free_str(&buyer_token_trim);
    return 0;
}

static void g3n_wallet_open_only_or_die(const char *url,
                                        const char *user,
                                        const char *pass,
                                        const char *wallet_name,
                                        const char *wallet_password,
                                        unsigned timeout_s) {
    json_t *params = json_object();
    json_t *res = NULL;
    char *err = NULL;

    if (params) {
        (void)g3n_wallet_rpc_call_ex(url, user, pass, "close_wallet", params, timeout_s, &res, &err);
        json_decref(params);
        if (res) json_decref(res);
        free(err);
        params = NULL;
        res = NULL;
        err = NULL;
    }

    params = json_object();
    if (!params) ff_die("oom");
    json_object_set_new(params, "filename", json_string(wallet_name));
    json_object_set_new(params, "password", json_string(wallet_password));
    if (g3n_wallet_rpc_call_ex(url, user, pass, "open_wallet", params, timeout_s, &res, &err) != 0) {
        json_decref(params);
        ff_die("%s", err ? err : "wallet-rpc open_wallet failed");
    }
    json_decref(params);
    json_decref(res);
    free(err);
}

static void g3n_wallet_refresh_or_die(const char *url,
                                      const char *user,
                                      const char *pass,
                                      unsigned timeout_s) {
    json_t *params = json_object();
    if (!params) ff_die("oom");
    json_t *res = g3n_wallet_rpc_call_or_die(url, user, pass, "refresh", params, timeout_s);
    json_decref(params);
    json_decref(res);
}

static char *g3n_json_dumps_pretty_or_die(json_t *v, const char *ctx) {
    char *s = json_dumps(v, JSON_INDENT(2) | JSON_SORT_KEYS);
    if (!s) ff_die("%s: json serialization failed", ctx ? ctx : "json");
    return s;
}

int cmd_escrow_fund(const char *base,
                    const char *socks5,
                    unsigned long long escrow_id,
                    const char *buyer_nick,
                    const char *buyer_token,
                    const char *wallet_rpc_url,
                    const char *wallet_rpc_user,
                    const char *wallet_rpc_pass,
                    const char *wallet_name,
                    const char *wallet_password_env,
                    const char *run_dir,
                    unsigned long long fund_buffer_atomic,
                    unsigned timeout_s) {
    pf_require_escrow_base_url_policy(base, 0, "escrow-fund");
    require_tor(base, socks5);
    if (!base || !base[0]) ff_die("escrow-fund requires --base");
    if (!buyer_nick || !buyer_nick[0] || !buyer_token || !buyer_token[0]) {
        ff_die("escrow-fund requires --buyer-nick and --buyer-token");
    }
    if (!wallet_rpc_url || !wallet_rpc_url[0] ||
        !wallet_rpc_user || !wallet_rpc_user[0] ||
        !wallet_rpc_pass || !wallet_rpc_pass[0] ||
        !wallet_name || !wallet_name[0] ||
        !wallet_password_env || !wallet_password_env[0]) {
        ff_die("escrow-fund: missing wallet-rpc arguments");
    }
    if (timeout_s == 0U) timeout_s = 120U;

    char *buyer_token_trim = g3n_trim_copy_or_die(buyer_token, "buyer token");
    char *wallet_password = g3n_resolve_wallet_password_env_or_die(wallet_password_env, "escrow-fund");

    char run_dir_auto[4096];
    const char *run_dir_eff = run_dir;
    if (!run_dir_eff || !run_dir_eff[0]) {
        char now_s[32];
        pf_utc_now(now_s);
        if (snprintf(run_dir_auto, sizeof(run_dir_auto), "/tmp/nexum-escrow-fund-%s", now_s) >= (int)sizeof(run_dir_auto)) {
            secure_free_str(&wallet_password);
            secure_free_str(&buyer_token_trim);
            ff_die("escrow-fund: generated run_dir path too long");
        }
        run_dir_eff = run_dir_auto;
        fprintf(stderr, "INFO: --run-dir not provided; using %s\n", run_dir_eff);
    }
    char flow_dir[4096];
    if (op_prepare_flow_run_dir(run_dir_eff, flow_dir, sizeof(flow_dir)) != 0) {
        secure_free_str(&wallet_password);
        secure_free_str(&buyer_token_trim);
        ff_die("escrow-fund: failed to initialize run_dir");
    }

    char *status_before = g3n_escrow_get_json_or_die(base, socks5, escrow_id, "", buyer_nick, buyer_token_trim, "escrow-fund status");
    char *status_before_path = g3n_path_join3_or_die(flow_dir, "status_before_fund", ".json");
    g3n_write_artifact_or_die(status_before_path, status_before);
    free(status_before_path);

    json_t *status_root = g3n_json_load_obj_or_die(status_before, "escrow-fund status");
    char *state = g3n_json_dup_string(status_root, "state");
    char *deposit_address = g3n_json_dup_string(status_root, "deposit_address");
    long long required_funding_ll = g3n_json_int_or_neg1(status_root, "required_funding_atomic");
    if (required_funding_ll < 0) required_funding_ll = g3n_json_int_or_neg1(status_root, "amount_atomic");
    json_decref(status_root);

    if (!state || !state[0]) {
        free(status_before);
        secure_free_str(&deposit_address);
        secure_free_str(&state);
        secure_free_str(&wallet_password);
        secure_free_str(&buyer_token_trim);
        ff_die("escrow-fund: escrow status missing state");
    }
    if (!deposit_address || !deposit_address[0]) {
        free(status_before);
        secure_free_str(&deposit_address);
        secure_free_str(&state);
        secure_free_str(&wallet_password);
        secure_free_str(&buyer_token_trim);
        ff_die("escrow-fund: escrow status missing deposit_address");
    }
    if (required_funding_ll <= 0) {
        free(status_before);
        secure_free_str(&deposit_address);
        secure_free_str(&state);
        secure_free_str(&wallet_password);
        secure_free_str(&buyer_token_trim);
        ff_die("escrow-fund: escrow status missing required_funding_atomic");
    }

    if (strcmp(state, "FUNDED") == 0 || strcmp(state, "RELEASED") == 0) {
        fprintf(stderr, "escrow-fund: escrow already in terminal-funded state=%s (skipping transfer)\n", state);
        op_print_escrow_status_summary(status_before, run_dir_eff);
        printf("%s\n", status_before);
        free(status_before);
        secure_free_str(&deposit_address);
        secure_free_str(&state);
        secure_free_str(&wallet_password);
        secure_free_str(&buyer_token_trim);
        return 0;
    }
    if (strcmp(state, "READY") != 0) {
        free(status_before);
        secure_free_str(&deposit_address);
        secure_free_str(&state);
        secure_free_str(&wallet_password);
        secure_free_str(&buyer_token_trim);
        ff_die("escrow-fund: expected escrow state=READY (got %s)", state);
    }

    unsigned long long required_funding_atomic = (unsigned long long)required_funding_ll;
    if (fund_buffer_atomic > ULLONG_MAX - required_funding_atomic) {
        free(status_before);
        secure_free_str(&deposit_address);
        secure_free_str(&state);
        secure_free_str(&wallet_password);
        secure_free_str(&buyer_token_trim);
        ff_die("escrow-fund: fund amount overflow");
    }
    unsigned long long fund_total_atomic = required_funding_atomic + fund_buffer_atomic;
    fprintf(stderr, "escrow-fund: state=%s required=%llu buffer=%llu total=%llu\n",
            state, required_funding_atomic, fund_buffer_atomic, fund_total_atomic);
    fprintf(stderr, "escrow-fund: deposit_address=%s\n", deposit_address);

    char *p_required = g3n_path_join3_or_die(flow_dir, "funding_base_atomic", ".txt");
    char *p_total = g3n_path_join3_or_die(flow_dir, "funding_total_atomic", ".txt");
    char buf_num[64];
    snprintf(buf_num, sizeof(buf_num), "%llu\n", required_funding_atomic);
    g3n_write_artifact_or_die(p_required, buf_num);
    snprintf(buf_num, sizeof(buf_num), "%llu\n", fund_total_atomic);
    g3n_write_artifact_or_die(p_total, buf_num);
    free(p_required);
    free(p_total);

    g3n_wallet_open_only_or_die(wallet_rpc_url, wallet_rpc_user, wallet_rpc_pass, wallet_name, wallet_password, timeout_s);
    g3n_wallet_refresh_or_die(wallet_rpc_url, wallet_rpc_user, wallet_rpc_pass, timeout_s);

    json_t *transfer_params = json_object();
    json_t *dest = json_object();
    json_t *dests = json_array();
    if (!transfer_params || !dest || !dests) ff_die("oom");
    json_object_set_new(dest, "address", json_string(deposit_address));
    json_object_set_new(dest, "amount", json_integer((json_int_t)fund_total_atomic));
    json_array_append_new(dests, dest);
    json_object_set_new(transfer_params, "destinations", dests);
    json_object_set_new(transfer_params, "do_not_relay", json_false());

    char *transfer_params_pretty = g3n_json_dumps_pretty_or_die(transfer_params, "escrow-fund transfer params");
    char *p_transfer_params = g3n_path_join3_or_die(flow_dir, "fund_transfer_params", ".json");
    g3n_write_artifact_or_die(p_transfer_params, transfer_params_pretty);
    free(p_transfer_params);
    secure_free_str(&transfer_params_pretty);

    json_t *transfer_result = NULL;
    char *wallet_err = NULL;
    if (g3n_wallet_rpc_call_ex(wallet_rpc_url, wallet_rpc_user, wallet_rpc_pass,
                               "transfer", transfer_params, timeout_s, &transfer_result, &wallet_err) != 0) {
        json_decref(transfer_params);
        free(status_before);
        secure_free_str(&deposit_address);
        secure_free_str(&state);
        secure_free_str(&wallet_password);
        secure_free_str(&buyer_token_trim);
        ff_die("%s", wallet_err ? wallet_err : "wallet-rpc transfer failed");
    }
    json_decref(transfer_params);
    free(wallet_err);

    char *transfer_result_pretty = g3n_json_dumps_pretty_or_die(transfer_result, "escrow-fund transfer result");
    char *p_transfer_res = g3n_path_join3_or_die(flow_dir, "fund_transfer", ".json");
    g3n_write_artifact_or_die(p_transfer_res, transfer_result_pretty);
    free(p_transfer_res);

    char *status_after_submit = NULL;
    for (int attempt = 1; attempt <= 3; attempt++) {
        ff_http_resp_t r;
        memset(&r, 0, sizeof(r));
        char *url = g3n_build_auth_query_url_or_die(base, escrow_id, "", buyer_nick, buyer_token_trim);
        if (ff_http_get_json_auth(url, socks5, buyer_token_trim, NULL, &r) == 0) {
            status_after_submit = r.data ? strdup(r.data) : strdup("{}");
            ff_http_resp_free(&r);
            free(url);
            break;
        }
        ff_http_resp_free(&r);
        free(url);
        if (attempt < 3) sleep(1);
    }
    if (status_after_submit) {
        char *p_status_after = g3n_path_join3_or_die(flow_dir, "status_after_fund_submit", ".json");
        g3n_write_artifact_or_die(p_status_after, status_after_submit);
        free(p_status_after);
        free(status_after_submit);
    }

    fprintf(stderr, "escrow-fund OK: escrow_id=%llu submitted transfer total=%llu\n", escrow_id, fund_total_atomic);
    fprintf(stderr, "  run_dir: %s\n", run_dir_eff);
    printf("%s\n", transfer_result_pretty);

    secure_free_str(&transfer_result_pretty);
    json_decref(transfer_result);
    free(status_before);
    secure_free_str(&deposit_address);
    secure_free_str(&state);
    secure_free_str(&wallet_password);
    secure_free_str(&buyer_token_trim);
    return 0;
}

static int wait_state_target_is_valid_char(unsigned char c) {
    return ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-');
}

static char *normalize_wait_state_target_or_die(const char *target_state, const char *ctx) {
    char *trim = dup_trimmed_copy(target_state);
    if (!trim) ff_die("oom");
    if (!trim[0]) {
        free(trim);
        ff_die("%s requires non-empty --state", ctx ? ctx : "escrow-wait-state");
    }
    if (strlen(trim) > 64) {
        free(trim);
        ff_die("%s: --state too long (max 64 chars)", ctx ? ctx : "escrow-wait-state");
    }
    for (size_t i = 0; trim[i]; i++) {
        unsigned char c = (unsigned char)trim[i];
        if (!wait_state_target_is_valid_char(c)) {
            free(trim);
            ff_die("%s: --state has invalid chars; allowed [A-Za-z0-9_-]",
                   ctx ? ctx : "escrow-wait-state");
        }
        trim[i] = (char)toupper(c);
    }
    return trim;
}

static void wait_state_slugify(char *dst, size_t dst_cap, const char *state_upper) {
    if (!dst || dst_cap == 0) return;
    size_t j = 0;
    if (!state_upper) state_upper = "";
    for (size_t i = 0; state_upper[i] && j + 1 < dst_cap; i++) {
        unsigned char c = (unsigned char)state_upper[i];
        if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) dst[j++] = (char)tolower(c);
        else if (c == '_' || c == '-') dst[j++] = '_';
    }
    if (j == 0 && dst_cap > 1) dst[j++] = 'x';
    dst[j] = 0;
}

static int cmd_escrow_wait_state_common(const char *ctx_label,
                                        const char *base,
                                        const char *socks5,
                                        unsigned long long escrow_id,
                                        const char *nick,
                                        const char *token,
                                        const char *target_state,
                                        const char *run_dir,
                                        unsigned wait_timeout_s,
                                        unsigned poll_interval_s,
                                        int funded_terminal_alias) {
    pf_require_escrow_base_url_policy(base, 0, ctx_label);
    require_tor(base, socks5);
    if (!base || !base[0]) ff_die("%s requires --base", ctx_label);
    if (!nick || !nick[0] || !token || !token[0]) ff_die("%s requires --nick and --token", ctx_label);
    if (wait_timeout_s == 0U) wait_timeout_s = 1800U;
    if (poll_interval_s == 0U) poll_interval_s = 5U;

    char *target = normalize_wait_state_target_or_die(target_state, ctx_label);
    char *token_trim = g3n_trim_copy_or_die(token, "token");
    char run_dir_auto[4096];
    const char *run_dir_eff = run_dir;
    if (!run_dir_eff || !run_dir_eff[0]) {
        char now_s[32];
        pf_utc_now(now_s);
        if (snprintf(run_dir_auto, sizeof(run_dir_auto), "/tmp/nexum-%s-%s",
                     ctx_label, now_s) >= (int)sizeof(run_dir_auto)) {
            secure_free_str(&token_trim);
            free(target);
            ff_die("%s: generated run_dir path too long", ctx_label);
        }
        run_dir_eff = run_dir_auto;
        fprintf(stderr, "INFO: --run-dir not provided; using %s\n", run_dir_eff);
    }
    char flow_dir[4096];
    if (op_prepare_flow_run_dir(run_dir_eff, flow_dir, sizeof(flow_dir)) != 0) {
        secure_free_str(&token_trim);
        free(target);
        ff_die("%s: failed to initialize run_dir", ctx_label);
    }

    time_t deadline = time(NULL) + (time_t)wait_timeout_s;
    char *last_state = NULL;
    for (;;) {
        char *status_json = g3n_escrow_get_json_or_die(base, socks5, escrow_id, "", nick, token_trim,
                                                       "escrow wait-state status poll");
        char *state = g3n_extract_state_from_escrow_json_or_die(status_json);
        if (!last_state || strcmp(last_state, state) != 0) {
            fprintf(stderr, "%s: state=%s\n", ctx_label, state);
            free(last_state);
            last_state = strdup(state);
            if (!last_state) ff_die("oom");
        }

        int success = (strcmp(state, target) == 0);
        if (!success && funded_terminal_alias &&
            (strcmp(target, "FUNDED") == 0) &&
            (strcmp(state, "FUNDED") == 0 || strcmp(state, "RELEASED") == 0)) {
            success = 1;
        }
        if (success) {
            char rel[128];
            if (funded_terminal_alias && strcmp(target, "FUNDED") == 0) {
                ff_strlcpy(rel, "flow/status_funded.json", sizeof(rel));
            } else {
                char slug[96];
                wait_state_slugify(slug, sizeof(slug), target);
                snprintf(rel, sizeof(rel), "flow/status_%s.json", slug);
            }
            char path_status[4096];
            if (snprintf(path_status, sizeof(path_status), "%s/%s", run_dir_eff, rel) >= (int)sizeof(path_status)) {
                free(status_json);
                free(state);
                free(last_state);
                secure_free_str(&token_trim);
                free(target);
                ff_die("%s: success artifact path too long", ctx_label);
            }
            if (pf_write_text(path_status, status_json ? status_json : "{}") != 0) {
                op_write_warn("failed to write flow wait-state artifact");
            }
            fprintf(stderr, "%s OK: escrow_id=%llu state=%s (target=%s)\n",
                    ctx_label, escrow_id, state, target);
            op_print_escrow_status_summary(status_json, run_dir_eff);
            printf("%s", status_json);
            if (status_json[0]) {
                size_t n = strlen(status_json);
                if (n == 0 || status_json[n - 1] != '\n') printf("\n");
            }
            free(status_json);
            free(state);
            free(last_state);
            secure_free_str(&token_trim);
            free(target);
            return 0;
        }

        free(state);
        free(status_json);
        if (time(NULL) >= deadline) {
            char *ls_copy = last_state ? strdup(last_state) : strdup("");
            free(last_state);
            secure_free_str(&token_trim);
            if (!ls_copy) ff_die("oom");
            ff_die("%s: timeout waiting for state=%s; last_state=%s", ctx_label, target, ls_copy);
        }
        sleep(poll_interval_s);
    }
}

int cmd_escrow_wait_state(const char *base,
                          const char *socks5,
                          unsigned long long escrow_id,
                          const char *nick,
                          const char *token,
                          const char *target_state,
                          const char *run_dir,
                          unsigned wait_timeout_s,
                          unsigned poll_interval_s) {
    return cmd_escrow_wait_state_common(
        "escrow-wait-state",
        base,
        socks5,
        escrow_id,
        nick,
        token,
        target_state,
        run_dir,
        wait_timeout_s,
        poll_interval_s,
        0
    );
}

int cmd_escrow_wait_funded(const char *base,
                           const char *socks5,
                           unsigned long long escrow_id,
                           const char *nick,
                           const char *token,
                           const char *run_dir,
                           unsigned wait_timeout_s,
                           unsigned poll_interval_s) {
    return cmd_escrow_wait_state_common(
        "escrow-wait-funded",
        base,
        socks5,
        escrow_id,
        nick,
        token,
        "FUNDED",
        run_dir,
        wait_timeout_s,
        poll_interval_s,
        1
    );
}

int cmd_escrow_funded_sync(const char *orch_bin_opt,
                           const char *base,
                           const char *socks5,
                           int allow_non_tor,
                           unsigned long long escrow_id,
                           const char *buyer_nick,
                           const char *buyer_token,
                           const char *arbiter_nick,
                           const char *arbiter_token,
                           const char *arbiter_token_fallback,
                           const char *buyer_rpc_endpoint,
                           const char *buyer_rpc_user,
                           const char *buyer_rpc_pass,
                           const char *buyer_wallet_name,
                           const char *buyer_wallet_pass,
                           const char *seller_rpc_endpoint,
                           const char *seller_rpc_user,
                           const char *seller_rpc_pass,
                           const char *seller_wallet_name,
                           const char *seller_wallet_pass,
                           const char *run_dir,
                           unsigned funded_timeout_s,
                           unsigned poll_interval_s,
                           unsigned http_timeout_s) {
    /* `--allow-non-tor` bypasses Tor requirement for local helpers, but remote cleartext http:// still needs explicit env override. */
    pf_require_escrow_base_url_policy(base, 0, "escrow-funded-sync");
    if (!allow_non_tor) require_tor(base, socks5);
    if (!base || !base[0]) ff_die("escrow-funded-sync requires --base");
    if (!buyer_nick || !buyer_nick[0] || !buyer_token || !buyer_token[0]) {
        ff_die("escrow-funded-sync requires --buyer-nick and --buyer-token");
    }
    if (!arbiter_nick || !arbiter_nick[0] || !arbiter_token || !arbiter_token[0]) {
        ff_die("escrow-funded-sync requires --arbiter-nick and --arbiter-token");
    }
    if (!buyer_rpc_endpoint || !buyer_rpc_user || !buyer_rpc_pass || !buyer_wallet_name || !buyer_wallet_pass ||
        !seller_rpc_endpoint || !seller_rpc_user || !seller_rpc_pass || !seller_wallet_name || !seller_wallet_pass) {
        ff_die("escrow-funded-sync: missing wallet-rpc arguments");
    }
    if (funded_timeout_s == 0U) funded_timeout_s = 1800U;
    if (poll_interval_s == 0U) poll_interval_s = 10U;
    if (http_timeout_s == 0U) http_timeout_s = 120U;

    char run_dir_auto[4096];
    const char *run_dir_eff = run_dir;
    if (!run_dir_eff || !run_dir_eff[0]) {
        char now_s[32];
        pf_utc_now(now_s);
        if (snprintf(run_dir_auto, sizeof(run_dir_auto), "/tmp/nexum-escrow-funded-sync-%s", now_s) >= (int)sizeof(run_dir_auto)) {
            ff_die("escrow-funded-sync: generated run_dir path too long");
        }
        run_dir_eff = run_dir_auto;
        fprintf(stderr, "INFO: --run-dir not provided; using %s\n", run_dir_eff);
    }
    char flow_dir[4096];
    if (op_prepare_flow_run_dir(run_dir_eff, flow_dir, sizeof(flow_dir)) != 0) {
        ff_die("escrow-funded-sync: failed to initialize run_dir");
    }

    const char *orch_bin = resolve_orch_bin(orch_bin_opt);
    char escrow_id_s[32];
    char funded_timeout_s_s[32];
    char poll_interval_s_s[32];
    char http_timeout_s_s[32];
    snprintf(escrow_id_s, sizeof(escrow_id_s), "%llu", escrow_id);
    snprintf(funded_timeout_s_s, sizeof(funded_timeout_s_s), "%u", funded_timeout_s);
    snprintf(poll_interval_s_s, sizeof(poll_interval_s_s), "%u", poll_interval_s);
    snprintf(http_timeout_s_s, sizeof(http_timeout_s_s), "%u", http_timeout_s);

    const char *env_buyer_token = "NEXUM_ORCH_FS_BUYER_TOKEN";
    const char *env_arbiter_token = "NEXUM_ORCH_FS_ARBITER_TOKEN";
    const char *env_arbiter_token_fallback = "NEXUM_ORCH_FS_ARBITER_TOKEN_FALLBACK";
    const char *env_buyer_rpc_user = "NEXUM_ORCH_FS_BUYER_RPC_USER";
    const char *env_buyer_rpc_pass = "NEXUM_ORCH_FS_BUYER_RPC_PASS";
    const char *env_buyer_wallet_pass = "NEXUM_ORCH_FS_BUYER_WALLET_PASS";
    const char *env_seller_rpc_user = "NEXUM_ORCH_FS_SELLER_RPC_USER";
    const char *env_seller_rpc_pass = "NEXUM_ORCH_FS_SELLER_RPC_PASS";
    const char *env_seller_wallet_pass = "NEXUM_ORCH_FS_SELLER_WALLET_PASS";
    pf_env_kv_t envs[10];
    size_t env_count = 0;

    envs[env_count++] = (pf_env_kv_t){ env_buyer_token, buyer_token };
    envs[env_count++] = (pf_env_kv_t){ env_arbiter_token, arbiter_token };
    if (arbiter_token_fallback && arbiter_token_fallback[0]) {
        envs[env_count++] = (pf_env_kv_t){ env_arbiter_token_fallback, arbiter_token_fallback };
    }
    envs[env_count++] = (pf_env_kv_t){ env_buyer_rpc_user, buyer_rpc_user };
    envs[env_count++] = (pf_env_kv_t){ env_buyer_rpc_pass, buyer_rpc_pass };
    envs[env_count++] = (pf_env_kv_t){ env_buyer_wallet_pass, buyer_wallet_pass };
    envs[env_count++] = (pf_env_kv_t){ env_seller_rpc_user, seller_rpc_user };
    envs[env_count++] = (pf_env_kv_t){ env_seller_rpc_pass, seller_rpc_pass };
    envs[env_count++] = (pf_env_kv_t){ env_seller_wallet_pass, seller_wallet_pass };

    char *argv[96];
    int ai = 0;
    argv[ai++] = (char *)orch_bin;
    argv[ai++] = "http-flow";
    argv[ai++] = "funded-sync";
    argv[ai++] = "--escrow-id";
    argv[ai++] = escrow_id_s;
    argv[ai++] = "--buyer-nick";
    argv[ai++] = (char *)buyer_nick;
    argv[ai++] = "--buyer-token-env";
    argv[ai++] = (char *)env_buyer_token;
    argv[ai++] = "--arbiter-nick";
    argv[ai++] = (char *)arbiter_nick;
    argv[ai++] = "--arbiter-token-env";
    argv[ai++] = (char *)env_arbiter_token;
    if (arbiter_token_fallback && arbiter_token_fallback[0]) {
        argv[ai++] = "--arbiter-token-fallback-env";
        argv[ai++] = (char *)env_arbiter_token_fallback;
    }
    argv[ai++] = "--base-url";
    argv[ai++] = (char *)base;
    argv[ai++] = "--buyer-rpc-endpoint";
    argv[ai++] = (char *)buyer_rpc_endpoint;
    argv[ai++] = "--buyer-rpc-user-env";
    argv[ai++] = (char *)env_buyer_rpc_user;
    argv[ai++] = "--buyer-rpc-pass-env";
    argv[ai++] = (char *)env_buyer_rpc_pass;
    argv[ai++] = "--buyer-wallet-name";
    argv[ai++] = (char *)buyer_wallet_name;
    argv[ai++] = "--buyer-wallet-pass-env";
    argv[ai++] = (char *)env_buyer_wallet_pass;
    argv[ai++] = "--seller-rpc-endpoint";
    argv[ai++] = (char *)seller_rpc_endpoint;
    argv[ai++] = "--seller-rpc-user-env";
    argv[ai++] = (char *)env_seller_rpc_user;
    argv[ai++] = "--seller-rpc-pass-env";
    argv[ai++] = (char *)env_seller_rpc_pass;
    argv[ai++] = "--seller-wallet-name";
    argv[ai++] = (char *)seller_wallet_name;
    argv[ai++] = "--seller-wallet-pass-env";
    argv[ai++] = (char *)env_seller_wallet_pass;
    argv[ai++] = "--funded-timeout-s";
    argv[ai++] = funded_timeout_s_s;
    argv[ai++] = "--poll-interval-s";
    argv[ai++] = poll_interval_s_s;
    argv[ai++] = "--http-timeout-s";
    argv[ai++] = http_timeout_s_s;
    argv[ai++] = "--artifact-root";
    argv[ai++] = (char *)run_dir_eff;
    if (socks5 && socks5[0]) {
        argv[ai++] = "--tor-socks5h";
        argv[ai++] = (char *)socks5;
    }
    if (allow_non_tor) {
        argv[ai++] = "--allow-non-tor";
    }
    argv[ai] = NULL;

    char orch_out[65536];
    int exit_code = -1;
    int rc = pf_run_orch_capture_env(orch_bin, argv, envs, env_count, orch_out, sizeof(orch_out), &exit_code);
    char *p_orch_json = g3n_path_join3_or_die(flow_dir, "orch_funded_sync", ".json");
    g3n_write_artifact_or_die(p_orch_json, orch_out[0] ? orch_out : "{}");
    free(p_orch_json);
    if (rc != 0) {
        ff_die("escrow-funded-sync: orchestrator http-flow funded-sync failed (exit=%d)", exit_code);
    }

    json_t *root = g3n_json_load_obj_or_die(orch_out, "escrow-funded-sync orchestrator output");
    char *orch_run_dir = g3n_json_dup_string(root, "run_dir");
    json_decref(root);
    if (!orch_run_dir || !orch_run_dir[0]) {
        secure_free_str(&orch_run_dir);
        ff_die("escrow-funded-sync: orchestrator output missing run_dir");
    }

    char status_src_path[8192];
    if (snprintf(status_src_path, sizeof(status_src_path), "%s/status_funded.json", orch_run_dir) >= (int)sizeof(status_src_path)) {
        secure_free_str(&orch_run_dir);
        ff_die("escrow-funded-sync: status_funded path too long");
    }
    char *status_funded_json = read_file_str(status_src_path, NULL);
    if (!status_funded_json || !status_funded_json[0]) {
        free(status_funded_json);
        secure_free_str(&orch_run_dir);
        ff_die("escrow-funded-sync: missing or empty %s", status_src_path);
    }
    char *p_status_funded = g3n_path_join3_or_die(flow_dir, "status_funded", ".json");
    g3n_write_artifact_or_die(p_status_funded, status_funded_json);
    free(p_status_funded);

    fprintf(stderr, "escrow-funded-sync OK: escrow_id=%llu\n", escrow_id);
    fprintf(stderr, "  run_dir: %s\n", run_dir_eff);
    fprintf(stderr, "  orchestrator_run_dir: %s\n", orch_run_dir);
    op_print_escrow_status_summary(status_funded_json, run_dir_eff);
    printf("%s", orch_out);
    if (orch_out[0]) {
        size_t n = strlen(orch_out);
        if (n == 0 || orch_out[n - 1] != '\n') printf("\n");
    }

    free(status_funded_json);
    secure_free_str(&orch_run_dir);
    return 0;
}

int cmd_preflight_escrow(const char *base,
                         const char *socks5_in,
                         const char *ui_base,
                         int require_ui,
                         int json_output,
                         const char *run_dir,
                         const char *orch_db,
                         const char *orch_bin,
                         const char *escrow_id_hex,
                         int strict_daemon_sync,
                         int allow_bootstrap,
                         int strict_wallet_multisig,
                         int check_transfer_dry_run,
                         unsigned timeout_ms,
                         int verbose) {
    pf_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.verbose = verbose;
    ctx.json_mode = json_output ? 1 : 0;
    append_or_die(&ctx.checks_tsv, &ctx.checks_tsv_len, "status\tcheck_id\treason_code\tmessage\thint\n");

    const char *socks5 = (socks5_in && socks5_in[0]) ? socks5_in : "socks5h://127.0.0.1:9050";
    const char *orch_bin_resolved = resolve_orch_bin(orch_bin);
    const char *orch_db_resolved = resolve_orch_db_path(orch_db);
    char now_s[32];
    pf_utc_now(now_s);

    char header[1024];
    snprintf(header, sizeof(header),
             "== nexum preflight escrow (operator/break-glass) ==\n"
             "date: %s\n"
             "target escrow-http: %s\n"
             "target nxms-serv: %s\n"
             "tor socks5: %s\n"
             "run_dir: %s\n"
             "\n",
             now_s,
             base ? base : "(missing)",
             (ui_base && ui_base[0]) ? ui_base : "(not set)",
             socks5,
             (run_dir && run_dir[0]) ? run_dir : "(none)");
    pf_append_line(&ctx, header);

    if (timeout_ms > 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "timeout budget accepted (%u ms); v1 uses built-in timeouts for some probes", timeout_ms);
        pf_record(&ctx, PF_ST_SKIP, "preflight.timeout_ms", "PREFLIGHT_TIMEOUT_PARTIAL", msg, NULL, 1);
    }

    if (!base || !base[0]) {
        pf_record(&ctx, PF_ST_FAIL, "input.base", "PREFLIGHT_MISSING_REQUIRED_INPUT",
                  "--base is required", "pass --base http://<escrow>.onion", 0);
    } else if (!url_host_is_onion_suffix(base)) {
        pf_record(&ctx, PF_ST_FAIL, "input.base", "PREFLIGHT_BASE_NOT_ONION",
                  "--base must be a .onion address", "use escrow-http onion hostname", 0);
    } else {
        pf_record(&ctx, PF_ST_PASS, "input.base", "", "base looks like .onion", NULL, 0);
    }

    if (!socks5 || !socks5[0]) {
        pf_record(&ctx, PF_ST_FAIL, "input.socks5", "PREFLIGHT_MISSING_REQUIRED_INPUT",
                  "--socks5 missing", "use socks5h://127.0.0.1:9050", 0);
    } else if (strncmp(socks5, "socks5h://", 10) != 0) {
        pf_record(&ctx, PF_ST_FAIL, "input.socks5", "PREFLIGHT_SOCKS5H_REQUIRED",
                  "Tor requires socks5h:// (DNS over Tor)", "replace socks5:// with socks5h://", 0);
    } else {
        pf_record(&ctx, PF_ST_PASS, "input.socks5", "", "socks5h scheme OK", NULL, 0);
    }

    if (escrow_id_hex && escrow_id_hex[0]) {
        pf_record(&ctx, PF_ST_PASS, "input.escrow_id_hex", "", "escrow id format accepted (32 hex)", NULL, 0);
    } else {
        pf_record(&ctx, PF_ST_SKIP, "input.escrow_id_hex", "WORKER_ROUTE_ESCROW_ID_NOT_PROVIDED",
                  "per-escrow worker-route checks skipped (no --escrow-id-hex)", NULL, 1);
    }

    if (ctx.fail_count == 0) {
        if (tor_proxy_reachable(socks5) != 0) {
            pf_record(&ctx, PF_ST_FAIL, "tor.socks", "TOR_SOCKS_UNREACHABLE",
                      "Tor SOCKS proxy not reachable", "check tor service and socks5h endpoint", 0);
        } else {
            char msg[256];
            snprintf(msg, sizeof(msg), "Tor SOCKS reachable at %s", socks5);
            pf_record(&ctx, PF_ST_PASS, "tor.socks", "", msg, NULL, 0);
        }
    } else {
        pf_record(&ctx, PF_ST_SKIP, "tor.socks", "PREFLIGHT_DEPENDENCY_FAILED",
                  "skipped due to input contract failure", NULL, 0);
    }

    char escrow_health_url[1024];
    if (ctx.fail_count == 0 && pf_join_url(escrow_health_url, sizeof(escrow_health_url), base, "/health") == 0) {
        char err[512];
        char *body = NULL;
        if (pf_http_get_2xx(escrow_health_url, socks5, err, sizeof(err), &body) != 0) {
            pf_record(&ctx, PF_ST_FAIL, "escrow-http.health", "ESCROW_HEALTH_CHECK_FAILED",
                      err[0] ? err : "escrow /health over Tor failed",
                      "verify onion hidden service and nx-escrow-rs runtime", 0);
        } else {
            if (body && strstr(body, "\"ok\":true")) {
                pf_record(&ctx, PF_ST_PASS, "escrow-http.health", "", "escrow-http /health over Tor OK (\"ok\":true)", NULL, 0);
            } else {
                pf_record(&ctx, PF_ST_PASS, "escrow-http.health", "", "escrow-http /health over Tor HTTP 2xx", NULL, 0);
            }
        }
        free(body);
    } else if (ctx.fail_count == 0) {
        pf_record(&ctx, PF_ST_FAIL, "escrow-http.health", "ESCROW_HEALTH_CHECK_FAILED",
                  "failed to build escrow /health URL", NULL, 0);
    }

    if (ui_base && ui_base[0]) {
        char ui_escrow_url[1024];
        if (pf_join_url(ui_escrow_url, sizeof(ui_escrow_url), ui_base, "/escrow") != 0) {
            pf_record(&ctx, require_ui ? PF_ST_FAIL : PF_ST_WARN,
                      "nxms-serv.escrow-ui",
                      "NXMS_SERV_ESCROW_ROUTE_UNREACHABLE",
                      "failed to build UI /escrow URL",
                      "check --ui-base value",
                      0);
        } else {
            char err[512];
            if (pf_http_get_2xx(ui_escrow_url, socks5, err, sizeof(err), NULL) != 0) {
                pf_record(&ctx, require_ui ? PF_ST_FAIL : PF_ST_WARN,
                          "nxms-serv.escrow-ui",
                          "NXMS_SERV_ESCROW_ROUTE_UNREACHABLE",
                          err[0] ? err : "UI /escrow over Tor failed",
                          require_ui ? "bring nxms-serv (UI) up or drop --require-ui for backend-only recovery preflight" :
                                       "UI optional for backend recovery preflight",
                          0);
            } else {
                pf_record(&ctx, PF_ST_PASS, "nxms-serv.escrow-ui", "", "nxms-serv /escrow reachable over Tor", NULL, 0);
            }
        }
    } else {
        pf_record(&ctx, require_ui ? PF_ST_FAIL : PF_ST_WARN,
                  "nxms-serv.escrow-ui",
                  require_ui ? "NXMS_SERV_UI_UNREACHABLE" : "NXMS_SERV_UI_NOT_CONFIGURED",
                  require_ui ? "UI required but --ui-base is not set" : "UI check skipped (no --ui-base)",
                  require_ui ? "pass --ui-base http://<nxms-serv>.onion" : "use --ui-base or --require-ui when validating end-user UI path",
                  0);
    }

    {
        char host[256];
        int port = 0;
        if (pf_parse_host_port_pair(pf_getenv_nonempty("XMR_DAEMON_RPC_HOST"),
                                    pf_getenv_nonempty("XMR_DAEMON_RPC_PORT"),
                                    "127.0.0.1", 38081,
                                    host, sizeof(host), &port) != 0) {
            pf_record(&ctx, PF_ST_FAIL, "monerod.rpc", "MONEROD_RPC_BAD_CONFIG",
                      "invalid monerod host/port env values", "check XMR_DAEMON_RPC_HOST/XMR_DAEMON_RPC_PORT", 0);
        } else if (pf_tcp_reachable(host, port) != 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "monerod RPC not reachable at %s:%d", host, port);
            pf_record(&ctx, PF_ST_FAIL, "monerod.rpc", "MONEROD_RPC_UNREACHABLE", msg,
                      "start monerod-stagenet and verify RPC listener", 0);
        } else {
            char url[512];
            ff_http_resp_t r;
            memset(&r, 0, sizeof(r));
            snprintf(url, sizeof(url), "http://%s:%d/json_rpc", host, port);
            const char *body = "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_info\"}";
            if (ff_http_post_json(url, NULL, body, &r) != 0) {
                char msg[512];
                snprintf(msg, sizeof(msg), "monerod JSON-RPC probe failed: %s", ff_http_last_error());
                pf_record(&ctx, PF_ST_FAIL, "monerod.get_info", "MONEROD_RPC_UNREACHABLE", msg, NULL, 0);
            } else {
                int synced = (r.data && strstr(r.data, "\"synchronized\":true")) ? 1 : 0;
                int bootstrap_seen = (r.data && strstr(r.data, "\"bootstrap_daemon_address\"")) ? 1 : 0;
                if (strict_daemon_sync && !synced) {
                    pf_record(&ctx, PF_ST_FAIL, "monerod.sync", "MONEROD_NOT_SYNCED",
                              "monerod get_info does not report synchronized=true",
                              "wait for sync or rerun without --strict-daemon-sync", 0);
                } else if (!synced) {
                    pf_record(&ctx, PF_ST_WARN, "monerod.sync", "MONEROD_NOT_SYNCED",
                              "monerod get_info does not report synchronized=true",
                              strict_daemon_sync ? NULL : "use --strict-daemon-sync to hard-fail on this", 0);
                } else {
                    pf_record(&ctx, PF_ST_PASS, "monerod.sync", "", "monerod synchronized=true", NULL, 0);
                }
                if (bootstrap_seen && !allow_bootstrap) {
                    pf_record(&ctx, PF_ST_WARN, "monerod.bootstrap", "MONEROD_BOOTSTRAP_MODE_DETECTED",
                              "monerod response includes bootstrap daemon field", "use --allow-bootstrap if this is expected", 0);
                } else if (bootstrap_seen && allow_bootstrap) {
                    pf_record(&ctx, PF_ST_PASS, "monerod.bootstrap", "", "bootstrap mode tolerated (--allow-bootstrap)", NULL, 0);
                } else {
                    pf_record(&ctx, PF_ST_SKIP, "monerod.bootstrap", "MONEROD_BOOTSTRAP_NOT_REPORTED",
                              "bootstrap mode not reported by monerod", NULL, 1);
                }
            }
            ff_http_resp_free(&r);
        }
    }

    {
        char host[256];
        int port = 0;
        if (pf_parse_host_port_pair(pf_getenv_nonempty("XMR_WALLET_RPC_HOST"),
                                    pf_getenv_nonempty("XMR_WALLET_RPC_PORT"),
                                    "127.0.0.1", 38083,
                                    host, sizeof(host), &port) != 0) {
            pf_record(&ctx, PF_ST_FAIL, "wallet-rpc-arbiter.tcp", "WALLET_RPC_ARBITER_BAD_CONFIG",
                      "invalid arbiter wallet-rpc host/port env values", "check XMR_WALLET_RPC_HOST/XMR_WALLET_RPC_PORT", 0);
        } else if (pf_tcp_reachable(host, port) != 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "arbiter wallet-rpc not reachable at %s:%d", host, port);
            pf_record(&ctx, PF_ST_FAIL, "wallet-rpc-arbiter.tcp", "WALLET_RPC_ARBITER_UNREACHABLE", msg, NULL, 0);
        } else {
            pf_record(&ctx, PF_ST_PASS, "wallet-rpc-arbiter.tcp", "", "arbiter wallet-rpc TCP reachable", NULL, 0);
            char url[512], detail[512];
            snprintf(url, sizeof(url), "http://%s:%d/json_rpc", host, port);
            int ar = pf_http_post_json_expect_auth_challenge_or_ok(url, "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_version\"}",
                                                                   detail, sizeof(detail));
            if (ar >= 0) {
                pf_record(&ctx, PF_ST_PASS, "wallet-rpc-arbiter.auth", "", detail[0] ? detail : "wallet-rpc auth probe OK", NULL, 0);
            } else {
                pf_record(&ctx, PF_ST_FAIL, "wallet-rpc-arbiter.auth", "WALLET_RPC_ARBITER_AUTH_FAILED",
                          detail[0] ? detail : "wallet-rpc auth challenge probe failed", NULL, 0);
            }
        }
    }

    {
        char host[256];
        int port = 0;
        if (pf_parse_host_port_pair(pf_getenv_nonempty("XMR_PARTY_WALLET_RPC_HOST"),
                                    pf_getenv_nonempty("XMR_PARTY_WALLET_RPC_PORT"),
                                    "127.0.0.1", 38084,
                                    host, sizeof(host), &port) != 0) {
            pf_record(&ctx, PF_ST_FAIL, "wallet-rpc-party.tcp", "WALLET_RPC_PARTY_BAD_CONFIG",
                      "invalid party wallet-rpc host/port env values", "check XMR_PARTY_WALLET_RPC_HOST/XMR_PARTY_WALLET_RPC_PORT", 0);
        } else if (pf_tcp_reachable(host, port) != 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "party wallet-rpc not reachable at %s:%d", host, port);
            pf_record(&ctx, PF_ST_FAIL, "wallet-rpc-party.tcp", "WALLET_RPC_PARTY_UNREACHABLE", msg, NULL, 0);
        } else {
            pf_record(&ctx, PF_ST_PASS, "wallet-rpc-party.tcp", "", "party wallet-rpc TCP reachable", NULL, 0);
            char url[512], detail[512];
            snprintf(url, sizeof(url), "http://%s:%d/json_rpc", host, port);
            int pr = pf_http_post_json_expect_auth_challenge_or_ok(url, "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_version\"}",
                                                                   detail, sizeof(detail));
            if (pr >= 0) {
                pf_record(&ctx, PF_ST_PASS, "wallet-rpc-party.auth", "", detail[0] ? detail : "wallet-rpc auth probe OK", NULL, 0);
            } else {
                pf_record(&ctx, PF_ST_FAIL, "wallet-rpc-party.auth", "WALLET_RPC_PARTY_AUTH_FAILED",
                          detail[0] ? detail : "wallet-rpc auth challenge probe failed", NULL, 0);
            }
        }
    }

    {
        char host[256];
        int port = 6379;
        const char *redis_url = pf_getenv_nonempty("ESCROW_RATE_LIMIT_REDIS_URL");
        if (redis_url && pf_parse_redis_url_host_port(redis_url, host, sizeof(host), &port) == 0) {
            /* parsed from URL */
        } else {
            ff_strlcpy(host, "127.0.0.1", sizeof(host));
            port = 6379;
        }
        if (pf_tcp_reachable(host, port) != 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "redis not reachable at %s:%d", host, port);
            pf_record(&ctx, PF_ST_FAIL, "redis.tcp", "REDIS_UNREACHABLE", msg, "start redis for escrow rate-limit backend", 0);
        } else {
            char msg[256];
            snprintf(msg, sizeof(msg), "redis TCP reachable at %s:%d", host, port);
            pf_record(&ctx, PF_ST_PASS, "redis.tcp", "", msg, NULL, 0);
        }
    }

    {
        char host[256];
        int port = 4010;
        const char *mb_bind = pf_getenv_nonempty("NXMS_MAILBOX_BIND");
        if (mb_bind && pf_parse_bind_host_port(mb_bind, host, sizeof(host), &port) == 0) {
            /* parsed from env */
        } else {
            ff_strlcpy(host, "127.0.0.1", sizeof(host));
            port = 4010;
        }
        if (pf_tcp_reachable(host, port) != 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "nxms-mailbox not reachable at %s:%d", host, port);
            pf_record(&ctx, PF_ST_FAIL, "nxms-mailbox.tcp", "NXMS_MAILBOX_DOWN", msg, NULL, 0);
        } else {
            char url[512], err[512];
            snprintf(url, sizeof(url), "http://%s:%d/health", host, port);
            if (pf_http_get_2xx(url, NULL, err, sizeof(err), NULL) != 0) {
                pf_record(&ctx, PF_ST_FAIL, "nxms-mailbox.health", "NXMS_MAILBOX_DOWN",
                          err[0] ? err : "nxms-mailbox /health failed", NULL, 0);
            } else {
                pf_record(&ctx, PF_ST_PASS, "nxms-mailbox.health", "", "nxms-mailbox /health OK", NULL, 0);
            }
        }
    }

    {
        char host[256];
        int port = 28090;
        const char *signer_url = pf_getenv_nonempty("NXMS_SELLER_SIGNER_WORKER_URL");
        if (signer_url && pf_parse_http_url_host_port(signer_url, host, sizeof(host), &port) == 0) {
            /* parsed from env */
        } else {
            ff_strlcpy(host, "127.0.0.1", sizeof(host));
            port = 28090;
        }
        if (pf_tcp_reachable(host, port) != 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "nxms-signer worker API not reachable at %s:%d", host, port);
            pf_record(&ctx, PF_ST_FAIL, "nxms-signer.tcp", "NXMS_SIGNER_DOWN", msg, NULL, 0);
        } else {
            char url[512], err[512];
            snprintf(url, sizeof(url), "http://%s:%d/healthz", host, port);
            if (pf_http_get_2xx(url, NULL, err, sizeof(err), NULL) != 0) {
                pf_record(&ctx, PF_ST_FAIL, "nxms-signer.health", "NXMS_SIGNER_DOWN",
                          err[0] ? err : "nxms-signer /healthz failed", NULL, 0);
            } else {
                pf_record(&ctx, PF_ST_PASS, "nxms-signer.health", "", "nxms-signer /healthz OK", NULL, 0);
            }
        }
    }

    {
        char found_bin[4096];
        if (pf_file_exists_executable_or_path_cmd(orch_bin_resolved, found_bin, sizeof(found_bin)) != 0) {
            char msg[512];
            snprintf(msg, sizeof(msg), "orchestrator binary not found/executable: %s", orch_bin_resolved);
            pf_record(&ctx, PF_ST_FAIL, "nxms-orch.bin", "NXMS_ORCH_DOWN", msg,
                      "set NXMS_ORCH_BIN or pass --orch-bin", 0);
        } else {
            char msg[512];
            snprintf(msg, sizeof(msg), "orchestrator binary resolved: %s", found_bin);
            pf_record(&ctx, PF_ST_PASS, "nxms-orch.bin", "", msg, NULL, 0);
        }

        char db_detail[512];
        if (pf_parent_dir_writable(orch_db_resolved, db_detail, sizeof(db_detail)) != 0) {
            char msg[768];
            snprintf(msg, sizeof(msg), "orchestrator DB path unavailable: %s (%s)",
                     orch_db_resolved, db_detail[0] ? db_detail : "write check failed");
            pf_record(&ctx, PF_ST_FAIL, "nxms-orch.db", "NXMS_ORCH_DB_UNAVAILABLE", msg,
                      "set NXMS_ORCH_DB_PATH or pass --orch-db to writable path", 0);
        } else {
            char msg[768];
            snprintf(msg, sizeof(msg), "orchestrator DB path OK: %s (%s)",
                     orch_db_resolved, db_detail[0] ? db_detail : "writable");
            pf_record(&ctx, PF_ST_PASS, "nxms-orch.db", "", msg, NULL, 0);
        }
    }

    {
        const char *v1 = pf_getenv_nonempty("NXMS_ESCROW_HTTP_WORKER_ROUTE_STRICT");
        const char *v2 = pf_getenv_nonempty("NXMS_ESCROW_HTTP_ORCH_WORKER_ROUTE_LOOKUP");
        const char *v3 = pf_getenv_nonempty("NXMS_ESCROW_HTTP_ORCH_WORKER_ROUTE_REQUIRED");
        const char *v4 = pf_getenv_nonempty("NXMS_ESCROW_HTTP_ARBITER_WORKER_SUBMIT_REQUIRED");

        pf_record(&ctx, pf_is_true(v1) ? PF_ST_PASS : PF_ST_FAIL,
                  "strict.worker_route", pf_is_true(v1) ? "" : "STRICT_PROFILE_FLAG_MISSING",
                  pf_is_true(v1) ? "NXMS_ESCROW_HTTP_WORKER_ROUTE_STRICT=true" :
                                   "NXMS_ESCROW_HTTP_WORKER_ROUTE_STRICT is not true",
                  "export strict worker-route flags before operator flow", 0);

        pf_record(&ctx, pf_is_true(v2) ? PF_ST_PASS : PF_ST_FAIL,
                  "strict.orch_route_lookup", pf_is_true(v2) ? "" : "STRICT_PROFILE_FLAG_MISSING",
                  pf_is_true(v2) ? "NXMS_ESCROW_HTTP_ORCH_WORKER_ROUTE_LOOKUP=true" :
                                   "NXMS_ESCROW_HTTP_ORCH_WORKER_ROUTE_LOOKUP is not true",
                  NULL, 0);

        pf_record(&ctx, pf_is_true(v3) ? PF_ST_PASS : PF_ST_FAIL,
                  "strict.orch_route_required", pf_is_true(v3) ? "" : "STRICT_PROFILE_FLAG_MISSING",
                  pf_is_true(v3) ? "NXMS_ESCROW_HTTP_ORCH_WORKER_ROUTE_REQUIRED=true" :
                                   "NXMS_ESCROW_HTTP_ORCH_WORKER_ROUTE_REQUIRED is not true",
                  NULL, 0);

        pf_record(&ctx, pf_is_true(v4) ? PF_ST_PASS : PF_ST_FAIL,
                  "strict.arbiter_submit_required", pf_is_true(v4) ? "" : "STRICT_PROFILE_FLAG_MISSING",
                  pf_is_true(v4) ? "NXMS_ESCROW_HTTP_ARBITER_WORKER_SUBMIT_REQUIRED=true" :
                                   "NXMS_ESCROW_HTTP_ARBITER_WORKER_SUBMIT_REQUIRED is not true",
                  NULL, 0);
    }

    {
        const char *legacy_direct = pf_getenv_nonempty("NXMS_ESCROW_HTTP_LEGACY_DIRECT_SIGN_SUBMIT");
        const char *wallet_fallback = pf_getenv_nonempty("NXMS_HTTP_FLOW_ALLOW_WALLET_RPC_FALLBACK");
        pf_record(&ctx, pf_is_true(legacy_direct) ? PF_ST_FAIL : PF_ST_PASS,
                  "boundary.legacy_direct_submit",
                  pf_is_true(legacy_direct) ? "LEGACY_DIRECT_SUBMIT_PATH_ENABLED" : "",
                  pf_is_true(legacy_direct) ? "legacy direct sign/submit path is enabled" :
                                             "legacy direct sign/submit path not enabled",
                  "keep legacy direct submit disabled in strict path", 0);
        pf_record(&ctx, pf_is_true(wallet_fallback) ? PF_ST_FAIL : PF_ST_PASS,
                  "boundary.wallet_fallback",
                  pf_is_true(wallet_fallback) ? "LEGACY_DIRECT_SUBMIT_PATH_ENABLED" : "",
                  pf_is_true(wallet_fallback) ? "wallet-rpc fallback is enabled" :
                                               "wallet-rpc fallback not enabled",
                  "keep wallet-rpc fallback disabled outside break-glass", 0);
    }

    {
        const char *shadow = pf_getenv_nonempty("NXMS_SIGNER_ALLOW_SHADOW_MODE");
        pf_record(&ctx, pf_is_true(shadow) ? PF_ST_WARN : PF_ST_PASS,
                  "nxms-signer.shadow_mode",
                  pf_is_true(shadow) ? "SIGNER_SHADOW_MODE_ACTIVE" : "",
                  pf_is_true(shadow) ? "NXMS_SIGNER_ALLOW_SHADOW_MODE=true (P0/runtime-check mode)" :
                                       "signer shadow-mode not enabled",
                  pf_is_true(shadow) ? "acceptable for P0 checks; not for production strict readiness" : NULL,
                  0);
    }

    if (strict_wallet_multisig) {
        char host[256];
        int port = 0;
        if (pf_parse_host_port_pair(pf_getenv_nonempty("XMR_WALLET_RPC_HOST"),
                                    pf_getenv_nonempty("XMR_WALLET_RPC_PORT"),
                                    "127.0.0.1", 38083,
                                    host, sizeof(host), &port) != 0) {
            pf_record(&ctx, PF_ST_FAIL, "wallet-rpc-arbiter.multisig_probe", "WALLET_RPC_ARBITER_BAD_CONFIG",
                      "cannot run strict multisig probe (invalid arbiter wallet-rpc host/port)", NULL, 0);
        } else {
            char url[512];
            snprintf(url, sizeof(url), "http://%s:%d/json_rpc", host, port);
            pf_probe_arbiter_wallet_multisig(&ctx, url, timeout_ms);
        }
    }
    if (check_transfer_dry_run) {
        char host[256];
        int port = 0;
        if (pf_parse_host_port_pair(pf_getenv_nonempty("XMR_PARTY_WALLET_RPC_HOST"),
                                    pf_getenv_nonempty("XMR_PARTY_WALLET_RPC_PORT"),
                                    "127.0.0.1", 38084,
                                    host, sizeof(host), &port) != 0) {
            pf_record(&ctx, PF_ST_FAIL, "wallet-rpc-party.transfer_dry_run", "WALLET_RPC_PARTY_BAD_CONFIG",
                      "cannot run transfer dry-run probe (invalid party wallet-rpc host/port)", NULL, 0);
        } else {
            char url[512];
            snprintf(url, sizeof(url), "http://%s:%d/json_rpc", host, port);
            pf_probe_party_wallet_transfer_dry_run(&ctx, url, timeout_ms);
        }
    }
    if (escrow_id_hex && escrow_id_hex[0]) {
        pf_probe_worker_routes_for_escrow(&ctx, orch_bin_resolved, orch_db_resolved, escrow_id_hex);
    }

    const char *verdict = (ctx.fail_count > 0) ? "NOT_READY" :
                          (ctx.warn_count > 0 ? "READY_WITH_WARNINGS" : "READY");

    char footer[1024];
    snprintf(footer, sizeof(footer),
             "\nSummary: PASS=%d WARN=%d FAIL=%d SKIP=%d\nVerdict: %s\n",
             ctx.pass_count, ctx.warn_count, ctx.fail_count, ctx.skip_count, verdict);
    pf_append_line(&ctx, footer);

    if (run_dir && run_dir[0]) {
        if (pf_write_artifacts(run_dir, &ctx, base, ui_base, socks5, verdict) == 0) {
            char msg[512];
            snprintf(msg, sizeof(msg), "preflight artifacts written to %s/preflight/", run_dir);
            pf_append_line(&ctx, msg);
            pf_append_line(&ctx, "\n");
        } else {
            pf_append_line(&ctx, "WARN: failed to write some preflight artifacts\n");
        }
    }

    if (ctx.json_mode) {
        pf_emit_json(&ctx, base, ui_base, socks5, verdict);
    }

    free(ctx.summary_buf);
    free(ctx.checks_tsv);
    free(ctx.checks_json);

    return (ctx.fail_count > 0) ? 3 : 0;
}
