#include "util.h"
#include "vault.h"
#include "pqc_falcon.h"
#include "pqc_kem.h"
#include "http.h"
#include "auth.h"
#include "pow.h"
#include "cli_common.h"
#include "cli_auth_core_cmds.h"

#include <sodium.h>
#include <oqs/oqs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef __linux__
#include <unistd.h> /* getpass */
#endif

/* Kluczowa poprawka: getpass() zwraca statyczny bufor, drugi getpass nadpisuje pierwszy.
   Dlatego pierwsze hasło kopiujemy NATYCHMIAST do out, a potem porównujemy z drugim. */
static int read_new_passphrase(char *out, size_t out_cap) {
#ifdef __linux__
    char *p1 = getpass("New vault passphrase: ");
    if (!p1) return -1;

    size_t n1 = strlen(p1);
    if (n1 < 12) {
        fprintf(stderr, "Passphrase too short (min 12 chars)\n");
        return -1;
    }
    if (n1 + 1 > out_cap) return -1;

    memcpy(out, p1, n1 + 1);

    char *p2 = getpass("Repeat passphrase: ");
    if (!p2) {
        sodium_memzero(out, out_cap);
        return -1;
    }
    if (strcmp(out, p2) != 0) {
        sodium_memzero(out, out_cap);
        fprintf(stderr, "Passphrases do not match\n");
        return -1;
    }
    return 0;
#else
    char a[256];
    char b[256];

    fprintf(stderr, "New vault passphrase: ");
    if (!fgets(a, sizeof(a), stdin)) return -1;
    a[strcspn(a, "\r\n")] = 0;

    fprintf(stderr, "Repeat passphrase: ");
    if (!fgets(b, sizeof(b), stdin)) { sodium_memzero(a, sizeof(a)); return -1; }
    b[strcspn(b, "\r\n")] = 0;

    if (strlen(a) < 12) { sodium_memzero(a, sizeof(a)); sodium_memzero(b, sizeof(b)); return -1; }
    if (strcmp(a, b) != 0) { sodium_memzero(a, sizeof(a)); sodium_memzero(b, sizeof(b)); return -1; }
    if (strlen(a) + 1 > out_cap) { sodium_memzero(a, sizeof(a)); sodium_memzero(b, sizeof(b)); return -1; }

    memcpy(out, a, strlen(a) + 1);
    sodium_memzero(a, sizeof(a));
    sodium_memzero(b, sizeof(b));
    return 0;
#endif
}
int cmd_init(const char *dir) {
    char pass[256];
    if (read_new_passphrase(pass, sizeof(pass)) != 0) ff_die("passphrase input failed");
    if (ff_vault_init(dir, pass) != 0) {
        sodium_memzero(pass, sizeof(pass));
        ff_die("vault init failed");
    }
    sodium_memzero(pass, sizeof(pass));
    printf("OK: vault created at %s/vault.bin\n", dir);
    return 0;
}

int cmd_keygen(const char *dir, const char *kem_alg) {
    char *pass = prompt_pass("Vault passphrase: ");
    if (!pass) ff_die("no passphrase");

    ff_vault_t v;
    if (ff_vault_load(dir, pass, &v) != 0) {
        secure_free_str(&pass);
        ff_die("vault load failed");
    }

    size_t sk_len = 0, pk_len = 0;
    if (ff_falcon_keygen(v.falcon_sk, &sk_len, v.falcon_pk, &pk_len) != 0) {
        ff_vault_free(&v);
        secure_free_str(&pass);
        ff_die("falcon keygen failed");
    }
    v.falcon_sk_len = sk_len;
    v.falcon_pk_len = pk_len;

    ff_kem_keys_t k;
    if (ff_kem_keygen(kem_alg, &k) != 0) {
        ff_vault_free(&v);
        secure_free_str(&pass);
        ff_die("kem keygen failed (is liboqs installed? is kem enabled?)");
    }

    ff_strlcpy(v.kem_alg, kem_alg, sizeof(v.kem_alg));
    v.kem_pk = k.pk; v.kem_pk_len = k.pk_len;
    v.kem_sk = k.sk; v.kem_sk_len = k.sk_len;
    k.pk = NULL; k.sk = NULL;

    /* Wypisz publiczne klucze PRZED zapisem do vault (ułatwia debug/flow) */
    char *b64pk_sig = NULL;
    char *b64pk_kem = NULL;
    if (v.falcon_pk_len && ff_b64enc(v.falcon_pk, v.falcon_pk_len, &b64pk_sig) != 0) {
        ff_vault_free(&v);
        secure_free_str(&pass);
        ff_die("b64 encode failed");
    }
    if (v.kem_pk && v.kem_pk_len && ff_b64enc(v.kem_pk, v.kem_pk_len, &b64pk_kem) != 0) {
        free(b64pk_sig);
        ff_vault_free(&v);
        secure_free_str(&pass);
        ff_die("b64 encode failed");
    }

    printf("kem: %s\n", v.kem_alg);
    printf("pk_sig_b64: %s\n", b64pk_sig ? b64pk_sig : "");
    printf("pk_kem_b64: %s\n", b64pk_kem ? b64pk_kem : "");

    free(b64pk_sig);
    free(b64pk_kem);

    if (ff_vault_save(dir, pass, &v) != 0) {
        ff_vault_free(&v);
        secure_free_str(&pass);
        ff_die("vault save failed");
    }

    printf("OK: generated Falcon-1024(CT) + KEM(%s)\n", v.kem_alg);

    ff_vault_free(&v);
    secure_free_str(&pass);
    return 0;
}

int cmd_show_keys(const char *dir) {
    char *pass = prompt_pass("Vault passphrase: ");
    if (!pass) ff_die("no passphrase");

    ff_vault_t v;
    if (ff_vault_load(dir, pass, &v) != 0) {
        secure_free_str(&pass);
        ff_die("vault load failed");
    }

    char *b64pk_sig = NULL;
    char *b64pk_kem = NULL;
    if (v.falcon_pk_len && ff_b64enc(v.falcon_pk, v.falcon_pk_len, &b64pk_sig) != 0) {
        ff_vault_free(&v);
        secure_free_str(&pass);
        ff_die("b64 encode failed");
    }
    if (v.kem_pk && v.kem_pk_len && ff_b64enc(v.kem_pk, v.kem_pk_len, &b64pk_kem) != 0) {
        free(b64pk_sig);
        ff_vault_free(&v);
        secure_free_str(&pass);
        ff_die("b64 encode failed");
    }

    printf("nick: %s\n", v.nick);
    printf("kem: %s\n", v.kem_alg);
    printf("pk_sig_b64: %s\n", b64pk_sig ? b64pk_sig : "");
    printf("pk_kem_b64: %s\n", b64pk_kem ? b64pk_kem : "");

    free(b64pk_sig);
    free(b64pk_kem);
    ff_vault_free(&v);
    secure_free_str(&pass);
    return 0;
}

int cmd_register(const char *dir, const char *base, const char *nick, const char *socks5) {
    require_tor(base, socks5);
    char *pass = prompt_pass("Vault passphrase: ");
    if (!pass) ff_die("no passphrase");

    ff_vault_t v;
    if (ff_vault_load(dir, pass, &v) != 0) {
        secure_free_str(&pass);
        ff_die("vault load failed");
    }

    if (!v.falcon_pk_len || !v.kem_pk || !v.kem_pk_len) {
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("missing keys in vault (run keygen first)");
    }

    char url_start[512];
    snprintf(url_start, sizeof(url_start), "%s/api/register/start", base);
    ff_http_resp_t rstart;
    if (ff_http_post_json(url_start, socks5, "{}", &rstart) != 0) {
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("register/start failed: %s", ff_http_last_error());
    }

    char *pow_token = ff_json_get_str(rstart.data, "pow_token");
    long long pow_diff = 0;
    if (ff_json_get_i64(rstart.data, "pow_difficulty", &pow_diff) != 0) pow_diff = 0;
    ff_http_resp_free(&rstart);
    if (!pow_token || pow_diff <= 0) {
        secure_free_str(&pow_token);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("register/start bad response");
    }

    uint64_t nonce = 0;
    if (ff_pow_solve(pow_token, "register", nick, (int)pow_diff, 0, &nonce) != 0) {
        secure_free_str(&pow_token);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("pow solve failed");
    }

    char *b64pk_sig = NULL;
    char *b64pk_kem = NULL;
    if (v.falcon_pk_len && ff_b64enc(v.falcon_pk, v.falcon_pk_len, &b64pk_sig) != 0) {
        secure_free_str(&pow_token);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("b64 encode failed");
    }
    if (v.kem_pk && v.kem_pk_len && ff_b64enc(v.kem_pk, v.kem_pk_len, &b64pk_kem) != 0) {
        secure_free_str(&pow_token);
        free(b64pk_sig);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("b64 encode failed");
    }

    const char *kem_alg = v.kem_alg[0] ? v.kem_alg : "ntru-hrss701";

    char url_finish[512];
    snprintf(url_finish, sizeof(url_finish), "%s/api/register/finish", base);

    char *pow_token_e = json_escape_or_die(pow_token);
    char *nick_e = json_escape_or_die(nick);
    char *kem_e = json_escape_or_die(kem_alg);
    char *pk_kem_e = json_escape_or_die(b64pk_kem ? b64pk_kem : "");
    char *pk_sig_e = json_escape_or_die(b64pk_sig ? b64pk_sig : "");

    char body[8192];
    int bw = snprintf(body, sizeof(body),
                      "{\"pow_token\":\"%s\",\"pow_difficulty\":%lld,\"pow_nonce\":%llu,"
                      "\"nick\":\"%s\",\"kem_id\":\"%s\",\"pk_kem_b64\":\"%s\",\"pk_sig_b64\":\"%s\"}",
                      pow_token_e, pow_diff, (unsigned long long)nonce,
                      nick_e, kem_e, pk_kem_e, pk_sig_e);
    free(pow_token_e); free(nick_e); free(kem_e); free(pk_kem_e); free(pk_sig_e);
    if (bw < 0 || bw >= (int)sizeof(body)) {
        secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("register/finish body too large");
    }

    ff_http_resp_t rfinish;
    if (ff_http_post_json(url_finish, socks5, body, &rfinish) != 0) {
        secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("register/finish failed: %s", ff_http_last_error());
    }

    ff_challenge_pkt pkt;
    if (ff_pkt_load_json_buf(rfinish.data, rfinish.len, &pkt) != 0) {
        ff_http_resp_free(&rfinish);
        secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("register/finish bad response");
    }
    ff_http_resp_free(&rfinish);

    if (!pkt.nick || pkt.nick[0] == 0) {
        if (pkt.nick) { free(pkt.nick); pkt.nick = NULL; }
        pkt.nick = strdup(nick);
        if (!pkt.nick) {
            ff_pkt_free(&pkt);
            secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
            ff_vault_free(&v); secure_free_str(&pass);
            ff_die("oom");
        }
    }

    if (pkt.kem_id && v.kem_alg[0]) {
        if (strcmp(pkt.kem_id, v.kem_alg) != 0) {
            ff_pkt_free(&pkt);
            secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
            ff_vault_free(&v); secure_free_str(&pass);
            ff_die("kem_id mismatch between challenge and vault");
        }
    }

    uint8_t challenge[FF_CHALLENGE_LEN];
    if (ff_recover_challenge(&pkt, v.kem_sk, v.kem_sk_len, challenge) != 0) {
        ff_pkt_free(&pkt);
        secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("challenge recover failed");
    }

    uint8_t *tr = NULL;
    size_t tr_len = 0;
    if (ff_build_transcript(&pkt, challenge, sizeof(challenge), &tr, &tr_len) != 0) {
        sodium_memzero(challenge, sizeof(challenge));
        ff_pkt_free(&pkt);
        secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("transcript build failed");
    }

    uint8_t sig[FF_FALCON_SIG_MAX];
    size_t sig_len = sizeof(sig);
    if (ff_falcon_sign_ct(v.falcon_sk, v.falcon_sk_len, tr, tr_len, sig, &sig_len) != 0) {
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("falcon sign failed");
    }

    char *sig_b64 = NULL;
    if (ff_b64enc(sig, sig_len, &sig_b64) != 0) {
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("b64 encode failed");
    }

    char *sid_b64u = NULL;
    if (ff_b64u_enc(pkt.sid_raw, pkt.sid_len, &sid_b64u) != 0) {
        free(sig_b64);
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("sid b64u encode failed");
    }

    char url_verify[512];
    snprintf(url_verify, sizeof(url_verify), "%s/api/register/verify", base);

    char *sid_e = json_escape_or_die(sid_b64u);
    char *sig_e = json_escape_or_die(sig_b64 ? sig_b64 : "");

    char body2[4096];
    int bw2 = snprintf(body2, sizeof(body2), "{\"sid\":\"%s\",\"sig_b64\":\"%s\"}", sid_e, sig_e);
    free(sid_e); free(sig_e);
    if (bw2 < 0 || bw2 >= (int)sizeof(body2)) {
        free(sid_b64u); free(sig_b64);
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("register/verify body too large");
    }
    ff_http_resp_t rverify;
    if (ff_http_post_json(url_verify, socks5, body2, &rverify) != 0) {
        free(sid_b64u); free(sig_b64);
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("register/verify failed: %s", ff_http_last_error());
    }
    ff_http_resp_free(&rverify);

    ff_strlcpy(v.nick, nick, sizeof(v.nick));
    if (ff_vault_save(dir, pass, &v) != 0) {
        free(sid_b64u); free(sig_b64);
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("vault save failed");
    }

    printf("OK: registered nick=%s\n", nick);

    free(sid_b64u); free(sig_b64);
    sodium_memzero(challenge, sizeof(challenge));
    sodium_memzero(tr, tr_len); free(tr);
    ff_pkt_free(&pkt);
    secure_free_str(&pow_token); free(b64pk_sig); free(b64pk_kem);
    ff_vault_free(&v);
    secure_free_str(&pass);
    return 0;
}

int cmd_login(const char *dir, const char *base, const char *nick, const char *socks5) {
    require_tor(base, socks5);
    char *pass = prompt_pass("Vault passphrase: ");
    if (!pass) ff_die("no passphrase");

    ff_vault_t v;
    if (ff_vault_load(dir, pass, &v) != 0) {
        secure_free_str(&pass);
        ff_die("vault load failed");
    }

    char url1[512];
    snprintf(url1, sizeof(url1), "%s/api/login/start", base);

    char *nick_e = json_escape_or_die(nick);
    char body1[512];
    int bw1 = snprintf(body1, sizeof(body1), "{\"nick\":\"%s\"}", nick_e);
    free(nick_e);
    if (bw1 < 0 || bw1 >= (int)sizeof(body1)) {
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("login/start body too large");
    }

    ff_http_resp_t r1;
    if (ff_http_post_json(url1, socks5, body1, &r1) != 0) {
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("login/start failed: %s", ff_http_last_error());
    }

    ff_challenge_pkt pkt;
    if (ff_pkt_load_json_buf(r1.data, r1.len, &pkt) != 0) {
        ff_http_resp_free(&r1);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("login/start bad response");
    }

    if (!pkt.nick || pkt.nick[0] == 0) {
        if (pkt.nick) { free(pkt.nick); pkt.nick = NULL; }
        pkt.nick = strdup(nick);
        if (!pkt.nick) {
            ff_pkt_free(&pkt);
            ff_http_resp_free(&r1);
            ff_vault_free(&v); secure_free_str(&pass);
            ff_die("oom");
        }
    }

    if (pkt.kem_id && v.kem_alg[0]) {
        if (strcmp(pkt.kem_id, v.kem_alg) != 0) {
            ff_pkt_free(&pkt);
            ff_http_resp_free(&r1);
            ff_vault_free(&v); secure_free_str(&pass);
            ff_die("kem_id mismatch between challenge and vault");
        }
    }

    uint8_t challenge[FF_CHALLENGE_LEN];
    if (ff_recover_challenge(&pkt, v.kem_sk, v.kem_sk_len, challenge) != 0) {
        ff_pkt_free(&pkt);
        ff_http_resp_free(&r1);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("challenge recover failed");
    }

    uint8_t *tr = NULL;
    size_t tr_len = 0;
    if (ff_build_transcript(&pkt, challenge, sizeof(challenge), &tr, &tr_len) != 0) {
        sodium_memzero(challenge, sizeof(challenge));
        ff_pkt_free(&pkt);
        ff_http_resp_free(&r1);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("transcript build failed");
    }

    uint8_t sig[FF_FALCON_SIG_MAX];
    size_t sig_len = sizeof(sig);
    if (ff_falcon_sign_ct(v.falcon_sk, v.falcon_sk_len, tr, tr_len, sig, &sig_len) != 0) {
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        ff_http_resp_free(&r1);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("falcon sign failed");
    }

    char *sig_b64 = NULL;
    if (ff_b64enc(sig, sig_len, &sig_b64) != 0) {
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        ff_http_resp_free(&r1);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("b64 encode failed");
    }

    char *sid_b64u = NULL;
    if (ff_b64u_enc(pkt.sid_raw, pkt.sid_len, &sid_b64u) != 0) {
        free(sig_b64);
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        ff_http_resp_free(&r1);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("sid b64u encode failed");
    }

    char url2[512];
    snprintf(url2, sizeof(url2), "%s/api/login/finish", base);

    char *sid_e = json_escape_or_die(sid_b64u);
    char *sig_e = json_escape_or_die(sig_b64 ? sig_b64 : "");
    char body2[8192];
    int bw2 = snprintf(body2, sizeof(body2),
                       "{\"sid\":\"%s\",\"sig_b64\":\"%s\"}",
                       sid_e, sig_e);
    free(sid_e); free(sig_e);
    if (bw2 < 0 || bw2 >= (int)sizeof(body2)) {
        free(sid_b64u); free(sig_b64);
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        ff_http_resp_free(&r1);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("login/finish body too large");
    }

    ff_http_resp_t r2;
    if (ff_http_post_json(url2, socks5, body2, &r2) != 0) {
        free(sid_b64u); free(sig_b64);
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        ff_http_resp_free(&r1);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("login/finish failed: %s", ff_http_last_error());
    }

    char *session_id = ff_json_get_str(r2.data, "session_id");
    char *csrf = ff_json_get_str(r2.data, "csrf");
    if (!session_id || !csrf) {
        free(sid_b64u); free(sig_b64);
        if (session_id) free(session_id);
        if (csrf) free(csrf);
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        ff_http_resp_free(&r1); ff_http_resp_free(&r2);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("no session_id/csrf in response");
    }

    if (v.session_id) { sodium_memzero(v.session_id, strlen(v.session_id)); free(v.session_id); v.session_id = NULL; }
    if (v.csrf) { sodium_memzero(v.csrf, strlen(v.csrf)); free(v.csrf); v.csrf = NULL; }
    v.session_id = strdup(session_id);
    v.csrf = strdup(csrf);
    ff_strlcpy(v.nick, nick, sizeof(v.nick));

    if (ff_vault_save(dir, pass, &v) != 0) {
        free(sid_b64u); free(sig_b64);
        free(session_id); free(csrf);
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        ff_http_resp_free(&r1); ff_http_resp_free(&r2);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("vault save failed");
    }

    printf("OK: logged in. session stored in vault.\n");

    free(sid_b64u); free(sig_b64);
    free(session_id); free(csrf);
    sodium_memzero(challenge, sizeof(challenge));
    sodium_memzero(tr, tr_len); free(tr);
    ff_pkt_free(&pkt);
    ff_http_resp_free(&r1); ff_http_resp_free(&r2);
    ff_vault_free(&v);
    secure_free_str(&pass);
    return 0;
}

int cmd_list_kem(const char *filter) {
    size_t kem_count = (size_t)OQS_KEM_alg_count();
    for (size_t i = 0; i < kem_count; i++) {
        const char *id = OQS_KEM_alg_identifier(i);
        if (!id) continue;
        if (filter && *filter) {
            if (strstr(id, filter) == NULL) continue;
        }
        if (!OQS_KEM_alg_is_enabled(id)) continue;
        printf("%s\n", id);
    }
    return 0;
}

int cmd_pow_solve_cli(const char *token, const char *purpose, const char *nick, int difficulty, uint64_t start) {
    uint64_t nonce = 0;
    if (ff_pow_solve(token, purpose, nick, difficulty, start, &nonce) != 0) ff_die("pow-solve failed");
    printf("%llu\n", (unsigned long long)nonce);
    return 0;
}

int cmd_respond(const char *dir, const char *challenge_path) {
    char *pass = prompt_pass("Vault passphrase: ");
    if (!pass) ff_die("no passphrase");

    ff_vault_t v;
    if (ff_vault_load(dir, pass, &v) != 0) {
        secure_free_str(&pass);
        ff_die("vault load failed");
    }

    ff_challenge_pkt pkt;
    if (ff_pkt_load_json(challenge_path, &pkt) != 0) {
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("bad challenge json");
    }

    /* nick jest częścią AAD i transcriptu — jeśli brak w JSON, weź z vaultu */
    if (!pkt.nick || pkt.nick[0] == 0) {
        if (pkt.nick) { free(pkt.nick); pkt.nick = NULL; }
        if (v.nick[0] == 0) {
            ff_pkt_free(&pkt);
            ff_vault_free(&v); secure_free_str(&pass);
            ff_die("challenge json missing nick and vault nick is empty");
        }
        pkt.nick = strdup(v.nick);
        if (!pkt.nick) {
            ff_pkt_free(&pkt);
            ff_vault_free(&v); secure_free_str(&pass);
            ff_die("oom");
        }
    }

    if (pkt.kem_id && v.kem_alg[0]) {
        if (strcmp(pkt.kem_id, v.kem_alg) != 0) {
            ff_pkt_free(&pkt);
            ff_vault_free(&v); secure_free_str(&pass);
            ff_die("kem_id mismatch between challenge and vault");
        }
    }

    uint8_t challenge[FF_CHALLENGE_LEN];
    if (ff_recover_challenge(&pkt, v.kem_sk, v.kem_sk_len, challenge) != 0) {
        ff_pkt_free(&pkt);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("challenge recover failed (tag mismatch or wrong key)");
    }

    uint8_t *tr = NULL;
    size_t tr_len = 0;
    if (ff_build_transcript(&pkt, challenge, sizeof(challenge), &tr, &tr_len) != 0) {
        sodium_memzero(challenge, sizeof(challenge));
        ff_pkt_free(&pkt);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("transcript build failed");
    }

    uint8_t sig[FF_FALCON_SIG_MAX];
    size_t sig_len = sizeof(sig);
    if (ff_falcon_sign_ct(v.falcon_sk, v.falcon_sk_len, tr, tr_len, sig, &sig_len) != 0) {
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("falcon sign failed");
    }

    char *sig_b64 = NULL;
    if (ff_b64enc(sig, sig_len, &sig_b64) != 0) {
        sodium_memzero(challenge, sizeof(challenge));
        sodium_memzero(sig, sizeof(sig));
        sodium_memzero(tr, tr_len); free(tr);
        ff_pkt_free(&pkt);
        ff_vault_free(&v); secure_free_str(&pass);
        ff_die("b64 encode failed");
    }

    printf("%s\n", sig_b64);

    free(sig_b64);
    sodium_memzero(sig, sizeof(sig));
    sodium_memzero(challenge, sizeof(challenge));
    sodium_memzero(tr, tr_len);
    free(tr);
    ff_pkt_free(&pkt);
    ff_vault_free(&v);
    secure_free_str(&pass);
    return 0;
}

