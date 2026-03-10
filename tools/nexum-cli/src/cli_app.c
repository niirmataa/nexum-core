#include "util.h"
#include "cli_config.h"
#include "cli_app.h"
#include "cli_auth_core_cmds.h"
#include "cli_ext_cmds.h"
#include "cli_common.h"

#include <sodium.h>
#include <curl/curl.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void usage(void) {
    printf("nexum (C)\n\n");
    printf("Global options:\n");
    printf("  --config <path>   path to config JSON (default: ~/.nexum/config.json)\n\n");
    printf("Usage:\n");
    printf("  nexum init [--dir <path>]\n");
    printf("  nexum keygen --kem <kem_id> [--dir <path>]\n");
    printf("  nexum show-keys [--dir <path>]\n");
    printf("  nexum list-kem [filter]\n");
    printf("  nexum pow-solve --purpose <p> --token <t> --nick <n> --difficulty <d> [--start <nonce>]\n");
    printf("  nexum respond --challenge <ch.json> [--dir <path>]\n");
    printf("\nNetwork (Tor-only):\n");
    printf("  nexum register --base http://xxxx.onion --nick <nick> --socks5 socks5h://127.0.0.1:9050 [--dir <path>]\n");
    printf("  nexum login    --base http://xxxx.onion --nick <nick> --socks5 socks5h://127.0.0.1:9050 [--dir <path>]\n");
    printf("  nexum tor-check [--socks5 socks5h://127.0.0.1:9050] [--base http://xxxx.onion]\n");
    printf("\nPrekeys (E2E DM):\n");
    printf("  nexum prekeys-gen    --count 20 --ttl-days 14 [--kem <kem_id>] [--dir <path>]\n");
    printf("  nexum prekeys-upload --base http://xxxx.onion --count 20 --socks5 socks5h://127.0.0.1:9050 [--dir <path>]\n");
    printf("  nexum prekeys-rotate --base http://xxxx.onion --count 20 --min 5 --ttl-days 14 [--kem <kem_id>] --socks5 socks5h://127.0.0.1:9050 [--dir <path>]\n");
    printf("  nexum prekeys-list   [--verbose] [--dir <path>]\n");
    printf("  nexum prekeys-prune  [--used] [--expired] [--dir <path>]\n");
    printf("\nDM:\n");
    printf("  nexum dm-send  --base http://xxxx.onion --to <nick> (--msg <text> | --file <path>) --socks5 socks5h://127.0.0.1:9050 [--dir <path>]\n");
    printf("  nexum dm-inbox --base http://xxxx.onion --limit 50 [--keep] --socks5 socks5h://127.0.0.1:9050 [--dir <path>]\n");
    printf("\nEscrow (Tor-only):\n");
    printf("  nexum escrow-create  --base http://xxxx.onion --buyer-nick <nick> --seller-nick <nick> --amount-atomic <u64> [--memo <text>] [--buyer-refund-address <addr>] [--idempotency-key <key>] [--run-dir <path>] --socks5 socks5h://127.0.0.1:9050\n");
    printf("  nexum escrow-status  --base http://xxxx.onion --id <escrow_id> --nick <nick> --token <token> [--run-dir <path>] --socks5 socks5h://127.0.0.1:9050\n");
    printf("  nexum escrow-r1 --base <url> --id <escrow_id> --nick <nick> --token <tok> --wallet-rpc-url <url> --wallet-rpc-user/... --wallet-rpc-pass/... --wallet-name <wallet> --wallet-password-env <ENV> [--refund-address <addr>]\n");
    printf("  nexum escrow-r2 --base <url> --id <escrow_id> --nick <nick> --token <tok> --wallet-rpc-url <url> --wallet-rpc-user/... --wallet-rpc-pass/... --wallet-name <wallet> --wallet-password-env <ENV> [--threshold 2]\n");
    printf("  nexum escrow-r3 --base <url> --id <escrow_id> --nick <nick> --token <tok> --wallet-rpc-url <url> --wallet-rpc-user/... --wallet-rpc-pass/... --wallet-name <wallet> --wallet-password-env <ENV>\n");
    printf("  nexum escrow-r4 --base <url> --id <escrow_id> --nick <nick> --token <tok> --wallet-rpc-url <url> --wallet-rpc-user/... --wallet-rpc-pass/... --wallet-name <wallet> --wallet-password-env <ENV>\n");
    printf("  nexum escrow-wait-state --base <url> --id <escrow_id> --nick <nick> --token <tok> --state <STATE> [--run-dir <path>]\n");
    printf("  nexum escrow-gate3-ready --base <url> --id <escrow_id> --buyer-nick <nick> --buyer-token <tok> --seller-nick <nick> [--seller-token <tok>|--seller-token-db-path <sqlite>] --buyer-wallet-rpc-url <url> --buyer-wallet-rpc-user <user>|--buyer-wallet-rpc-user-file <path>|--buyer-wallet-rpc-user-env <ENV> --buyer-wallet-rpc-pass <pass>|--buyer-wallet-rpc-pass-file <path>|--buyer-wallet-rpc-pass-env <ENV> --buyer-wallet-name <wallet> --buyer-wallet-password-env <ENV> --seller-wallet-rpc-url <url> --seller-wallet-rpc-user <user>|--seller-wallet-rpc-user-file <path>|--seller-wallet-rpc-user-env <ENV> --seller-wallet-rpc-pass <pass>|--seller-wallet-rpc-pass-file <path>|--seller-wallet-rpc-pass-env <ENV> --seller-wallet-name <wallet> --seller-wallet-password-env <ENV> [--run-dir <path>]\n");
    printf("  nexum escrow-fund --base <url> --id <escrow_id> --buyer-nick <nick> --buyer-token <tok> --wallet-rpc-url <url> --wallet-rpc-user <user>|--wallet-rpc-user-file <path>|--wallet-rpc-user-env <ENV> --wallet-rpc-pass <pass>|--wallet-rpc-pass-file <path>|--wallet-rpc-pass-env <ENV> --wallet-name <wallet> --wallet-password-env <ENV> [--fund-buffer-atomic <u64>] [--run-dir <path>]\n");
    printf("  nexum escrow-wait-funded --base <url> --id <escrow_id> --nick <nick> --token <tok> [--run-dir <path>] [--wait-timeout <sec>] [--poll-interval <sec>]\n");
    printf("  nexum escrow-funded-sync --base <url> --id <escrow_id> --buyer-nick <nick> --buyer-token <tok> --arbiter-nick <nick> --arbiter-token <tok> --buyer-rpc-endpoint <url> --buyer-rpc-user/... --buyer-wallet-name <wallet> --buyer-wallet-pass/... --seller-rpc-endpoint <url> --seller-rpc-user/... --seller-wallet-name <wallet> --seller-wallet-pass/... [--run-dir <path>] [--orch-bin <path>]\n");
    printf("  nexum escrow-proposal --base http://xxxx.onion --id <escrow_id> --nick <nick> --token <token> --socks5 socks5h://127.0.0.1:9050\n");
    printf("  nexum escrow-confirm-release --base http://xxxx.onion --id <escrow_id> --nick <nick> --token <tok> --txid <64hex> [--idempotency-prefix <p>] [--retry-max <n>] [--retry-backoff-ms <ms>] --socks5 socks5h://127.0.0.1:9050\n");
    printf("  nexum escrow-confirm-refund  --base http://xxxx.onion --id <escrow_id> --nick <nick> --token <tok> --txid <64hex> [--idempotency-prefix <p>] [--retry-max <n>] [--retry-backoff-ms <ms>] --socks5 socks5h://127.0.0.1:9050\n");
    printf("  nexum escrow-release  --base http://xxxx.onion --id <escrow_id> --nick <nick> --token <token> [--tx-data-hex <hex>] [--txid <txid>] [--signer-wallet-password <pw>|--signer-wallet-password-file <path>|--signer-wallet-password-env <VAR>] [--signer-action-token <tok>|--signer-action-token-file <path>|--signer-action-token-env <VAR>] [--signer-sign-action-token <tok>|--signer-sign-action-token-file <path>|--signer-sign-action-token-env <VAR>] [--signer-submit-action-token <tok>|--signer-submit-action-token-file <path>|--signer-submit-action-token-env <VAR>] [--idempotency-key <key>] [--retry-max <n>] [--retry-backoff-ms <ms>] --socks5 socks5h://127.0.0.1:9050\n");
    printf("  nexum escrow-refund   --base http://xxxx.onion --id <escrow_id> --nick <nick> --token <token> [--tx-data-hex <hex>] [--txid <txid>] [--signer-action-token <tok>|--signer-action-token-file <path>|--signer-action-token-env <VAR>] [--idempotency-key <key>] [--retry-max <n>] [--retry-backoff-ms <ms>] --socks5 socks5h://127.0.0.1:9050\n");
    printf("  nexum escrow-release-pipeline --base http://xxxx.onion --id <escrow_id> --seller-nick <nick> --seller-token <tok> --arbiter-nick <nick> --arbiter-token <tok> [--seller-wallet-password <pw>|--seller-wallet-password-file <path>|--seller-wallet-password-env <VAR>] [--seller-signer-action-token <tok>|--seller-signer-action-token-file <path>|--seller-signer-action-token-env <VAR>] [--seller-signer-sign-action-token <tok>|--seller-signer-sign-action-token-file <path>|--seller-signer-sign-action-token-env <VAR>] [--seller-signer-submit-action-token <tok>|--seller-signer-submit-action-token-file <path>|--seller-signer-submit-action-token-env <VAR>] [--arbiter-signer-action-token <tok>|--arbiter-signer-action-token-file <path>|--arbiter-signer-action-token-env <VAR>] [--arbiter-signer-submit-action-token <tok>|--arbiter-signer-submit-action-token-file <path>|--arbiter-signer-submit-action-token-env <VAR>] [--idempotency-prefix <key>] [--retry-max <n>] [--retry-backoff-ms <ms>] --socks5 socks5h://127.0.0.1:9050\n");
    printf("\nOperator (local orchestrator):\n");
    printf("  nexum preflight escrow --base http://xxxx.onion [--socks5 socks5h://127.0.0.1:9050] [--ui-base http://xxxx.onion] [--require-ui] [--run-dir <path>]\n");
    printf("  nexum worker-route-set --escrow-id-hex <32hex> --role buyer|seller|arbiter --endpoint <url> [--orch-db <path>] [--orch-bin <path>]\n");
    printf("  nexum worker-route-show --escrow-id-hex <32hex> --role buyer|seller|arbiter [--orch-db <path>] [--orch-bin <path>]\n");
    printf("  nexum worker-route-reconcile [--stale-after-ms <ms>] [--limit <n>] [--include-terminal] [--fail-on-findings] [--orch-db <path>] [--orch-bin <path>]\n");
    printf("  nexum escrow-arbiter-token --escrow-id <id> [--master-token <tok>|--master-token-file <path>|--master-token-env <ENV>]\n");
    printf("  nexum escrow-token-from-db --db-path <sqlite> --escrow-id <id> --role buyer|seller\n");
    printf("  nexum env-export-visible-flow [--out-dir VISIBLE_FLOW] [--include-real3p] [--include-config-secrets] [--include-tokens]\n");
    printf("\n");
}

static const char *arg_val(int *i, int argc, char **argv) {
    if (*i + 1 >= argc) ff_die("missing value for %s", argv[*i]);
    (*i)++;
    return argv[*i];
}

static char *dup_trimmed_copy_cli(const char *in) {
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

static int parse_nonneg_int_cli_or_die(const char *raw, const char *opt_name, int max_value) {
    if (!raw || !raw[0]) ff_die("invalid %s: (empty)", opt_name ? opt_name : "value");
    char *endp = NULL;
    long v = strtol(raw, &endp, 10);
    if (endp == raw || (endp && *endp) || v < 0 || v > (long)max_value) {
        ff_die("invalid %s: %s", opt_name ? opt_name : "value", raw);
    }
    return (int)v;
}

static char *resolve_cli_secret_opt(const char *inline_v,
                                    const char *file_path,
                                    const char *env_name,
                                    const char *label,
                                    const char *source_hint) {
    int sources = 0;
    if (inline_v && inline_v[0]) sources++;
    if (file_path && file_path[0]) sources++;
    if (env_name && env_name[0]) sources++;
    if (sources > 1) ff_die("%s: use only one source (%s)", label, source_hint);

    char *raw = NULL;
    if (inline_v && inline_v[0]) {
        raw = strdup(inline_v);
    } else if (file_path && file_path[0]) {
        raw = read_file_str(file_path, NULL);
        if (!raw) ff_die("%s: failed to read file: %s", label, file_path);
    } else if (env_name && env_name[0]) {
        const char *v = getenv(env_name);
        if (!v || !v[0]) ff_die("%s: env var %s is empty or missing", label, env_name);
        raw = strdup(v);
    }
    if (!raw) return NULL;

    char *trim = dup_trimmed_copy_cli(raw);
    if (!trim) {
        secure_free_str(&raw);
        ff_die("oom");
    }
    secure_free_str(&raw);
    if (!trim[0]) {
        secure_free_str(&trim);
        return NULL;
    }
    return trim;
}

static void usage_preflight_escrow(void) {
    printf("Usage:\n");
    printf("  nexum preflight escrow --base http://xxxx.onion [options]\n");
    printf("  nexum escrow-preflight    --base http://xxxx.onion [options]  (alias)\n");
    printf("\nOptions:\n");
    printf("  --base <url>             escrow-http onion base (required)\n");
    printf("  --socks5 <url>           Tor SOCKS5H proxy (default from config or socks5h://127.0.0.1:9050)\n");
    printf("  --ui-base <url>          optional nxms-serv (/escrow UI) onion base\n");
    printf("  --require-ui             fail if UI /escrow is unreachable\n");
    printf("  --run-dir <path>         write preflight artifacts under <path>/preflight/\n");
    printf("  --orch-db <path>         orchestrator DB path override (for local/manual runtime checks)\n");
    printf("  --orch-bin <path>        orchestrator binary override\n");
    printf("  --escrow-id-hex <32hex>  optional escrow id for future per-escrow checks (v1 validates format only)\n");
    printf("  --strict-daemon-sync     fail if monerod reports not synchronized\n");
    printf("  --allow-bootstrap        allow monerod bootstrap mode (reserved for future checks)\n");
    printf("  --strict-wallet-multisig run deeper authenticated arbiter wallet-rpc multisig probe\n");
    printf("  --check-transfer-dry-run run deeper authenticated party wallet-rpc transfer dry-run probe (do_not_relay)\n");
    printf("  --timeout-ms <ms>        per-check timeout budget (v1 accepted; partial use)\n");
    printf("  --json                   print machine-readable JSON preflight output\n");
    printf("  --verbose                include SKIP/resolution detail\n");
    printf("  -h, --help               show this help\n");
}

static void usage_escrow_create(void) {
    printf("Usage:\n");
    printf("  nexum escrow-create --base http://xxxx.onion --buyer-nick <nick> --seller-nick <nick> --amount-atomic <u64> [options]\n");
    printf("\nOptions:\n");
    printf("  --base <url>                  escrow-http onion base (required)\n");
    printf("  --socks5 <url>                Tor SOCKS5H proxy (default from config)\n");
    printf("  --buyer-nick <nick>           buyer nickname (required)\n");
    printf("  --seller-nick <nick>          seller nickname (required)\n");
    printf("  --amount-atomic <u64>         escrow amount in atomic units (required)\n");
    printf("  --memo <text>                 optional escrow memo (max enforced by server)\n");
    printf("  --buyer-refund-address <addr> optional Monero refund address for buyer\n");
    printf("  --idempotency-key <key>       optional x-idempotency-key for safe retries\n");
    printf("  --run-dir <path>              write flow artifacts under <path>/flow/\n");
    printf("  -h, --help                    show this help\n");
}

static void usage_escrow_status(void) {
    printf("Usage:\n");
    printf("  nexum escrow-status --base http://xxxx.onion --id <escrow_id> --nick <nick> --token <token> [options]\n");
    printf("\nOptions:\n");
    printf("  --base <url>        escrow-http onion base (required)\n");
    printf("  --socks5 <url>      Tor SOCKS5H proxy (default from config)\n");
    printf("  --id <escrow_id>    escrow numeric id (required)\n");
    printf("  --nick <nick>       escrow participant nick (required)\n");
    printf("  --token <token>     escrow participant token (required)\n");
    printf("  --run-dir <path>    write status artifact under <path>/flow/\n");
    printf("  -h, --help          show this help\n");
}

static void usage_escrow_r1(void) {
    printf("Usage:\n");
    printf("  nexum escrow-r1 --base <url> --id <escrow_id> --nick <nick> --token <tok> [options]\n");
    printf("\nNotes:\n");
    printf("  Native C round-1 helper. Role (buyer/seller/arbiter) is inferred from escrow-status by --nick.\n");
    printf("\nOptions:\n");
    printf("  --base <url>                 escrow-http onion base (required)\n");
    printf("  --socks5 <url>               Tor SOCKS5H proxy (default from config)\n");
    printf("  --id <escrow_id>             escrow numeric id (required)\n");
    printf("  --nick <nick>                participant nick (required; buyer/seller/arbiter)\n");
    printf("  --token <tok>                participant token (required)\n");
    printf("  --wallet-rpc-url <url>       wallet-rpc URL (required)\n");
    printf("  --wallet-rpc-user <v>|...    wallet-rpc user (inline/file/env)\n");
    printf("  --wallet-rpc-pass <v>|...    wallet-rpc pass (inline/file/env)\n");
    printf("  --wallet-name <wallet>       multisig wallet name (required)\n");
    printf("  --wallet-password-env <ENV>  wallet password env var name (required)\n");
    printf("  --refund-address <addr>      optional refund address (used for buyer/seller only)\n");
    printf("  --idempotency-prefix <p>     prefix for x-idempotency-key (default: gate3)\n");
    printf("  --timeout-s <sec>            wallet/http timeout (default: 20)\n");
    printf("  --retry-max <n>              retries for transient r1 POST errors (default: 8)\n");
    printf("  --poll-interval <sec>        retry backoff/poll interval (default: 5)\n");
    printf("  -h, --help                   show this help\n");
}

static void usage_escrow_r2(void) {
    printf("Usage:\n");
    printf("  nexum escrow-r2 --base <url> --id <escrow_id> --nick <nick> --token <tok> [options]\n");
    printf("\nNotes:\n");
    printf("  Native C round-2 helper. Role is inferred from escrow-status by --nick; peer blobs are fetched from /xmr/r1.\n");
    printf("\nOptions:\n");
    printf("  --base <url>                 escrow-http onion base (required)\n");
    printf("  --socks5 <url>               Tor SOCKS5H proxy (default from config)\n");
    printf("  --id <escrow_id>             escrow numeric id (required)\n");
    printf("  --nick <nick>                participant nick (required; buyer/seller/arbiter)\n");
    printf("  --token <tok>                participant token (required)\n");
    printf("  --wallet-rpc-url <url>       wallet-rpc URL (required)\n");
    printf("  --wallet-rpc-user <v>|...    wallet-rpc user (inline/file/env)\n");
    printf("  --wallet-rpc-pass <v>|...    wallet-rpc pass (inline/file/env)\n");
    printf("  --wallet-name <wallet>       multisig wallet name (required)\n");
    printf("  --wallet-password-env <ENV>  wallet password env var name (required)\n");
    printf("  --threshold <n>              multisig threshold (2 or 3; default: 2)\n");
    printf("  --idempotency-prefix <p>     prefix for x-idempotency-key (default: gate3)\n");
    printf("  --timeout-s <sec>            wallet/http timeout (default: 20)\n");
    printf("  --retry-max <n>              retries for transient r2 POST errors (default: 8)\n");
    printf("  --poll-interval <sec>        retry backoff/poll interval (default: 5)\n");
    printf("  -h, --help                   show this help\n");
}

static void usage_escrow_r3(void) {
    printf("Usage:\n");
    printf("  nexum escrow-r3 --base <url> --id <escrow_id> --nick <nick> --token <tok> [options]\n");
    printf("\nNotes:\n");
    printf("  Native C round-3 helper. Role is inferred from escrow-status by --nick; peer blobs are fetched from /xmr/r2.\n");
    printf("\nOptions:\n");
    printf("  --base <url>                 escrow-http onion base (required)\n");
    printf("  --socks5 <url>               Tor SOCKS5H proxy (default from config)\n");
    printf("  --id <escrow_id>             escrow numeric id (required)\n");
    printf("  --nick <nick>                participant nick (required; buyer/seller/arbiter)\n");
    printf("  --token <tok>                participant token (required)\n");
    printf("  --wallet-rpc-url <url>       wallet-rpc URL (required)\n");
    printf("  --wallet-rpc-user <v>|...    wallet-rpc user (inline/file/env)\n");
    printf("  --wallet-rpc-pass <v>|...    wallet-rpc pass (inline/file/env)\n");
    printf("  --wallet-name <wallet>       multisig wallet name (required)\n");
    printf("  --wallet-password-env <ENV>  wallet password env var name (required)\n");
    printf("  --idempotency-prefix <p>     prefix for x-idempotency-key (default: gate3)\n");
    printf("  --timeout-s <sec>            wallet/http timeout (default: 20)\n");
    printf("  --retry-max <n>              retries for transient r3 POST errors (default: 8)\n");
    printf("  --poll-interval <sec>        retry backoff/poll interval (default: 5)\n");
    printf("  -h, --help                   show this help\n");
}

static void usage_escrow_r4(void) {
    printf("Usage:\n");
    printf("  nexum escrow-r4 --base <url> --id <escrow_id> --nick <nick> --token <tok> [options]\n");
    printf("\nNotes:\n");
    printf("  Native C round-4 local finalize helper. Role is inferred from escrow-status by --nick; peer blobs are fetched from /xmr/r3.\n");
    printf("  Outputs local JSON (exchange + is_multisig) and verifies wallet is multisig-ready.\n");
    printf("\nOptions:\n");
    printf("  --base <url>                 escrow-http onion base (required)\n");
    printf("  --socks5 <url>               Tor SOCKS5H proxy (default from config)\n");
    printf("  --id <escrow_id>             escrow numeric id (required)\n");
    printf("  --nick <nick>                participant nick (required; buyer/seller/arbiter)\n");
    printf("  --token <tok>                participant token (required)\n");
    printf("  --wallet-rpc-url <url>       wallet-rpc URL (required)\n");
    printf("  --wallet-rpc-user <v>|...    wallet-rpc user (inline/file/env)\n");
    printf("  --wallet-rpc-pass <v>|...    wallet-rpc pass (inline/file/env)\n");
    printf("  --wallet-name <wallet>       multisig wallet name (required)\n");
    printf("  --wallet-password-env <ENV>  wallet password env var name (required)\n");
    printf("  --timeout-s <sec>            wallet/http timeout (default: 20)\n");
    printf("  -h, --help                   show this help\n");
}

static void usage_escrow_wait_state(void) {
    printf("Usage:\n");
    printf("  nexum escrow-wait-state --base <url> --id <escrow_id> --nick <nick> --token <tok> --state <STATE> [options]\n");
    printf("\nNotes:\n");
    printf("  Emergency/operator parity helper. Primary happy-path remains auto multisig flow commands.\n");
    printf("\nOptions:\n");
    printf("  --base <url>                 escrow-http onion base (required)\n");
    printf("  --socks5 <url>               Tor SOCKS5H proxy (default from config)\n");
    printf("  --id <escrow_id>             escrow numeric id (required)\n");
    printf("  --nick <nick>                participant nick (required)\n");
    printf("  --token <tok>                participant token (required)\n");
    printf("  --state <STATE>              target escrow state (required, e.g. READY/FUNDED)\n");
    printf("  --run-dir <path>             write success status artifact under <path>/flow/\n");
    printf("  --wait-timeout <sec>         timeout waiting for target state (default: 1800)\n");
    printf("  --poll-interval <sec>        poll interval (default: 5)\n");
    printf("  -h, --help                   show this help\n");
}

static void usage_escrow_arbiter_token(void) {
    printf("Usage:\n");
    printf("  nexum escrow-arbiter-token --escrow-id <id> [options]\n");
    printf("\nOptions:\n");
    printf("  --escrow-id <id>                escrow numeric id (required, > 0)\n");
    printf("  --master-token <tok>            arbiter master token (avoid argv in prod)\n");
    printf("  --master-token-file <path>      file containing arbiter master token (trimmed)\n");
    printf("  --master-token-env <ENV>        env var with arbiter master token (default fallback: ESCROW_ARBITER_TOKEN)\n");
    printf("  -h, --help                      show this help\n");
}

static void usage_escrow_token_from_db(void) {
    printf("Usage:\n");
    printf("  nexum escrow-token-from-db --db-path <sqlite> --escrow-id <id> --role buyer|seller\n");
    printf("\nOptions:\n");
    printf("  --db-path <sqlite>   escrow sqlite DB path (required)\n");
    printf("  --escrow-id <id>     escrow numeric id (required, > 0)\n");
    printf("  --role <role>        buyer|seller (required)\n");
    printf("  -h, --help           show this help\n");
}

static void usage_escrow_gate3_ready(void) {
    printf("Usage:\n");
    printf("  nexum escrow-gate3-ready --base <url> --id <escrow_id> --buyer-nick <nick> --buyer-token <tok> --seller-nick <nick> [options]\n");
    printf("\nOptions:\n");
    printf("  --base <url>                     escrow-http onion base (required)\n");
    printf("  --socks5 <url>                   Tor SOCKS5H proxy (default from config)\n");
    printf("  --id <escrow_id>                 escrow numeric id (required)\n");
    printf("  --buyer-nick <nick>              buyer nick (required)\n");
    printf("  --buyer-token <tok>              buyer token (required)\n");
    printf("  --seller-nick <nick>             seller nick (required)\n");
    printf("  --seller-token <tok>             seller token (optional if --seller-token-db-path is provided)\n");
    printf("  --seller-token-db-path <sqlite>  sqlite DB path for native break-glass seller token lookup\n");
    printf("  --buyer-wallet-rpc-url <url>     buyer wallet-rpc URL (required)\n");
    printf("  --buyer-wallet-rpc-user <user>    buyer wallet-rpc user (optional if *_file/env used)\n");
    printf("  --buyer-wallet-rpc-user-file <p>  buyer wallet-rpc user file (trimmed)\n");
    printf("  --buyer-wallet-rpc-user-env <ENV> buyer wallet-rpc user env var\n");
    printf("  --buyer-wallet-rpc-pass <pass>    buyer wallet-rpc pass (optional if *_file/env used; avoid argv for prod)\n");
    printf("  --buyer-wallet-rpc-pass-file <p>  buyer wallet-rpc pass file (trimmed)\n");
    printf("  --buyer-wallet-rpc-pass-env <ENV> buyer wallet-rpc pass env var\n");
    printf("  --buyer-wallet-name <wallet>      buyer multisig wallet name (required)\n");
    printf("  --buyer-wallet-password-env <ENV> buyer wallet password env name (required)\n");
    printf("  --seller-wallet-rpc-url <url>     seller wallet-rpc URL (required)\n");
    printf("  --seller-wallet-rpc-user <user>   seller wallet-rpc user (optional if *_file/env used)\n");
    printf("  --seller-wallet-rpc-user-file <p> seller wallet-rpc user file (trimmed)\n");
    printf("  --seller-wallet-rpc-user-env <ENV> seller wallet-rpc user env var\n");
    printf("  --seller-wallet-rpc-pass <pass>   seller wallet-rpc pass (optional if *_file/env used; avoid argv for prod)\n");
    printf("  --seller-wallet-rpc-pass-file <p> seller wallet-rpc pass file (trimmed)\n");
    printf("  --seller-wallet-rpc-pass-env <ENV> seller wallet-rpc pass env var\n");
    printf("  --seller-wallet-name <wallet>     seller multisig wallet name (required)\n");
    printf("  --seller-wallet-password-env <ENV> seller wallet password env name (required)\n");
    printf("  --buyer-refund-address <addr>     optional buyer refund address used in r1\n");
    printf("  --seller-refund-address <addr>    optional seller refund address used in r1\n");
    printf("  --idempotency-prefix <prefix>     default: gate3\n");
    printf("  --run-dir <path>                  write multisig flow artifacts under <path>/flow/\n");
    printf("  --wait-ready-timeout <sec>        default: 900\n");
    printf("  --poll-interval <sec>             default: 5\n");
    printf("  --timeout-s <sec>                 helper HTTP timeout (default: 20)\n");
    printf("  --round-retries <n>               retry count for r1-r4 on HTTP 429 (default: 8)\n");
    printf("  -h, --help                        show this help\n");
}

static void usage_escrow_fund(void) {
    printf("Usage:\n");
    printf("  nexum escrow-fund --base <url> --id <escrow_id> --buyer-nick <nick> --buyer-token <tok> [options]\n");
    printf("\nOptions:\n");
    printf("  --base <url>                 escrow-http onion base (required)\n");
    printf("  --socks5 <url>               Tor SOCKS5H proxy (default from config)\n");
    printf("  --id <escrow_id>             escrow numeric id (required)\n");
    printf("  --buyer-nick <nick>          buyer nick (required)\n");
    printf("  --buyer-token <tok>          buyer token (required)\n");
    printf("  --wallet-rpc-url <url>       funding wallet-rpc URL (required)\n");
    printf("  --wallet-rpc-user <user>     funding wallet-rpc user (optional if *_file/env used)\n");
    printf("  --wallet-rpc-user-file <p>   funding wallet-rpc user file (trimmed)\n");
    printf("  --wallet-rpc-user-env <ENV>  funding wallet-rpc user env var\n");
    printf("  --wallet-rpc-pass <pass>     funding wallet-rpc pass (optional if *_file/env used; avoid argv)\n");
    printf("  --wallet-rpc-pass-file <p>   funding wallet-rpc pass file (trimmed)\n");
    printf("  --wallet-rpc-pass-env <ENV>  funding wallet-rpc pass env var\n");
    printf("  --wallet-name <wallet>       funding wallet name (required)\n");
    printf("  --wallet-password-env <ENV>  funding wallet password env var (required)\n");
    printf("  --fund-buffer-atomic <u64>   optional extra atomic units above required_funding_atomic (default: 0)\n");
    printf("  --run-dir <path>             write artifacts under <path>/flow/\n");
    printf("  --timeout-s <sec>            wallet-rpc timeout (default: 120)\n");
    printf("  -h, --help                   show this help\n");
}

static void usage_escrow_wait_funded(void) {
    printf("Usage:\n");
    printf("  nexum escrow-wait-funded --base <url> --id <escrow_id> --nick <nick> --token <tok> [options]\n");
    printf("\nOptions:\n");
    printf("  --base <url>                 escrow-http onion base (required)\n");
    printf("  --socks5 <url>               Tor SOCKS5H proxy (default from config)\n");
    printf("  --id <escrow_id>             escrow numeric id (required)\n");
    printf("  --nick <nick>                participant nick (required)\n");
    printf("  --token <tok>                participant token (required)\n");
    printf("  --run-dir <path>             write status_funded artifact under <path>/flow/\n");
    printf("  --wait-timeout <sec>         timeout waiting for FUNDED (default: 1800)\n");
    printf("  --poll-interval <sec>        poll interval (default: 5)\n");
    printf("  -h, --help                   show this help\n");
}

static void usage_escrow_confirm_release(void) {
    printf("Usage:\n");
    printf("  nexum escrow-confirm-release --base <url> --id <escrow_id> --nick <nick> --token <tok> --txid <64hex> [options]\n");
    printf("\nNotes:\n");
    printf("  Emergency/operator parity helper for txid-only release confirmation.\n");
    printf("  For signer-worker paths and full release flow use `nexum escrow-release` / `escrow-release-pipeline`.\n");
    printf("\nOptions:\n");
    printf("  --base <url>                 escrow-http onion base (required)\n");
    printf("  --socks5 <url>               Tor SOCKS5H proxy (default from config)\n");
    printf("  --id <escrow_id>             escrow numeric id (required)\n");
    printf("  --nick <nick>                participant nick (required)\n");
    printf("  --token <tok>                participant token (required)\n");
    printf("  --txid <64hex>               settlement txid (required)\n");
    printf("  --idempotency-prefix <p>     legacy-compatible prefix (default: stagenet-live)\n");
    printf("  --retry-max <n>              retries on transient/idempotency in-progress errors (default: 0)\n");
    printf("  --retry-backoff-ms <ms>      retry backoff (default: 1200)\n");
    printf("  -h, --help                   show this help\n");
}

static void usage_escrow_confirm_refund(void) {
    printf("Usage:\n");
    printf("  nexum escrow-confirm-refund --base <url> --id <escrow_id> --nick <nick> --token <tok> --txid <64hex> [options]\n");
    printf("\nNotes:\n");
    printf("  Emergency/operator parity helper for txid-only refund confirmation.\n");
    printf("  For signer-token paths use `nexum escrow-refund`.\n");
    printf("\nOptions:\n");
    printf("  --base <url>                 escrow-http onion base (required)\n");
    printf("  --socks5 <url>               Tor SOCKS5H proxy (default from config)\n");
    printf("  --id <escrow_id>             escrow numeric id (required)\n");
    printf("  --nick <nick>                participant nick (required)\n");
    printf("  --token <tok>                participant token (required)\n");
    printf("  --txid <64hex>               settlement txid (required)\n");
    printf("  --idempotency-prefix <p>     legacy-compatible prefix (default: stagenet-live)\n");
    printf("  --retry-max <n>              retries on transient/idempotency in-progress errors (default: 0)\n");
    printf("  --retry-backoff-ms <ms>      retry backoff (default: 1200)\n");
    printf("  -h, --help                   show this help\n");
}

static void usage_escrow_funded_sync(void) {
    printf("Usage:\n");
    printf("  nexum escrow-funded-sync --base <url> --id <escrow_id> --buyer-nick <nick> --buyer-token <tok> --arbiter-nick <nick> --arbiter-token <tok> [options]\n");
    printf("\nOptions:\n");
    printf("  --orch-bin <path>                 orchestrator binary (default from env/path)\n");
    printf("  --base <url>                      escrow-http base/onion (required)\n");
    printf("  --socks5 <url>                    Tor SOCKS5H proxy (default from config)\n");
    printf("  --allow-non-tor                   allow non-Tor base URL (passed to orchestrator)\n");
    printf("  --id <escrow_id>                  escrow numeric id (required)\n");
    printf("  --buyer-nick <nick>               buyer nick (required)\n");
    printf("  --buyer-token <tok>               buyer token (required)\n");
    printf("  --arbiter-nick <nick>             arbiter nick (required)\n");
    printf("  --arbiter-token <tok>             arbiter token (required)\n");
    printf("  --arbiter-token-fallback <tok>    optional fallback arbiter token\n");
    printf("  --buyer-rpc-endpoint <url>        buyer wallet-rpc endpoint (required)\n");
    printf("  --buyer-rpc-user <v>|...          buyer wallet-rpc user (inline/file/env)\n");
    printf("  --buyer-rpc-pass <v>|...          buyer wallet-rpc pass (inline/file/env)\n");
    printf("  --buyer-wallet-name <wallet>      buyer wallet name (required)\n");
    printf("  --buyer-wallet-pass <v>|...       buyer wallet password (inline/file/env)\n");
    printf("  --seller-rpc-endpoint <url>       seller wallet-rpc endpoint (required)\n");
    printf("  --seller-rpc-user <v>|...         seller wallet-rpc user (inline/file/env)\n");
    printf("  --seller-rpc-pass <v>|...         seller wallet-rpc pass (inline/file/env)\n");
    printf("  --seller-wallet-name <wallet>     seller wallet name (required)\n");
    printf("  --seller-wallet-pass <v>|...      seller wallet password (inline/file/env)\n");
    printf("  --run-dir <path>                  write/copy artifacts under <path>/flow/\n");
    printf("  --funded-timeout <sec>            wait timeout for FUNDED (default: 1800)\n");
    printf("  --poll-interval <sec>             poll interval (default: 10)\n");
    printf("  --http-timeout <sec>              http timeout (default: 120)\n");
    printf("  -h, --help                        show this help\n");
}

static void usage_env_export_visible_flow(void) {
    printf("Usage:\n");
    printf("  nexum env-export-visible-flow [options]\n");
    printf("\nNotes:\n");
    printf("  Local operator snapshot helper replacing scripts/export_visible_flow_state.sh for parity/recovery.\n");
    printf("  Safe defaults: token values and sensitive runtime/credential vars are REDACTED from disk output.\n");
    printf("  Use break-glass flags only for emergency operator recovery and treat outputs as secrets.\n");
    printf("\nOptions:\n");
    printf("  --out-dir <path>          output dir (default: VISIBLE_FLOW)\n");
    printf("  --base-url <url>          BASE_URL value for ACTIVE_FLOW.env (default: http://127.0.0.1:9000)\n");
    printf("  --db-path <sqlite>        escrow sqlite DB path (default: /var/lib/freeforum-escrow/escrow_rust.db)\n");
    printf("  --nx-conf <path>          nx-escrow-rs runtime env file (default: /etc/conf.d/nx-escrow-rs)\n");
    printf("  --real3p-env <path>       legacy real3p credentials env file\n");
    printf("  --include-real3p          include legacy real3p block (requires --include-config-secrets)\n");
    printf("  --include-config-secrets  break-glass: include sensitive runtime/credential values in ACTIVE_FLOW.env\n");
    printf("  --include-tokens          break-glass: include buyer/seller escrow tokens in ACTIVE_FLOW.env and JSON\n");
    printf("  -h, --help                show this help\n");
}

static int is_hex_32(const char *s) {
    if (!s) return 0;
    size_t n = strlen(s);
    if (n != 32) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        int ok = ((c >= '0' && c <= '9') ||
                  (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F'));
        if (!ok) return 0;
    }
    return 1;
}

static int dispatch_preflight_escrow(int argc, char **argv, int arg_start, const ff_cli_config_t *cfg) {
    const char *base = cfg ? cfg->base : NULL;
    const char *socks5 = (cfg && cfg->socks5[0]) ? cfg->socks5 : "socks5h://127.0.0.1:9050";
    const char *ui_base = NULL;
    const char *run_dir = NULL;
    const char *orch_db = NULL;
    const char *orch_bin = NULL;
    const char *escrow_id_hex = NULL;
    int require_ui = 0;
    int strict_daemon_sync = 0;
    int allow_bootstrap = 0;
    int strict_wallet_multisig = 0;
    int check_transfer_dry_run = 0;
    int json_output = 0;
    int verbose = 0;
    unsigned timeout_ms = 0;

    for (int i = arg_start; i < argc; i++) {
        if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
        else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
        else if (strcmp(argv[i], "--ui-base") == 0) ui_base = arg_val(&i, argc, argv);
        else if (strcmp(argv[i], "--require-ui") == 0) require_ui = 1;
        else if (strcmp(argv[i], "--run-dir") == 0) run_dir = arg_val(&i, argc, argv);
        else if (strcmp(argv[i], "--orch-db") == 0) orch_db = arg_val(&i, argc, argv);
        else if (strcmp(argv[i], "--orch-bin") == 0) orch_bin = arg_val(&i, argc, argv);
        else if (strcmp(argv[i], "--escrow-id-hex") == 0) escrow_id_hex = arg_val(&i, argc, argv);
        else if (strcmp(argv[i], "--strict-daemon-sync") == 0) strict_daemon_sync = 1;
        else if (strcmp(argv[i], "--allow-bootstrap") == 0) allow_bootstrap = 1;
        else if (strcmp(argv[i], "--strict-wallet-multisig") == 0) strict_wallet_multisig = 1;
        else if (strcmp(argv[i], "--check-transfer-dry-run") == 0) check_transfer_dry_run = 1;
        else if (strcmp(argv[i], "--verbose") == 0) verbose = 1;
        else if (strcmp(argv[i], "--timeout-ms") == 0) {
            const char *raw = arg_val(&i, argc, argv);
            char *endp = NULL;
            unsigned long parsed = strtoul(raw, &endp, 10);
            if (endp == raw || (endp && *endp) || parsed > 600000UL) {
                fprintf(stderr, "invalid --timeout-ms: %s\n", raw);
                return 2;
            }
            timeout_ms = (unsigned)parsed;
        } else if (strcmp(argv[i], "--json") == 0) {
            json_output = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage_preflight_escrow();
            return 0;
        } else {
            fprintf(stderr, "unknown preflight escrow option: %s\n", argv[i]);
            usage_preflight_escrow();
            return 2;
        }
    }

    if (!base || !base[0]) {
        fprintf(stderr, "preflight escrow requires --base\n");
        usage_preflight_escrow();
        return 2;
    }
    if (escrow_id_hex && !is_hex_32(escrow_id_hex)) {
        fprintf(stderr, "--escrow-id-hex must be exactly 32 hex chars\n");
        return 2;
    }

    return cmd_preflight_escrow(
        base,
        socks5,
        ui_base,
        require_ui,
        json_output,
        run_dir,
        orch_db,
        orch_bin,
        escrow_id_hex,
        strict_daemon_sync,
        allow_bootstrap,
        strict_wallet_multisig,
        check_transfer_dry_run,
        timeout_ms,
        verbose
    );
}

int ff_cli_run(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    if (sodium_init() < 0) ff_die("sodium_init failed");
    curl_global_init(CURL_GLOBAL_DEFAULT);

    char config_path[4096];
    ff_cli_config_default_path(config_path, sizeof(config_path));

    int cmd_index = 1;
    int config_explicit = 0;
    if (cmd_index < argc && strcmp(argv[cmd_index], "--config") == 0) {
        if (cmd_index + 1 >= argc) ff_die("missing value for --config");
        ff_strlcpy(config_path, argv[cmd_index + 1], sizeof(config_path));
        config_explicit = 1;
        cmd_index += 2;
    }

    if (cmd_index >= argc) {
        usage();
        return 1;
    }

    for (int i = cmd_index + 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            ff_strlcpy(config_path, arg_val(&i, argc, argv), sizeof(config_path));
            config_explicit = 1;
        }
    }

    ff_cli_config_t cfg;
    ff_cli_config_defaults(&cfg);
    int cfg_load_rc = ff_cli_config_load(config_path, &cfg);
    if (cfg_load_rc < 0) {
        ff_die("failed to load config: %s", config_path);
    }
    if (cfg_load_rc == 0 && config_explicit) {
        ff_die("config not found: %s", config_path);
    }

    char dir[4096];
    ff_strlcpy(dir, cfg.dir, sizeof(dir));

    const char *cmd = argv[cmd_index];
    int arg_start = cmd_index + 1;

    if (strcmp(cmd, "init") == 0) {
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--dir") == 0) {
                ff_strlcpy(dir, arg_val(&i, argc, argv), sizeof(dir));
            }
        }
        int rc = cmd_init(dir);
        ff_strlcpy(cfg.dir, dir, sizeof(cfg.dir));
        if (ff_cli_config_write(config_path, &cfg) != 0) {
            ff_die("failed to write config: %s", config_path);
        }
        printf("OK: config saved at %s\n", config_path);
        return rc;
    }

    if (strcmp(cmd, "keygen") == 0) {
        const char *kem = NULL;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--kem") == 0) kem = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--dir") == 0) ff_strlcpy(dir, arg_val(&i, argc, argv), sizeof(dir));
        }
        if (!kem) ff_die("--kem required");
        return cmd_keygen(dir, kem);
    }

    if (strcmp(cmd, "show-keys") == 0) {
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--dir") == 0) ff_strlcpy(dir, arg_val(&i, argc, argv), sizeof(dir));
        }
        return cmd_show_keys(dir);
    }

    if (strcmp(cmd, "register") == 0) {
        const char *base = cfg.base;
        const char *nick = NULL;
        const char *socks5 = cfg.socks5;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--dir") == 0) ff_strlcpy(dir, arg_val(&i, argc, argv), sizeof(dir));
        }
        if (!nick) ff_die("--nick required");
        return cmd_register(dir, base, nick, socks5);
    }

    if (strcmp(cmd, "login") == 0) {
        const char *base = cfg.base;
        const char *nick = NULL;
        const char *socks5 = cfg.socks5;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--dir") == 0) ff_strlcpy(dir, arg_val(&i, argc, argv), sizeof(dir));
        }
        if (!nick) ff_die("--nick required");
        return cmd_login(dir, base, nick, socks5);
    }

    if (strcmp(cmd, "tor-check") == 0) {
        const char *base = NULL;
        const char *socks5 = cfg.socks5;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
        }
        return cmd_tor_check(base, socks5);
    }

    if (strcmp(cmd, "preflight") == 0) {
        if (arg_start >= argc) {
            fprintf(stderr, "preflight requires subcommand (supported: escrow)\n");
            usage_preflight_escrow();
            return 2;
        }
        if (strcmp(argv[arg_start], "escrow") == 0) {
            return dispatch_preflight_escrow(argc, argv, arg_start + 1, &cfg);
        }
        if (strcmp(argv[arg_start], "-h") == 0 || strcmp(argv[arg_start], "--help") == 0) {
            usage_preflight_escrow();
            return 0;
        }
        fprintf(stderr, "unsupported preflight subcommand: %s\n", argv[arg_start]);
        usage_preflight_escrow();
        return 2;
    }

    if (strcmp(cmd, "escrow-preflight") == 0) {
        return dispatch_preflight_escrow(argc, argv, arg_start, &cfg);
    }

    if (strcmp(cmd, "prekeys-gen") == 0) {
        const char *kem = NULL;
        int count = 20;
        int ttl_days = 14;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--kem") == 0) kem = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--count") == 0) count = atoi(arg_val(&i, argc, argv));
            else if (strcmp(argv[i], "--ttl-days") == 0) ttl_days = atoi(arg_val(&i, argc, argv));
            else if (strcmp(argv[i], "--dir") == 0) ff_strlcpy(dir, arg_val(&i, argc, argv), sizeof(dir));
        }
        return cmd_prekeys_gen(dir, kem, count, ttl_days);
    }

    if (strcmp(cmd, "prekeys-upload") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        int count = 20;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--count") == 0) count = atoi(arg_val(&i, argc, argv));
            else if (strcmp(argv[i], "--dir") == 0) ff_strlcpy(dir, arg_val(&i, argc, argv), sizeof(dir));
        }
        return cmd_prekeys_upload(dir, base, socks5, count);
    }

    if (strcmp(cmd, "prekeys-rotate") == 0) {
        const char *base = cfg.base;
        const char *kem = NULL;
        const char *socks5 = cfg.socks5;
        int count = 20;
        int min = 5;
        int ttl_days = 14;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--kem") == 0) kem = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--count") == 0) count = atoi(arg_val(&i, argc, argv));
            else if (strcmp(argv[i], "--min") == 0) min = atoi(arg_val(&i, argc, argv));
            else if (strcmp(argv[i], "--ttl-days") == 0) ttl_days = atoi(arg_val(&i, argc, argv));
            else if (strcmp(argv[i], "--dir") == 0) ff_strlcpy(dir, arg_val(&i, argc, argv), sizeof(dir));
        }
        return cmd_prekeys_rotate(dir, base, socks5, kem, count, min, ttl_days);
    }

    if (strcmp(cmd, "prekeys-list") == 0) {
        int verbose = 0;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--verbose") == 0) verbose = 1;
            else if (strcmp(argv[i], "--dir") == 0) ff_strlcpy(dir, arg_val(&i, argc, argv), sizeof(dir));
        }
        return cmd_prekeys_list(dir, verbose);
    }

    if (strcmp(cmd, "prekeys-prune") == 0) {
        int prune_used = 0;
        int prune_expired = 0;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--used") == 0) prune_used = 1;
            else if (strcmp(argv[i], "--expired") == 0) prune_expired = 1;
            else if (strcmp(argv[i], "--dir") == 0) ff_strlcpy(dir, arg_val(&i, argc, argv), sizeof(dir));
        }
        if (!prune_used && !prune_expired) {
            prune_used = 1;
            prune_expired = 1;
        }
        return cmd_prekeys_prune(dir, prune_used, prune_expired);
    }

    if (strcmp(cmd, "dm-send") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *to = NULL;
        const char *msg = NULL;
        const char *file_path = NULL;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--to") == 0) to = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--msg") == 0) msg = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--file") == 0) file_path = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--dir") == 0) ff_strlcpy(dir, arg_val(&i, argc, argv), sizeof(dir));
        }
        return cmd_dm_send(dir, base, socks5, to, msg, file_path);
    }

    if (strcmp(cmd, "dm-inbox") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        int limit = 50;
        int keep = 0;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--limit") == 0) limit = atoi(arg_val(&i, argc, argv));
            else if (strcmp(argv[i], "--keep") == 0) keep = 1;
            else if (strcmp(argv[i], "--dir") == 0) ff_strlcpy(dir, arg_val(&i, argc, argv), sizeof(dir));
        }
        return cmd_dm_inbox(dir, base, socks5, limit, keep);
    }

    if (strcmp(cmd, "escrow-create") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *buyer_nick = NULL;
        const char *seller_nick = NULL;
        const char *amount_raw = NULL;
        const char *memo = NULL;
        const char *buyer_refund_address = NULL;
        const char *idempotency_key = NULL;
        const char *run_dir = NULL;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-nick") == 0) buyer_nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-nick") == 0) seller_nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--amount-atomic") == 0) amount_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--memo") == 0) memo = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-refund-address") == 0) buyer_refund_address = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--idempotency-key") == 0) idempotency_key = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--run-dir") == 0) run_dir = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_create();
                return 0;
            } else {
                ff_die("unknown escrow-create option: %s", argv[i]);
            }
        }
        if (!base || !base[0] || !buyer_nick || !seller_nick || !amount_raw) {
            usage_escrow_create();
            ff_die("escrow-create requires --base --buyer-nick --seller-nick --amount-atomic");
        }
        char *endp = NULL;
        unsigned long long amount_atomic = strtoull(amount_raw, &endp, 10);
        if (endp == amount_raw || (endp && *endp)) ff_die("invalid --amount-atomic: %s", amount_raw);
        return cmd_escrow_create(
            base, socks5, buyer_nick, seller_nick, amount_atomic,
            memo, buyer_refund_address, idempotency_key, run_dir
        );
    }

    if (strcmp(cmd, "escrow-status") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *nick = NULL;
        const char *token = NULL;
        const char *run_dir = NULL;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--token") == 0) token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--run-dir") == 0) run_dir = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_status();
                return 0;
            } else {
                ff_die("unknown escrow-status option: %s", argv[i]);
            }
        }
        if (!base || !base[0] || !id_raw || !nick || !token) {
            usage_escrow_status();
            ff_die("escrow-status requires --base --id --nick --token");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) ff_die("invalid --id: %s", id_raw);
        return cmd_escrow_status(base, socks5, escrow_id, nick, token, run_dir);
    }

    if (strcmp(cmd, "escrow-r1") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *nick = NULL;
        const char *token = NULL;
        const char *wallet_rpc_url = NULL;
        const char *wallet_rpc_user = NULL;
        const char *wallet_rpc_user_file = NULL;
        const char *wallet_rpc_user_env = NULL;
        const char *wallet_rpc_pass = NULL;
        const char *wallet_rpc_pass_file = NULL;
        const char *wallet_rpc_pass_env = NULL;
        const char *wallet_name = NULL;
        const char *wallet_password_env = NULL;
        const char *refund_address = NULL;
        const char *idempotency_prefix = "gate3";
        unsigned timeout_s = 20U;
        unsigned retry_max = 8U;
        unsigned poll_interval_s = 5U;

        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--token") == 0) token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-url") == 0) wallet_rpc_url = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user") == 0) wallet_rpc_user = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user-file") == 0) wallet_rpc_user_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user-env") == 0) wallet_rpc_user_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass") == 0) wallet_rpc_pass = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass-file") == 0) wallet_rpc_pass_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass-env") == 0) wallet_rpc_pass_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-name") == 0) wallet_name = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-password-env") == 0) wallet_password_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--refund-address") == 0) refund_address = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--idempotency-prefix") == 0) idempotency_prefix = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--timeout-s") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 3600UL) ff_die("invalid --timeout-s: %s", raw);
                timeout_s = (unsigned)v;
            } else if (strcmp(argv[i], "--retry-max") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 100UL) ff_die("invalid --retry-max: %s", raw);
                retry_max = (unsigned)v;
            } else if (strcmp(argv[i], "--poll-interval") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 600UL) ff_die("invalid --poll-interval: %s", raw);
                poll_interval_s = (unsigned)v;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_r1();
                return 0;
            } else {
                ff_die("unknown escrow-r1 option: %s", argv[i]);
            }
        }

        char *wallet_rpc_user_owned = resolve_cli_secret_opt(
            wallet_rpc_user,
            wallet_rpc_user_file,
            wallet_rpc_user_env,
            "escrow-r1 wallet-rpc user",
            "--wallet-rpc-user | --wallet-rpc-user-file | --wallet-rpc-user-env");
        char *wallet_rpc_pass_owned = resolve_cli_secret_opt(
            wallet_rpc_pass,
            wallet_rpc_pass_file,
            wallet_rpc_pass_env,
            "escrow-r1 wallet-rpc pass",
            "--wallet-rpc-pass | --wallet-rpc-pass-file | --wallet-rpc-pass-env");
        const char *wallet_rpc_user_eff = wallet_rpc_user_owned ? wallet_rpc_user_owned : wallet_rpc_user;
        const char *wallet_rpc_pass_eff = wallet_rpc_pass_owned ? wallet_rpc_pass_owned : wallet_rpc_pass;

        if (!base || !base[0] || !id_raw || !nick || !token ||
            !wallet_rpc_url || !wallet_rpc_user_eff || !wallet_rpc_pass_eff ||
            !wallet_name || !wallet_password_env) {
            secure_free_str(&wallet_rpc_user_owned);
            secure_free_str(&wallet_rpc_pass_owned);
            usage_escrow_r1();
            ff_die("escrow-r1 missing required arguments");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) {
            secure_free_str(&wallet_rpc_user_owned);
            secure_free_str(&wallet_rpc_pass_owned);
            ff_die("invalid --id: %s", id_raw);
        }
        int rc = cmd_escrow_r1(
            base, socks5, escrow_id, nick, token,
            wallet_rpc_url, wallet_rpc_user_eff, wallet_rpc_pass_eff,
            wallet_name, wallet_password_env, refund_address, idempotency_prefix,
            timeout_s, retry_max, poll_interval_s
        );
        secure_free_str(&wallet_rpc_user_owned);
        secure_free_str(&wallet_rpc_pass_owned);
        return rc;
    }

    if (strcmp(cmd, "escrow-r2") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *nick = NULL;
        const char *token = NULL;
        const char *wallet_rpc_url = NULL;
        const char *wallet_rpc_user = NULL;
        const char *wallet_rpc_user_file = NULL;
        const char *wallet_rpc_user_env = NULL;
        const char *wallet_rpc_pass = NULL;
        const char *wallet_rpc_pass_file = NULL;
        const char *wallet_rpc_pass_env = NULL;
        const char *wallet_name = NULL;
        const char *wallet_password_env = NULL;
        int threshold = 2;
        const char *idempotency_prefix = "gate3";
        unsigned timeout_s = 20U;
        unsigned retry_max = 8U;
        unsigned poll_interval_s = 5U;

        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--token") == 0) token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-url") == 0) wallet_rpc_url = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user") == 0) wallet_rpc_user = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user-file") == 0) wallet_rpc_user_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user-env") == 0) wallet_rpc_user_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass") == 0) wallet_rpc_pass = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass-file") == 0) wallet_rpc_pass_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass-env") == 0) wallet_rpc_pass_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-name") == 0) wallet_name = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-password-env") == 0) wallet_password_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--threshold") == 0) {
                threshold = parse_nonneg_int_cli_or_die(arg_val(&i, argc, argv), "--threshold", 3);
            } else if (strcmp(argv[i], "--idempotency-prefix") == 0) idempotency_prefix = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--timeout-s") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 3600UL) ff_die("invalid --timeout-s: %s", raw);
                timeout_s = (unsigned)v;
            } else if (strcmp(argv[i], "--retry-max") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 100UL) ff_die("invalid --retry-max: %s", raw);
                retry_max = (unsigned)v;
            } else if (strcmp(argv[i], "--poll-interval") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 600UL) ff_die("invalid --poll-interval: %s", raw);
                poll_interval_s = (unsigned)v;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_r2();
                return 0;
            } else {
                ff_die("unknown escrow-r2 option: %s", argv[i]);
            }
        }

        char *wallet_rpc_user_owned = resolve_cli_secret_opt(
            wallet_rpc_user,
            wallet_rpc_user_file,
            wallet_rpc_user_env,
            "escrow-r2 wallet-rpc user",
            "--wallet-rpc-user | --wallet-rpc-user-file | --wallet-rpc-user-env");
        char *wallet_rpc_pass_owned = resolve_cli_secret_opt(
            wallet_rpc_pass,
            wallet_rpc_pass_file,
            wallet_rpc_pass_env,
            "escrow-r2 wallet-rpc pass",
            "--wallet-rpc-pass | --wallet-rpc-pass-file | --wallet-rpc-pass-env");
        const char *wallet_rpc_user_eff = wallet_rpc_user_owned ? wallet_rpc_user_owned : wallet_rpc_user;
        const char *wallet_rpc_pass_eff = wallet_rpc_pass_owned ? wallet_rpc_pass_owned : wallet_rpc_pass;

        if (!base || !base[0] || !id_raw || !nick || !token ||
            !wallet_rpc_url || !wallet_rpc_user_eff || !wallet_rpc_pass_eff ||
            !wallet_name || !wallet_password_env) {
            secure_free_str(&wallet_rpc_user_owned);
            secure_free_str(&wallet_rpc_pass_owned);
            usage_escrow_r2();
            ff_die("escrow-r2 missing required arguments");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) {
            secure_free_str(&wallet_rpc_user_owned);
            secure_free_str(&wallet_rpc_pass_owned);
            ff_die("invalid --id: %s", id_raw);
        }
        int rc = cmd_escrow_r2(
            base, socks5, escrow_id, nick, token,
            wallet_rpc_url, wallet_rpc_user_eff, wallet_rpc_pass_eff,
            wallet_name, wallet_password_env, threshold, idempotency_prefix,
            timeout_s, retry_max, poll_interval_s
        );
        secure_free_str(&wallet_rpc_user_owned);
        secure_free_str(&wallet_rpc_pass_owned);
        return rc;
    }

    if (strcmp(cmd, "escrow-r3") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *nick = NULL;
        const char *token = NULL;
        const char *wallet_rpc_url = NULL;
        const char *wallet_rpc_user = NULL;
        const char *wallet_rpc_user_file = NULL;
        const char *wallet_rpc_user_env = NULL;
        const char *wallet_rpc_pass = NULL;
        const char *wallet_rpc_pass_file = NULL;
        const char *wallet_rpc_pass_env = NULL;
        const char *wallet_name = NULL;
        const char *wallet_password_env = NULL;
        const char *idempotency_prefix = "gate3";
        unsigned timeout_s = 20U;
        unsigned retry_max = 8U;
        unsigned poll_interval_s = 5U;

        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--token") == 0) token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-url") == 0) wallet_rpc_url = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user") == 0) wallet_rpc_user = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user-file") == 0) wallet_rpc_user_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user-env") == 0) wallet_rpc_user_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass") == 0) wallet_rpc_pass = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass-file") == 0) wallet_rpc_pass_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass-env") == 0) wallet_rpc_pass_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-name") == 0) wallet_name = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-password-env") == 0) wallet_password_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--idempotency-prefix") == 0) idempotency_prefix = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--timeout-s") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 3600UL) ff_die("invalid --timeout-s: %s", raw);
                timeout_s = (unsigned)v;
            } else if (strcmp(argv[i], "--retry-max") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 100UL) ff_die("invalid --retry-max: %s", raw);
                retry_max = (unsigned)v;
            } else if (strcmp(argv[i], "--poll-interval") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 600UL) ff_die("invalid --poll-interval: %s", raw);
                poll_interval_s = (unsigned)v;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_r3();
                return 0;
            } else {
                ff_die("unknown escrow-r3 option: %s", argv[i]);
            }
        }

        char *wallet_rpc_user_owned = resolve_cli_secret_opt(
            wallet_rpc_user,
            wallet_rpc_user_file,
            wallet_rpc_user_env,
            "escrow-r3 wallet-rpc user",
            "--wallet-rpc-user | --wallet-rpc-user-file | --wallet-rpc-user-env");
        char *wallet_rpc_pass_owned = resolve_cli_secret_opt(
            wallet_rpc_pass,
            wallet_rpc_pass_file,
            wallet_rpc_pass_env,
            "escrow-r3 wallet-rpc pass",
            "--wallet-rpc-pass | --wallet-rpc-pass-file | --wallet-rpc-pass-env");
        const char *wallet_rpc_user_eff = wallet_rpc_user_owned ? wallet_rpc_user_owned : wallet_rpc_user;
        const char *wallet_rpc_pass_eff = wallet_rpc_pass_owned ? wallet_rpc_pass_owned : wallet_rpc_pass;

        if (!base || !base[0] || !id_raw || !nick || !token ||
            !wallet_rpc_url || !wallet_rpc_user_eff || !wallet_rpc_pass_eff ||
            !wallet_name || !wallet_password_env) {
            secure_free_str(&wallet_rpc_user_owned);
            secure_free_str(&wallet_rpc_pass_owned);
            usage_escrow_r3();
            ff_die("escrow-r3 missing required arguments");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) {
            secure_free_str(&wallet_rpc_user_owned);
            secure_free_str(&wallet_rpc_pass_owned);
            ff_die("invalid --id: %s", id_raw);
        }
        int rc = cmd_escrow_r3(
            base, socks5, escrow_id, nick, token,
            wallet_rpc_url, wallet_rpc_user_eff, wallet_rpc_pass_eff,
            wallet_name, wallet_password_env, idempotency_prefix,
            timeout_s, retry_max, poll_interval_s
        );
        secure_free_str(&wallet_rpc_user_owned);
        secure_free_str(&wallet_rpc_pass_owned);
        return rc;
    }

    if (strcmp(cmd, "escrow-r4") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *nick = NULL;
        const char *token = NULL;
        const char *wallet_rpc_url = NULL;
        const char *wallet_rpc_user = NULL;
        const char *wallet_rpc_user_file = NULL;
        const char *wallet_rpc_user_env = NULL;
        const char *wallet_rpc_pass = NULL;
        const char *wallet_rpc_pass_file = NULL;
        const char *wallet_rpc_pass_env = NULL;
        const char *wallet_name = NULL;
        const char *wallet_password_env = NULL;
        unsigned timeout_s = 20U;

        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--token") == 0) token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-url") == 0) wallet_rpc_url = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user") == 0) wallet_rpc_user = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user-file") == 0) wallet_rpc_user_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user-env") == 0) wallet_rpc_user_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass") == 0) wallet_rpc_pass = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass-file") == 0) wallet_rpc_pass_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass-env") == 0) wallet_rpc_pass_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-name") == 0) wallet_name = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-password-env") == 0) wallet_password_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--timeout-s") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 3600UL) ff_die("invalid --timeout-s: %s", raw);
                timeout_s = (unsigned)v;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_r4();
                return 0;
            } else {
                ff_die("unknown escrow-r4 option: %s", argv[i]);
            }
        }

        char *wallet_rpc_user_owned = resolve_cli_secret_opt(
            wallet_rpc_user,
            wallet_rpc_user_file,
            wallet_rpc_user_env,
            "escrow-r4 wallet-rpc user",
            "--wallet-rpc-user | --wallet-rpc-user-file | --wallet-rpc-user-env");
        char *wallet_rpc_pass_owned = resolve_cli_secret_opt(
            wallet_rpc_pass,
            wallet_rpc_pass_file,
            wallet_rpc_pass_env,
            "escrow-r4 wallet-rpc pass",
            "--wallet-rpc-pass | --wallet-rpc-pass-file | --wallet-rpc-pass-env");
        const char *wallet_rpc_user_eff = wallet_rpc_user_owned ? wallet_rpc_user_owned : wallet_rpc_user;
        const char *wallet_rpc_pass_eff = wallet_rpc_pass_owned ? wallet_rpc_pass_owned : wallet_rpc_pass;

        if (!base || !base[0] || !id_raw || !nick || !token ||
            !wallet_rpc_url || !wallet_rpc_user_eff || !wallet_rpc_pass_eff ||
            !wallet_name || !wallet_password_env) {
            secure_free_str(&wallet_rpc_user_owned);
            secure_free_str(&wallet_rpc_pass_owned);
            usage_escrow_r4();
            ff_die("escrow-r4 missing required arguments");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) {
            secure_free_str(&wallet_rpc_user_owned);
            secure_free_str(&wallet_rpc_pass_owned);
            ff_die("invalid --id: %s", id_raw);
        }
        int rc = cmd_escrow_r4(
            base, socks5, escrow_id, nick, token,
            wallet_rpc_url, wallet_rpc_user_eff, wallet_rpc_pass_eff,
            wallet_name, wallet_password_env, timeout_s
        );
        secure_free_str(&wallet_rpc_user_owned);
        secure_free_str(&wallet_rpc_pass_owned);
        return rc;
    }

    if (strcmp(cmd, "escrow-gate3-ready") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *buyer_nick = NULL;
        const char *buyer_token = NULL;
        const char *seller_nick = NULL;
        const char *seller_token = NULL;
        const char *seller_token_db_path = "/var/lib/freeforum-escrow/escrow_rust.db";
        const char *buyer_wallet_rpc_url = NULL;
        const char *buyer_wallet_rpc_user = NULL;
        const char *buyer_wallet_rpc_user_file = NULL;
        const char *buyer_wallet_rpc_user_env = NULL;
        const char *buyer_wallet_rpc_pass = NULL;
        const char *buyer_wallet_rpc_pass_file = NULL;
        const char *buyer_wallet_rpc_pass_env = NULL;
        const char *buyer_wallet_name = NULL;
        const char *buyer_wallet_password_env = NULL;
        const char *seller_wallet_rpc_url = NULL;
        const char *seller_wallet_rpc_user = NULL;
        const char *seller_wallet_rpc_user_file = NULL;
        const char *seller_wallet_rpc_user_env = NULL;
        const char *seller_wallet_rpc_pass = NULL;
        const char *seller_wallet_rpc_pass_file = NULL;
        const char *seller_wallet_rpc_pass_env = NULL;
        const char *seller_wallet_name = NULL;
        const char *seller_wallet_password_env = NULL;
        const char *buyer_refund_address = NULL;
        const char *seller_refund_address = NULL;
        const char *idempotency_prefix = "gate3";
        const char *run_dir = NULL;
        unsigned wait_ready_timeout_s = 900;
        unsigned poll_interval_s = 5;
        unsigned timeout_s = 20;
        unsigned round_retries = 8;

        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-nick") == 0) buyer_nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-token") == 0) buyer_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-nick") == 0) seller_nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-token") == 0) seller_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-token-db-path") == 0) seller_token_db_path = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-wallet-rpc-url") == 0) buyer_wallet_rpc_url = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-wallet-rpc-user") == 0) buyer_wallet_rpc_user = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-wallet-rpc-user-file") == 0) buyer_wallet_rpc_user_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-wallet-rpc-user-env") == 0) buyer_wallet_rpc_user_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-wallet-rpc-pass") == 0) buyer_wallet_rpc_pass = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-wallet-rpc-pass-file") == 0) buyer_wallet_rpc_pass_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-wallet-rpc-pass-env") == 0) buyer_wallet_rpc_pass_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-wallet-name") == 0) buyer_wallet_name = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-wallet-password-env") == 0) buyer_wallet_password_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-rpc-url") == 0) seller_wallet_rpc_url = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-rpc-user") == 0) seller_wallet_rpc_user = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-rpc-user-file") == 0) seller_wallet_rpc_user_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-rpc-user-env") == 0) seller_wallet_rpc_user_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-rpc-pass") == 0) seller_wallet_rpc_pass = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-rpc-pass-file") == 0) seller_wallet_rpc_pass_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-rpc-pass-env") == 0) seller_wallet_rpc_pass_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-name") == 0) seller_wallet_name = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-password-env") == 0) seller_wallet_password_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-refund-address") == 0) buyer_refund_address = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-refund-address") == 0) seller_refund_address = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--idempotency-prefix") == 0) idempotency_prefix = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--run-dir") == 0) run_dir = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wait-ready-timeout") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 86400UL) ff_die("invalid --wait-ready-timeout: %s", raw);
                wait_ready_timeout_s = (unsigned)v;
            } else if (strcmp(argv[i], "--poll-interval") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 600UL) ff_die("invalid --poll-interval: %s", raw);
                poll_interval_s = (unsigned)v;
            } else if (strcmp(argv[i], "--timeout-s") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 3600UL) ff_die("invalid --timeout-s: %s", raw);
                timeout_s = (unsigned)v;
            } else if (strcmp(argv[i], "--round-retries") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 100UL) ff_die("invalid --round-retries: %s", raw);
                round_retries = (unsigned)v;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_gate3_ready();
                return 0;
            } else {
                ff_die("unknown escrow-gate3-ready option: %s", argv[i]);
            }
        }
        char *buyer_wallet_rpc_user_owned = resolve_cli_secret_opt(
            buyer_wallet_rpc_user,
            buyer_wallet_rpc_user_file,
            buyer_wallet_rpc_user_env,
            "escrow-gate3-ready buyer wallet-rpc user",
            "--buyer-wallet-rpc-user | --buyer-wallet-rpc-user-file | --buyer-wallet-rpc-user-env");
        char *buyer_wallet_rpc_pass_owned = resolve_cli_secret_opt(
            buyer_wallet_rpc_pass,
            buyer_wallet_rpc_pass_file,
            buyer_wallet_rpc_pass_env,
            "escrow-gate3-ready buyer wallet-rpc pass",
            "--buyer-wallet-rpc-pass | --buyer-wallet-rpc-pass-file | --buyer-wallet-rpc-pass-env");
        char *seller_wallet_rpc_user_owned = resolve_cli_secret_opt(
            seller_wallet_rpc_user,
            seller_wallet_rpc_user_file,
            seller_wallet_rpc_user_env,
            "escrow-gate3-ready seller wallet-rpc user",
            "--seller-wallet-rpc-user | --seller-wallet-rpc-user-file | --seller-wallet-rpc-user-env");
        char *seller_wallet_rpc_pass_owned = resolve_cli_secret_opt(
            seller_wallet_rpc_pass,
            seller_wallet_rpc_pass_file,
            seller_wallet_rpc_pass_env,
            "escrow-gate3-ready seller wallet-rpc pass",
            "--seller-wallet-rpc-pass | --seller-wallet-rpc-pass-file | --seller-wallet-rpc-pass-env");

        const char *buyer_wallet_rpc_user_eff = buyer_wallet_rpc_user_owned ? buyer_wallet_rpc_user_owned : buyer_wallet_rpc_user;
        const char *buyer_wallet_rpc_pass_eff = buyer_wallet_rpc_pass_owned ? buyer_wallet_rpc_pass_owned : buyer_wallet_rpc_pass;
        const char *seller_wallet_rpc_user_eff = seller_wallet_rpc_user_owned ? seller_wallet_rpc_user_owned : seller_wallet_rpc_user;
        const char *seller_wallet_rpc_pass_eff = seller_wallet_rpc_pass_owned ? seller_wallet_rpc_pass_owned : seller_wallet_rpc_pass;

        if (!base || !base[0] || !id_raw || !buyer_nick || !buyer_token || !seller_nick ||
            !buyer_wallet_rpc_url || !buyer_wallet_rpc_user_eff || !buyer_wallet_rpc_pass_eff ||
            !buyer_wallet_name || !buyer_wallet_password_env ||
            !seller_wallet_rpc_url || !seller_wallet_rpc_user_eff || !seller_wallet_rpc_pass_eff ||
            !seller_wallet_name || !seller_wallet_password_env) {
            secure_free_str(&buyer_wallet_rpc_user_owned);
            secure_free_str(&buyer_wallet_rpc_pass_owned);
            secure_free_str(&seller_wallet_rpc_user_owned);
            secure_free_str(&seller_wallet_rpc_pass_owned);
            usage_escrow_gate3_ready();
            ff_die("escrow-gate3-ready missing required arguments");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) {
            secure_free_str(&buyer_wallet_rpc_user_owned);
            secure_free_str(&buyer_wallet_rpc_pass_owned);
            secure_free_str(&seller_wallet_rpc_user_owned);
            secure_free_str(&seller_wallet_rpc_pass_owned);
            ff_die("invalid --id: %s", id_raw);
        }
        int rc = cmd_escrow_gate3_ready(
            base, socks5, escrow_id,
            buyer_nick, buyer_token,
            seller_nick, seller_token, seller_token_db_path,
            buyer_wallet_rpc_url, buyer_wallet_rpc_user_eff, buyer_wallet_rpc_pass_eff, buyer_wallet_name, buyer_wallet_password_env,
            seller_wallet_rpc_url, seller_wallet_rpc_user_eff, seller_wallet_rpc_pass_eff, seller_wallet_name, seller_wallet_password_env,
            buyer_refund_address, seller_refund_address,
            idempotency_prefix, run_dir,
            wait_ready_timeout_s, poll_interval_s, timeout_s, round_retries
        );
        secure_free_str(&buyer_wallet_rpc_user_owned);
        secure_free_str(&buyer_wallet_rpc_pass_owned);
        secure_free_str(&seller_wallet_rpc_user_owned);
        secure_free_str(&seller_wallet_rpc_pass_owned);
        return rc;
    }

    if (strcmp(cmd, "escrow-fund") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *buyer_nick = NULL;
        const char *buyer_token = NULL;
        const char *wallet_rpc_url = NULL;
        const char *wallet_rpc_user = NULL;
        const char *wallet_rpc_user_file = NULL;
        const char *wallet_rpc_user_env = NULL;
        const char *wallet_rpc_pass = NULL;
        const char *wallet_rpc_pass_file = NULL;
        const char *wallet_rpc_pass_env = NULL;
        const char *wallet_name = NULL;
        const char *wallet_password_env = NULL;
        const char *run_dir = NULL;
        unsigned timeout_s = 120U;
        unsigned long long fund_buffer_atomic = 0ULL;

        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-nick") == 0) buyer_nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-token") == 0) buyer_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-url") == 0) wallet_rpc_url = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user") == 0) wallet_rpc_user = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user-file") == 0) wallet_rpc_user_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-user-env") == 0) wallet_rpc_user_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass") == 0) wallet_rpc_pass = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass-file") == 0) wallet_rpc_pass_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-rpc-pass-env") == 0) wallet_rpc_pass_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-name") == 0) wallet_name = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wallet-password-env") == 0) wallet_password_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--run-dir") == 0) run_dir = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--fund-buffer-atomic") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                fund_buffer_atomic = strtoull(raw, &endp, 10);
                if (endp == raw || (endp && *endp)) ff_die("invalid --fund-buffer-atomic: %s", raw);
            } else if (strcmp(argv[i], "--timeout-s") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 3600UL) ff_die("invalid --timeout-s: %s", raw);
                timeout_s = (unsigned)v;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_fund();
                return 0;
            } else {
                ff_die("unknown escrow-fund option: %s", argv[i]);
            }
        }

        char *wallet_rpc_user_owned = resolve_cli_secret_opt(
            wallet_rpc_user,
            wallet_rpc_user_file,
            wallet_rpc_user_env,
            "escrow-fund wallet-rpc user",
            "--wallet-rpc-user | --wallet-rpc-user-file | --wallet-rpc-user-env");
        char *wallet_rpc_pass_owned = resolve_cli_secret_opt(
            wallet_rpc_pass,
            wallet_rpc_pass_file,
            wallet_rpc_pass_env,
            "escrow-fund wallet-rpc pass",
            "--wallet-rpc-pass | --wallet-rpc-pass-file | --wallet-rpc-pass-env");
        const char *wallet_rpc_user_eff = wallet_rpc_user_owned ? wallet_rpc_user_owned : wallet_rpc_user;
        const char *wallet_rpc_pass_eff = wallet_rpc_pass_owned ? wallet_rpc_pass_owned : wallet_rpc_pass;

        if (!base || !base[0] || !id_raw || !buyer_nick || !buyer_token ||
            !wallet_rpc_url || !wallet_rpc_user_eff || !wallet_rpc_pass_eff ||
            !wallet_name || !wallet_password_env) {
            secure_free_str(&wallet_rpc_user_owned);
            secure_free_str(&wallet_rpc_pass_owned);
            usage_escrow_fund();
            ff_die("escrow-fund missing required arguments");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) {
            secure_free_str(&wallet_rpc_user_owned);
            secure_free_str(&wallet_rpc_pass_owned);
            ff_die("invalid --id: %s", id_raw);
        }

        int rc = cmd_escrow_fund(
            base, socks5, escrow_id, buyer_nick, buyer_token,
            wallet_rpc_url, wallet_rpc_user_eff, wallet_rpc_pass_eff,
            wallet_name, wallet_password_env, run_dir, fund_buffer_atomic, timeout_s
        );
        secure_free_str(&wallet_rpc_user_owned);
        secure_free_str(&wallet_rpc_pass_owned);
        return rc;
    }

    if (strcmp(cmd, "escrow-wait-state") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *nick = NULL;
        const char *token = NULL;
        const char *state = NULL;
        const char *run_dir = NULL;
        unsigned wait_timeout_s = 1800U;
        unsigned poll_interval_s = 5U;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--token") == 0) token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--state") == 0) state = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--run-dir") == 0) run_dir = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wait-timeout") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 86400UL) ff_die("invalid --wait-timeout: %s", raw);
                wait_timeout_s = (unsigned)v;
            } else if (strcmp(argv[i], "--poll-interval") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 600UL) ff_die("invalid --poll-interval: %s", raw);
                poll_interval_s = (unsigned)v;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_wait_state();
                return 0;
            } else {
                ff_die("unknown escrow-wait-state option: %s", argv[i]);
            }
        }
        if (!base || !base[0] || !id_raw || !nick || !token || !state) {
            usage_escrow_wait_state();
            ff_die("escrow-wait-state requires --base --id --nick --token --state");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) ff_die("invalid --id: %s", id_raw);
        return cmd_escrow_wait_state(
            base, socks5, escrow_id, nick, token, state, run_dir, wait_timeout_s, poll_interval_s
        );
    }

    if (strcmp(cmd, "escrow-wait-funded") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *nick = NULL;
        const char *token = NULL;
        const char *run_dir = NULL;
        unsigned wait_timeout_s = 1800U;
        unsigned poll_interval_s = 5U;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--token") == 0) token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--run-dir") == 0) run_dir = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--wait-timeout") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 86400UL) ff_die("invalid --wait-timeout: %s", raw);
                wait_timeout_s = (unsigned)v;
            } else if (strcmp(argv[i], "--poll-interval") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 600UL) ff_die("invalid --poll-interval: %s", raw);
                poll_interval_s = (unsigned)v;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_wait_funded();
                return 0;
            } else {
                ff_die("unknown escrow-wait-funded option: %s", argv[i]);
            }
        }
        if (!base || !base[0] || !id_raw || !nick || !token) {
            usage_escrow_wait_funded();
            ff_die("escrow-wait-funded requires --base --id --nick --token");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) ff_die("invalid --id: %s", id_raw);
        return cmd_escrow_wait_funded(
            base, socks5, escrow_id, nick, token, run_dir, wait_timeout_s, poll_interval_s
        );
    }

    if (strcmp(cmd, "escrow-funded-sync") == 0) {
        const char *orch_bin = NULL;
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        int allow_non_tor = 0;
        const char *id_raw = NULL;
        const char *buyer_nick = NULL;
        const char *buyer_token = NULL;
        const char *arbiter_nick = NULL;
        const char *arbiter_token = NULL;
        const char *arbiter_token_fallback = NULL;
        const char *buyer_rpc_endpoint = NULL;
        const char *buyer_rpc_user = NULL;
        const char *buyer_rpc_user_file = NULL;
        const char *buyer_rpc_user_env = NULL;
        const char *buyer_rpc_pass = NULL;
        const char *buyer_rpc_pass_file = NULL;
        const char *buyer_rpc_pass_env = NULL;
        const char *buyer_wallet_name = NULL;
        const char *buyer_wallet_pass = NULL;
        const char *buyer_wallet_pass_file = NULL;
        const char *buyer_wallet_pass_env = NULL;
        const char *seller_rpc_endpoint = NULL;
        const char *seller_rpc_user = NULL;
        const char *seller_rpc_user_file = NULL;
        const char *seller_rpc_user_env = NULL;
        const char *seller_rpc_pass = NULL;
        const char *seller_rpc_pass_file = NULL;
        const char *seller_rpc_pass_env = NULL;
        const char *seller_wallet_name = NULL;
        const char *seller_wallet_pass = NULL;
        const char *seller_wallet_pass_file = NULL;
        const char *seller_wallet_pass_env = NULL;
        const char *run_dir = NULL;
        unsigned funded_timeout_s = 1800U;
        unsigned poll_interval_s = 10U;
        unsigned http_timeout_s = 120U;

        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--orch-bin") == 0) orch_bin = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--allow-non-tor") == 0) allow_non_tor = 1;
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-nick") == 0) buyer_nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-token") == 0) buyer_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--arbiter-nick") == 0) arbiter_nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--arbiter-token") == 0) arbiter_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--arbiter-token-fallback") == 0) arbiter_token_fallback = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-rpc-endpoint") == 0) buyer_rpc_endpoint = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-rpc-user") == 0) buyer_rpc_user = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-rpc-user-file") == 0) buyer_rpc_user_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-rpc-user-env") == 0) buyer_rpc_user_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-rpc-pass") == 0) buyer_rpc_pass = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-rpc-pass-file") == 0) buyer_rpc_pass_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-rpc-pass-env") == 0) buyer_rpc_pass_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-wallet-name") == 0) buyer_wallet_name = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-wallet-pass") == 0) buyer_wallet_pass = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-wallet-pass-file") == 0) buyer_wallet_pass_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--buyer-wallet-pass-env") == 0) buyer_wallet_pass_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-rpc-endpoint") == 0) seller_rpc_endpoint = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-rpc-user") == 0) seller_rpc_user = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-rpc-user-file") == 0) seller_rpc_user_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-rpc-user-env") == 0) seller_rpc_user_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-rpc-pass") == 0) seller_rpc_pass = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-rpc-pass-file") == 0) seller_rpc_pass_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-rpc-pass-env") == 0) seller_rpc_pass_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-name") == 0) seller_wallet_name = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-pass") == 0) seller_wallet_pass = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-pass-file") == 0) seller_wallet_pass_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-pass-env") == 0) seller_wallet_pass_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--run-dir") == 0) run_dir = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--funded-timeout") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 86400UL) ff_die("invalid --funded-timeout: %s", raw);
                funded_timeout_s = (unsigned)v;
            } else if (strcmp(argv[i], "--poll-interval") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 600UL) ff_die("invalid --poll-interval: %s", raw);
                poll_interval_s = (unsigned)v;
            } else if (strcmp(argv[i], "--http-timeout") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long v = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || v > 3600UL) ff_die("invalid --http-timeout: %s", raw);
                http_timeout_s = (unsigned)v;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_funded_sync();
                return 0;
            } else {
                ff_die("unknown escrow-funded-sync option: %s", argv[i]);
            }
        }

        char *buyer_rpc_user_owned = resolve_cli_secret_opt(
            buyer_rpc_user, buyer_rpc_user_file, buyer_rpc_user_env,
            "escrow-funded-sync buyer rpc user",
            "--buyer-rpc-user | --buyer-rpc-user-file | --buyer-rpc-user-env");
        char *buyer_rpc_pass_owned = resolve_cli_secret_opt(
            buyer_rpc_pass, buyer_rpc_pass_file, buyer_rpc_pass_env,
            "escrow-funded-sync buyer rpc pass",
            "--buyer-rpc-pass | --buyer-rpc-pass-file | --buyer-rpc-pass-env");
        char *buyer_wallet_pass_owned = resolve_cli_secret_opt(
            buyer_wallet_pass, buyer_wallet_pass_file, buyer_wallet_pass_env,
            "escrow-funded-sync buyer wallet pass",
            "--buyer-wallet-pass | --buyer-wallet-pass-file | --buyer-wallet-pass-env");
        char *seller_rpc_user_owned = resolve_cli_secret_opt(
            seller_rpc_user, seller_rpc_user_file, seller_rpc_user_env,
            "escrow-funded-sync seller rpc user",
            "--seller-rpc-user | --seller-rpc-user-file | --seller-rpc-user-env");
        char *seller_rpc_pass_owned = resolve_cli_secret_opt(
            seller_rpc_pass, seller_rpc_pass_file, seller_rpc_pass_env,
            "escrow-funded-sync seller rpc pass",
            "--seller-rpc-pass | --seller-rpc-pass-file | --seller-rpc-pass-env");
        char *seller_wallet_pass_owned = resolve_cli_secret_opt(
            seller_wallet_pass, seller_wallet_pass_file, seller_wallet_pass_env,
            "escrow-funded-sync seller wallet pass",
            "--seller-wallet-pass | --seller-wallet-pass-file | --seller-wallet-pass-env");

        const char *buyer_rpc_user_eff = buyer_rpc_user_owned ? buyer_rpc_user_owned : buyer_rpc_user;
        const char *buyer_rpc_pass_eff = buyer_rpc_pass_owned ? buyer_rpc_pass_owned : buyer_rpc_pass;
        const char *buyer_wallet_pass_eff = buyer_wallet_pass_owned ? buyer_wallet_pass_owned : buyer_wallet_pass;
        const char *seller_rpc_user_eff = seller_rpc_user_owned ? seller_rpc_user_owned : seller_rpc_user;
        const char *seller_rpc_pass_eff = seller_rpc_pass_owned ? seller_rpc_pass_owned : seller_rpc_pass;
        const char *seller_wallet_pass_eff = seller_wallet_pass_owned ? seller_wallet_pass_owned : seller_wallet_pass;

        if (!base || !base[0] || !id_raw ||
            !buyer_nick || !buyer_token || !arbiter_nick || !arbiter_token ||
            !buyer_rpc_endpoint || !buyer_rpc_user_eff || !buyer_rpc_pass_eff ||
            !buyer_wallet_name || !buyer_wallet_pass_eff ||
            !seller_rpc_endpoint || !seller_rpc_user_eff || !seller_rpc_pass_eff ||
            !seller_wallet_name || !seller_wallet_pass_eff) {
            secure_free_str(&buyer_rpc_user_owned);
            secure_free_str(&buyer_rpc_pass_owned);
            secure_free_str(&buyer_wallet_pass_owned);
            secure_free_str(&seller_rpc_user_owned);
            secure_free_str(&seller_rpc_pass_owned);
            secure_free_str(&seller_wallet_pass_owned);
            usage_escrow_funded_sync();
            ff_die("escrow-funded-sync missing required arguments");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) {
            secure_free_str(&buyer_rpc_user_owned);
            secure_free_str(&buyer_rpc_pass_owned);
            secure_free_str(&buyer_wallet_pass_owned);
            secure_free_str(&seller_rpc_user_owned);
            secure_free_str(&seller_rpc_pass_owned);
            secure_free_str(&seller_wallet_pass_owned);
            ff_die("invalid --id: %s", id_raw);
        }

        int rc = cmd_escrow_funded_sync(
            orch_bin,
            base, socks5, allow_non_tor,
            escrow_id,
            buyer_nick, buyer_token,
            arbiter_nick, arbiter_token, arbiter_token_fallback,
            buyer_rpc_endpoint, buyer_rpc_user_eff, buyer_rpc_pass_eff, buyer_wallet_name, buyer_wallet_pass_eff,
            seller_rpc_endpoint, seller_rpc_user_eff, seller_rpc_pass_eff, seller_wallet_name, seller_wallet_pass_eff,
            run_dir,
            funded_timeout_s, poll_interval_s, http_timeout_s
        );
        secure_free_str(&buyer_rpc_user_owned);
        secure_free_str(&buyer_rpc_pass_owned);
        secure_free_str(&buyer_wallet_pass_owned);
        secure_free_str(&seller_rpc_user_owned);
        secure_free_str(&seller_rpc_pass_owned);
        secure_free_str(&seller_wallet_pass_owned);
        return rc;
    }

    if (strcmp(cmd, "escrow-proposal") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *nick = NULL;
        const char *token = NULL;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--token") == 0) token = arg_val(&i, argc, argv);
        }
        if (!id_raw || !nick || !token) ff_die("escrow-proposal requires --id --nick --token");
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) ff_die("invalid --id: %s", id_raw);
        return cmd_escrow_proposal_show(base, socks5, escrow_id, nick, token);
    }

    if (strcmp(cmd, "escrow-confirm-release") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *nick = NULL;
        const char *token = NULL;
        const char *txid = NULL;
        const char *idempotency_prefix = "stagenet-live";
        int retry_max = 0;
        unsigned retry_backoff_ms = 1200U;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--token") == 0) token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--txid") == 0) txid = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--idempotency-prefix") == 0) idempotency_prefix = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--retry-max") == 0) {
                retry_max = parse_nonneg_int_cli_or_die(arg_val(&i, argc, argv), "--retry-max", 1000);
            }
            else if (strcmp(argv[i], "--retry-backoff-ms") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long parsed = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || parsed > 120000UL) ff_die("invalid --retry-backoff-ms: %s", raw);
                retry_backoff_ms = (unsigned)parsed;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_confirm_release();
                return 0;
            } else {
                ff_die("unknown escrow-confirm-release option: %s", argv[i]);
            }
        }
        if (!id_raw || !nick || !token || !txid) {
            usage_escrow_confirm_release();
            ff_die("escrow-confirm-release requires --id --nick --token --txid");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) ff_die("invalid --id: %s", id_raw);
        return cmd_escrow_confirm_release(
            base, socks5, escrow_id, nick, token, txid,
            idempotency_prefix, retry_max, retry_backoff_ms
        );
    }

    if (strcmp(cmd, "escrow-confirm-refund") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *nick = NULL;
        const char *token = NULL;
        const char *txid = NULL;
        const char *idempotency_prefix = "stagenet-live";
        int retry_max = 0;
        unsigned retry_backoff_ms = 1200U;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--token") == 0) token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--txid") == 0) txid = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--idempotency-prefix") == 0) idempotency_prefix = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--retry-max") == 0) {
                retry_max = parse_nonneg_int_cli_or_die(arg_val(&i, argc, argv), "--retry-max", 1000);
            }
            else if (strcmp(argv[i], "--retry-backoff-ms") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long parsed = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || parsed > 120000UL) ff_die("invalid --retry-backoff-ms: %s", raw);
                retry_backoff_ms = (unsigned)parsed;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_confirm_refund();
                return 0;
            } else {
                ff_die("unknown escrow-confirm-refund option: %s", argv[i]);
            }
        }
        if (!id_raw || !nick || !token || !txid) {
            usage_escrow_confirm_refund();
            ff_die("escrow-confirm-refund requires --id --nick --token --txid");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) ff_die("invalid --id: %s", id_raw);
        return cmd_escrow_confirm_refund(
            base, socks5, escrow_id, nick, token, txid,
            idempotency_prefix, retry_max, retry_backoff_ms
        );
    }

    if (strcmp(cmd, "escrow-release") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *nick = NULL;
        const char *token = NULL;
        const char *tx_data_hex = NULL;
        const char *txid = NULL;
        const char *signer_wallet_password = NULL;
        const char *signer_wallet_password_file = NULL;
        const char *signer_wallet_password_env = NULL;
        const char *signer_action_token = NULL;
        const char *signer_action_token_file = NULL;
        const char *signer_action_token_env = NULL;
        const char *signer_sign_action_token = NULL;
        const char *signer_sign_action_token_file = NULL;
        const char *signer_sign_action_token_env = NULL;
        const char *signer_submit_action_token = NULL;
        const char *signer_submit_action_token_file = NULL;
        const char *signer_submit_action_token_env = NULL;
        const char *idempotency_key = NULL;
        int retry_max = 0;
        unsigned retry_backoff_ms = 1200;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--token") == 0) token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--tx-data-hex") == 0) tx_data_hex = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--txid") == 0) txid = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-wallet-password") == 0) signer_wallet_password = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-wallet-password-file") == 0) signer_wallet_password_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-wallet-password-env") == 0) signer_wallet_password_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-action-token") == 0) signer_action_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-action-token-file") == 0) signer_action_token_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-action-token-env") == 0) signer_action_token_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-sign-action-token") == 0) signer_sign_action_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-sign-action-token-file") == 0) signer_sign_action_token_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-sign-action-token-env") == 0) signer_sign_action_token_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-submit-action-token") == 0) signer_submit_action_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-submit-action-token-file") == 0) signer_submit_action_token_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-submit-action-token-env") == 0) signer_submit_action_token_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--idempotency-key") == 0) idempotency_key = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--retry-max") == 0) {
                retry_max = parse_nonneg_int_cli_or_die(arg_val(&i, argc, argv), "--retry-max", 1000);
            }
            else if (strcmp(argv[i], "--retry-backoff-ms") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long parsed = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || parsed > 120000UL) {
                    ff_die("invalid --retry-backoff-ms: %s", raw);
                }
                retry_backoff_ms = (unsigned)parsed;
            }
        }
        if (!id_raw || !nick || !token) ff_die("escrow-release requires --id --nick --token");
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) ff_die("invalid --id: %s", id_raw);
        char *signer_wallet_password_owned = resolve_cli_secret_opt(
            signer_wallet_password,
            signer_wallet_password_file,
            signer_wallet_password_env,
            "escrow-release signer wallet password",
            "--signer-wallet-password | --signer-wallet-password-file | --signer-wallet-password-env");
        const char *signer_wallet_password_eff =
            signer_wallet_password_owned ? signer_wallet_password_owned : signer_wallet_password;
        int rc = cmd_escrow_release(
            base, socks5, escrow_id, nick, token,
            tx_data_hex, txid, signer_wallet_password_eff,
            signer_action_token, signer_action_token_file, signer_action_token_env,
            signer_sign_action_token, signer_sign_action_token_file, signer_sign_action_token_env,
            signer_submit_action_token, signer_submit_action_token_file, signer_submit_action_token_env,
            idempotency_key, retry_max, retry_backoff_ms
        );
        secure_free_str(&signer_wallet_password_owned);
        return rc;
    }

    if (strcmp(cmd, "escrow-refund") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *nick = NULL;
        const char *token = NULL;
        const char *tx_data_hex = NULL;
        const char *txid = NULL;
        const char *signer_action_token = NULL;
        const char *signer_action_token_file = NULL;
        const char *signer_action_token_env = NULL;
        const char *idempotency_key = NULL;
        int retry_max = 0;
        unsigned retry_backoff_ms = 1200;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--token") == 0) token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--tx-data-hex") == 0) tx_data_hex = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--txid") == 0) txid = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-action-token") == 0) signer_action_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-action-token-file") == 0) signer_action_token_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--signer-action-token-env") == 0) signer_action_token_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--idempotency-key") == 0) idempotency_key = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--retry-max") == 0) {
                retry_max = parse_nonneg_int_cli_or_die(arg_val(&i, argc, argv), "--retry-max", 1000);
            }
            else if (strcmp(argv[i], "--retry-backoff-ms") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long parsed = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || parsed > 120000UL) {
                    ff_die("invalid --retry-backoff-ms: %s", raw);
                }
                retry_backoff_ms = (unsigned)parsed;
            }
        }
        if (!id_raw || !nick || !token) ff_die("escrow-refund requires --id --nick --token");
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) ff_die("invalid --id: %s", id_raw);
        return cmd_escrow_refund(
            base, socks5, escrow_id, nick, token,
            tx_data_hex, txid,
            signer_action_token, signer_action_token_file, signer_action_token_env,
            idempotency_key, retry_max, retry_backoff_ms
        );
    }

    if (strcmp(cmd, "escrow-release-pipeline") == 0) {
        const char *base = cfg.base;
        const char *socks5 = cfg.socks5;
        const char *id_raw = NULL;
        const char *seller_nick = NULL;
        const char *seller_token = NULL;
        const char *arbiter_nick = NULL;
        const char *arbiter_token = NULL;
        const char *seller_wallet_password = NULL;
        const char *seller_wallet_password_file = NULL;
        const char *seller_wallet_password_env = NULL;
        const char *seller_signer_action_token = NULL;
        const char *seller_signer_action_token_file = NULL;
        const char *seller_signer_action_token_env = NULL;
        const char *seller_signer_sign_action_token = NULL;
        const char *seller_signer_sign_action_token_file = NULL;
        const char *seller_signer_sign_action_token_env = NULL;
        const char *seller_signer_submit_action_token = NULL;
        const char *seller_signer_submit_action_token_file = NULL;
        const char *seller_signer_submit_action_token_env = NULL;
        const char *arbiter_signer_action_token = NULL;
        const char *arbiter_signer_action_token_file = NULL;
        const char *arbiter_signer_action_token_env = NULL;
        const char *arbiter_signer_submit_action_token = NULL;
        const char *arbiter_signer_submit_action_token_file = NULL;
        const char *arbiter_signer_submit_action_token_env = NULL;
        const char *idempotency_prefix = NULL;
        int retry_max = 0;
        unsigned retry_backoff_ms = 1200;

        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--base") == 0) base = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--socks5") == 0) socks5 = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--id") == 0) id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-nick") == 0) seller_nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-token") == 0) seller_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--arbiter-nick") == 0) arbiter_nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--arbiter-token") == 0) arbiter_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-password") == 0) seller_wallet_password = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-password-file") == 0) seller_wallet_password_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-wallet-password-env") == 0) seller_wallet_password_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-signer-action-token") == 0) seller_signer_action_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-signer-action-token-file") == 0) seller_signer_action_token_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-signer-action-token-env") == 0) seller_signer_action_token_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-signer-sign-action-token") == 0) seller_signer_sign_action_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-signer-sign-action-token-file") == 0) seller_signer_sign_action_token_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-signer-sign-action-token-env") == 0) seller_signer_sign_action_token_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-signer-submit-action-token") == 0) seller_signer_submit_action_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-signer-submit-action-token-file") == 0) seller_signer_submit_action_token_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--seller-signer-submit-action-token-env") == 0) seller_signer_submit_action_token_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--arbiter-signer-action-token") == 0) arbiter_signer_action_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--arbiter-signer-action-token-file") == 0) arbiter_signer_action_token_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--arbiter-signer-action-token-env") == 0) arbiter_signer_action_token_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--arbiter-signer-submit-action-token") == 0) arbiter_signer_submit_action_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--arbiter-signer-submit-action-token-file") == 0) arbiter_signer_submit_action_token_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--arbiter-signer-submit-action-token-env") == 0) arbiter_signer_submit_action_token_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--idempotency-prefix") == 0) idempotency_prefix = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--retry-max") == 0) {
                retry_max = parse_nonneg_int_cli_or_die(arg_val(&i, argc, argv), "--retry-max", 1000);
            }
            else if (strcmp(argv[i], "--retry-backoff-ms") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long parsed = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || parsed > 120000UL) {
                    ff_die("invalid --retry-backoff-ms: %s", raw);
                }
                retry_backoff_ms = (unsigned)parsed;
            }
        }

        if (!id_raw || !seller_nick || !seller_token || !arbiter_nick || !arbiter_token) {
            ff_die("escrow-release-pipeline requires --id --seller-nick --seller-token --arbiter-nick --arbiter-token");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(id_raw, &endp, 10);
        if (endp == id_raw || (endp && *endp)) ff_die("invalid --id: %s", id_raw);
        char *seller_wallet_password_owned = resolve_cli_secret_opt(
            seller_wallet_password,
            seller_wallet_password_file,
            seller_wallet_password_env,
            "escrow-release-pipeline seller wallet password",
            "--seller-wallet-password | --seller-wallet-password-file | --seller-wallet-password-env");
        const char *seller_wallet_password_eff =
            seller_wallet_password_owned ? seller_wallet_password_owned : seller_wallet_password;
        int rc = cmd_escrow_release_pipeline(
            base,
            socks5,
            escrow_id,
            seller_nick,
            seller_token,
            arbiter_nick,
            arbiter_token,
            seller_wallet_password_eff,
            seller_signer_action_token,
            seller_signer_action_token_file,
            seller_signer_action_token_env,
            seller_signer_sign_action_token,
            seller_signer_sign_action_token_file,
            seller_signer_sign_action_token_env,
            seller_signer_submit_action_token,
            seller_signer_submit_action_token_file,
            seller_signer_submit_action_token_env,
            arbiter_signer_action_token,
            arbiter_signer_action_token_file,
            arbiter_signer_action_token_env,
            arbiter_signer_submit_action_token,
            arbiter_signer_submit_action_token_file,
            arbiter_signer_submit_action_token_env,
            idempotency_prefix,
            retry_max,
            retry_backoff_ms
        );
        secure_free_str(&seller_wallet_password_owned);
        return rc;
    }

    if (strcmp(cmd, "worker-route-set") == 0) {
        const char *escrow_id_hex = NULL;
        const char *role = NULL;
        const char *endpoint = NULL;
        const char *orch_db = NULL;
        const char *orch_bin = NULL;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--escrow-id-hex") == 0) escrow_id_hex = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--role") == 0) role = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--endpoint") == 0) endpoint = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--orch-db") == 0) orch_db = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--orch-bin") == 0) orch_bin = arg_val(&i, argc, argv);
        }
        if (!escrow_id_hex || !role || !endpoint) {
            ff_die("worker-route-set requires --escrow-id-hex --role --endpoint");
        }
        return cmd_worker_route_set(orch_bin, orch_db, escrow_id_hex, role, endpoint);
    }

    if (strcmp(cmd, "escrow-arbiter-token") == 0) {
        const char *escrow_id_raw = NULL;
        const char *master_token = NULL;
        const char *master_token_file = NULL;
        const char *master_token_env = NULL;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--escrow-id") == 0) escrow_id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--master-token") == 0) master_token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--master-token-file") == 0) master_token_file = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--master-token-env") == 0) master_token_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_arbiter_token();
                return 0;
            } else {
                ff_die("unknown escrow-arbiter-token option: %s", argv[i]);
            }
        }
        if (!escrow_id_raw) {
            usage_escrow_arbiter_token();
            ff_die("escrow-arbiter-token requires --escrow-id");
        }
        if (!master_token && !master_token_file && !master_token_env) {
            master_token_env = "ESCROW_ARBITER_TOKEN";
        }
        char *master_token_owned = resolve_cli_secret_opt(
            master_token,
            master_token_file,
            master_token_env,
            "escrow-arbiter-token master token",
            "--master-token | --master-token-file | --master-token-env");
        if (!master_token_owned || !master_token_owned[0]) {
            secure_free_str(&master_token_owned);
            ff_die("escrow-arbiter-token missing master token");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(escrow_id_raw, &endp, 10);
        if (endp == escrow_id_raw || (endp && *endp)) {
            secure_free_str(&master_token_owned);
            ff_die("invalid --escrow-id: %s", escrow_id_raw);
        }
        int rc = cmd_escrow_arbiter_token(escrow_id, master_token_owned);
        secure_free_str(&master_token_owned);
        return rc;
    }

    if (strcmp(cmd, "escrow-token-from-db") == 0) {
        const char *db_path = NULL;
        const char *escrow_id_raw = NULL;
        const char *role = NULL;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--db-path") == 0) db_path = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--escrow-id") == 0) escrow_id_raw = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--role") == 0) role = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_escrow_token_from_db();
                return 0;
            } else {
                ff_die("unknown escrow-token-from-db option: %s", argv[i]);
            }
        }
        if (!db_path || !escrow_id_raw || !role) {
            usage_escrow_token_from_db();
            ff_die("escrow-token-from-db requires --db-path --escrow-id --role");
        }
        char *endp = NULL;
        unsigned long long escrow_id = strtoull(escrow_id_raw, &endp, 10);
        if (endp == escrow_id_raw || (endp && *endp)) ff_die("invalid --escrow-id: %s", escrow_id_raw);
        return cmd_escrow_token_from_db(db_path, escrow_id, role);
    }

    if (strcmp(cmd, "env-export-visible-flow") == 0) {
        const char *out_dir = "VISIBLE_FLOW";
        const char *base_url = "http://127.0.0.1:9000";
        const char *db_path = "/var/lib/freeforum-escrow/escrow_rust.db";
        const char *nx_conf = "/etc/conf.d/nx-escrow-rs";
        const char *real3p_env = "/var/lib/monero/real3p_20260218_105633/credentials.env";
        int include_real3p = 0;
        int include_tokens = 0;
        int include_config_secrets = 0;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--out-dir") == 0) out_dir = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--base-url") == 0) base_url = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--db-path") == 0) db_path = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nx-conf") == 0) nx_conf = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--real3p-env") == 0) real3p_env = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--include-real3p") == 0) include_real3p = 1;
            else if (strcmp(argv[i], "--include-tokens") == 0) include_tokens = 1;
            else if (strcmp(argv[i], "--include-config-secrets") == 0) include_config_secrets = 1;
            else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage_env_export_visible_flow();
                return 0;
            } else {
                ff_die("unknown env-export-visible-flow option: %s", argv[i]);
            }
        }
        return cmd_env_export_visible_flow(
            out_dir,
            base_url,
            db_path,
            nx_conf,
            real3p_env,
            include_real3p,
            include_tokens,
            include_config_secrets
        );
    }

    if (strcmp(cmd, "worker-route-show") == 0) {
        const char *escrow_id_hex = NULL;
        const char *role = NULL;
        const char *orch_db = NULL;
        const char *orch_bin = NULL;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--escrow-id-hex") == 0) escrow_id_hex = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--role") == 0) role = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--orch-db") == 0) orch_db = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--orch-bin") == 0) orch_bin = arg_val(&i, argc, argv);
        }
        if (!escrow_id_hex || !role) {
            ff_die("worker-route-show requires --escrow-id-hex --role");
        }
        return cmd_worker_route_show(orch_bin, orch_db, escrow_id_hex, role);
    }

    if (strcmp(cmd, "worker-route-reconcile") == 0) {
        const char *orch_db = NULL;
        const char *orch_bin = NULL;
        unsigned long long stale_after_ms = 86400000ULL;
        unsigned limit = 500;
        int include_terminal = 0;
        int fail_on_findings = 0;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--stale-after-ms") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                stale_after_ms = strtoull(raw, &endp, 10);
                if (endp == raw || (endp && *endp)) ff_die("invalid --stale-after-ms: %s", raw);
            } else if (strcmp(argv[i], "--limit") == 0) {
                const char *raw = arg_val(&i, argc, argv);
                char *endp = NULL;
                unsigned long parsed = strtoul(raw, &endp, 10);
                if (endp == raw || (endp && *endp) || parsed > 100000UL) {
                    ff_die("invalid --limit: %s", raw);
                }
                limit = (unsigned)parsed;
            } else if (strcmp(argv[i], "--include-terminal") == 0) {
                include_terminal = 1;
            } else if (strcmp(argv[i], "--fail-on-findings") == 0) {
                fail_on_findings = 1;
            } else if (strcmp(argv[i], "--orch-db") == 0) {
                orch_db = arg_val(&i, argc, argv);
            } else if (strcmp(argv[i], "--orch-bin") == 0) {
                orch_bin = arg_val(&i, argc, argv);
            }
        }
        return cmd_worker_route_reconcile(
            orch_bin,
            orch_db,
            stale_after_ms,
            include_terminal,
            limit,
            fail_on_findings
        );
    }

    if (strcmp(cmd, "list-kem") == 0) {
        const char *filter = NULL;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--config") == 0) {
                i++;
                continue;
            }
            if (argv[i][0] == '-') continue;
            filter = argv[i];
            break;
        }
        return cmd_list_kem(filter);
    }

    if (strcmp(cmd, "pow-solve") == 0) {
        const char *purpose = NULL;
        const char *token = NULL;
        const char *nick = NULL;
        int difficulty = 0;
        uint64_t start = 0;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--purpose") == 0) purpose = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--token") == 0) token = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--nick") == 0) nick = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--difficulty") == 0) difficulty = atoi(arg_val(&i, argc, argv));
            else if (strcmp(argv[i], "--start") == 0) start = (uint64_t)strtoull(arg_val(&i, argc, argv), NULL, 10);
        }
        if (!purpose || !token || !nick || difficulty <= 0) ff_die("pow-solve requires --purpose --token --nick --difficulty");
        return cmd_pow_solve_cli(token, purpose, nick, difficulty, start);
    }

    if (strcmp(cmd, "respond") == 0) {
        const char *challenge = NULL;
        for (int i = arg_start; i < argc; i++) {
            if (strcmp(argv[i], "--challenge") == 0) challenge = arg_val(&i, argc, argv);
            else if (strcmp(argv[i], "--dir") == 0) ff_strlcpy(dir, arg_val(&i, argc, argv), sizeof(dir));
        }
        if (!challenge) ff_die("--challenge required");
        return cmd_respond(dir, challenge);
    }

    usage();
    return 1;
}
