#!/bin/bash
# OPS: NXMS STACK v2 — rownolegle instancje all-in-one jako "zadania" dockerowe
# z REALNA granica Monero (wallet-rpc 0.18.5) i prawdziwym escrow multisig 2/3.
#
# Kazde zadanie task-NN = osobny kontener Alpine (host network) z:
#   - wlasnym Tor + ukryta usluga (.onion; relacje Tor-only),
#   - rola mailbox (nxms-mailbox) na 127.0.0.1:41NN,
#   - dwoma signerami (nxms-signer) przez socks5h wlasnego Tor do .onion mailboxa,
#   - DWOMA realnymi wallet-rpc (monero 0.18.5) na 127.0.0.1:43NN/44NN z
#     wlasnym portfelem multisig 2/3 (escrow_wallet_a/b; ceremonia wg monerodocs).
# Sterta escrow 2/3 powstaje przy provision (prepare -> make_multisig 2 ->
# exchange_multisig_keys x2, z obejsciem buga zapisu 0.18.5.0: ask-password 0).
#
# Stan instancji: ~/.local/share/nxms-stack/task-NN/ (configi, sekrety, portfele,
# logi, klucze .onion). Rekord zadan: ~/.local/share/nxms-tasks/task-NN.json
# (dashboard /api/tasks/status + nxms-exporter w Grafanie).
#
# Usage: bash tools/nxms-stack.sh {up [N]|status|fund|down|clean}
#   up [N]  — N instancji all-in-one (domyslnie 2; ceremonie portfeli w srodku)
#   status  — odswiez stany rol, kroki i adresy escrow
#   fund    — dofinansuj escrow instancji z faucetu (NXMS_STACK_FUND_XMR)
#   down    — usun kontenery (stan i portfele zostaja)
#   clean   — usun kontenery i caly stan instancji
set -u

STATE=${NXMS_STACK_STATE:-$HOME/.local/share/nxms-stack}
TASKS=${NXMS_TASKS_STATE:-$HOME/.local/share/nxms-tasks}
DEV=${NXMS_STACK_DEV_CONTAINER:-nexum-alpine-dev}
CT=${NXMS_STACK_IMAGE:-alpine:3.23}
MONERO_PKG=${NXMS_STACK_MONERO_PKG:-monero=0.18.5.0-r0}
DAEMON=${NXMS_STACK_DAEMON:-http://127.0.0.1:38081}
FUND_XMR=${NXMS_STACK_FUND_XMR:-0.005}
RPC_USER=${NXMS_LAB_RPC_USER:-wallet-rpc-user-a}
RPC_PASS=${NXMS_LAB_RPC_PASS:-$(cat /etc/nxms/secrets-src/monero-a/wallet_rpc_password 2>/dev/null \
    || echo 58f5a40d381f1edc6d37144c8f7747e8f5d06854a5c568529e616c171feeff9e)}
FAUCET_PASS=${NXMS_LAB_FAUCET_PASS:-faucet-stagenet-2026}
label=io.nexum.stack.workspace

die() { printf 'nxms-stack: %s\n' "$*" >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
dock() {
    env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
        /usr/bin/docker --host unix:///var/run/docker.sock "$@"
}
install -d -m 0700 "$STATE/bin"
install -d -m 0755 "$STATE" "$TASKS"

ensure_binaries() {
    for bin in nxms-mailbox nxms-signer nxms-host-bootstrap; do
        [ -x "$STATE/bin/$bin" ] && continue
        printf 'dogrywam %s z buildu musl...\n' "$bin"
        dock cp "$DEV:/cache/target/release/$bin" "$STATE/bin/$bin" >/dev/null \
            || die "brak $bin w $DEV:/cache/target/release — najpierw: cargo build --release --workspace"
        chmod 0755 "$STATE/bin/$bin"
    done
}

gen_token() { openssl rand -hex 24; }

write_task_record() { # write_task_record <id> <state> <step> <container> <tor> <mbox> <sign> <wrpc> <onion>
    TASKS="$TASKS" /usr/bin/python3 - "$@" <<'PYEOF'
import json, os, sys
from datetime import datetime, timezone
tid, state, step, container, tor, mbox, sign, wrpc, onion = sys.argv[1:10]
sign, wrpc = int(sign), int(wrpc)
path = os.path.join(os.environ["TASKS"], tid + ".json")
try:
    doc = json.loads(open(path).read())
except Exception:
    doc = {"id": tid, "created_at": datetime.now(timezone.utc).isoformat()}
if state in ("done", "failed", "stopped") and not doc.get("finished_at"):
    doc["finished_at"] = datetime.now(timezone.utc).isoformat()
roles = [
    {"name": "tor", "state": "active" if tor == "1" else "down", "detail": onion},
    {"name": "mailbox", "state": "active" if mbox == "1" else "down", "detail": "http://" + onion if onion else ""},
    {"name": "signer-a", "state": "active" if sign >= 1 else "down", "detail": ""},
    {"name": "signer-b", "state": "active" if sign >= 2 else "down", "detail": ""},
    {"name": "wallet-rpc-a", "state": "active" if wrpc >= 1 else "down", "detail": "monero 0.18.5"},
    {"name": "wallet-rpc-b", "state": "active" if wrpc >= 2 else "down", "detail": "monero 0.18.5"},
]
active = sum(1 for r in roles if r["state"] == "active")
doc.update({
    "id": tid, "kind": "allinone", "state": state, "step": step, "container": container,
    "started_at": doc.get("started_at") or datetime.now(timezone.utc).isoformat(),
    "finished_at": doc.get("finished_at", ""),
    "roles": roles,
    "onion": {"mailbox": onion},
    "note": doc.get("note", ""),
})
doc["roles_active"] = active
open(path, "w").write(json.dumps(doc, indent=2))
PYEOF
}

provision() { # provision <id> <port> <socks_port>
    local id=$1 port=$2 socks=$3 dir=$STATE/$1
    local wrpc_a=$((port + 200)) wrpc_b=$((port + 300))
    install -d -m 0755 "$dir/etc" "$dir/lib" "$dir/logs" "$dir/secrets" "$dir/tor" "$dir/lib/wallets"
    install -d -m 0700 "$dir/lib/host-vault-a" "$dir/lib/host-vault-b"
    local s=$dir/secrets
    if [ ! -f "$s/mailbox_admin_token" ]; then
        gen_token > "$s/mailbox_admin_token"; gen_token > "$s/mailbox_push_token"
        for r in orchestrator signer-a signer-b; do gen_token > "$s/mailbox_pull_token_$r"; gen_token > "$s/mailbox_ack_token_$r"; done
        for r in a b; do gen_token > "$s/worker_service_token_$r"; gen_token > "$s/host_vault_passphrase_$r"; done
        openssl genpkey -algorithm ed25519 -out "$s/action_token_priv.pem" 2>/dev/null
        openssl pkey -in "$s/action_token_priv.pem" -pubout -out "$s/action_token_pub.pem" 2>/dev/null
        gen_token > "$s/token_issuer_pass"
        gen_token > "$s/wallet_pass_a"; gen_token > "$s/wallet_pass_b"; gen_token > "$s/wallet_pass_buyer"
        for r in a b; do
            echo "stack-$id-$r" > "$s/wrpc_user_$r"; gen_token > "$s/wrpc_pass_$r"
            echo "lab-only" > "$s/wallet_rpc_wallet_password_$r"
            echo "lab-only" > "$s/wallet_rpc_password_$r"
        done
    fi
    chmod 700 "$s"; chmod 600 "$s"/* 2>/dev/null || true
    # Klucze ukrytej uslugi z gory (root, jak runtime) — stabilny .onion miedzy
    # restartami i znany przed ceremonia tozsamosci (wymog .onion w peerach).
    if [ ! -s "$dir/lib/onion.txt" ]; then
        dock run --rm --network host --mount "type=bind,source=$dir,target=/nxms" "$CT" sh -c '
            apk add --no-cache tor >/dev/null 2>&1
            mkdir -p /nxms/tor/data /nxms/tor/hs && chmod 700 /nxms/tor /nxms/tor/hs
            printf "DataDirectory /nxms/tor/data\nSocksPort 0\nHiddenServiceDir /nxms/tor/hs\nHiddenServiceVersion 3\nHiddenServicePort 80 127.0.0.1:1\n" > /nxms/etc/torrc.keygen
            tor -f /nxms/etc/torrc.keygen >/dev/null 2>&1 &
            for i in $(seq 1 30); do [ -s /nxms/tor/hs/hostname ] && break; sleep 1; done
            kill %1 2>/dev/null
            chmod 700 /nxms/tor/hs' >/dev/null 2>&1
        local fresh=""
        fresh=$(dock run --rm --network none --mount "type=bind,source=$dir,target=/nxms" "$CT" \
            cat /nxms/tor/hs/hostname 2>/dev/null | tr -d '\r\n')
        [ -n "$fresh" ] && printf '%s\n' "$fresh" > "$dir/lib/onion.txt"
    fi
    local onion=""
    onion=$(cat "$dir/lib/onion.txt" 2>/dev/null || true)
    [ -n "$onion" ] || die "nie wygenerowano .onion dla $id"

    cat > "$dir/etc/torrc" <<EOF
DataDirectory /nxms/tor/data
SocksPort 127.0.0.1:$socks
RunAsDaemon 0
Log notice stdout
HiddenServiceDir /nxms/tor/hs
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:$port
EOF
    cat > "$dir/etc/mailbox.toml" <<EOF
# NXMS stack $id: rola mailbox.
bind = "127.0.0.1:$port"
db_path = "/nxms/lib/nxms_mailbox.db"
max_body_bytes = 16777216
default_ttl_secs = 86400
max_ttl_secs = 604800
lease_secs = 60
max_wait_ms = 20000
cleanup_secs = 30
checkpoint_secs = 300
max_messages_per_inbox = 10000
max_bytes_per_inbox = 67108864
max_rows_global = 1000000
rate_limit_ip_per_min = 300
rate_limit_to_per_min = 600
production_hardening = false
push_token = "vault:$s/mailbox_push_token"
admin_token = "vault:$s/mailbox_admin_token"
[pull_tokens]
orchestrator = "vault:$s/mailbox_pull_token_orchestrator"
signer-a = "vault:$s/mailbox_pull_token_signer-a"
signer-b = "vault:$s/mailbox_pull_token_signer-b"
[ack_tokens]
orchestrator = "vault:$s/mailbox_ack_token_orchestrator"
signer-a = "vault:$s/mailbox_ack_token_signer-a"
signer-b = "vault:$s/mailbox_ack_token_signer-b"
EOF
    local x
    for x in a b; do
        cat > "$dir/etc/signer-$x.toml" <<EOF
# NXMS stack $id: signer-$x (realna granica Monero).
local_id = "signer_$x"
signer_role = "$([ "$x" = a ] && echo arbiter || echo seller)"
sandbox_id = "sandbox-$id-$x"
wallet_id = "wallet-$id-$x"
nettype = "stagenet"
peers_path = "/nxms/etc/peers-$x.json"
host_vault_dir = "/nxms/lib/host-vault-$x"
host_vault_passphrase = "vault:$s/host_vault_passphrase_$x"
runtime_trust_bundle_path = "/nxms/etc/runtime-trust.final.json"
db_path = "/nxms/lib/signer-$x.db"
mailbox_url = "http://$onion"
mailbox_push_token = "vault:$s/mailbox_push_token"
mailbox_pull_token = "vault:$s/mailbox_pull_token_signer-$x"
mailbox_ack_token = "vault:$s/mailbox_ack_token_signer-$x"
mailbox_admin_token = "vault:$s/mailbox_admin_token"
worker_service_token = "vault:$s/worker_service_token_$x"
tor_socks5h = "socks5h://127.0.0.1:$socks"
allow_remote_wallet_rpc = false
production_hardening = false
snapshot_quorum = 3
pull_max = 20
pull_wait_ms = 20000
poll_interval_ms = 800
default_ttl_secs = 86400
max_txset_hex_len = 16777216
[wallet_rpc]
endpoint = "http://127.0.0.1:$([ "$x" = a ] && echo "$wrpc_a" || echo "$wrpc_b")"
wallet_name = "escrow_wallet_$x"
wallet_password = "vault:$s/wallet_pass_$x"
username = "vault:$s/wrpc_user_$x"
password = "vault:$s/wrpc_pass_$x"
[wallet_provision]
enabled = false
wallet_cli_path = "/usr/bin/monero-wallet-cli"
wallet_dir = "/nxms/lib/wallets"
daemon_address = "$DAEMON"
trusted_daemon = true
extra_args = []
timeout_secs = 60
[action_token]
required = true
issuer = "nxms-auth"
audience = "sandbox:sandbox-$id-$x"
algorithm = "EDDSA"
public_key_pem_path = "/nxms/secrets/action_token_pub.pem"
clock_skew_secs = 5
max_ttl_secs = 120
EOF
    done

    # --- Ceremonia tozsamosci i zaufania (nxms-host-bootstrap) ---
    if [ ! -f "$dir/lib/provisioned" ]; then
        local hb=$STATE/bin/nxms-host-bootstrap
        "$hb" generate-host-vault --local-id signer_a --host-vault-dir "$dir/lib/host-vault-a" \
            --host-vault-passphrase-file "$s/host_vault_passphrase_a" >/dev/null || die "host-vault signer_a ($id)"
        "$hb" generate-host-vault --local-id signer_b --host-vault-dir "$dir/lib/host-vault-b" \
            --host-vault-passphrase-file "$s/host_vault_passphrase_b" >/dev/null || die "host-vault signer_b ($id)"
        "$hb" export-host-identity --local-id signer_a --role ag-01 --host "$onion" --port 80 \
            --host-vault-dir "$dir/lib/host-vault-a" --host-vault-passphrase-file "$s/host_vault_passphrase_a" \
            --out "$dir/lib/id-a.json" >/dev/null || die "export identity a ($id)"
        "$hb" export-host-identity --local-id signer_b --role ag-02 --host "$onion" --port 80 \
            --host-vault-dir "$dir/lib/host-vault-b" --host-vault-passphrase-file "$s/host_vault_passphrase_b" \
            --out "$dir/lib/id-b.json" >/dev/null || die "export identity b ($id)"
        "$hb" generate-action-token-issuer-vault --issuer nxms-auth --algorithm EDDSA \
            --action-token-issuer-vault-dir "$dir/lib/token-issuer" \
            --action-token-issuer-vault-passphrase-file "$s/token_issuer_pass" >/dev/null || die "token issuer vault ($id)"
        "$hb" export-action-token-issuer --action-token-issuer-vault-dir "$dir/lib/token-issuer" \
            --action-token-issuer-vault-passphrase-file "$s/token_issuer_pass" \
            --out "$dir/lib/issuer.json" >/dev/null || die "token issuer export ($id)"
        "$hb" init-bundle --trust-epoch "stack-$id-$(date -u +%Y%m%d)" \
            --host-identity "$dir/lib/id-a.json" --host-identity "$dir/lib/id-b.json" \
            --action-token-issuer-bundle "$dir/lib/issuer.json" \
            --out "$dir/lib/bundle.json" >/dev/null || die "init-bundle ($id)"
        "$hb" sign-bundle --bundle "$dir/lib/bundle.json" --signer-id signer_a --signer-role ag-01 \
            --host-vault-dir "$dir/lib/host-vault-a" --host-vault-passphrase-file "$s/host_vault_passphrase_a" \
            --out "$dir/lib/bundle.s1.json" >/dev/null || die "sign-bundle a ($id)"
        "$hb" sign-bundle --bundle "$dir/lib/bundle.s1.json" --signer-id signer_b --signer-role ag-02 \
            --host-vault-dir "$dir/lib/host-vault-b" --host-vault-passphrase-file "$s/host_vault_passphrase_b" \
            --out "$dir/lib/bundle.s2.json" >/dev/null || die "sign-bundle b ($id)"
        "$hb" verify-bundle --bundle "$dir/lib/bundle.s2.json" >/dev/null || die "verify-bundle ($id)"
        cp "$dir/lib/bundle.s2.json" "$dir/etc/runtime-trust.final.json"
        "$hb" materialize-local --bundle "$dir/lib/bundle.s2.json" --local-id signer_a \
            --host-vault-dir "$dir/lib/host-vault-a" --host-vault-passphrase-file "$s/host_vault_passphrase_a" \
            --peers-out "$dir/etc/peers-a.json" --action-token-public-key-pem-out "$s/action_token_pub.pem" >/dev/null || die "materialize a ($id)"
        "$hb" materialize-local --bundle "$dir/lib/bundle.s2.json" --local-id signer_b \
            --host-vault-dir "$dir/lib/host-vault-b" --host-vault-passphrase-file "$s/host_vault_passphrase_b" \
            --peers-out "$dir/etc/peers-b.json" --action-token-public-key-pem-out "$s/action_token_pub.pem" >/dev/null || die "materialize b ($id)"

        # --- Ceremonia multisig 2/3 (monero 0.18.5 w kontenerze) ---
        printf 'ceremonia multisig 2/3 dla %s...\n' "$id"
        dock run --rm --network host --mount "type=bind,source=$dir,target=/nxms" "$CT" sh -c "
            set -e
            apk add --no-cache $MONERO_PKG >/dev/null 2>&1
            export HOME=/nxms/lib
            grab() { grep -o 'Multisig[A-Za-z0-9+/=]\{30,\}' | tail -1; }
            wcli() { # wcli <rola> <haslo> <komenda...>
                local role=\$1 pw=\$2; shift 2
                printf '%s\n' \"\$pw\" | timeout 600 monero-wallet-cli --stagenet \
                    --daemon-address 127.0.0.1:38081 --trusted-daemon \
                    --wallet-file \"/nxms/lib/wallets/escrow_wallet_\$role\" --password \"\$pw\" \
                    --command \"\$@\" 2>&1
            }
            ch=\$(curl -s -m 10 $DAEMON/get_info | grep -o '\"height\":[0-9]*' | grep -o '[0-9]*')
            restore=\$(( ch > 500 ? ch - 500 : 0 ))
            for spec in a:\$(cat /nxms/secrets/wallet_pass_a) b:\$(cat /nxms/secrets/wallet_pass_b); do
                role=\${spec%%:*}; pw=\${spec#*:}
                rm -f /nxms/lib/wallets/escrow_wallet_\$role /nxms/lib/wallets/escrow_wallet_\$role.keys
                timeout 600 monero-wallet-cli --stagenet --daemon-address 127.0.0.1:38081 \
                    --trusted-daemon --generate-new-wallet /nxms/lib/wallets/escrow_wallet_\$role \
                    --password \"\$pw\" --mnemonic-language English --restore-height \"\$restore\" \
                    --command address >/dev/null 2>&1
                wcli \$role \"\$pw\" set ask-password 0 >/dev/null
                wcli \$role \"\$pw\" set enable-multisig-experimental 1 >/dev/null
            done
            pw_c=\$(cat /nxms/secrets/wallet_pass_buyer)
            rm -f /nxms/lib/wallets/buyer_wallet /nxms/lib/wallets/buyer_wallet.keys
            timeout 600 monero-wallet-cli --stagenet --daemon-address 127.0.0.1:38081 \
                --trusted-daemon --generate-new-wallet /nxms/lib/wallets/buyer_wallet \
                --password \"\$pw_c\" --mnemonic-language English --restore-height \"\$restore\" \
                --command address >/dev/null 2>&1
            printf '%s\n' \"\$pw_c\" | timeout 600 monero-wallet-cli --stagenet --daemon-address 127.0.0.1:38081 \
                --trusted-daemon --wallet-file /nxms/lib/wallets/buyer_wallet --password \"\$pw_c\" \
                --command set ask-password 0 >/dev/null 2>&1
            printf '%s\n' \"\$pw_c\" | timeout 600 monero-wallet-cli --stagenet --daemon-address 127.0.0.1:38081 \
                --trusted-daemon --wallet-file /nxms/lib/wallets/buyer_wallet --password \"\$pw_c\" \
                --command set enable-multisig-experimental 1 >/dev/null 2>&1
            pw_a=\$(cat /nxms/secrets/wallet_pass_a); pw_b=\$(cat /nxms/secrets/wallet_pass_b)
            p_a=\$(wcli a \"\$pw_a\" prepare_multisig | grab)
            p_b=\$(wcli b \"\$pw_b\" prepare_multisig | grab)
            p_c=\$(printf '%s\n' \"\$pw_c\" | timeout 600 monero-wallet-cli --stagenet --daemon-address 127.0.0.1:38081 --trusted-daemon --wallet-file /nxms/lib/wallets/buyer_wallet --password \"\$pw_c\" --command prepare_multisig 2>&1 | grab)
            m_a=\$(wcli a \"\$pw_a\" make_multisig 2 \"\$p_b\" \"\$p_c\" | grab)
            m_b=\$(wcli b \"\$pw_b\" make_multisig 2 \"\$p_a\" \"\$p_c\" | grab)
            m_c=\$(printf '%s\n' \"\$pw_c\" | timeout 600 monero-wallet-cli --stagenet --daemon-address 127.0.0.1:38081 --trusted-daemon --wallet-file /nxms/lib/wallets/buyer_wallet --password \"\$pw_c\" --command make_multisig 2 \"\$p_a\" \"\$p_b\" 2>&1 | grab)
            x_a=\$(wcli a \"\$pw_a\" exchange_multisig_keys \"\$m_b\" \"\$m_c\" | grab)
            x_b=\$(wcli b \"\$pw_b\" exchange_multisig_keys \"\$m_a\" \"\$m_c\" | grab)
            x_c=\$(printf '%s\n' \"\$pw_c\" | timeout 600 monero-wallet-cli --stagenet --daemon-address 127.0.0.1:38081 --trusted-daemon --wallet-file /nxms/lib/wallets/buyer_wallet --password \"\$pw_c\" --command exchange_multisig_keys \"\$m_a\" \"\$m_b\" 2>&1 | grab)
            o_a=\$(wcli a \"\$pw_a\" exchange_multisig_keys \"\$x_b\" \"\$x_c\")
            o_b=\$(wcli b \"\$pw_b\" exchange_multisig_keys \"\$x_a\" \"\$x_c\")
            o_c=\$(printf '%s\n' \"\$pw_c\" | timeout 600 monero-wallet-cli --stagenet --daemon-address 127.0.0.1:38081 --trusted-daemon --wallet-file /nxms/lib/wallets/buyer_wallet --password \"\$pw_c\" --command exchange_multisig_keys \"\$x_a\" \"\$x_b\" 2>&1)
            a_a=\$(printf '%s' \"\$o_a\" | grep -oE 'Multisig address: [1-9A-HJ-NP-Za-km-z]{60,}' | awk '{print \$3}')
            a_b=\$(printf '%s' \"\$o_b\" | grep -oE 'Multisig address: [1-9A-HJ-NP-Za-km-z]{60,}' | awk '{print \$3}')
            a_c=\$(printf '%s' \"\$o_c\" | grep -oE 'Multisig address: [1-9A-HJ-NP-Za-km-z]{60,}' | awk '{print \$3}')
            [ -n \"\$a_a\" ] && [ \"\$a_a\" = \"\$a_b\" ] && [ \"\$a_a\" = \"\$a_c\" ] || { echo 'ceremonia: adresy niezgodne' >&2; exit 1; }
            printf '%s\n' \"\$a_a\" > /nxms/lib/multisig-address.txt
            echo \"ceremonia OK: \$a_a\"
        " || die "ceremonia multisig nie przeszla ($id)"
        touch "$dir/lib/provisioned"
    fi

    cat > "$dir/run.sh" <<'EOF'
#!/bin/sh
# Nadzorca instancji: Tor -> wallet-rpc x2 -> mailbox -> signerzy.
set -u
cd /nxms
echo tor > /nxms/logs/stage
apk add --no-cache tor python3 MONERO_PKG >/dev/null 2>&1
chmod 700 /nxms/tor /nxms/tor/hs 2>/dev/null
tor -f /nxms/etc/torrc > /nxms/logs/tor.log 2>&1 &
for i in $(seq 1 90); do
    [ -s /nxms/tor/hs/hostname ] && break
    sleep 2
done
onion=$(cat /nxms/tor/hs/hostname 2>/dev/null || true)
printf '%s\n' "$onion" > /nxms/logs/onion
echo wallet-rpc > /nxms/logs/stage
monero-wallet-rpc --stagenet --non-interactive --daemon-address 127.0.0.1:38081 \
    --trusted-daemon --wallet-file /nxms/lib/wallets/escrow_wallet_a \
    --password "$(cat /nxms/secrets/wallet_pass_a)" \
    --rpc-bind-ip 127.0.0.1 --rpc-bind-port WRPC_A \
    --rpc-login "$(cat /nxms/secrets/wrpc_user_a):$(cat /nxms/secrets/wrpc_pass_a)" \
    --log-file /nxms/logs/wallet-rpc-a.log --disable-rpc-ban > /nxms/logs/wallet-rpc-a.out 2>&1 &
monero-wallet-rpc --stagenet --non-interactive --daemon-address 127.0.0.1:38081 \
    --trusted-daemon --wallet-file /nxms/lib/wallets/escrow_wallet_b \
    --password "$(cat /nxms/secrets/wallet_pass_b)" \
    --rpc-bind-ip 127.0.0.1 --rpc-bind-port WRPC_B \
    --rpc-login "$(cat /nxms/secrets/wrpc_user_b):$(cat /nxms/secrets/wrpc_pass_b)" \
    --log-file /nxms/logs/wallet-rpc-b.log --disable-rpc-ban > /nxms/logs/wallet-rpc-b.out 2>&1 &
echo mailbox > /nxms/logs/stage
/opt/nxms/bin/nxms-mailbox serve --config /nxms/etc/mailbox.toml >> /nxms/logs/mailbox.log 2>&1 &
sleep 3
echo signers > /nxms/logs/stage
/opt/nxms/bin/nxms-signer run --config /nxms/etc/signer-a.toml >> /nxms/logs/signer-a.log 2>&1 &
/opt/nxms/bin/nxms-signer run --config /nxms/etc/signer-b.toml >> /nxms/logs/signer-b.log 2>&1 &
sleep 2
echo running > /nxms/logs/stage
wait -n
echo "proces zakonczyl sie — patrz /nxms/logs" >> /nxms/logs/mailbox.log
echo crashed > /nxms/logs/stage
sleep 3600
EOF
    chmod 0755 "$dir/run.sh"
    sed -i "s/MONERO_PKG/$MONERO_PKG/; s/WRPC_A/$wrpc_a/; s/WRPC_B/$wrpc_b/" "$dir/run.sh"
    cp "$script_dir/../tools/wallet-rpc-stub.py" "$dir/etc/wallet-rpc-stub.py" 2>/dev/null || true
}

role_state() { # role_state <kontener> -> "tor mbox sign wrpc"
    local name=$1 tor=0 mbox=0 sign=0 wrpc=0
    dock exec "$name" pidof tor >/dev/null 2>&1 && tor=1
    dock exec "$name" pidof nxms-mailbox >/dev/null 2>&1 && mbox=1
    sign=$(dock exec "$name" sh -c 'pidof nxms-signer | wc -w' 2>/dev/null || echo 0)
    wrpc=$(dock exec "$name" sh -c 'pidof monero-wallet-rpc | wc -w' 2>/dev/null || echo 0)
    echo "$tor $mbox ${sign:-0} ${wrpc:-0}"
}

up_instance() { # up_instance <id> <port> <socks>
    local id=$1 port=$2 socks=$3 dir=$STATE/$1 name=nxms-$1
    provision "$id" "$port" "$socks"
    if dock container inspect "$name" >/dev/null 2>&1; then
        [ "$(dock container inspect --format '{{.State.Running}}' "$name")" = true ] || dock start "$name" >/dev/null
    else
        dock run -d --name "$name" --label "$label=$workspace" --network host \
            --restart unless-stopped --security-opt no-new-privileges --pids-limit 512 --memory 1536m \
            --mount "type=bind,source=$dir,target=/nxms" \
            --mount "type=bind,source=$STATE/bin,target=/opt/nxms/bin,readonly" \
            "$CT" /bin/sh /nxms/run.sh >/dev/null || die "nie udalo sie uruchomic $name"
    fi
    printf '%-10s %s (mailbox :%s, wallet-rpc :%s/:%s) — startuje\n' "$id" "$name" "$port" "$((port + 200))" "$((port + 300))"
    write_task_record "$id" "running" "tor bootstrap" "$name" 0 0 0 0 ""
}

case ${1:-} in
    up)
        dock info >/dev/null 2>&1 || die 'brak dostepu do docker.'
        ensure_binaries
        n=${2:-2}
        case "$n" in ''|*[!0-9]*) die 'N musi byc liczba.' ;; esac
        [ "$n" -ge 1 ] && [ "$n" -le 9 ] || die 'N w zakresie 1..9.'
        workspace=$(pwd -P)
        i=1
        while [ "$i" -le "$n" ]; do
            id=$(printf 'task-%02d' "$i")
            up_instance "$id" "$((4100 + i))" "$((9300 + i))"
            i=$((i + 1))
        done
        printf '\nStany: bash tools/nxms-stack.sh status\n'
        ;;
    status)
        for dir in "$STATE"/task-*; do
            [ -d "$dir" ] || continue
            id=$(basename "$dir"); name=nxms-$id
            if [ "$(dock container inspect --format '{{.State.Running}}' "$name" 2>/dev/null)" = true ]; then
                read -r tor mbox sign wrpc <<< "$(role_state "$name")"
                stage=$(cat "$dir/logs/stage" 2>/dev/null || echo start)
                onion=$(cat "$dir/logs/onion" 2>/dev/null || cat "$dir/lib/onion.txt" 2>/dev/null || true)
                write_task_record "$id" "running" "$stage" "$name" "${tor:-0}" "${mbox:-0}" "${sign:-0}" "${wrpc:-0}" "${onion:-}"
                escrow=$(cat "$dir/lib/multisig-address.txt" 2>/dev/null | cut -c1-12 || echo '-')
                printf '%-10s running · krok: %-11s role: %s/6  escrow: %s…  %s\n' \
                    "$id" "$stage" "$((tor + mbox + sign + wrpc))" "${escrow:--}" "${onion:-?}"
            else
                write_task_record "$id" "stopped" "" "$name" 0 0 0 0 "$(cat "$dir/lib/onion.txt" 2>/dev/null || true)"
                printf '%-10s stopped\n' "$id"
            fi
        done
        ;;
    fund)
        amt=$(/usr/bin/python3 -c "print(int($FUND_XMR * 10**12))")
        for dir in "$STATE"/task-*; do
            [ -d "$dir" ] || continue
            id=$(basename "$dir")
            addr=$(cat "$dir/lib/multisig-address.txt" 2>/dev/null || true)
            [ -n "$addr" ] || { echo "[$id] brak adresu escrow"; continue; }
            [ -f "$dir/lib/funded" ] && { echo "[$id] juz finansowane"; continue; }
            fa() { curl -s -m 90 --digest -u "$RPC_USER:$RPC_PASS" \
                -H 'Content-Type: application/json' -d "$1" http://127.0.0.1:38088/json_rpc; }
            fa '{"jsonrpc":"2.0","id":"1","method":"open_wallet","params":{"filename":"faucet_wallet","password":"'"$FAUCET_PASS"'"}}' >/dev/null
            raw=$(fa '{"jsonrpc":"2.0","id":"1","method":"transfer","params":{"destinations":[{"amount":'"$amt"',"address":"'"$addr"'"}],"priority":0,"get_tx_key":true}}')
            fa '{"jsonrpc":"2.0","id":"1","method":"close_wallet","params":{}}' >/dev/null 2>&1 || true
            if printf '%s' "$raw" | grep -q '"tx_hash"'; then
                date -u +%Y-%m-%dT%H:%M:%SZ > "$dir/lib/funded"
                echo "[$id] finansowanie OK: $FUND_XMR XMR -> $addr"
            else
                echo "[$id] finansowanie nieudane: $(printf '%s' "$raw" | tr -d '\n' | cut -c1-140)"
            fi
        done
        ;;
    down)
        for name in $(dock ps -a --format '{{.Names}}' | grep '^nxms-task-' || true); do
            dock rm -f "$name" >/dev/null 2>&1 && echo "usunieto $name"
        done
        ;;
    clean)
        for name in $(dock ps -a --format '{{.Names}}' | grep '^nxms-task-' || true); do
            dock rm -f "$name" >/dev/null 2>&1 && echo "usunieto $name"
        done
        dock run --rm --network none --mount "type=bind,source=$STATE,target=/nxms" "$CT" \
            sh -c 'rm -rf /nxms/task-* 2>/dev/null' >/dev/null 2>&1 || true
        rm -f "$TASKS"/task-*.json 2>/dev/null || true
        echo 'nxms-stack: stan wyczyszczony.'
        ;;
    *) echo "Usage: bash tools/nxms-stack.sh {up [N]|status|fund|down|clean}"; exit 2 ;;
esac
