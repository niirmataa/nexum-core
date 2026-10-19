#!/bin/bash
# OPS: NXMS STACK v2 — rownolegle instancje all-in-one jako "zadania" dockerowe
# z REALNA granica Monero (wallet-rpc 0.18.5) i prawdziwym escrow multisig 2/3.
#
# Kazde zadanie task-NN = osobny kontener Alpine (host network) z:
#   - wlasnym Tor + ukryta usluga (.onion; relacje Tor-only),
#   - rola mailbox (nxms-mailbox) na 127.0.0.1:41NN,
#   - TRIADA signerow 2/3 (nxms-signer) przez socks5h wlasnego Tor do .onion
#     mailboxa: signer-a (arbiter), signer-b (seller), signer-c (buyer) —
#     dwaj z trzech niezaleznych stron zatwierdzaja wydatek escrow,
#   - TRZEMA realnymi wallet-rpc (monero 0.18.5) na 127.0.0.1:43NN/44NN/45NN z
#     portfelami multisig 2/3 (escrow_wallet_a, escrow_wallet_b, buyer_wallet;
#     ceremonia wg monerodocs),
#   - peerem przeplywu escrow (peer1): host-vault + tozsamosc w bundlu zaufania
#     i w allowlistach peers-*.json signerow (nadawca tx_sign_req dla
#     tools/nxms-flow.sh; skrzynka odbiorcza peer1 w mailboxu).
# Sterta escrow 2/3 powstaje przy provision (prepare -> make_multisig 2 ->
# exchange_multisig_keys x2, z obejsciem buga zapisu 0.18.5.0: ask-password 0).
#
# Egzekwienie escrow-admission jest WLACZONE (runtime_trust_bundle_path w
# signer-*.toml): kazdy tx_sign_req niesie artefakt admission podpisany przez
# wartownikow ag-01+ag-02 (Falcon-1024-CT). Artefakt buduje i pieczetuje
# 'nxms-host-bootstrap admission', a przeplyw przekazuje go przez
# 'nxms-peer sign-req --admission-file' (patrz tools/nxms-flow.sh).
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
# Realny przeplyw escrow (peer -> mailbox -> signer) na zywym stosie:
#   bash tools/nxms-flow.sh <task-id> [kwota-xmr] [--submit]
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
    {"name": "signer-a", "state": "active" if sign >= 1 else "down", "detail": "arbiter"},
    {"name": "signer-b", "state": "active" if sign >= 2 else "down", "detail": "seller"},
    {"name": "signer-c", "state": "active" if sign >= 3 else "down", "detail": "buyer"},
    {"name": "wallet-rpc-a", "state": "active" if wrpc >= 1 else "down", "detail": "monero 0.18.5"},
    {"name": "wallet-rpc-b", "state": "active" if wrpc >= 2 else "down", "detail": "monero 0.18.5"},
    {"name": "wallet-rpc-c", "state": "active" if wrpc >= 3 else "down", "detail": "monero 0.18.5"},
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

# --- Peer przeplywu escrow (peer1): host-vault + tozsamosc + allowlisty ---
provision_peer_identity() { # provision_peer_identity <id> <dir> <onion>
    local id=$1 dir=$2 onion=$3 s=$dir/secrets hb=$STATE/bin/nxms-host-bootstrap
    [ -f "$dir/lib/id-peer.json" ] && return 0
    "$hb" generate-host-vault --local-id peer1 --host-vault-dir "$dir/lib/peer-vault" \
        --host-vault-passphrase-file "$s/peer_vault_pass" >/dev/null || die "host-vault peer1 ($id)"
    "$hb" export-host-identity --local-id peer1 --role peer --host "$onion" --port 80 \
        --host-vault-dir "$dir/lib/peer-vault" --host-vault-passphrase-file "$s/peer_vault_pass" \
        --out "$dir/lib/id-peer.json" >/dev/null || die "export identity peer1 ($id)"
    printf '%s\n' "peer1: host-vault + tozsamosc ($id)"
}

ensure_peer_in_peers_files() { # ensure_peer_in_peers_files <dir>
    # Idempotentnie dopisuje wpis peer1 do peers-*.json (struktura Peer z
    # nxms-transport). Dla nowych stosow materialize-local wypisze peera sam
    # (bundle zawiera jego tozsamosc); to jest backfill dla stosow starszych.
    local dir=$1
    PEER_IDENTITY="$dir/lib/id-peer.json" /usr/bin/python3 - "$dir/etc/peers-a.json" "$dir/etc/peers-b.json" "$dir/etc/peers-c.json" <<'PYEOF'
import json, os, sys
ident = json.load(open(os.environ["PEER_IDENTITY"]))
peer = {"id": ident["host_id"], "host": ident["host"], "port": ident["port"],
        "kem_pk_b64": ident["kem_pk_b64"], "sig_pk_b64": ident["sig_pk_b64"]}
for path in sys.argv[1:]:
    if not os.path.exists(path):
        continue
    doc = json.load(open(path))
    peers = doc.setdefault("peers", [])
    if any(p.get("id") == peer["id"] for p in peers):
        print(f"peers: wpis {peer['id']} juz jest w {path}")
        continue
    peers.append(peer)
    open(path, "w").write(json.dumps(doc, indent=2))
    print(f"peers: dopisano wpis {peer['id']} do {path}")
PYEOF
}

provision() { # provision <id> <port> <socks_port>
    local id=$1 port=$2 socks=$3 dir=$STATE/$1
    local wrpc_a=$((port + 200)) wrpc_b=$((port + 300)) wrpc_c=$((port + 400))
    install -d -m 0755 "$dir/etc" "$dir/lib" "$dir/logs" "$dir/secrets" "$dir/tor" "$dir/lib/wallets"
    install -d -m 0700 "$dir/lib/host-vault-a" "$dir/lib/host-vault-b" "$dir/lib/host-vault-c"
    local s=$dir/secrets
    if [ ! -f "$s/mailbox_admin_token" ]; then
        gen_token > "$s/mailbox_admin_token"; gen_token > "$s/mailbox_push_token"
        for r in orchestrator signer-a signer-b signer-c peer1; do gen_token > "$s/mailbox_pull_token_$r"; gen_token > "$s/mailbox_ack_token_$r"; done
        for r in a b c; do gen_token > "$s/worker_service_token_$r"; gen_token > "$s/host_vault_passphrase_$r"; done
        gen_token > "$s/peer_vault_pass"
        openssl genpkey -algorithm ed25519 -out "$s/action_token_priv.pem" 2>/dev/null
        openssl pkey -in "$s/action_token_priv.pem" -pubout -out "$s/action_token_pub.pem" 2>/dev/null
        gen_token > "$s/token_issuer_pass"
        gen_token > "$s/wallet_pass_a"; gen_token > "$s/wallet_pass_b"; gen_token > "$s/wallet_pass_buyer"
        for r in a b c; do
            echo "stack-$id-$r" > "$s/wrpc_user_$r"; gen_token > "$s/wrpc_pass_$r"
            echo "lab-only" > "$s/wallet_rpc_wallet_password_$r"
            echo "lab-only" > "$s/wallet_rpc_password_$r"
        done
    fi
    # Backfill sekretow dodanych po pierwszym provisionie (stosy juz istniejace).
    local sf
    for sf in mailbox_pull_token_peer1 mailbox_ack_token_peer1 peer_vault_pass \
        mailbox_pull_token_signer-c mailbox_ack_token_signer-c \
        worker_service_token_c host_vault_passphrase_c wrpc_user_c wrpc_pass_c \
        wallet_rpc_wallet_password_c wallet_rpc_password_c; do
        [ -f "$s/$sf" ] || gen_token > "$s/$sf"
    done
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
push_token = "vault:/nxms/secrets/mailbox_push_token"
admin_token = "vault:/nxms/secrets/mailbox_admin_token"
[pull_tokens]
# Klucze to NAZWY SKRZYNEK (to z koperty = lokalne id roli) — uwierzytelnienie
# pull jest per-inbox; historyczne klucze signer-a/signer-b nie dzialaly, bo
# signerzy pulluja skrzynke signer_a/signer_b (underscore, = local_id).
orchestrator = "vault:/nxms/secrets/mailbox_pull_token_orchestrator"
signer_a = "vault:/nxms/secrets/mailbox_pull_token_signer-a"
signer_b = "vault:/nxms/secrets/mailbox_pull_token_signer-b"
signer_c = "vault:/nxms/secrets/mailbox_pull_token_signer-c"
peer1 = "vault:/nxms/secrets/mailbox_pull_token_peer1"
[ack_tokens]
orchestrator = "vault:/nxms/secrets/mailbox_ack_token_orchestrator"
signer_a = "vault:/nxms/secrets/mailbox_ack_token_signer-a"
signer_b = "vault:/nxms/secrets/mailbox_ack_token_signer-b"
signer_c = "vault:/nxms/secrets/mailbox_ack_token_signer-c"
peer1 = "vault:/nxms/secrets/mailbox_ack_token_peer1"
EOF
    local x
    # Egzekwienie escrow-admission: tx_sign_req wymaga artefaktu admission
    # podpisanego przez ag-01+ag-02 (Falcon-1024-CT) — buduje go komenda
    # 'nxms-host-bootstrap admission', patrz tools/nxms-flow.sh.
    local trust_line='runtime_trust_bundle_path = "/nxms/etc/runtime-trust.final.json"'
    for x in a b c; do
        # Triada signerow 2/3: arbiter (a), seller (b), buyer (c). Portfel buyera
        # z ceremonii multisig nazywa sie buyer_wallet (haslo: wallet_pass_buyer).
        case "$x" in
            a) s_role=arbiter; s_wallet=escrow_wallet_a; s_wallet_pass=wallet_pass_a; s_wrpc=$wrpc_a ;;
            b) s_role=seller;   s_wallet=escrow_wallet_b; s_wallet_pass=wallet_pass_b; s_wrpc=$wrpc_b ;;
            c) s_role=buyer;    s_wallet=buyer_wallet;    s_wallet_pass=wallet_pass_buyer; s_wrpc=$wrpc_c ;;
        esac
        cat > "$dir/etc/signer-$x.toml" <<EOF
# NXMS stack $id: signer-$x (realna granica Monero).
local_id = "signer_$x"
signer_role = "$s_role"
sandbox_id = "sandbox-$id-$x"
wallet_id = "wallet-$id-$x"
nettype = "stagenet"
peers_path = "/nxms/etc/peers-$x.json"
host_vault_dir = "/nxms/lib/host-vault-$x"
host_vault_passphrase = "vault:/nxms/secrets/host_vault_passphrase_$x"
$trust_line
db_path = "/nxms/lib/signer-$x.db"
mailbox_url = "http://$onion"
mailbox_push_token = "vault:/nxms/secrets/mailbox_push_token"
mailbox_pull_token = "vault:/nxms/secrets/mailbox_pull_token_signer-$x"
mailbox_ack_token = "vault:/nxms/secrets/mailbox_ack_token_signer-$x"
mailbox_admin_token = "vault:/nxms/secrets/mailbox_admin_token"
worker_service_token = "vault:/nxms/secrets/worker_service_token_$x"
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
endpoint = "http://127.0.0.1:$s_wrpc"
wallet_name = "$s_wallet"
wallet_password = "vault:/nxms/secrets/$s_wallet_pass"
username = "vault:/nxms/secrets/wrpc_user_$x"
password = "vault:/nxms/secrets/wrpc_pass_$x"
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
        # signer-c (buyer) to trzecia tozsamosc bundlu. Rola ag-03 jest zgodna
        # z walidacja (role peerow dowolne 1..=128 znakow); quorum sygnatariuszy
        # bundlu/admission zostaje ag-01+ag-02 (REQUIRED_GUARD_ROLES).
        "$hb" generate-host-vault --local-id signer_c --host-vault-dir "$dir/lib/host-vault-c" \
            --host-vault-passphrase-file "$s/host_vault_passphrase_c" >/dev/null || die "host-vault signer_c ($id)"
        "$hb" export-host-identity --local-id signer_c --role ag-03 --host "$onion" --port 80 \
            --host-vault-dir "$dir/lib/host-vault-c" --host-vault-passphrase-file "$s/host_vault_passphrase_c" \
            --out "$dir/lib/id-c.json" >/dev/null || die "export identity c ($id)"
        provision_peer_identity "$id" "$dir" "$onion"
        "$hb" generate-action-token-issuer-vault --issuer nxms-auth --algorithm EDDSA \
            --action-token-issuer-vault-dir "$dir/lib/token-issuer" \
            --action-token-issuer-vault-passphrase-file "$s/token_issuer_pass" >/dev/null || die "token issuer vault ($id)"
        "$hb" export-action-token-issuer --action-token-issuer-vault-dir "$dir/lib/token-issuer" \
            --action-token-issuer-vault-passphrase-file "$s/token_issuer_pass" \
            --out "$dir/lib/issuer.json" >/dev/null || die "token issuer export ($id)"
        "$hb" init-bundle --trust-epoch "stack-$id-$(date -u +%Y%m%d)" \
            --host-identity "$dir/lib/id-a.json" --host-identity "$dir/lib/id-b.json" \
            --host-identity "$dir/lib/id-c.json" \
            --host-identity "$dir/lib/id-peer.json" \
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
        "$hb" materialize-local --bundle "$dir/lib/bundle.s2.json" --local-id signer_c \
            --host-vault-dir "$dir/lib/host-vault-c" --host-vault-passphrase-file "$s/host_vault_passphrase_c" \
            --peers-out "$dir/etc/peers-c.json" --action-token-public-key-pem-out "$s/action_token_pub.pem" >/dev/null || die "materialize c ($id)"
        ensure_peer_in_peers_files "$dir"

        # --- Ceremonia multisig 2/3 (monero 0.18.5 w kontenerze) ---
        printf 'ceremonia multisig 2/3 dla %s...\n' "$id"
        dock run --rm --network host --mount "type=bind,source=$dir,target=/nxms" "$CT" sh -c "
            set -e
            apk add --no-cache $MONERO_PKG curl >/dev/null 2>&1
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

    # Backfill dla stosow provisionowanych przed pojawieniem sie peera przeplywu:
    # brakujacy host-vault/tozsamosc peer1 + wpis w allowlistach peers-*.json.
    provision_peer_identity "$id" "$dir" "$onion"
    ensure_peer_in_peers_files "$dir"

    cat > "$dir/run.sh" <<'EOF'
#!/bin/sh
# Nadzorca instancji: Tor -> wallet-rpc x3 -> mailbox -> signerzy (triada 2/3).
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
# Uwaga (poligon): --disable-rpc-login zamiast digest — klient digest signera
# nie przechodzi wyzwania epee (zadanie CORE do zbadania; curl --digest dziala).
monero-wallet-rpc --stagenet --non-interactive --daemon-address 127.0.0.1:38081 \
    --trusted-daemon --wallet-dir /nxms/lib/wallets \
    --rpc-bind-ip 127.0.0.1 --rpc-bind-port WRPC_A --disable-rpc-login \
    --log-file /nxms/logs/wallet-rpc-a.log --disable-rpc-ban > /nxms/logs/wallet-rpc-a.out 2>&1 &
monero-wallet-rpc --stagenet --non-interactive --daemon-address 127.0.0.1:38081 \
    --trusted-daemon --wallet-dir /nxms/lib/wallets \
    --rpc-bind-ip 127.0.0.1 --rpc-bind-port WRPC_B --disable-rpc-login \
    --log-file /nxms/logs/wallet-rpc-b.log --disable-rpc-ban > /nxms/logs/wallet-rpc-b.out 2>&1 &
# wallet-rpc-c (buyer_wallet) tylko przy pelnej triadzie — stare stosy bez
# host-vault-c dzialaja dalej w wariancie 2-signerowym.
if [ -f /nxms/lib/host-vault-c/vault.bin ]; then
    monero-wallet-rpc --stagenet --non-interactive --daemon-address 127.0.0.1:38081 \
        --trusted-daemon --wallet-dir /nxms/lib/wallets \
        --rpc-bind-ip 127.0.0.1 --rpc-bind-port WRPC_C --disable-rpc-login \
        --log-file /nxms/logs/wallet-rpc-c.log --disable-rpc-ban > /nxms/logs/wallet-rpc-c.out 2>&1 &
fi
echo mailbox > /nxms/logs/stage
/opt/nxms/bin/nxms-mailbox serve --config /nxms/etc/mailbox.toml >> /nxms/logs/mailbox.log 2>&1 &
echo "czekam na wallet-rpc..." >> /nxms/logs/mailbox.log
for i in $(seq 1 60); do
    nc -z 127.0.0.1 WRPC_A 2>/dev/null && nc -z 127.0.0.1 WRPC_B 2>/dev/null \
        && { [ ! -f /nxms/lib/host-vault-c/vault.bin ] || nc -z 127.0.0.1 WRPC_C 2>/dev/null; } && break
    sleep 2
done
echo signers > /nxms/logs/stage
/opt/nxms/bin/nxms-signer run --config /nxms/etc/signer-a.toml >> /nxms/logs/signer-a.log 2>&1 &
/opt/nxms/bin/nxms-signer run --config /nxms/etc/signer-b.toml >> /nxms/logs/signer-b.log 2>&1 &
if [ -f /nxms/lib/host-vault-c/vault.bin ]; then
    /opt/nxms/bin/nxms-signer run --config /nxms/etc/signer-c.toml >> /nxms/logs/signer-c.log 2>&1 &
fi
sleep 2
echo running > /nxms/logs/stage
wait -n
echo "proces zakonczyl sie — patrz /nxms/logs" >> /nxms/logs/mailbox.log
echo crashed > /nxms/logs/stage
sleep 3600
EOF
    chmod 0755 "$dir/run.sh"
    sed -i "s/MONERO_PKG/$MONERO_PKG/; s/WRPC_A/$wrpc_a/; s/WRPC_B/$wrpc_b/; s/WRPC_C/$wrpc_c/" "$dir/run.sh"
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
                printf '%-10s running · krok: %-11s role: %s/8  escrow: %s…  %s\n' \
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
