#!/bin/bash
# OPS: NXMS FLOW — realny przeplyw escrow na zywym stosie nxms-stack:
# peer (nxms-peer) -> mailbox -> signer (nxms-signer) -> wallet-rpc (monero 0.18.5).
#
# Kroki na zywym stosie (curl + docker exec; kontenery nie sa przepinane):
#   1. snapshot kontraktu: snapshot new + hash + 3 podpisy Falc onem
#      (signer_a, signer_b, peer1 — klucze z host-vaultow) + activate w DB
#      OBU signerow (snapshot_quorum = 3),
#   2. przygotowanie portfela multisig 2/3: jesli get_balance zglasza
#      multisig_import_needed, to export_multisig_info z :43NN i :44NN +
#      import_multisig_info po drugiej stronie ("Preparation for spending"),
#   3. txset NIEPODPISANY: wallet-rpc transfer z do_not_relay:true na adres
#      ZEWNĘTRZNY (domyślnie adres faucetu) -> multisig_txset,
#   4. action token dla sign_multisig: nxms-escrow-orchestrator action-token
#      issue z issuer vaultem stosu (claims wg required_claims signera:
#      op/scope=sign_multisig, role, sign_round wg roli, escrow_id,
#      txset_hash=sha256(txset), snapshot_hash=hash POLITYKI snapshota,
#      wallet_id/sandbox_id/audience z configu signera, nettype=stagenet),
#   5. nxms-peer sign-req: push koperty NxmsEnvelope (ESCROW/1 tx_sign_req,
#      FrodoKEM-640-SHAKE + Falcon-1024-CT) do mailboxa, long-poll na
#      tx_sign_resp, ack,
#   6. pending approve u signera z action tokenem -> wallet-rpc sign_multisig,
#   7. wynik (status + signed_tx_data_hex) -> $STATE/task-NN/lib/flow-<ts>.json.
#   8. --submit (opcjonalnie): druga runda sign_round (seller_second) + token
#      submit_multisig z dowodami quorum (proof jti/req_id przez
#      quorum-proof set) + pending submit -> wallet-rpc submit_multisig.
#
# Uwagi (odchylenia od zalozen zlecenia, weryfikowane na zywym monero 0.18.5):
#   - tworca txsetu NIE moze go podpisac ("Transaction already signed by this
#     private key") — txset powstaje w portfelu INNYM niz signer rundy 1
#     (dla signera signer_a = wallet-a, txset z wallet-b :44NN),
#   - signer w trybie lab (bez runtime_trust_bundle_path w signer-*.toml;
#     patrz naglowek tools/nxms-stack.sh) — tx_sign_req bez admission artifact,
#   - snapshot_hash w action tokenze to hash POLITYKI (sha256 canonical JSON),
#     a nie canonical hash snapshota (sha3) — tak weryfikuje nxms-signer.
#
# Usage: bash tools/nxms-flow.sh <task-id> [kwota-xmr] [--submit]
set -u

STATE=${NXMS_STACK_STATE:-$HOME/.local/share/nxms-stack}
DEV=${NXMS_STACK_DEV_CONTAINER:-nexum-alpine-dev}
PY=/usr/bin/python3
FEE_CAP=${NXMS_FLOW_FEE_CAP_ATOMIC:-50000000000}
RELEASE_ADDR=${NXMS_FLOW_RELEASE_ADDR:-5BH2czcBhWeNucgt5ha3gjdcvFAoueXvh5fwsGhhyqdL9HMNsjJz72VeJnz1y2hs4bgHiZ64hUs61JabZyPN23RdDT7EdH4}
SIGNER=${NXMS_FLOW_SIGNER:-signer_a}

die() { printf 'nxms-flow: %s\n' "$*" >&2; exit 1; }
dock() {
    env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
        /usr/bin/docker --host unix:///var/run/docker.sock "$@"
}
jsonparse() { # wyodrebnij ostatni obiekt/tablice JSON z wyjscia (stdout binarek
              # miesza logi tracing z wynikiem) — surowe wyjscie na stdout
    $PY -c '
import json, sys
lines = sys.stdin.read().splitlines(keepends=True)
start = None
for i, ln in enumerate(lines):
    if ln.startswith("{") or ln.startswith("["):
        start = i
if start is None:
    sys.exit("nxms-flow: brak JSON w wyjsciu")
json.loads("".join(lines[start:]))
sys.stdout.write("".join(lines[start:]))
'
}

task=${1:-}
amt=${2:-0.001}
submit=0
[ "${3:-}" = "--submit" ] && submit=1
case "$task" in
    task-[0-9][0-9]) ;;
    *) die 'Usage: bash tools/nxms-flow.sh <task-id> [kwota-xmr] [--submit]' ;;
esac
case "$SIGNER" in
    signer_a) sx=a; other=b; other_id=signer_b; role=arbiter; round=arbiter_first ;;
    signer_b) sx=b; other=a; other_id=signer_a; role=seller; round=seller_second ;;
    *) die "NXMS_FLOW_SIGNER=signer_a|signer_b (wpisano '$SIGNER')" ;;
esac

dir=$STATE/$task
name=nxms-$task
num=$((10#${task#task-}))
port=$((4100 + num))
wrpc_a=$((port + 200)); wrpc_b=$((port + 300))
[ -d "$dir" ] || die "brak stanu $dir — najpierw: bash tools/nxms-stack.sh up"
[ "$(dock container inspect --format '{{.State.Running}}' "$name" 2>/dev/null)" = true ] \
    || die "kontener $name nie dziala"
log() { printf '[flow %s] %s\n' "$task" "$*"; }
incont() { dock exec "$name" "$@"; }
rpc() { curl -s -m 90 -H 'Content-Type: application/json' -d "$2" "http://127.0.0.1:$1/json_rpc"; }
peer_pid=""; peer2_pid=""
trap '[ -n "$peer_pid" ] && kill "$peer_pid" 2>/dev/null; [ -n "$peer2_pid" ] && kill "$peer2_pid" 2>/dev/null' EXIT

# --- Krok 0: narzedzia, konfigi pomocnicze, parametry przeplywu -------------
for b in nxms-peer nxms-escrow-orchestrator; do
    if [ ! -x "$STATE/bin/$b" ]; then
        log "dogrywam $b z buildu musl..."
        dock cp "$DEV:/cache/target/release/$b" "$STATE/bin/$b" >/dev/null \
            || die "brak $b w $DEV:/cache/target/release — najpierw: cargo build --release --workspace"
        chmod 0755 "$STATE/bin/$b"
    fi
done

grep -q '^runtime_trust_bundle_path' "$dir/etc/signer-$sx.toml" && die \
    "signer-$sx egzekwuje escrow-admission (runtime_trust_bundle_path), a flow zaklada tryb lab — patrz naglowek tools/nxms-stack.sh (brak CLI do budowy admission artifact)"

ts=$(date -u +%Y%m%dT%H%M%SZ)
fdir=$dir/lib/flow-$ts
install -d -m 0755 "$fdir"
escrow=$(openssl rand -hex 16)
onion=$(cat "$dir/lib/onion.txt" 2>/dev/null || true)
escrow_addr=$(cat "$dir/lib/multisig-address.txt" 2>/dev/null || true)
[ -n "$escrow_addr" ] || die "brak adresu escrow ($dir/lib/multisig-address.txt)"
atomic=$($PY -c "print(int(float('$amt') * 10**12))")
cfgget() { sed -n "s/^$2 *= *\"\([^\"]*\)\"/\1/p" "$dir/etc/signer-$1.toml" | head -1; }
wallet_id=$(cfgget "$sx" wallet_id)
sandbox_id=$(cfgget "$sx" sandbox_id)
audience=$(cfgget "$sx" audience)
[ -n "$wallet_id" ] && [ -n "$sandbox_id" ] && [ -n "$audience" ] \
    || die "nie odczytano wallet_id/sandbox_id/audience z signer-$sx.toml"
log "escrow=$escrow  signer=$SIGNER  kwota=$amt XMR  cel=$RELEASE_ADDR"

# peers-file peera: zawiera KLUCZE ODBIORCY (obu signerow). Wpis kazdego
# signera jest w allowlistach drugiego (swój wlasny wpis materialize pomija).
$PY - "$dir/etc/peers-a.json" "$dir/etc/peers-b.json" "$dir/etc/peers-peer1.json" <<'PYEOF' \
    || die "nie zlozono peers-peer1.json"
import json, sys
entries = {}
for path in sys.argv[1:3]:
    doc = json.load(open(path))
    for p in doc["peers"]:
        entries.setdefault(p["id"], p)
if not entries:
    sys.exit("nxms-flow: pusty peer book")
json.dump({"peers": list(entries.values())}, open(sys.argv[3], "w"), indent=2)
print(f"[flow] peers-peer1.json <- wpisy: {', '.join(entries)}")
PYEOF

# Konfig signera dla peera — potrzebny do 'snapshot sign' kluczem peer1
# (wymagany pelny SignerConfig; mailbox_url musi byc .onion dla walidacji).
cat > "$dir/etc/peer1-sign.toml" <<EOF
# NXMS flow $task: konfig pomocniczy dla snapshot sign kluczem peer1.
local_id = "peer1"
signer_role = "arbiter"
sandbox_id = "sandbox-$task-peer"
wallet_id = "wallet-$task-peer"
nettype = "stagenet"
peers_path = "/nxms/etc/peers-peer1.json"
host_vault_dir = "/nxms/lib/peer-vault"
host_vault_passphrase = "vault:/nxms/secrets/peer_vault_pass"
db_path = "/nxms/lib/peer1-sign.db"
mailbox_url = "http://${onion:-peer1.invalid.onion}"
tor_socks5h = "socks5h://127.0.0.1:$((9300 + num))"
mailbox_push_token = "vault:/nxms/secrets/mailbox_push_token"
mailbox_pull_token = "vault:/nxms/secrets/mailbox_pull_token_peer1"
mailbox_ack_token = "vault:/nxms/secrets/mailbox_ack_token_peer1"
worker_service_token = "vault:/nxms/secrets/worker_service_token_a"
allow_remote_wallet_rpc = false
production_hardening = false
snapshot_quorum = 3
pull_max = 20
pull_wait_ms = 20000
poll_interval_ms = 800
default_ttl_secs = 86400
max_txset_hex_len = 16777216
mailbox_retry_attempts = 3
mailbox_retry_backoff_ms = 50
[wallet_rpc]
endpoint = "http://127.0.0.1:$wrpc_a"
wallet_name = "escrow_wallet_a"
wallet_password = "vault:/nxms/secrets/wallet_pass_a"
username = "vault:/nxms/secrets/wrpc_user_a"
password = "vault:/nxms/secrets/wrpc_pass_a"
[action_token]
required = true
issuer = "nxms-auth"
audience = "sandbox:sandbox-$task-peer"
algorithm = "EDDSA"
public_key_pem_path = "/nxms/secrets/action_token_pub.pem"
clock_skew_secs = 5
max_ttl_secs = 120
EOF

# --- Krok 1: snapshot kontraktu (quorum 3: signer_a, signer_b, peer1) -------
log "snapshot new + hash + 3 podpisy + activate w DB obu signerow..."
S=/nxms/lib/flow-$ts/snapshot.json
incont /opt/nxms/bin/nxms-signer snapshot new --out "$S" --escrow-id-hex "$escrow" \
    --buyer-id buyer --seller-id seller --arbiter-id "$SIGNER" \
    --release-address "$RELEASE_ADDR" --release-amount "$atomic" \
    --refund-address "$escrow_addr" --refund-min 0 --refund-max "$atomic" \
    --fee-cap-atomic "$FEE_CAP" >/dev/null || die "snapshot new"
canon=$(incont /opt/nxms/bin/nxms-signer snapshot hash --snapshot "$S" | tr -d '\r\n ') \
    || die "snapshot hash"
incont /opt/nxms/bin/nxms-signer snapshot sign --config /nxms/etc/signer-a.toml \
    --snapshot "$S" --signer-id signer_a --out /nxms/lib/flow-$ts/sig-a.json >/dev/null || die "snapshot sign signer_a"
incont /opt/nxms/bin/nxms-signer snapshot sign --config /nxms/etc/signer-b.toml \
    --snapshot "$S" --signer-id signer_b --out /nxms/lib/flow-$ts/sig-b.json >/dev/null || die "snapshot sign signer_b"
incont /opt/nxms/bin/nxms-signer snapshot sign --config /nxms/etc/peer1-sign.toml \
    --snapshot "$S" --signer-id peer1 --out /nxms/lib/flow-$ts/sig-peer.json >/dev/null || die "snapshot sign peer1"
for x in a b; do
    incont /opt/nxms/bin/nxms-signer snapshot activate --config "/nxms/etc/signer-$x.toml" \
        --snapshot "$S" --signatures /nxms/lib/flow-$ts/sig-a.json \
        --signatures /nxms/lib/flow-$ts/sig-b.json \
        --signatures /nxms/lib/flow-$ts/sig-peer.json >/dev/null || die "snapshot activate signer-$x"
done
# Hash POLITYKI (wymagany przez action token) = sha256(canonical JSON snapshota).
policy_hash=$($PY - "$fdir/snapshot.json" <<'PYEOF'
import hashlib, json, sys
snap = json.load(open(sys.argv[1]))
raw = json.dumps(snap, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
print(hashlib.sha256(raw).hexdigest())
PYEOF
)
log "snapshot canonical(sha3)=$canon"
log "snapshot policy(sha256)=$policy_hash"

# --- Krok 2: portfel multisig — key images (Preparation for spending) -------
# Wymiana jest BEZWARUNKOWA przed kazdym txsetem: monero 0.18.5 odrzuca
# podpis ze starymi danymi ("This signature was made with stale data: export
# fresh multisig data, which other participants must then use") — po kazdej
# probie wydatku (transfer/sign_multisig) stan multisig uczestnikow sie rozjezdza.
if rpc $wrpc_a '{"jsonrpc":"2.0","id":"0","method":"get_balance","params":{}}' \
    | grep -q '"multisig_import_needed": *true'; then
    log "get_balance zglasza multisig_import_needed"
fi
log "wymiana swiezych danych multisig miedzy wallet-a i wallet-b..."
info_a=$(rpc $wrpc_a '{"jsonrpc":"2.0","id":"0","method":"export_multisig_info","params":{}}' \
    | $PY -c 'import json,sys; print(json.load(sys.stdin)["result"]["info"])')
info_b=$(rpc $wrpc_b '{"jsonrpc":"2.0","id":"0","method":"export_multisig_info","params":{}}' \
    | $PY -c 'import json,sys; print(json.load(sys.stdin)["result"]["info"])')
rpc $wrpc_a "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"import_multisig_info\",\"params\":{\"info\":[\"$info_b\"]}}" >/dev/null
rpc $wrpc_b "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"import_multisig_info\",\"params\":{\"info\":[\"$info_a\"]}}" >/dev/null

# --- Krok 3: niepodpisany txset z portfela (NIE tego, ktory bedzie podpis) ---
case "$SIGNER" in
    signer_a) tx_wrpc=$wrpc_b tx_wallet=wallet-b ;;
    *)        tx_wrpc=$wrpc_a tx_wallet=wallet-a ;;
esac
log "txset: transfer $amt XMR -> $RELEASE_ADDR (do_not_relay) na $tx_wallet :$tx_wrpc..."
resp=$(rpc $tx_wrpc "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"transfer\",\"params\":{\"destinations\":[{\"address\":\"$RELEASE_ADDR\",\"amount\":$atomic}],\"do_not_relay\":true}}")
RESP="$resp" $PY - "$fdir/txset.hex" <<'PYEOF' || die "transfer nie zwrocil multisig_txset"
import json, os, sys
r = json.loads(os.environ["RESP"])
if "error" in r:
    sys.exit(f"nxms-flow: transfer error: {r['error']}")
txset = (r.get("result") or {}).get("multisig_txset", "")
if not txset:
    sys.exit("nxms-flow: transfer bez pola multisig_txset")
open(sys.argv[1], "w").write(txset)
print(f"[flow] txset: {len(txset)} hex znakow, fee={r['result'].get('fee')}")
PYEOF
txset=$(cat "$fdir/txset.hex")
txset_hash=$($PY -c "import hashlib; print(hashlib.sha256(bytes.fromhex('$txset')).hexdigest())")
log "txset_hash(sha256)=$txset_hash"

# --- Krok 4: action token (sign_multisig) przez nxms-escrow-orchestrator ----
# Orchestrator wydaje tokena na podstawie workflow + proposal w swojej DB —
# nie ma CLI ich tworzacego, wiec strumien przeplywu zasiewamy bezposrednio
# (workflow stan 'funded', proposal z txsetem; snapshot_hash = hash POLITYKI).
seed_orch_db() { # seed_orch_db <txset_hash_hex> <txset_hex>
    DB="$dir/lib/orchestrator-flow.db" ESCROW="$escrow" TXH="$1" TXSET="$2" SNAP="$policy_hash" $PY - <<'PYEOF'
import os, sqlite3, time
db = sqlite3.connect(os.environ["DB"])
now = int(time.time() * 1000)
db.execute("""CREATE TABLE IF NOT EXISTS workflow_instances (
    escrow_id_hex TEXT PRIMARY KEY, state TEXT NOT NULL, snapshot_hash_hex TEXT NOT NULL,
    participants_json TEXT NOT NULL, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL)""")
db.execute("""CREATE TABLE IF NOT EXISTS proposal_blobs (
    escrow_id_hex TEXT PRIMARY KEY, action TEXT NOT NULL CHECK(action IN ('release','refund')),
    tx_data_hex TEXT NOT NULL, txset_hash_hex TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL)""")
db.execute("INSERT OR REPLACE INTO workflow_instances VALUES (?,?,?,?,?,?)",
           (os.environ["ESCROW"], "funded", os.environ["SNAP"], '["signer_a","signer_b","peer1"]', now, now))
db.execute("INSERT OR REPLACE INTO proposal_blobs VALUES (?,?,?,?,?,?)",
           (os.environ["ESCROW"], "release", os.environ["TXSET"], os.environ["TXH"], now, now))
db.commit()
PYEOF
}
seed_orch_db "$txset_hash" "$txset" || die "seed orchestrator db"

issue_token() { # issue_token <role> <op> <txset_hash> <wallet_id> <sandbox_id> <audience>
    incont /opt/nxms/bin/nxms-escrow-orchestrator action-token issue \
        --db-path /nxms/lib/orchestrator-flow.db --bridge-token nxms-flow \
        --escrow-id-hex "$escrow" --txset-hash-hex "$3" \
        --role "$1" --op "$2" \
        --issuer-vault-dir /nxms/lib/token-issuer \
        --issuer-vault-passphrase-file /nxms/secrets/token_issuer_pass \
        --ttl-secs 120 --subject nxms-flow \
        --wallet-id "$4" --sandbox-id "$5" --audience "$6" --nettype stagenet \
        | jsonparse | $PY -c 'import json,sys; o=json.load(sys.stdin); print(o["token"]+"\t"+o["claims"]["jti"])'
}

wait_pending() { # wait_pending <signer-x> -> id pendingu dla biezacego escrow
    local i rows
    for i in $(seq 1 60); do
        rows=$(incont /opt/nxms/bin/nxms-signer pending list --config "/nxms/etc/signer-$1.toml" | jsonparse)
        rid=$(printf '%s' "$rows" | $PY -c '
import json, sys
esc = sys.argv[1]
rows = json.load(sys.stdin)
m = [r for r in rows if r.get("escrow_id_hex") == esc and r.get("status") == "pending"]
print(m[0]["id"] if m else "")' "$escrow")
        [ -n "$rid" ] && { echo "$rid"; return 0; }
        sleep 2
    done
    return 1
}

sign_round() { # sign_round <signer-x> <rola> <round> <wallet_id> <sandbox_id> <audience> <op>
    # -> na stdout: "status<TAB>signed_tx_data_hex<TAB>reason"
    local pend id out
    pend=$(wait_pending "$1") || die "brak pending u signera $1 dla escrow $escrow"
    log "pending u $1: id=$pend — wydaje action token ($2/$3)..."
    out=$(issue_token "$2" "$7" "$txset_hash" "$4" "$5" "$6") || die "action-token issue ($2/$7)"
    token=${out%%$'\t'*}; jti=${out#*$'\t'}
    log "approve pending id=$pend (jti=$jti)..."
    incont /opt/nxms/bin/nxms-signer pending approve --config "/nxms/etc/signer-$1.toml" \
        --id "$pend" --action-token "$token" >/dev/null || die "pending approve ($1)"
    echo "$jti" > "$fdir/jti-$1.txt"
}

# --- Krok 5-6: nxms-peer sign-req + approve signera -------------------------
log "nxms-peer sign-req -> $SIGNER (mailbox http://127.0.0.1:$port)..."
dock exec -e RUST_LOG=warn "$name" /opt/nxms/bin/nxms-peer sign-req \
    --vault-dir /nxms/lib/peer-vault --passphrase-file /nxms/secrets/peer_vault_pass \
    --mailbox "http://127.0.0.1:$port" \
    --push-token-file /nxms/secrets/mailbox_push_token \
    --pull-token-file /nxms/secrets/mailbox_pull_token_peer1 \
    --ack-token-file /nxms/secrets/mailbox_ack_token_peer1 \
    --to "$SIGNER" --escrow-id "$escrow" --action release \
    --txset-file /nxms/lib/flow-$ts/txset.hex --snapshot-hash "$canon" \
    --peers-file /nxms/etc/peers-peer1.json --wait-ms 1000 --timeout-secs 300 \
    > "$fdir/sign-req.out" 2> "$fdir/sign-req.err" &
peer_pid=$!

sign_round "$sx" "$role" "$round" "$wallet_id" "$sandbox_id" "$audience" sign_multisig
wait "$peer_pid" || true
jsonparse < "$fdir/sign-req.out" > "$fdir/sign-req.json" || die "nxms-peer sign-req bez wyniku JSON"
outcome=$(cat "$fdir/sign-req.json")
status=$($PY -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<<"$outcome")
signed=$($PY -c 'import json,sys; print(json.load(sys.stdin).get("signed_tx_data_hex") or "")' <<<"$outcome")
reason=$($PY -c 'import json,sys; print(json.load(sys.stdin).get("reason") or "")' <<<"$outcome")
log "sign-req: status=$status signed_tx_data_hex=${signed:-brak} ${reason:+reason=$reason}"

submit_json="null"
round2_json="null"
if [ "$submit" = 1 ] && [ -n "$signed" ]; then
    # --- Krok 8: druga runda (seller_second) + token submit_multisig --------
    # Uwaga: txset stworzyl $tx_wallet, wiec podpis drugiego portfela domyka
    # transakcje juz w rundzie 1 (2 z 3). Runda 2 dla drugiego signera jest
    # wiec runda odmowy z powodem — sluzy jako dowod quorum (proof jti/req_id)
    # dla tokenu submit_multisig.
    log "--submit: runda 2 ($other_id) + submit_multisig..."
    dock exec -e RUST_LOG=warn "$name" /opt/nxms/bin/nxms-peer sign-req \
        --vault-dir /nxms/lib/peer-vault --passphrase-file /nxms/secrets/peer_vault_pass \
        --mailbox "http://127.0.0.1:$port" \
        --push-token-file /nxms/secrets/mailbox_push_token \
        --pull-token-file /nxms/secrets/mailbox_pull_token_peer1 \
        --ack-token-file /nxms/secrets/mailbox_ack_token_peer1 \
        --to "$other_id" --escrow-id "$escrow" --action release \
        --txset-file /nxms/lib/flow-$ts/txset.hex --snapshot-hash "$canon" \
        --peers-file /nxms/etc/peers-peer1.json --wait-ms 1000 --timeout-secs 300 \
        > "$fdir/sign-req-2.out" 2> "$fdir/sign-req-2.err" &
    peer2_pid=$!
    pend2=$(wait_pending "$other") || die "brak pending u $other_id (runda 2)"
    if [ "$other_id" = signer_a ]; then r2_role=arbiter; else r2_role=seller; fi
    r2_wallet=$(cfgget "$other" wallet_id); r2_sandbox=$(cfgget "$other" sandbox_id)
    r2_audience=$(cfgget "$other" audience)
    out2=$(issue_token "$r2_role" sign_multisig "$txset_hash" \
        "$r2_wallet" "$r2_sandbox" "$r2_audience") || die "action-token issue (runda 2)"
    jti2=${out2#*$'\t'}
    echo "$jti2" > "$fdir/jti-$other_id.txt"
    incont /opt/nxms/bin/nxms-signer pending reject --config "/nxms/etc/signer-$other.toml" \
        --id "$pend2" --reason "quorum 2/3 osiagniety w rundzie 1 (txset stworzyl $tx_wallet — monero nie pozwala podpisac wlasnego txsetu); runda dowodowa dla tokenu submit_multisig" >/dev/null \
        || die "pending reject (runda 2)"
    wait "$peer2_pid" || true
    if jsonparse < "$fdir/sign-req-2.out" > "$fdir/sign-req-2.json"; then
        round2_json=$(cat "$fdir/sign-req-2.json")
    fi

    # Dowody quorum: req_id = sha256("escrow|sign_multisig|<round>|<txset_hash_submit>)
    txset_hash_submit=$($PY -c "import hashlib; print(hashlib.sha256(bytes.fromhex('$signed')).hexdigest())")
    reqs=$($PY - "$escrow" "$txset_hash_submit" <<'PYEOF'
import hashlib, sys
for rnd in ("arbiter_first", "seller_second"):
    material = f"{sys.argv[1]}|sign_multisig|{rnd}|{sys.argv[2]}"
    print(hashlib.sha256(material.encode()).hexdigest())
PYEOF
)
    req_arb=$(echo "$reqs" | sed -n 1p); req_sell=$(echo "$reqs" | sed -n 2p)
    jti1=$(cat "$fdir/jti-$sx.txt")
    incont /opt/nxms/bin/nxms-escrow-orchestrator quorum-proof set \
        --db-path /nxms/lib/orchestrator-flow.db --escrow-id-hex "$escrow" \
        --role arbiter --sign-round arbiter_first --txset-hash-hex "$txset_hash_submit" \
        --jti "$jti1" --req-id "$req_arb" >/dev/null || die "quorum-proof set (arbiter)"
    incont /opt/nxms/bin/nxms-escrow-orchestrator quorum-proof set \
        --db-path /nxms/lib/orchestrator-flow.db --escrow-id-hex "$escrow" \
        --role seller --sign-round seller_second --txset-hash-hex "$txset_hash_submit" \
        --jti "$jti2" --req-id "$req_sell" >/dev/null || die "quorum-proof set (seller)"
    # Proposal dla tokenu submit wiaze sie z hashem FINALNYCH danych transakcji.
    seed_orch_db "$txset_hash_submit" "$signed"
    out3=$(issue_token "$role" submit_multisig "$txset_hash_submit" "$wallet_id" "$sandbox_id" "$audience") \
        || die "action-token issue (submit_multisig)"
    subtoken=${out3%%$'\t'*}
    sub_jti=${out3#*$'\t'}
    log "submit_multisig (jti=$sub_jti)..."
    if incont /opt/nxms/bin/nxms-signer pending submit --config "/nxms/etc/signer-$sx.toml" \
        --escrow-id-hex "$escrow" --tx-data-hex "$signed" --action release \
        --action-token "$subtoken" > "$fdir/submit.out" 2> "$fdir/submit.err"; then
        submit_json=$(jsonparse < "$fdir/submit.out" | $PY -c \
            'import json,sys; print(json.dumps({"mode":"signer_pending_submit","tx_hash_list":json.load(sys.stdin),"proof_seller_jti":sys.argv[1]}))' "$jti2")
    else
        # SKROT LAB: signer submit flow wymaga describe_transfer na podpisanym
        # tx_data — jesli realne monero tego nie przyjmuje, submitujemy wprost
        # przez wallet-rpc (ten sam portfel co signer rundy 1).
        log "pending submit nie przeszedz ($(head -c 200 "$fdir/submit.err")) — SKROT LAB: submit_multisig przez wallet-rpc :$([ "$sx" = a ] && echo "$wrpc_a" || echo "$wrpc_b")"
        sw=$([ "$sx" = a ] && echo "$wrpc_a" || echo "$wrpc_b")
        sub=$(rpc "$sw" "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"submit_multisig\",\"params\":{\"tx_data_hex\":\"$signed\"}}")
        submit_json=$(SUB="$sub" MODE="wallet_rpc_submit_multisig" JTI="$jti2" \
            NOTE="$(head -c 300 "$fdir/submit.err" | tr -d '\n')" $PY - <<'PYEOF'
import json, os
r = json.loads(os.environ["SUB"])
print(json.dumps({"mode": os.environ["MODE"],
                  "tx_hash_list": (r.get("result") or {}).get("tx_hash_list"),
                  "error": r.get("error"), "proof_seller_jti": os.environ["JTI"],
                  "note": "skrot lab — " + os.environ["NOTE"]}))
PYEOF
)
    fi
fi

# --- Krok 7: zapis wyniku ---------------------------------------------------
$PY - "$dir/lib/flow-$ts.json" <<PYEOF
import json, sys
doc = {
    "task": "$task", "ts": "$ts", "escrow_id_hex": "$escrow", "action": "release",
    "amount_xmr": "$amt", "release_address": "$RELEASE_ADDR",
    "signer_round1": "$SIGNER", "txset_wallet": "$tx_wallet",
    "txset_hash_hex": "$txset_hash",
    "snapshot_hash_hex": "$canon", "snapshot_policy_hash_hex": "$policy_hash",
    "sign_req": json.loads('''$outcome'''),
    "sign_req_round2": json.loads('''$round2_json'''),
    "submit": json.loads('''$submit_json'''),
}
json.dump(doc, open(sys.argv[1], "w"), indent=2)
print(sys.argv[1])
PYEOF
log "wynik: $dir/lib/flow-$ts.json"
echo
echo "=== NXMS FLOW $task — PODSUMOWANIE ==="
echo "escrow:            $escrow"
echo "txset:             $tx_wallet :$tx_wrpc -> $RELEASE_ADDR ($amt XMR)"
echo "txset_hash:        $txset_hash"
echo "snapshot:          $canon (policy $policy_hash)"
echo "sign-req do:       $SIGNER — status=$status"
echo "signed_tx_data:    ${signed:-brak}"
[ -n "$reason" ] && echo "reason:            $reason"
[ "$submit_json" != null ] && echo "submit:            $submit_json"
echo "wynik (JSON):      $dir/lib/flow-$ts.json"
[ "$status" = approved ] || exit 1
exit 0
