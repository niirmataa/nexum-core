#!/bin/bash
# OPS: NXMS FLOW — realny przeplyw escrow na zywym stosie nxms-stack:
# peer (nxms-peer) -> mailbox -> signer (nxms-signer) -> wallet-rpc (monero 0.18.5).
# Quorum escrow: DWIE z TRZECH niezaleznych stron (signer-a arbiter,
# signer-b seller, signer-c buyer) zatwierdzaja wydatek.
#
# Kroki na zywym stosie (curl + docker exec; kontenery nie sa przepinane):
#   1. snapshot kontraktu: snapshot new + hash + 3 podpisy Falconem
#      (signer_a, signer_b, signer_c — klucze z host-vaultow) + activate w DB
#      WSZYSTKICH signerow (snapshot_quorum = 3),
#   1a. artefakt escrow admission: nxms-host-bootstrap admission pieczetowany
#      kolejno przez wartownikow ag-01 i ag-02 (Falcon-1024-CT, hash POLITYKI
#      snapshota, epoch z bundlu) — wymagany w kazdym tx_sign_req przy
#      egzekwji runtime trust,
#   2. przygotowanie portfela multisig 2/3: bezwarunkowa wymiana swiezych
#      danych multisig miedzy WSZYSTKIMI trzema portfelami (a, b, buyer) —
#      "Preparation for spending" wg monerodocs,
#   3. txset: wallet-rpc transfer z do_not_relay:true na adres ZEWNĘTRZNY —
#      z portfela TRZECIEJ strony (tej, ktora nie podpisuje w rundach),
#   4. action tokeny dla sign_multisig: nxms-escrow-orchestrator action-token
#      issue z issuer vaultem stosu (op=sign_multisig, role/sign_round wg roli:
#      arbiter_first / buyer_second, txset_hash=sha256(txset),
#      snapshot_hash=hash POLITYKI snapshota, wallet_id/sandbox_id/audience
#      z configu signera),
#   5. runda 1: nxms-peer sign-req -> signer_a (arbiter) -> pending approve
#      z action tokenem -> wallet-rpc sign_multisig,
#   6. runda 2: nxms-peer sign-req -> signer_c (buyer, sign_round=buyer_second)
#      z drugim action tokenem -> pending approve -> wallet-rpc sign_multisig
#      na ZBIERANYM txsecie (sign_multisig doklada podpis do txsetu),
#   7. --submit: submit_multisig przez wallet-rpc na zbieranym txsecie po
#      dwoch podpisach -> tx w sieci. Wynik -> $STATE/task-NN/lib/flow-<ts>.json.
#
# Realia Monero 0.18.5 (weryfikowane na zywym stosie):
#   - tworca txsetu nie moze go podpisac ("Transaction already signed by this
#     private key"); udzial tworcy jest PIERWSZYM podpisem, kazdy
#     sign_multisig doklada kolejny i przy progu 2/3 DOMYKA zbierany txset
#     ("Transaction is already fully signed" dla trzeciego udzialu),
#   - wiec zbierany txset niesie DWA podpisy: tworcy (trzecia strona, proposal)
#     + signera rundy 2 (buyer). Domyślny przebieg: podpisy seller+buyer
#     (NXMS_FLOW_SIGNER=signer_b daje wariant arbiter+buyer — obie pary
#     akceptowane; runda 1 zawsze idzie do wybranego signera, runda 2 do
#     buyera),
#   - udzial podpisu wymaga SWIEZYCH danych multisig wszystkich uczestnikow
#     ("This signature was made with stale data"),
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
    signer_a) sx=a; role=arbiter; round=arbiter_first ;;
    signer_b) sx=b; role=seller;  round=seller_second ;;
    *) die "NXMS_FLOW_SIGNER=signer_a|signer_b (wpisano '$SIGNER')" ;;
esac
# Runda 2 zawsze do signera buyera (signer_c) — trzecia niezalezna strona.
SIGNER2=signer_c

dir=$STATE/$task
name=nxms-$task
num=$((10#${task#task-}))
port=$((4100 + num))
wrpc_a=$((port + 200)); wrpc_b=$((port + 300)); wrpc_c=$((port + 400))
[ -d "$dir" ] || die "brak stanu $dir — najpierw: bash tools/nxms-stack.sh up"
[ "$(dock container inspect --format '{{.State.Running}}' "$name" 2>/dev/null)" = true ] \
    || die "kontener $name nie dziala"
log() { printf '[flow %s] %s\n' "$task" "$*"; }
incont() { dock exec "$name" "$@"; }
rpc() { curl -s -m 90 -H 'Content-Type: application/json' -d "$2" "http://127.0.0.1:$1/json_rpc"; }
peer_pid=""; peer2_pid=""
trap '[ -n "$peer_pid" ] && kill "$peer_pid" 2>/dev/null; [ -n "$peer2_pid" ] && kill "$peer2_pid" 2>/dev/null' EXIT

# --- Krok 0: narzedzia, konfigi pomocnicze, parametry przeplywu -------------
# Binarki sa zawsze odswiezane z buildu musl — flow zalezy od ich API
# (np. --admission-file w nxms-peer).
for b in nxms-peer nxms-escrow-orchestrator nxms-host-bootstrap; do
    log "dogrywam $b z buildu musl..."
    dock cp "$DEV:/cache/target/release/$b" "$STATE/bin/$b" >/dev/null \
        || die "brak $b w $DEV:/cache/target/release — najpierw: cargo build --release --workspace"
    chmod 0755 "$STATE/bin/$b"
done

grep -q '^runtime_trust_bundle_path' "$dir/etc/signer-$sx.toml" \
    || die "signer-$sx nie egzekwuje escrow-admission (brak runtime_trust_bundle_path) — flow wymaga enforcementu (patrz naglowek tools/nxms-stack.sh)"

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

# peers-file peera: zawiera KLUCZE ODBIORCY (wszystkich trzech signerow).
# Wpis kazdego signera jest w allowlistach pozostalych (swój wlasny wpis
# materialize pomija).
$PY - "$dir/etc/peers-a.json" "$dir/etc/peers-b.json" "$dir/etc/peers-c.json" "$dir/etc/peers-peer1.json" <<'PYEOF' \
    || die "nie zlozono peers-peer1.json"
import json, os, sys
entries = {}
for path in sys.argv[1:4]:
    if not os.path.exists(path):
        continue
    doc = json.load(open(path))
    for p in doc["peers"]:
        entries.setdefault(p["id"], p)
if not entries:
    sys.exit("nxms-flow: pusty peer book")
json.dump({"peers": list(entries.values())}, open(sys.argv[4], "w"), indent=2)
print(f"[flow] peers-peer1.json <- wpisy: {', '.join(entries)}")
PYEOF

# --- Krok 1: snapshot kontraktu (quorum 3: signer_a, signer_b, signer_c) ----
log "snapshot new + hash + 3 podpisy (a/b/c) + activate w DB wszystkich signerow..."
S=/nxms/lib/flow-$ts/snapshot.json
incont /opt/nxms/bin/nxms-signer snapshot new --out "$S" --escrow-id-hex "$escrow" \
    --buyer-id buyer --seller-id seller --arbiter-id "$SIGNER" \
    --release-address "$RELEASE_ADDR" --release-amount "$atomic" \
    --refund-address "$escrow_addr" --refund-min 0 --refund-max "$atomic" \
    --fee-cap-atomic "$FEE_CAP" >/dev/null || die "snapshot new"
canon=$(incont /opt/nxms/bin/nxms-signer snapshot hash --snapshot "$S" | tr -d '\r\n ') \
    || die "snapshot hash"
for x in a b c; do
    incont /opt/nxms/bin/nxms-signer snapshot sign --config "/nxms/etc/signer-$x.toml" \
        --snapshot "$S" --signer-id "signer_$x" --out "/nxms/lib/flow-$ts/sig-$x.json" >/dev/null \
        || die "snapshot sign signer_$x"
done
for x in a b c; do
    incont /opt/nxms/bin/nxms-signer snapshot activate --config "/nxms/etc/signer-$x.toml" \
        --snapshot "$S" --signatures /nxms/lib/flow-$ts/sig-a.json \
        --signatures /nxms/lib/flow-$ts/sig-b.json \
        --signatures /nxms/lib/flow-$ts/sig-c.json >/dev/null || die "snapshot activate signer-$x"
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

# --- Krok 1a: artefakt escrow admission (ag-01 + ag-02) --------------------
# Wymagany przez signerow z egzekwja runtime trust: tx_sign_req niesie
# artefakt podpisany przez wartownikow ag-01 i ag-02 (Falcon-1024-CT).
# Zwiezywany hash POLITYKI snapshota (tak weryfikuje signera) + epoch z bundlu.
A=/nxms/lib/flow-$ts/admission.json
ainfo=$(incont /opt/nxms/bin/nxms-host-bootstrap admission \
    --bundle /nxms/etc/runtime-trust.final.json \
    --escrow-id "$escrow" --snapshot-hash "$policy_hash" --action release \
    --host-vault-dir /nxms/lib/host-vault-a \
    --host-vault-passphrase-file /nxms/secrets/host_vault_passphrase_a \
    --out "$A") || die "admission artifact (ag-01)"
ainfo=$(incont /opt/nxms/bin/nxms-host-bootstrap admission \
    --bundle /nxms/etc/runtime-trust.final.json \
    --escrow-id "$escrow" --snapshot-hash "$policy_hash" --action release \
    --host-vault-dir /nxms/lib/host-vault-b \
    --host-vault-passphrase-file /nxms/secrets/host_vault_passphrase_b \
    --in "$A" --out "$A") || die "admission artifact (ag-02)"
ainfo=$(printf '%s' "$ainfo" | jsonparse)
admission_hash=$(printf '%s' "$ainfo" | $PY -c 'import json,sys; print(json.load(sys.stdin)["artifact_hash_hex"])')
trust_epoch=$(printf '%s' "$ainfo" | $PY -c 'import json,sys; print(json.load(sys.stdin)["runtime_trust_epoch"])')
log "admission artifact: hash=$admission_hash epoch=$trust_epoch (2/2 sygnatur ag)"

# --- Krok 2: portfel multisig — key images (Preparation for spending) -------
# Wymiana jest BEZWARUNKOWA miedzy WSZYSTKIMI trzema portfelami przed kazdym
# txsetem: monero 0.18.5 odrzuca podpis ze starymi danymi ("This signature was
# made with stale data: export fresh multisig data, which other participants
# must then use") — po kazdej probie wydatku stan multisig uczestnikow sie
# rozjezdza (dotyczy tez buyera, ktory podpisuje w rundzie 2).
if rpc $wrpc_a '{"jsonrpc":"2.0","id":"0","method":"get_balance","params":{}}' \
    | grep -q '"multisig_import_needed": *true'; then
    log "get_balance zglasza multisig_import_needed"
fi
log "wymiana swiezych danych multisig miedzy wallet-a, wallet-b i wallet-c (buyer)..."
info_a=$(rpc $wrpc_a '{"jsonrpc":"2.0","id":"0","method":"export_multisig_info","params":{}}' \
    | $PY -c 'import json,sys; print(json.load(sys.stdin)["result"]["info"])')
info_b=$(rpc $wrpc_b '{"jsonrpc":"2.0","id":"0","method":"export_multisig_info","params":{}}' \
    | $PY -c 'import json,sys; print(json.load(sys.stdin)["result"]["info"])')
info_c=$(rpc $wrpc_c '{"jsonrpc":"2.0","id":"0","method":"export_multisig_info","params":{}}' \
    | $PY -c 'import json,sys; print(json.load(sys.stdin)["result"]["info"])')
rpc $wrpc_a "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"import_multisig_info\",\"params\":{\"info\":[\"$info_b\",\"$info_c\"]}}" >/dev/null
rpc $wrpc_b "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"import_multisig_info\",\"params\":{\"info\":[\"$info_a\",\"$info_c\"]}}" >/dev/null
rpc $wrpc_c "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"import_multisig_info\",\"params\":{\"info\":[\"$info_a\",\"$info_b\"]}}" >/dev/null

# --- Krok 3: txset z portfela TRZECIEJ strony ------------------------------
# Tworca txsetu nie moze go podpisac (monero: "Transaction already signed by
# this private key"), a jego udzial jest pierwszym podpisem zbieranego txsetu —
# wiec tworzy go strona, ktora NIE podpisuje w rundach 1-2 (dla domyslnego
# SIGNER=signer_a i buyera w rundzie 2: wallet-b seller; dla SIGNER=signer_b:
# wallet-a arbiter).
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
    DB="$dir/lib/orchestrator-flow.db" ESCROW="$escrow" TXH="$1" TXSET="$2" SNAP="$policy_hash" \
        ADM="$fdir/admission.json" ADM_HASH="$admission_hash" EPOCH="$trust_epoch" $PY - <<'PYEOF'
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
db.execute("""CREATE TABLE IF NOT EXISTS escrow_admission_artifacts (
    escrow_id_hex TEXT PRIMARY KEY, snapshot_hash_hex TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('release','refund')),
    runtime_trust_epoch TEXT NOT NULL, artifact_hash_hex TEXT NOT NULL,
    artifact_json TEXT NOT NULL, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL)""")
db.execute("INSERT OR REPLACE INTO workflow_instances VALUES (?,?,?,?,?,?)",
           (os.environ["ESCROW"], "funded", os.environ["SNAP"], '["signer_a","signer_b","signer_c","peer1"]', now, now))
db.execute("INSERT OR REPLACE INTO proposal_blobs VALUES (?,?,?,?,?,?)",
           (os.environ["ESCROW"], "release", os.environ["TXSET"], os.environ["TXH"], now, now))
artifact_json = open(os.environ["ADM"]).read()
db.execute("INSERT OR REPLACE INTO escrow_admission_artifacts VALUES (?,?,?,?,?,?,?,?)",
           (os.environ["ESCROW"], os.environ["SNAP"], "release", os.environ["EPOCH"],
            os.environ["ADM_HASH"], artifact_json, now, now))
db.commit()
PYEOF
}
seed_orch_db "$txset_hash" "$txset" || die "seed orchestrator db"

issue_token() { # issue_token <role> <op> <txset_hash> <wallet_id> <sandbox_id> <audience>
    # --runtime-trust-bundle-path wlacza claims runtime_trust_epoch +
    # escrow_admission_hash (wymagane przy egzekwji admission; orchestrator
    # bierze hash z zasianego wiersza escrow_admission_artifacts).
    incont /opt/nxms/bin/nxms-escrow-orchestrator action-token issue \
        --db-path /nxms/lib/orchestrator-flow.db --bridge-token nxms-flow \
        --runtime-trust-bundle-path /nxms/etc/runtime-trust.final.json \
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

# --- Krok 5: runda 1 — nxms-peer sign-req + approve signera -----------------
log "runda 1: nxms-peer sign-req -> $SIGNER (mailbox http://127.0.0.1:$port)..."
dock exec -e RUST_LOG=warn "$name" /opt/nxms/bin/nxms-peer sign-req \
    --vault-dir /nxms/lib/peer-vault --passphrase-file /nxms/secrets/peer_vault_pass \
    --mailbox "http://127.0.0.1:$port" \
    --push-token-file /nxms/secrets/mailbox_push_token \
    --pull-token-file /nxms/secrets/mailbox_pull_token_peer1 \
    --ack-token-file /nxms/secrets/mailbox_ack_token_peer1 \
    --to "$SIGNER" --escrow-id "$escrow" --action release \
    --txset-file /nxms/lib/flow-$ts/txset.hex --snapshot-hash "$canon" \
    --admission-file /nxms/lib/flow-$ts/admission.json \
    --peers-file /nxms/etc/peers-peer1.json --wait-ms 1000 --timeout-secs 300 \
    > "$fdir/sign-req.out" 2> "$fdir/sign-req.err" &
peer_pid=$!

sign_round "$sx" "$role" "$round" "$wallet_id" "$sandbox_id" "$audience" sign_multisig
wait "$peer_pid" || true
jsonparse < "$fdir/sign-req.out" > "$fdir/sign-req.json" || die "nxms-peer sign-req (runda 1) bez wyniku JSON"
outcome=$(cat "$fdir/sign-req.json")
status=$($PY -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<<"$outcome")
signed=$($PY -c 'import json,sys; print(json.load(sys.stdin).get("signed_tx_data_hex") or "")' <<<"$outcome")
reason=$($PY -c 'import json,sys; print(json.load(sys.stdin).get("reason") or "")' <<<"$outcome")
log "runda 1 ($SIGNER/$role): status=$status ${reason:+reason=$reason}"

# --- Krok 6: runda 2 — signer_c (buyer, sign_round=buyer_second) ------------
# sign_multisig buyera doklada drugi podpis do zbieranego txsetu (pierwszy
# niesie tworca, $tx_wallet) — po tej rundze zbierany txset ma DWA podpisy
# z niezaleznych portfeli.
log "runda 2: nxms-peer sign-req -> $SIGNER2 (buyer, sign_round=buyer_second)..."
dock exec -e RUST_LOG=warn "$name" /opt/nxms/bin/nxms-peer sign-req \
    --vault-dir /nxms/lib/peer-vault --passphrase-file /nxms/secrets/peer_vault_pass \
    --mailbox "http://127.0.0.1:$port" \
    --push-token-file /nxms/secrets/mailbox_push_token \
    --pull-token-file /nxms/secrets/mailbox_pull_token_peer1 \
    --ack-token-file /nxms/secrets/mailbox_ack_token_peer1 \
    --to "$SIGNER2" --escrow-id "$escrow" --action release \
    --txset-file /nxms/lib/flow-$ts/txset.hex --snapshot-hash "$canon" \
    --admission-file /nxms/lib/flow-$ts/admission.json \
    --peers-file /nxms/etc/peers-peer1.json --wait-ms 1000 --timeout-secs 300 \
    > "$fdir/sign-req-2.out" 2> "$fdir/sign-req-2.err" &
peer2_pid=$!
r2_wallet=$(cfgget c wallet_id); r2_sandbox=$(cfgget c sandbox_id); r2_audience=$(cfgget c audience)
[ -n "$r2_wallet" ] && [ -n "$r2_sandbox" ] && [ -n "$r2_audience" ] \
    || die "nie odczytano wallet_id/sandbox_id/audience z signer-c.toml"
sign_round c buyer buyer_second "$r2_wallet" "$r2_sandbox" "$r2_audience" sign_multisig
wait "$peer2_pid" || true
jsonparse < "$fdir/sign-req-2.out" > "$fdir/sign-req-2.json" || die "nxms-peer sign-req (runda 2) bez wyniku JSON"
round2_json=$(cat "$fdir/sign-req-2.json")
r2_status=$($PY -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<<"$round2_json")
zbierany=$($PY -c 'import json,sys; print(json.load(sys.stdin).get("signed_tx_data_hex") or "")' <<<"$round2_json")
r2_reason=$($PY -c 'import json,sys; print(json.load(sys.stdin).get("reason") or "")' <<<"$round2_json")
log "runda 2 ($SIGNER2/buyer): status=$r2_status ${r2_reason:+reason=$r2_reason}"

# --- Krok 7: --submit — submit_multisig na zbieranym txsecie ----------------
# Po dwoch podpisach ($tx_wallet + buyer) zbierany txset idzie do sieci wprost
# przez wallet-rpc buyera (submit_multisig).
submit_json="null"
if [ "$submit" = 1 ] && [ -n "$zbierany" ]; then
    log "submit_multisig na zbieranym txsecie (podpisy $tx_wallet + buyer) przez wallet-rpc :$wrpc_c..."
    sub=$(rpc $wrpc_c "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"submit_multisig\",\"params\":{\"tx_data_hex\":\"$zbierany\"}}")
    submit_json=$(SUB="$sub" MODE="wallet_rpc_submit_multisig" $PY - <<'PYEOF'
import json, os
r = json.loads(os.environ["SUB"])
print(json.dumps({"mode": os.environ["MODE"],
                  "tx_hash_list": (r.get("result") or {}).get("tx_hash_list"),
                  "error": r.get("error")}))
PYEOF
)
fi

# --- Krok 8: zapis wyniku ---------------------------------------------------
$PY - "$dir/lib/flow-$ts.json" <<PYEOF
import json, sys
doc = {
    "task": "$task", "ts": "$ts", "escrow_id_hex": "$escrow", "action": "release",
    "amount_xmr": "$amt", "release_address": "$RELEASE_ADDR",
    "signer_round1": "$SIGNER", "signer_round2": "$SIGNER2",
    "txset_wallet": "$tx_wallet", "signed_by": "$tx_wallet+buyer",
    "quorum": "2 z 3 niezaleznych stron",
    "txset_hash_hex": "$txset_hash",
    "admission_hash_hex": "$admission_hash", "runtime_trust_epoch": "$trust_epoch",
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
echo "admission:         $admission_hash (ag-01+ag-02, epoch $trust_epoch)"
echo "snapshot:          $canon (policy $policy_hash)"
echo "runda 1:           $SIGNER ($role) — status=$status"
echo "runda 2:           $SIGNER2 (buyer_second) — status=$r2_status"
echo "podpisy (quorum):  $tx_wallet + buyer — 2 z 3 niezaleznych portfeli"
echo "zbierany txset:    ${zbierany:0:48}... (${#zbierany} hex)"
[ -n "$reason" ] && echo "reason r1:         $reason"
[ -n "$r2_reason" ] && echo "reason r2:         $r2_reason"
[ "$submit_json" != null ] && echo "submit:            $submit_json"
echo "wynik (JSON):      $dir/lib/flow-$ts.json"
[ "$status" = approved ] && [ "$r2_status" = approved ] || exit 1
exit 0
