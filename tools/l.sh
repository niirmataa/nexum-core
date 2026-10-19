#!/bin/bash
# OPS: NXMS LAB — rownolegla fabryka instancji multisig 2/3 pod podglad dashboardu.
#
# Kazda instancja lab-NN to TRZY swieze portfele w kontenerze Alpine
# (monero 0.18.5, /state/lab/lab-NN/{arbiter,seller,buyer}) i pelny, realny
# przeplyw 2/3 wg monerodocs (prepare -> make_multisig 2 -> exchange x2),
# z obejsciem buga zapisu 0.18.5.0 (set ask-password 0).
#
# Instancje moga powstawac ROWNOLEGLE (N procesow w tle), a ich stan
# (adres, tx finansowania, potwierdzenia) trafia do lab.json — czyta go
# dashboard przez /api/lab/status.
#
# Dziala jako zwykly uzytkownik (wymaga dostepu do docker). Bez sudo.
# Usage: bash tools/l.sh {up [N]|fund|status|down}
#   up [N]   — N rownoleglych instancji multisig (domyslnie 3) + finansowanie
#   fund     — dofinansowanie instancji bez tx (NXMS_LAB_FUND_XMR, domyslnie 2)
#   status   — przelicz potwierdzenia i zapisz lab.json
#   down     — usun instancje i stan labu
# Stan: ~/.local/share/nxms-lab/  (lab.json + *.result + *.secrets + *.log)
set -u

LAB_DIR=${NXMS_LAB_DIR:-$HOME/.local/share/nxms-lab}
STATE=$LAB_DIR/lab.json
CT=${NXMS_STAGENET_CONTAINER:-nexum-alpine-stagenet}
FUND_XMR=${NXMS_LAB_FUND_XMR:-0.005}
DAEMON=${NXMS_LAB_DAEMON:-http://127.0.0.1:38081}
RPC_USER=${NXMS_LAB_RPC_USER:-wallet-rpc-user-a}
RPC_PASS=${NXMS_LAB_RPC_PASS:-$(cat /etc/nxms/secrets-src/monero-a/wallet_rpc_password 2>/dev/null \
    || echo 58f5a40d381f1edc6d37144c8f7747e8f5d06854a5c568529e616c171feeff9e)}
FAUCET_PASS=${NXMS_LAB_FAUCET_PASS:-faucet-stagenet-2026}

die() { echo "nxms-lab: $*"; exit 1; }
dock() {
    env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
        /usr/bin/docker --host unix:///var/run/docker.sock "$@"
}
install -d -m 0700 "$LAB_DIR"

# Uwaga: nazwy portfeli w instancji to arbiter/seller/buyer w katalogu /state/lab/<id>/.
wcli2() { # wcli2 <id> <rola> <haslo> <komenda...>
    local id=$1 role=$2 pw=$3; shift 3
    printf '%s\n' "$pw" | dock exec -i --user nxms "$CT" timeout 600 monero-wallet-cli --stagenet \
        --daemon-address 127.0.0.1:38081 --trusted-daemon \
        --wallet-file "/state/lab/$id/$role" --password "$pw" --command "$@" 2>&1
}
grab() { grep -o 'Multisig[A-Za-z0-9+/=]\{30,\}' | tail -1; }

ceremony() { # ceremony <id> — pelna ceremonia 2/3 dla jednej instancji
    local id=$1 log=$LAB_DIR/$1.log res=$LAB_DIR/$1.result
    {
        echo "=== $id $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
        local pw_a pw_b pw_c
        pw_a=$(openssl rand -hex 16); pw_b=$(openssl rand -hex 16); pw_c=$(openssl rand -hex 16)
        { echo "arbiter=$pw_a"; echo "seller=$pw_b"; echo "buyer=$pw_c"; } > "$LAB_DIR/$id.secrets"
        chmod 600 "$LAB_DIR/$id.secrets"
        dock exec --user nxms "$CT" mkdir -p "/state/lab/$id"
        local h restore
        h=$(curl -s -m 10 "$DAEMON/get_info" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin).get("height",0))')
        restore=$(( h > 500 ? h - 500 : 0 ))
        local role pw
        for spec in "arbiter:$pw_a" "seller:$pw_b" "buyer:$pw_c"; do
            role=${spec%%:*}; pw=${spec#*:}
            dock exec --user nxms "$CT" rm -f "/state/lab/$id/$role" "/state/lab/$id/$role.keys"
            dock exec --user nxms "$CT" timeout 600 monero-wallet-cli --stagenet \
                --daemon-address 127.0.0.1:38081 --trusted-daemon \
                --generate-new-wallet "/state/lab/$id/$role" --password "$pw" \
                --mnemonic-language English --restore-height "$restore" --command address >/dev/null 2>&1 \
                || { echo "state=failed"; echo "note=create $role"; exit 1; }
            wcli2 "$id" "$role" "$pw" set ask-password 0 >/dev/null
            wcli2 "$id" "$role" "$pw" set enable-multisig-experimental 1 >/dev/null
        done
        local p_a p_b p_c m_a m_b m_c x_a x_b x_c
        p_a=$(wcli2 "$id" arbiter "$pw_a" prepare_multisig | grab)
        p_b=$(wcli2 "$id" seller "$pw_b" prepare_multisig | grab)
        p_c=$(wcli2 "$id" buyer "$pw_c" prepare_multisig | grab)
        echo "prepare: ${#p_a}/${#p_b}/${#p_c}"
        [ "${#p_a}" -gt 100 ] && [ "${#p_b}" -gt 100 ] && [ "${#p_c}" -gt 100 ] || { echo "state=failed"; echo "note=prepare"; exit 1; }
        m_a=$(wcli2 "$id" arbiter "$pw_a" make_multisig 2 "$p_b" "$p_c" | grab)
        m_b=$(wcli2 "$id" seller "$pw_b" make_multisig 2 "$p_a" "$p_c" | grab)
        m_c=$(wcli2 "$id" buyer "$pw_c" make_multisig 2 "$p_a" "$p_b" | grab)
        echo "make: ${#m_a}/${#m_b}/${#m_c}"
        [ "${#m_a}" -gt 100 ] && [ "${#m_b}" -gt 100 ] && [ "${#m_c}" -gt 100 ] || { echo "state=failed"; echo "note=make"; exit 1; }
        x_a=$(wcli2 "$id" arbiter "$pw_a" exchange_multisig_keys "$m_b" "$m_c" | grab)
        x_b=$(wcli2 "$id" seller "$pw_b" exchange_multisig_keys "$m_a" "$m_c" | grab)
        x_c=$(wcli2 "$id" buyer "$pw_c" exchange_multisig_keys "$m_a" "$m_b" | grab)
        echo "exchange r1: ${#x_a}/${#x_b}/${#x_c}"
        [ "${#x_a}" -gt 100 ] && [ "${#x_b}" -gt 100 ] && [ "${#x_c}" -gt 100 ] || { echo "state=failed"; echo "note=exchange r1"; exit 1; }
        local o_a o_b o_c a_a a_b a_c
        o_a=$(wcli2 "$id" arbiter "$pw_a" exchange_multisig_keys "$x_b" "$x_c")
        o_b=$(wcli2 "$id" seller "$pw_b" exchange_multisig_keys "$x_a" "$x_c")
        o_c=$(wcli2 "$id" buyer "$pw_c" exchange_multisig_keys "$x_a" "$x_b")
        a_a=$(printf '%s' "$o_a" | grep -oE 'Multisig address: [1-9A-HJ-NP-Za-km-z]{60,}' | awk '{print $3}')
        a_b=$(printf '%s' "$o_b" | grep -oE 'Multisig address: [1-9A-HJ-NP-Za-km-z]{60,}' | awk '{print $3}')
        a_c=$(printf '%s' "$o_c" | grep -oE 'Multisig address: [1-9A-HJ-NP-Za-km-z]{60,}' | awk '{print $3}')
        if [ -n "$a_a" ] && [ "$a_a" = "$a_b" ] && [ "$a_a" = "$a_c" ]; then
            echo "id=$id"; echo "address=$a_a"; echo "state=ready"
            echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        else
            echo "id=$id"; echo "state=failed"; echo "note=address mismatch a=$a_a b=$a_b c=$a_c"
        fi
    } > "$LAB_DIR/$id.result.tmp" 2> "$log"
    # wynik (stdout) do .result, diagnostyka do .log
    grep -E '^(id|address|state|created|note)=' "$LAB_DIR/$id.result.tmp" > "$res" 2>/dev/null \
        || { echo "id=$id"; echo "state=failed"; echo "note=no result"; } >> "$res"
    cat "$LAB_DIR/$id.result.tmp" >> "$log"
    rm -f "$LAB_DIR/$id.result.tmp"
}

fund_instance() { # fund_instance <id> — przelew z faucetu na adres instancji
    local id=$1 res=$LAB_DIR/$1.result
    grep -q '^state=ready' "$res" 2>/dev/null || return 0
    grep -q '^tx_hash=' "$res" 2>/dev/null && return 0
    local addr amt raw
    addr=$(grep '^address=' "$res" | cut -d= -f2)
    [ -n "$addr" ] || return 0
    amt=$(/usr/bin/python3 -c "print(int($FUND_XMR * 10**12))")
    fa() { curl -s -m 90 --digest -u "$RPC_USER:$RPC_PASS" \
        -H 'Content-Type: application/json' -d "$1" http://127.0.0.1:38088/json_rpc; }
    fa '{"jsonrpc":"2.0","id":"1","method":"open_wallet","params":{"filename":"faucet_wallet","password":"'"$FAUCET_PASS"'"}}' >/dev/null
    raw=$(fa '{"jsonrpc":"2.0","id":"1","method":"transfer","params":{"destinations":[{"amount":'"$amt"',"address":"'"$addr"'"}],"priority":0,"get_tx_key":true}}')
    fa '{"jsonrpc":"2.0","id":"1","method":"close_wallet","params":{}}' >/dev/null 2>&1 || true
    local tx
    tx=$(printf '%s' "$raw" | /usr/bin/python3 -c '
import json,sys
try: print(json.load(sys.stdin).get("result",{}).get("tx_hash",""))
except Exception: print("")')
    if [ -n "$tx" ]; then
        echo "tx_hash=$tx" >> "$res"
        echo "funded_xmr=$FUND_XMR" >> "$res"
        echo "[$id] finansowanie OK: $FUND_XMR XMR, tx ${tx:0:16}..."
    else
        echo "[$id] finansowanie NIEUDANE: $(printf '%s' "$raw" | tr -d '\n' | cut -c1-160)"
    fi
}

build_state() { # agregacja *.result + potwierdzenia z daemon -> lab.json
    LAB_DIR="$LAB_DIR" DAEMON="$DAEMON" /usr/bin/python3 - <<'PYEOF'
import json, os, urllib.request
from datetime import datetime, timezone
from pathlib import Path

lab = Path(os.environ["LAB_DIR"])
daemon = os.environ["DAEMON"].rstrip("/")
instances = []
for res in sorted(lab.glob("*.result")):
    data = {}
    for line in res.read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    inst = {
        "id": data.get("id", res.stem),
        "state": data.get("state", "unknown"),
        "address": data.get("address", ""),
        "funded_xmr": float(data.get("funded_xmr", 0) or 0),
        "tx_hash": data.get("tx_hash", ""),
        "confirmations": 0,
        "created_at": data.get("created", ""),
        "note": data.get("note", ""),
    }
    if inst["tx_hash"]:
        try:
            req = urllib.request.Request(
                daemon + "/get_transactions",
                data=json.dumps({"txs_hashes": [inst["tx_hash"]], "decode_as_json": False}).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                txs = json.loads(resp.read()).get("txs") or []
            if txs:
                inst["confirmations"] = txs[0].get("confirmations", 0)
                if inst["confirmations"] >= 10:
                    inst["state"] = "confirmed"
                elif inst["confirmations"] >= 1:
                    inst["state"] = "confirming"
                else:
                    inst["state"] = "funded"
        except Exception:
            pass
    instances.append(inst)
summary = {}
for inst in instances:
    summary[inst["state"]] = summary.get(inst["state"], 0) + 1
doc = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "chain_height": 0,
    "summary": summary,
    "instances": instances,
}
(lab / "lab.json").write_text(json.dumps(doc, indent=2))
print(f"lab.json: {len(instances)} instancji — {summary}")
PYEOF
}

case ${1:-} in
    up)
        n=${2:-3}
        case "$n" in ''|*[!0-9]*) die 'N musi byc liczba.' ;; esac
        [ "$n" -ge 1 ] && [ "$n" -le 9 ] || die 'N w zakresie 1..9.'
        dock info >/dev/null 2>&1 || die 'brak dostepu do docker.'
        [ "$(dock container inspect --format '{{.State.Running}}' "$CT" 2>/dev/null)" = true ] \
            || die "kontener $CT nie dziala — najpierw: sudo sh tools/alpine-stagenet.sh start"
        echo "nxms-lab: $n rownoleglych instancji multisig 2/3..."
        pids=""
        i=1
        while [ "$i" -le "$n" ]; do
            id=$(printf 'lab-%02d' "$i")
            if grep -q '^state=ready' "$LAB_DIR/$id.result" 2>/dev/null; then
                echo "[$id] juz gotowa — pomijam"
            else
                ceremony "$id" &
                pids="$pids $!"
            fi
            i=$((i + 1))
        done
        for pid in $pids; do wait "$pid" || true; done
        echo '--- finansowanie ---'
        i=1
        while [ "$i" -le "$n" ]; do
            fund_instance "$(printf 'lab-%02d' "$i")"
            i=$((i + 1))
        done
        build_state
        ;;
    fund)
        for res in "$LAB_DIR"/*.result; do
            [ -f "$res" ] || continue
            fund_instance "$(basename "$res" .result)"
        done
        build_state
        ;;
    status)
        build_state
        ;;
    down)
        dock exec --user nxms "$CT" rm -rf /state/lab 2>/dev/null || true
        rm -f "$LAB_DIR"/*.result "$LAB_DIR"/*.secrets "$LAB_DIR"/*.log "$STATE"
        echo 'nxms-lab: sprzatniete.'
        ;;
    *) echo "Usage: bash tools/l.sh {up [N]|fund|status|down}"; exit 2 ;;
esac
