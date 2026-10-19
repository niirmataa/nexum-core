#!/bin/bash
# OPS: sonda-domkniecie multisig 2/3 dla Monero 0.18.4.
#
# Fakt ze zrodel v0.18.4.3 (wallet_rpc_server.cpp:4455): on_finalize_multisig
# to STUB (return false z pustym er) — finalize_multisig w 0.18.4 NIE ISTNIEJE.
# Domkniecie idzie przez exchange_multisig_keys w rundach do ready:true
# (handler zwraca 'address', gdy ready). Przeplyw: prepare -> make -> exchange xN.
#
# Dziala NA GOTOWYCH STANACH po prepare/make z ostatniej ceremonii.
# Usage: sudo bash tools/p.sh   (log: /tmp/opencode/multisig-probe.log)
set -u
LOG=/tmp/opencode/multisig-probe.log
exec > >(tee "$LOG") 2>&1
echo "=== nxms-multisig-probe v2 $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
[ "$(id -u)" = 0 ] || { echo 'Run as root (sudo bash tools/p.sh).'; exit 1; }

CLI_DIR=/var/lib/nxms-ceremony
pass_a=$(cat /etc/nxms/secrets-src/signer-a/wallet_rpc_wallet_password)
pass_b=$(cat /etc/nxms/secrets-src/signer-b/wallet_rpc_wallet_password)
rpc_pass_a=$(cat /etc/nxms/secrets-src/monero-a/wallet_rpc_password)
rpc_pass_b=$(cat /etc/nxms/secrets-src/monero-b/wallet_rpc_password)
pass_buyer=$(cat "$CLI_DIR/buyer-multisig/buyer-wallet-password.txt")

# --- Diagnoza i sprzatanie blokad portfeli ---
echo '--- trzymacze blokad (przed sprzataniem) ---'
ps -eo pid,user,args | grep '[m]onero-wallet-cli' | cut -c1-120 || true
for f in /var/lib/nxms-monero-a/wallets/*.keys /var/lib/nxms-monero-b/wallets/*.keys; do
    fuser -v "$f" 2>&1 | head -3 || true
done
pkill -9 -f 'monero-wallet-cli' 2>/dev/null || true
for f in /var/lib/nxms-monero-a/wallets/*.keys /var/lib/nxms-monero-b/wallets/*.keys; do
    fuser -k "$f" 2>/dev/null || true
done
sleep 2
systemctl restart nxms-wallet-rpc-a nxms-wallet-rpc-b
sleep 4
for i in $(seq 1 20); do
    c=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -d '{}' http://127.0.0.1:38088/json_rpc 2>/dev/null || true)
    case "$c" in 200|401) break ;; esac; sleep 2
done

# Stringi make z ostatniej ceremonii (zrzuty w logu runnera).
m_a=$(sed -n '/\[make-a\]/,/\[make-b\]/p' /tmp/opencode/allinone-run.log | grep -o 'Multisig[A-Za-z0-9+/=]\{30,\}' | tail -1)
m_b=$(sed -n '/\[make-b\]/,/\[make-buyer\]/p' /tmp/opencode/allinone-run.log | grep -o 'Multisig[A-Za-z0-9+/=]\{30,\}' | tail -1)
m_buyer=$(sed -n '/\[make-buyer\]/,/\[finalize a\]/p' /tmp/opencode/allinone-run.log | grep -o 'Multisig[A-Za-z0-9+/=]\{30,\}' | tail -1)
echo "stringi make: a=${#m_a} b=${#m_b} buyer=${#m_buyer} znakow"
[ "${#m_a}" -gt 100 ] && [ "${#m_b}" -gt 100 ] && [ "${#m_buyer}" -gt 100 ] || { echo 'brak stringow make w logu'; exit 1; }

rpc() {
    curl -s -m 60 --digest -u "$2:$3" -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"$4\",\"params\":$5}" \
        "http://127.0.0.1:$1/json_rpc" 2>/dev/null
}
pyget() { /usr/bin/python3 -c "
import json,sys
try:
    d=json.load(sys.stdin); r=d.get('result') or {}
    v=r.get('$1','')
    print(' '.join(v) if isinstance(v,list) else v)
except Exception:
    pass
"; }
pyerr() { /usr/bin/python3 -c "
import json,sys
try:
    d=json.load(sys.stdin); e=d.get('error') or {}
    print('BLAD %s: %s' % (e.get('code',''), e.get('message','')[:120]))
except Exception:
    print('brak odpowiedzi')
"; }
open_w() {
    local raw
    for i in 1 2 3 4 5; do
        raw=$(rpc "$1" "$2" "$3" open_wallet "{\"filename\":\"$4\",\"password\":\"$5\"}")
        printf '%s' "$raw" | grep -q '"result"' && return 0
        echo "[open $6] proba $i: $(printf '%s' "$raw" | tr -d '\n' | cut -c1-140)"
        sleep 3
    done
    return 1
}

# exchange_round <opis> <port> <user> <rpcpass> <wpass> <plik> <s1> <s2>
# -> na STDOUT: <nowy_string>|<adres>; diagnostyka na stderr.
exchange_round() {
    local raw res addr err
    open_w "$2" "$3" "$4" "$6" "$5" "$1" || { echo "[$1] NIE OTWARTO" >&2; printf '|\n'; return 0; }
    raw=$(rpc "$2" "$3" "$4" exchange_multisig_keys "{\"multisig_info\":[\"$7\",\"$8\"],\"password\":\"$5\"}")
    err=$(printf '%s' "$raw" | pyerr)
    res=$(printf '%s' "$raw" | pyget multisig_info)
    addr=$(printf '%s' "$raw" | pyget address)
    echo "[$1] ${err:-ok} | nowy=${#res} zn | addr=${addr:0:20}" >&2
    rpc "$2" "$3" "$4" close_wallet '{}' >/dev/null 2>&1 || true
    printf '%s|%s' "$res" "$addr"
}

p_a=$m_a; p_b=$m_b; p_buyer=$m_buyer   # stringi WEJSCIOWE rundy dla kazdego (poczatkowo: make)
addr_a=; addr_b=; addr_buyer=
for round in 1 2 3; do
    echo "=== RUNDA $round ==="
    out=$(exchange_round "r$round arbiter" 38088 wallet-rpc-user-a "$rpc_pass_a" "$pass_a" escrow_wallet_a "$p_b" "$p_buyer")
    x_a=${out%%|*}; addr_a=${out#*|}
    out=$(exchange_round "r$round seller" 38089 wallet-rpc-user-b "$rpc_pass_b" "$pass_b" escrow_wallet_b "$p_a" "$p_buyer")
    x_b=${out%%|*}; addr_b=${out#*|}
    out=$(exchange_round "r$round buyer" 38088 wallet-rpc-user-a "$rpc_pass_a" "$pass_buyer" buyer_wallet "$p_a" "$p_b")
    x_buyer=${out%%|*}; addr_buyer=${out#*|}
    if [ -n "$addr_a" ] && [ -n "$addr_b" ] && [ -n "$addr_buyer" ]; then
        echo "WSZYSTKIE READY po rundzie $round"
        break
    fi
    [ -n "$x_a" ] && p_a=$x_a; [ -n "$x_b" ] && p_b=$x_b; [ -n "$x_buyer" ] && p_buyer=$x_buyer
    [ -z "$x_a$x_b$x_buyer" ] && { echo 'wymiana nie zwraca nowych stringow — stop'; break; }
done

echo '--- weryfikacja stanu ---'
open_w 38088 wallet-rpc-user-a "$rpc_pass_a" escrow_wallet_a "$pass_a" arbiter || true
echo "[is_multisig arbiter] $(rpc 38088 wallet-rpc-user-a "$rpc_pass_a" is_multisig '{}' | tr -d '\n' | cut -c1-200)"
echo "[get_address arbiter] $(rpc 38088 wallet-rpc-user-a "$rpc_pass_a" get_address '{}' | pyget address)"
rpc 38088 wallet-rpc-user-a "$rpc_pass_a" close_wallet '{}' >/dev/null 2>&1 || true
open_w 38089 wallet-rpc-user-b "$rpc_pass_b" escrow_wallet_b "$pass_b" seller || true
echo "[is_multisig seller]  $(rpc 38089 wallet-rpc-user-b "$rpc_pass_b" is_multisig '{}' | tr -d '\n' | cut -c1-200)"
rpc 38089 wallet-rpc-user-b "$rpc_pass_b" close_wallet '{}' >/dev/null 2>&1 || true
if [ -n "$addr_a" ] && [ -n "$addr_b" ] && [ -n "$addr_buyer" ]; then
    echo "done $(date -u +%Y-%m-%dT%H:%M:%SZ) (exchange rounds)" > "$CLI_DIR/ceremony.complete"
    echo "ADRES MULTISIG 2/3: $addr_a"
    echo "zgodnosc adresow: a=[$addr_a] b=[$addr_b] buyer=[$addr_buyer]"
fi
echo "=== probe END $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
