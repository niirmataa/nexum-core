#!/bin/bash
# OPS: ceremonia multisig 2/3 na Alpine — monero 0.18.5.0 (apk) w kontenerze
# nexum-alpine-stagenet (ten sam, ktory trzyma chain stagenet).
#
# Przeplyw DOKLADNIE wg monerodocs "Multisignature" (2/3 = N-1/N):
#   0. set ask-password 0  +  set enable-multisig-experimental 1
#   1. prepare_multisig                   -> stringi r1 (MultisigxV2R1..., 189)
#   2. make_multisig 2 <r1 innych>        -> stringi r2 (MultisigxV2Rn1..., 236)
#   3. exchange_multisig_keys <r2 innych> -> "Another step is needed" + (236)
#   4. exchange_multisig_keys <r3 innych> -> "Multisig wallet has been
#      successfully created. Current wallet type: 2/3. Multisig address: 5..."
#
# Fakty techniczne (zweryfikowane w zrodlach v0.18.5.0 i na zywym sprzecie):
#   - 'finalize_multisig' NIE istnieje w kodzie Monero (zaslepka w 0.18.4/
#     0.18.5.0 RPC, usunieta w 0.18.5.1+) — dokumentacja wallet-rpc ja opisuje,
#     ale to jej blad. Domkniecie 2/3 idzie WYLACZNIE exchange_multisig_keys
#     (runda 2 zwraca adres).
#   - BUG 0.18.5.0: exchange_multisig_keys w rundzie nie-ostatniej zapisuje
#     plik kluczy w zlym stanie szyfrowania przy domyslnym ask-password
#     2 (decrypt) — nastepna sesja dostaje smieciowy klucz ("Failed to derive
#     public key"). Obejscie: set ask-password 0 (never) PRZED wszystkim.
#   - komendy multisig prosza o haslo ('get_and_verify_password') — haslo
#     podajemy na stdin przez docker exec -i.
#   - --command przyjmuje JEDNA komende; slowa jako osobne argv
#     (process_command_vec: front=komenda, reszta=argumenty).
#   - flaga enable-multisig jest zapisywana w pliku portfela (wallet2.cpp
#     4855/5332) — wystarczy ustawic raz.
#
# Usage: sudo bash tools/a.sh   (log: /tmp/opencode/alpine-ceremony.log)
set -u
LOG=/tmp/opencode/alpine-ceremony.log
exec > >(tee "$LOG") 2>&1
echo "=== nxms-alpine-multisig $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
[ "$(id -u)" = 0 ] || { echo 'Run as root (sudo bash tools/a.sh).'; exit 1; }

die() { echo "nxms-alpine-multisig: $*"; echo "=== FAILED $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="; exit 1; }

dock() {
    env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
        /usr/bin/docker --host unix:///var/run/docker.sock "$@"
}
CT=${NXMS_STAGENET_CONTAINER:-nexum-alpine-stagenet}
dock info >/dev/null 2>&1 || die 'Docker niedostepny.'
if [ "$(dock container inspect --format '{{.State.Running}}' "$CT" 2>/dev/null)" != true ]; then
    echo 'kontener nie dziala — start z ustawieniami odczytanymi z kontenera'
    env_of() { dock container inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$CT" 2>/dev/null | awk -F= -v k="$1" '$1==k {print $2}'; }
    net=$(env_of NXMS_STAGENET_NETWORK);  [ -n "$net" ] || net=direct
    dwn=$(env_of NXMS_STAGENET_DOWNLOAD_KIB); [ -n "$dwn" ] || dwn=104857600
    upp=$(env_of NXMS_STAGENET_UP);        [ -n "$upp" ] || upp=128
    echo "start: network=$net download=$dwn up=$upp"
    NXMS_STAGENET_NETWORK=$net NXMS_STAGENET_DOWNLOAD_KIB=$dwn NXMS_STAGENET_UP=$upp \
        sh "$(dirname "$0")/alpine-stagenet.sh" start || die 'nie udalo sie uruchomic kontenera'
fi

dock exec --user nxms "$CT" monero-wallet-cli --version 2>/dev/null | head -1
for i in $(seq 1 40); do
    h=$(dock exec --user nxms "$CT" curl -s --noproxy '*' -m 5 http://127.0.0.1:38081/get_info 2>/dev/null \
        | /usr/bin/python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("height",0))
except Exception: print(0)')
    [ "${h:-0}" -gt 0 ] && break
    sleep 5
done
[ "${h:-0}" -gt 0 ] || die 'monerod w kontenerze nie odpowiada (get_info).'
echo "chain height (kontener): $h"

pass_a=$(cat /etc/nxms/secrets-src/signer-a/wallet_rpc_wallet_password)
pass_b=$(cat /etc/nxms/secrets-src/signer-b/wallet_rpc_wallet_password)
pass_buyer=$(cat /var/lib/nxms-ceremony/buyer-multisig/buyer-wallet-password.txt 2>/dev/null || true)
[ -n "$pass_buyer" ] || pass_buyer=$(openssl rand -hex 32)
restore_h=$(( h > 1000 ? h - 1000 : 0 ))

dock exec --user nxms "$CT" mkdir -p /state/wallets

# Finansowanie escrow z faucetu (100 XMR stagenet juz czeka) — idempotentne
# przez znacznik .funded, zeby nie wysylac dwa razy.
fund_escrow() { # fund_escrow <adres>
    local addr=$1 fund_xmr=${NXMS_ESCROW_FUND_XMR:-0.05} rpc_pass_a amt raw
    [ -f /var/lib/nxms-ceremony/alpine-multisig.funded ] && { echo 'finansowanie: juz wykonane (znacznik .funded)'; return 0; }
    rpc_pass_a=$(cat /etc/nxms/secrets-src/monero-a/wallet_rpc_password)
    fa() { curl -s -m 90 --digest -u "wallet-rpc-user-a:$rpc_pass_a" \
        -H 'Content-Type: application/json' -d "$1" http://127.0.0.1:38088/json_rpc; }
    amt=$(/usr/bin/python3 -c "print(int($fund_xmr * 10**12))")
    echo "--- finansowanie escrow: $fund_xmr XMR z faucetu ---"
    fa '{"jsonrpc":"2.0","id":"1","method":"open_wallet","params":{"filename":"faucet_wallet","password":"faucet-stagenet-2026"}}' >/dev/null
    raw=$(fa '{"jsonrpc":"2.0","id":"1","method":"transfer","params":{"destinations":[{"amount":'"$amt"',"address":"'"$addr"'"}],"priority":0,"get_tx_key":true}}')
    echo "[fund] $(printf '%s' "$raw" | tr -d '\n' | cut -c1-260)"
    if printf '%s' "$raw" | grep -q '"tx_hash"'; then
        echo "done $(date -u +%Y-%m-%dT%H:%M:%SZ) fund $fund_xmr XMR" > /var/lib/nxms-ceremony/alpine-multisig.funded
        echo "przelew escrow nadany ($fund_xmr XMR -> $addr)"
    else
        echo 'finansowanie NIE powiodlo sie — sprobuj ponownie (brak znacznika .funded)'
    fi
    fa '{"jsonrpc":"2.0","id":"1","method":"close_wallet","params":{}}' >/dev/null 2>&1 || true
}

# --- Idempotencja: jesli komplet gotowy, tylko raportujemy adres + finansujemy ---
if [ -f /var/lib/nxms-ceremony/alpine-multisig.complete ]; then
    addr=$(dock exec --user nxms "$CT" timeout 120 monero-wallet-cli --stagenet \
        --daemon-address 127.0.0.1:38081 --wallet-file /state/wallets/escrow_wallet_a \
        --password "$pass_a" --command wallet_info 2>/dev/null | grep -oE '[1-9A-HJ-NP-Za-km-z]{80,106}' | tail -1)
    echo "multisig 2/3 juz gotowy. ADRES: $addr"
    [ -n "$addr" ] && fund_escrow "$addr"
    echo "=== END $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    exit 0
fi

# Jeden krok CLI na wywolanie; haslo na stdin (komendy multisig pytaja o nie).
wcli() { # wcli <plik> <haslo> <slowo komendy> [argumenty...]
    local f=$1 pw=$2; shift 2
    printf '%s\n' "$pw" | dock exec -i --user nxms "$CT" timeout 600 monero-wallet-cli --stagenet \
        --daemon-address 127.0.0.1:38081 --trusted-daemon \
        --wallet-file "/state/wallets/$f" --password "$pw" --command "$@" 2>&1
}
grab() { grep -o 'Multisig[A-Za-z0-9+/=]\{30,\}' | tail -1; }

# --- 0. Swiezy komplet portfeli ---
for f in escrow_wallet_a escrow_wallet_b buyer_wallet; do
    dock exec --user nxms "$CT" rm -f "/state/wallets/$f" "/state/wallets/$f.keys"
done
rm -f /var/lib/nxms-ceremony/alpine-multisig.complete
echo '--- tworzenie portfeli + flagi ---'
for spec in "escrow_wallet_a:$pass_a" "escrow_wallet_b:$pass_b" "buyer_wallet:$pass_buyer"; do
    f=${spec%%:*}; pw=${spec#*:}
    out=$(dock exec --user nxms "$CT" timeout 600 monero-wallet-cli --stagenet \
        --daemon-address 127.0.0.1:38081 --trusted-daemon \
        --generate-new-wallet "/state/wallets/$f" --password "$pw" \
        --mnemonic-language English --restore-height "$restore_h" --command address 2>&1)
    echo "[$f utworzony] $(printf '%s' "$out" | grep -oE '[1-9A-HJ-NP-Za-km-z]{80,106}' | tail -1 | cut -c1-30)..."
    dock exec --user nxms "$CT" test -f "/state/wallets/$f.keys" || die "nie utworzono $f"
    wcli "$f" "$pw" set ask-password 0 >/dev/null   # never — omija bug zapisu 0.18.5.0
    wcli "$f" "$pw" set enable-multisig-experimental 1 >/dev/null
done

# --- 1. prepare_multisig x3 ---
echo '--- prepare_multisig ---'
p_a=$(wcli escrow_wallet_a "$pass_a" prepare_multisig | grab)
p_b=$(wcli escrow_wallet_b "$pass_b" prepare_multisig | grab)
p_buyer=$(wcli buyer_wallet "$pass_buyer" prepare_multisig | grab)
echo "prepare: a=${#p_a} b=${#p_b} buyer=${#p_buyer} znakow"
[ "${#p_a}" -gt 100 ] && [ "${#p_b}" -gt 100 ] && [ "${#p_buyer}" -gt 100 ] || die 'prepare_multisig nie zwrocil stringow.'

# --- 2. make_multisig 2 <r1 innych> x3 ---
echo '--- make_multisig 2 ---'
m_a=$(wcli escrow_wallet_a "$pass_a" make_multisig 2 "$p_b" "$p_buyer" | grab)
m_b=$(wcli escrow_wallet_b "$pass_b" make_multisig 2 "$p_a" "$p_buyer" | grab)
m_buyer=$(wcli buyer_wallet "$pass_buyer" make_multisig 2 "$p_a" "$p_b" | grab)
echo "make: a=${#m_a} b=${#m_b} buyer=${#m_buyer} znakow"
[ "${#m_a}" -gt 100 ] && [ "${#m_b}" -gt 100 ] && [ "${#m_buyer}" -gt 100 ] || die 'make_multisig nie zwrocil stringow.'

# --- 3. exchange_multisig_keys — runda 1 (na stringach make) ---
echo '--- exchange runda 1 ---'
x_a=$(wcli escrow_wallet_a "$pass_a" exchange_multisig_keys "$m_b" "$m_buyer" | grab)
x_b=$(wcli escrow_wallet_b "$pass_b" exchange_multisig_keys "$m_a" "$m_buyer" | grab)
x_buyer=$(wcli buyer_wallet "$pass_buyer" exchange_multisig_keys "$m_a" "$m_b" | grab)
echo "exchange r1: a=${#x_a} b=${#x_b} buyer=${#x_buyer} znakow"
[ "${#x_a}" -gt 100 ] && [ "${#x_b}" -gt 100 ] && [ "${#x_buyer}" -gt 100 ] || die 'exchange_multisig_keys (r1) nie zwrocil stringow.'

# --- 4. exchange_multisig_keys — runda 2 (domkniecie 2/3 -> adres) ---
echo '--- exchange runda 2 (domkniecie) ---'
out_a=$(wcli escrow_wallet_a "$pass_a" exchange_multisig_keys "$x_b" "$x_buyer")
out_b=$(wcli escrow_wallet_b "$pass_b" exchange_multisig_keys "$x_a" "$x_buyer")
out_buyer=$(wcli buyer_wallet "$pass_buyer" exchange_multisig_keys "$x_a" "$x_b")
echo "[r2 a] $(printf '%s' "$out_a" | tail -2 | tr '\n' ' ' | cut -c1-170)"
echo "[r2 b] $(printf '%s' "$out_b" | tail -2 | tr '\n' ' ' | cut -c1-170)"
echo "[r2 buyer] $(printf '%s' "$out_buyer" | tail -2 | tr '\n' ' ' | cut -c1-170)"
addr_a=$(printf '%s' "$out_a" | grep -oE 'Multisig address: [1-9A-HJ-NP-Za-km-z]{60,}' | awk '{print $3}')
addr_b=$(printf '%s' "$out_b" | grep -oE 'Multisig address: [1-9A-HJ-NP-Za-km-z]{60,}' | awk '{print $3}')
addr_buyer=$(printf '%s' "$out_buyer" | grep -oE 'Multisig address: [1-9A-HJ-NP-Za-km-z]{60,}' | awk '{print $3}')

# --- 5. Weryfikacja: ten sam adres u wszystkich ---
echo '--- weryfikacja wallet_info x3 ---'
for spec in "escrow_wallet_a:$pass_a" "escrow_wallet_b:$pass_b" "buyer_wallet:$pass_buyer"; do
    f=${spec%%:*}; pw=${spec#*:}
    echo "[wallet_info $f] $(wcli "$f" "$pw" wallet_info | tail -3 | tr '\n' ' ' | cut -c1-180)"
done

if [ -n "$addr_a" ] && [ "$addr_a" = "$addr_b" ] && [ "$addr_a" = "$addr_buyer" ]; then
    echo "done $(date -u +%Y-%m-%dT%H:%M:%SZ) alpine-2/3" > /var/lib/nxms-ceremony/alpine-multisig.complete
    printf '%s\n' "$addr_a" > /var/lib/nxms-ceremony/alpine-multisig-address.txt
    dock cp "$CT:/state/wallets/buyer_wallet" /var/lib/nxms-ceremony/buyer-multisig/buyer_wallet.alpine 2>/dev/null || true
    dock cp "$CT:/state/wallets/buyer_wallet.keys" /var/lib/nxms-ceremony/buyer-multisig/buyer_wallet.alpine.keys 2>/dev/null || true
    echo "ADRES MULTISIG 2/3 (wszystkie zgodne): $addr_a"
    fund_escrow "$addr_a"
    echo "Nastepny krok: granica wallet-rpc 0.18.5 w kontenerze + podpiecie signerow (roadmap D)."
else
    die "adresy niezgodne lub brak: a=[$addr_a] b=[$addr_b] buyer=[$addr_buyer]"
fi
echo "=== END $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
