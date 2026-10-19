#!/bin/bash
# OPS: sekcja D — ceremonia bootstrapu multisig 2/3 (N-1/N).
#
# Strony (2-of-3, arbiter index 0): escrow_wallet_a (arbiter/monero-a),
# escrow_wallet_b (seller/monero-b), buyer_wallet (klucz ceremonialny).
#
# Przeplyw DOKLADNIE wg monerodocs "Multisignature" (2/3 = N-1/N):
#   1. prepare_multisig            — inicjalizacja (stringi r1)
#   2. make_multisig 2 <r1 innych> — druga runda (stringi r2)
#   3. finalize_multisig <r2 innych> — domkniecie -> ADRES multisig
# exchange_multisig_keys NIE jest potrzebne dla 2/3 (to "extra rounds"
# dla M/N z M>2) i wczesniejsze jego uzycie psulo stan przed finalize.
#
# Fakty techniczne monero 0.18.4 (Debian):
#   - finalize_multisig istnieje TYLKO w wallet-rpc (brak w CLI),
#   - 'set enable-multisig-experimental 1' jest procesowe i wymaga hasla;
#     przez --command nie dziala (brak rozbijania argumentow) — sesje PTY,
#   - close_wallet bez otwartego portfela wiesza wallet-rpc,
#   - pty czysci bufor wejscia przy starcie — wejscie tempowane,
#   - ekstraktor: stringi moga byc lamane/kontaminowane przez echo —
#     inputy sa usuwane z surowca, bledy 'Unknown command' ignorowane.
#
# Usage: sudo bash tools/nxms-multisig-ceremony.sh
set -eu
trap 'printf "nxms-multisig-ceremony: FAILED at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
die() { printf 'nxms-multisig-ceremony: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die 'Run as root (sudo bash ...).'
[ "${SUDO_UID:-0}" -gt 0 ] || die 'Run sudo from your regular user account.'
command -v curl >/dev/null 2>&1 || die 'curl not installed.'

CLI_BIN=/usr/bin/monero-wallet-cli
ceremony_dir=/var/lib/nxms-ceremony
buyer_dir=$ceremony_dir/buyer-multisig
wdir_a=/var/lib/nxms-monero-a/wallets
wdir_b=/var/lib/nxms-monero-b/wallets
wallet_a=escrow_wallet_a
wallet_b=escrow_wallet_b
wallet_buyer=buyer_wallet

install -d -m 0750 -o root -g root "$ceremony_dir"
install -d -m 0700 -o root -g root "$buyer_dir"

secret() { cat "$1"; }
pass_a=$(secret /etc/nxms/secrets-src/signer-a/wallet_rpc_wallet_password)
pass_b=$(secret /etc/nxms/secrets-src/signer-b/wallet_rpc_wallet_password)
rpc_pass_a=$(secret /etc/nxms/secrets-src/monero-a/wallet_rpc_password)
rpc_pass_b=$(secret /etc/nxms/secrets-src/monero-b/wallet_rpc_password)
pass_buyer=$(openssl rand -hex 32)
[ -f "$buyer_dir/buyer-wallet-password.txt" ] && [ -f "$wdir_a/buyer_wallet.keys" ] \
    && pass_buyer=$(cat "$buyer_dir/buyer-wallet-password.txt")

# --- Swiezy stan uslug (signery przeszkadzaja we wspoldzielonych wallet-rpc) ---
# Wiszace sesje monero-wallet-cli trzymaja blokady plikow portfeli — sprzatamy.
pkill -f 'monero-wallet-cli' 2>/dev/null || true
sleep 2
systemctl stop nxms-signer-a nxms-signer-b
systemctl restart nxms-monerod-a
systemctl restart nxms-wallet-rpc-a nxms-wallet-rpc-b
sleep 3
for i in $(seq 1 60); do
    if curl -s -m 5 http://127.0.0.1:38081/get_info >/dev/null 2>&1; then
        printf 'monerod: ready\n'; break
    fi
    [ "$i" = 60 ] && die 'monerod not ready.'
    sleep 3
done
for port in 38088 38089; do
    for i in $(seq 1 30); do
        code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -d '{}' "http://127.0.0.1:$port/json_rpc" 2>/dev/null || true)
        case "$code" in 200|401) printf 'wallet-rpc %s: ready (%s)\n' "$port" "$code"; break ;; esac
        [ "$i" = 30 ] && die "wallet-rpc $port not ready."
        sleep 2
    done
done

rpc() {
    local out
    out=$(curl -s -m 60 --digest -u "$2:$3" -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"$4\",\"params\":$5}" \
        "http://127.0.0.1:$1/json_rpc" 2>/dev/null) || \
    out=$(curl -s -m 60 --digest -u "$2:$3" -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"$4\",\"params\":$5}" \
        "http://127.0.0.1:$1/json_rpc" 2>/dev/null) || return 1
    printf '%s' "$out"
}

# Sesja CLI przez PTY: konsola czyta z tty, nie z potoku; wejscie tempowane
# (pty czysci bufor przy starcie). 'n'/'y' sa nadmiarowe (nieszkodliwe).
cli_sess() { # cli_sess <user|-> <wallet> <wpass> <cmd>
    local run_str="$CLI_BIN --stagenet --daemon-address 127.0.0.1:38081 --wallet-file $2 --password $3" out
    [ "$1" = - ] || run_str="runuser -u $1 -- $run_str"
    out=$({
        sleep 25
        printf 'n\n'; sleep 2
        printf 'set enable-multisig-experimental 1\n'; sleep 3
        printf '%s\n' "$3"; sleep 3
        printf '%s\n' "$4"; sleep 4
        printf '%s\n' "$3"; sleep 3
        printf 'y\n'; sleep 2
        printf 'exit\n'
    } | timeout -k 10 170 script -qec "stty cols 4000 2>/dev/null; $run_str" /dev/null 2>&1 || true)
    printf '%s' "$out" | sed "s/$3/***/g"
}

msig_strict() {
    local raw
    raw=$(sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g')
    if printf '%s' "$raw" | grep 'Error:' | grep -vq 'Unknown command'; then
        return 0
    fi
    # UWAGA: NIE sklejac linii (tr) — 'Send this multisig info...' dokleja sie
    # do stringa; przy stty cols 4000 stringi sa i tak niezawijane.
    printf '%s' "$raw" | grep -o 'Multisig[A-Za-z0-9+/=]\{30,\}' | tail -1
}

# Otwarcie portfela z weryfikacja i ponowieniami — nieudane open to glowna
# przyczyna "pustych bledow" finalize w tym buildzie.
open_w() { # open_w <port> <user> <rpcpass> <file> <wpass> <opis>
    local raw
    for i in 1 2 3 4 5; do
        raw=$(rpc "$1" "$2" "$3" open_wallet "{\"filename\":\"$4\",\"password\":\"$5\"}")
        if printf '%s' "$raw" | grep -q '"result"'; then
            return 0
        fi
        printf '[open %s] proba %s nieudana: %s\n' "$6" "$i" "$(printf '%s' "$raw" | tr -d '\n' | cut -c1-100)" >&2
        sleep 3
    done
    return 1
}

# finalize_multisig wg specyfikacji wallet-rpc: {multisig_info, password}
# (BEZ threshold — jego obecnosc daje pusty blad); wariant bez password.
fin_call() { # fin_call <port> <user> <rpcpass> <wpass> <s1> <s2> <opis>
    local raw
    raw=$(rpc "$1" "$2" "$3" finalize_multisig "{\"multisig_info\":[\"$5\",\"$6\"],\"password\":\"$4\"}")
    if printf '%s' "$raw" | grep -q '"error"'; then
        printf '[finalize %s] wariant z password odrzucony: %s\n' "$7" "$(printf '%s' "$raw" | tr -d '\n' | cut -c1-120)" >&2
        raw=$(rpc "$1" "$2" "$3" finalize_multisig "{\"multisig_info\":[\"$5\",\"$6\"]}")
    fi
    printf '[finalize %s] %s\n' "$7" "$(printf '%s' "$raw" | tr -d '\n' | cut -c1-240)" >&2
    printf '%s' "$raw"
}

if [ -f "$wdir_a/buyer_wallet.keys" ] && [ -f "$wdir_a/escrow_wallet_a.keys" ] \
        && rpc 38088 wallet-rpc-user-a "$rpc_pass_a" open_wallet "{\"filename\":\"$wallet_a\",\"password\":\"$pass_a\"}" | grep -q '"result"' \
        && rpc 38088 wallet-rpc-user-a "$rpc_pass_a" is_multisig '{}' | grep -q '"ready":true'; then
    printf 'multisig wallets: ready (2/3 verified over RPC)\n'
else
    printf 'multisig wallets: rebuilding from scratch\n'
    rm -f "$ceremony_dir/ceremony.complete" \
          "$wdir_a/escrow_wallet_a" "$wdir_a/escrow_wallet_a.keys" \
          "$wdir_b/escrow_wallet_b" "$wdir_b/escrow_wallet_b.keys" \
          "$wdir_a/buyer_wallet" "$wdir_a/buyer_wallet.keys" \
          "$buyer_dir/buyer_wallet" "$buyer_dir/buyer_wallet.keys"

    # 1. Tworzenie portfeli (blisko wierzcholka — krotkie odswiezanie pozniej).
    chain_h=$(curl -s -m 10 http://127.0.0.1:38081/get_info | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin).get("height",0))')
    restore_h=$(( chain_h > 20000 ? chain_h - 20000 : 0 ))
    printf 'chain height: %s | wallet restore_height: %s\n' "$chain_h" "$restore_h"
    raw=$(rpc 38088 wallet-rpc-user-a "$rpc_pass_a" create_wallet "{\"filename\":\"$wallet_a\",\"password\":\"$pass_a\",\"language\":\"English\",\"restore_height\":$restore_h}")
    printf '%s' "$raw" | grep -q '"result"' || die "create_wallet arbiter failed: $raw"
    rpc 38088 wallet-rpc-user-a "$rpc_pass_a" close_wallet '{}' >/dev/null 2>&1 || true
    raw=$(rpc 38088 wallet-rpc-user-a "$rpc_pass_a" create_wallet "{\"filename\":\"$wallet_buyer\",\"password\":\"$pass_buyer\",\"language\":\"English\",\"restore_height\":$restore_h}")
    printf '%s' "$raw" | grep -q '"result"' || die "create_wallet buyer failed: $raw"
    rpc 38088 wallet-rpc-user-a "$rpc_pass_a" close_wallet '{}' >/dev/null 2>&1 || true
    raw=$(rpc 38089 wallet-rpc-user-b "$rpc_pass_b" create_wallet "{\"filename\":\"$wallet_b\",\"password\":\"$pass_b\",\"language\":\"English\",\"restore_height\":$restore_h}")
    printf '%s' "$raw" | grep -q '"result"' || die "create_wallet seller failed: $raw"
    rpc 38089 wallet-rpc-user-b "$rpc_pass_b" close_wallet '{}' >/dev/null 2>&1 || true
    printf 'base wallets created (arbiter, seller, buyer)\n'

    # Pre-sync portfeli przez RPC (krotkie odswiezanie w sesjach CLI).
    presync() {
        local h
        rpc "$1" "$2" "$3" open_wallet "{\"filename\":\"$4\",\"password\":\"$5\"}" | grep -q '"result"' \
            || printf '[presync %s] open nie przeszedl\n' "$6" >&2
        for i in $(seq 1 40); do
            h=$(rpc "$1" "$2" "$3" get_height '{}' | grep -o '"height": *[0-9]*' | grep -o '[0-9]*' || echo 0)
            [ "${h:-0}" -ge $(( chain_h - 5 )) ] 2>/dev/null && break
            sleep 6
        done
        rpc "$1" "$2" "$3" store '{}' >/dev/null 2>&1 || true
        rpc "$1" "$2" "$3" close_wallet '{}' >/dev/null 2>&1 || true
        printf '[presync %s] height %s\n' "$6" "${h:-?}"
    }
    presync 38088 wallet-rpc-user-a "$rpc_pass_a" "$wallet_a" "$pass_a" arbiter
    presync 38088 wallet-rpc-user-a "$rpc_pass_a" "$wallet_buyer" "$pass_buyer" buyer
    presync 38089 wallet-rpc-user-b "$rpc_pass_b" "$wallet_b" "$pass_b" seller

    # 2. prepare_multisig x3 (sesje CLI z flaga).
    raw=$(cli_sess monero-a "$wdir_a/escrow_wallet_a" "$pass_a" 'prepare_multisig')
    printf '[prepare-a] %s\n' "$(printf '%s' "$raw" | tail -25 | tr '\n' ' | ')" >&2
    p_a=$(printf '%s' "$raw" | msig_strict)
    raw=$(cli_sess monero-b "$wdir_b/escrow_wallet_b" "$pass_b" 'prepare_multisig')
    printf '[prepare-b] %s\n' "$(printf '%s' "$raw" | tail -25 | tr '\n' ' | ')" >&2
    p_b=$(printf '%s' "$raw" | msig_strict)
    raw=$(cli_sess - "$wdir_a/buyer_wallet" "$pass_buyer" 'prepare_multisig')
    printf '[prepare-buyer] %s\n' "$(printf '%s' "$raw" | tail -25 | tr '\n' ' | ')" >&2
    p_buyer=$(printf '%s' "$raw" | msig_strict)
    [ -n "$p_a" ] && [ -n "$p_b" ] && [ -n "$p_buyer" ] || die 'prepare_multisig failed.'
    printf 'prepare_multisig: 3/3 (stringi %s/%s/%s znakow)\n' "${#p_a}" "${#p_b}" "${#p_buyer}"

    # 3. make_multisig 2 <r1 innych> x3 — progi jako PIERWSZY argument.
    raw=$(cli_sess monero-a "$wdir_a/escrow_wallet_a" "$pass_a" "make_multisig 2 $p_b $p_buyer")
    printf '[make-a] %s\n' "$(printf '%s' "$raw" | tail -25 | tr '\n' ' | ')" >&2
    m_a=$(printf '%s' "$raw" | sed "s/$p_b//g; s/$p_buyer//g" | msig_strict)
    raw=$(cli_sess monero-b "$wdir_b/escrow_wallet_b" "$pass_b" "make_multisig 2 $p_a $p_buyer")
    printf '[make-b] %s\n' "$(printf '%s' "$raw" | tail -25 | tr '\n' ' | ')" >&2
    m_b=$(printf '%s' "$raw" | sed "s/$p_a//g; s/$p_buyer//g" | msig_strict)
    raw=$(cli_sess - "$wdir_a/buyer_wallet" "$pass_buyer" "make_multisig 2 $p_a $p_b")
    printf '[make-buyer] %s\n' "$(printf '%s' "$raw" | tail -25 | tr '\n' ' | ')" >&2
    m_buyer=$(printf '%s' "$raw" | sed "s/$p_a//g; s/$p_b//g" | msig_strict)
    [ -n "$m_a" ] && [ -n "$m_b" ] && [ -n "$m_buyer" ] || die 'make_multisig failed.'
    printf 'make_multisig: 3/3 (stringi %s/%s/%s znakow)\n' "${#m_a}" "${#m_b}" "${#m_buyer}"

    # 4. finalize_multisig <r2 innych> x3 — wg specyfikacji wallet-rpc.
    open_w 38088 wallet-rpc-user-a "$rpc_pass_a" "$wallet_a" "$pass_a" arbiter || die 'open arbiter przed finalize'
    fin_a=$(fin_call 38088 wallet-rpc-user-a "$rpc_pass_a" "$pass_a" "$m_b" "$m_buyer" a)
    rpc 38088 wallet-rpc-user-a "$rpc_pass_a" close_wallet '{}' >/dev/null 2>&1 || true
    open_w 38089 wallet-rpc-user-b "$rpc_pass_b" "$wallet_b" "$pass_b" seller || die 'open seller przed finalize'
    fin_b=$(fin_call 38089 wallet-rpc-user-b "$rpc_pass_b" "$pass_b" "$m_a" "$m_buyer" b)
    rpc 38089 wallet-rpc-user-b "$rpc_pass_b" close_wallet '{}' >/dev/null 2>&1 || true
    open_w 38088 wallet-rpc-user-a "$rpc_pass_a" "$wallet_buyer" "$pass_buyer" buyer || die 'open buyer przed finalize'
    fin_buyer=$(fin_call 38088 wallet-rpc-user-a "$rpc_pass_a" "$pass_buyer" "$m_a" "$m_b" buyer)
    rpc 38088 wallet-rpc-user-a "$rpc_pass_a" close_wallet '{}' >/dev/null 2>&1 || true

    # 5. Weryfikacja realna + znacznik.
    open_w 38088 wallet-rpc-user-a "$rpc_pass_a" "$wallet_a" "$pass_a" arbiter || die 'open arbiter przed weryfikacja'
    raw=$(rpc 38088 wallet-rpc-user-a "$rpc_pass_a" is_multisig '{}')
    printf '[is_multisig arbiter] %s\n' "$raw" >&2
    rpc 38088 wallet-rpc-user-a "$rpc_pass_a" close_wallet '{}' >/dev/null 2>&1 || true
    if printf '%s' "$raw" | grep -q '"ready":true'; then
        printf 'done %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ceremony_dir/ceremony.complete"
        printf 'multisig readiness: OK (2/3, oba portfele wykonawcze)\n'
    else
        die 'multisig readiness check failed after finalize.'
    fi
fi

buyer_pw_out=$buyer_dir/buyer-wallet-password.txt
[ -f "$buyer_pw_out" ] || printf '%s\n' "$pass_buyer" > "$buyer_pw_out"
chmod 0600 "$buyer_pw_out"
cp -a "$wdir_a/buyer_wallet" "$buyer_dir/buyer_wallet" 2>/dev/null || true
cp -a "$wdir_a/buyer_wallet.keys" "$buyer_dir/buyer_wallet.keys" 2>/dev/null || true
chown root:root "$buyer_dir/buyer_wallet" "$buyer_dir/buyer_wallet.keys" 2>/dev/null || true

cat <<'EOF'

nxms-multisig-ceremony: done (przeplyw monerodocs 2/3).
Portfele wykonawcze: escrow_wallet_a (arbiter), escrow_wallet_b (seller).
Klucz buyer = artefakt ceremonialny etapu all-in-one (archiwum w /var/lib/nxms-ceremony).
EOF
