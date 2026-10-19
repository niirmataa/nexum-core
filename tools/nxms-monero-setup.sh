#!/bin/bash
# OPS: sekcja D — realna granica Monero dla all-in-one.
# - monerod (stagenet, pruned, Tor-only przez --proxy) na roli monero-a,
# - realny wallet-rpc w miejscu stubow (porty 38088/38089, loopback-only),
# - łańcuch kopiowany z wolumenu kontenera (bez ponownej synchronizacji).
#
# Kompromis etapu all-in-one (do rozdzielenia w Etapie 2/3): jeden monerod
# sluzy obu wallet-rpc; para signer-X + monero-X jest jedna rola logiczna
# (katalog portfeli wspolny wewnatrz pary).
#
# Usage: sudo bash tools/nxms-monero-setup.sh
set -eu
die() { printf 'nxms-monero-setup: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die 'Run as root (sudo bash ...).'
[ "${SUDO_UID:-0}" -gt 0 ] || die 'Run sudo from your regular user account.'
command -v monerod >/dev/null 2>&1 || die 'monerod not installed. Run: sudo apt install monero'
command -v monero-wallet-rpc >/dev/null 2>&1 || die 'monero-wallet-rpc not installed.'

chain_src=/var/lib/nexum-docker/docker/volumes/nexum-alpine-stagenet-data/_data/monero
chain_dst=/var/lib/nxms-monero-a/stagenet

# Pary: para signer-X + monero-X dzieli katalog portfeli (jedna rola logiczna).
for X in a b; do
    usermod -aG "monero-$X" "nxms-signer-$X" 2>/dev/null || true
    install -d -m 0770 -o "monero-$X" -g "monero-$X" "/var/lib/nxms-monero-$X/wallets"
    install -d -m 0751 -o "monero-$X" -g "monero-$X" "/var/log/nxms-monero-$X"
    # Sekret RPC (digest) jest dzielony miedzy wallet-rpc a signerem pary.
    if [ ! -e "/etc/nxms/secrets-src/monero-$X/wallet_rpc_password" ]; then
        if [ -e "/etc/nxms/secrets-src/signer-$X/wallet_rpc_password" ]; then
            install -m 0600 -o root -g root \
                "/etc/nxms/secrets-src/signer-$X/wallet_rpc_password" \
                "/etc/nxms/secrets-src/monero-$X/wallet_rpc_password"
        else
            ( umask 077; openssl rand -hex 32 > "/etc/nxms/secrets-src/monero-$X/wallet_rpc_password" )
        fi
        printf 'secret monero-%s/wallet_rpc_password prepared\n' "$X"
    fi
done

# Lancuch stagenet: kopia z wolumenu kontenera (kontener zostaje archiwum).
if [ -d "$chain_dst/data.mdb" ] || [ -f "$chain_dst/data.mdb" ] || [ -d "$chain_dst/lmdb" ] || [ -f "$chain_dst/lmdb/data.mdb" ]; then
    printf 'chain: kept (%s)\n' "$chain_dst"
elif [ -d "$chain_src" ]; then
    printf 'chain: copying %s -> %s (ok. 10 GB, moze chwile trwac)...\n' "$chain_src" "$chain_dst"
    install -d -m 0750 -o monero-a -g monero-a /var/lib/nxms-monero-a/stagenet
    cp -a "$chain_src/." "$chain_dst/"
    chown -R monero-a:monero-a "$chain_dst"
    printf 'chain: copied\n'
else
    die "Missing chain source $chain_src; run the stagenet container first."
fi

# --- Jednostki systemd ---
units_src="$(dirname "$(readlink -f "$0")")/../deploy/allinone/systemd"
install -m 0755 -o root -g root "$(dirname "$(readlink -f "$0")")/nxms-monerod-watchdog.sh" \
    /opt/nxms/bin/nxms-monerod-watchdog
for unit in nxms-monerod-a.service nxms-wallet-rpc-a.service nxms-wallet-rpc-b.service \
            nxms-monerod-watchdog.service nxms-monerod-watchdog.timer; do
    [ -f "$units_src/$unit" ] || die "Missing unit: $units_src/$unit"
    install -m 0644 -o root -g root "$units_src/$unit" "/etc/systemd/system/$unit"
done

# Stuby etapu C oddaja porty realnemu wallet-rpc.
systemctl stop nxms-wallet-stub-a nxms-wallet-stub-b 2>/dev/null || true
systemctl disable nxms-wallet-stub-a nxms-wallet-stub-b 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now nxms-monerod-watchdog.timer >/dev/null 2>&1 || true

cat <<'EOF'

nxms-monero-setup: done.

Kolejnosc startu (C5+D):
  systemctl start nxms-monerod-a
  systemctl start nxms-wallet-rpc-a nxms-wallet-rpc-b
  systemctl restart nxms-signer-a nxms-signer-b

Weryfikacja: wallet-rpc tylko na loopback (38088/38089), monerod Tor-only
(--proxy socks5://127.0.0.1:9050), provisioning portfeli signerow przez
monero-wallet-cli. Kontener nexum-alpine-stagenet pozostaje archiwum lancucha.
EOF
