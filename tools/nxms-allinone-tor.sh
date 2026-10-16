#!/bin/bash
# OPS: all-in-one — hidden services dla wszystkich ról (krok C4).
# Kod nxms-transport wymaga, by kazda tozsamosc hosta miala adres .onion,
# wiec kazda rola dostaje wlasny ukryty serwis (jakby byla osobnym hostem).
#
# Usage: sudo bash tools/nxms-allinone-tor.sh
set -eu
die() { printf 'nxms-allinone-tor: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die 'Run as root (sudo bash ...).'
[ "${SUDO_UID:-0}" -gt 0 ] || die 'Run sudo from your regular user account.'
command -v tor >/dev/null 2>&1 || die 'Tor is not installed. Run: sudo apt install tor'
[ -f /etc/tor/torrc ] || die 'Missing /etc/tor/torrc.'
[ -d /etc/nxms/trust ] || die 'Missing /etc/nxms/trust; run nxms-allinone-setup.sh first.'

# rola|port wirtualny HS|port lokalny uslugi
HS=(
    'ag01|28081|28081'
    'ag02|28082|28082'
    'orch|28083|28083'
    'mailbox|80|4010'
    'signer-a|28090|28090'
    'signer-b|28091|28091'
)

for entry in "${HS[@]}"; do
    IFS='|' read -r slug vport rport <<< "$entry"
    install -d -m 0700 -o debian-tor -g debian-tor "/var/lib/tor/nxms-$slug"
done

# Blok konfiguracyjny: zawsze odtwarzany od nowa (idempotentnie).
sed -i '/^# BEGIN nxms-allinone$/,/^# END nxms-allinone$/d' /etc/tor/torrc
{
    echo '# BEGIN nxms-allinone'
    for entry in "${HS[@]}"; do
        IFS='|' read -r slug vport rport <<< "$entry"
        echo "HiddenServiceDir /var/lib/tor/nxms-$slug"
        echo "HiddenServicePort $vport 127.0.0.1:$rport"
    done
    echo '# END nxms-allinone'
} >> /etc/tor/torrc
printf 'torrc: hidden service block written (%d services)\n' "${#HS[@]}"

systemctl restart tor
sleep 3

for entry in "${HS[@]}"; do
    IFS='|' read -r slug vport rport <<< "$entry"
    hs="/var/lib/tor/nxms-$slug"
    [ -f "$hs/hostname" ] || die "No hostname for $slug; inspect: systemctl status tor"
    install -m 0644 -o root -g root "$hs/hostname" "/etc/nxms/trust/$slug.onion"
    printf '%-9s %s\n' "$slug" "$(cat "$hs/hostname")"
done

for X in a b; do
    cfg="/etc/nxms/signer-$X/signer.toml"
    [ -f "$cfg" ] || die "Missing $cfg"
    onion=$(cat /etc/nxms/trust/mailbox.onion)
    if grep -q 'REPLACE-WITH-MAILBOX-ONION' "$cfg"; then
        sed -i "s|REPLACE-WITH-MAILBOX-ONION|$onion|" "$cfg"
        printf 'config %s: mailbox_url -> %s\n' "$cfg" "$onion"
    else
        printf 'config %s: mailbox_url already set\n' "$cfg"
    fi
done

printf '\nnxms-allinone-tor: done. Relacje przez Tor: orchestrator/signer-a/signer-b -> mailbox (socks5h://127.0.0.1:9050).\n'
