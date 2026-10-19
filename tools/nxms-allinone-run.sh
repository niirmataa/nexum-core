#!/bin/bash
# OPS: all-in-one — jednostrzalowy runner krokow C1-C4 sekcji C roadmapy.
# Kolejnosc: paczka tor (jesli brak) -> setup kont/katalogow/configow ->
# hidden service mailboxa -> ceremonia guardow i bootstrap trustu.
#
# Usage: sudo bash tools/nxms-allinone-run.sh
set -eu
die() { printf 'nxms-allinone-run: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die 'Run as root (sudo bash ...) from your regular account.'
[ "${SUDO_UID:-0}" -gt 0 ] || die 'Run sudo from your regular user account.'

self=$(readlink -f -- "$0")
workspace=$(cd -- "$(dirname -- "$self")/.." && pwd -P)

if ! command -v tor >/dev/null 2>&1 || ! command -v monerod >/dev/null 2>&1; then
    printf '== installing tor + monero ==\n'
    DEBIAN_FRONTEND=noninteractive apt-get install -y tor monero
fi

printf '\n== C1/C2: setup ==\n'
bash "$workspace/tools/nxms-allinone-setup.sh" --bin-dir "$workspace/target/debug"

printf '\n== C4: tor hidden service ==\n'
bash "$workspace/tools/nxms-allinone-tor.sh"

printf '\n== C3: ceremony ==\n'
bash "$workspace/tools/nxms-allinone-ceremony.sh"

printf '\n== D: granica Monero ==\n'
bash "$workspace/tools/nxms-monero-setup.sh"

printf '\n== D: ceremonia multisig 2-of-3 ==\n'
bash "$workspace/tools/nxms-multisig-ceremony.sh"

printf '\n== C5+D: start rol ==\n'
systemctl restart nxms-monerod-a
sleep 5
systemctl restart nxms-wallet-rpc-a nxms-wallet-rpc-b nxms-mailbox
sleep 3
systemctl restart nxms-signer-a nxms-signer-b
sleep 3
systemctl is-active nxms-monerod-a nxms-wallet-rpc-a nxms-wallet-rpc-b nxms-mailbox nxms-signer-a nxms-signer-b
