#!/bin/sh
# OPS: unseal sekretow roli do tmpfs /run/secrets/nxms-<rola> (etap all-in-one).
# Uruchamiane jako root z ExecStartPre jednostki systemd.
# Zrodlo: root-owned /etc/nxms/secrets-src/<rola>; docelowo zastapi to TPM2 unseal.
set -eu
role=${1:-}
case "$role" in
    ag01|ag02|orch|mailbox|signer-a|signer-b|monero-a|monero-b) ;;
    *) printf 'nxms-allinone-unseal: unknown role\n' >&2; exit 2 ;;
esac
[ "$(id -u)" = 0 ] || { printf 'nxms-allinone-unseal: root required\n' >&2; exit 1; }

src="/etc/nxms/secrets-src/$role"
dst="/run/secrets/nxms-$role"
case "$role" in
    ag01) user=nxms-ag01 ;; ag02) user=nxms-ag02 ;;
    orch) user=nxms-orch ;; mailbox) user=nxms-mailbox ;;
    signer-a) user=nxms-signer-a ;; signer-b) user=nxms-signer-b ;;
    monero-a) user=monero-a ;; monero-b) user=monero-b ;;
esac

[ -d "$src" ] || { printf 'nxms-allinone-unseal: missing %s\n' "$src" >&2; exit 1; }
install -d -m 0700 -o "$user" -g "$user" "$dst"
for f in "$src"/*; do
    [ -e "$f" ] || continue
    install -m 0600 -o "$user" -g "$user" "$f" "$dst/$(basename "$f")"
done
printf 'nxms-allinone-unseal: %s -> %s (owner %s)\n' "$src" "$dst" "$user"
