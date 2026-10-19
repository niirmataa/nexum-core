#!/bin/sh
# OPS: watchdog moneroda (sekcja D).
# Build monero 0.18.4 (Debian) potrafi sie zawiesic po wyjatku watku P2P
# (widac w logu stacktrace) — proces zyje, RPC nie odpowiada, a zależne
# wallet-rpc pietrza zapytania. Watchdog wykrywa brak odpowiedzi i restaruje.
#
# Ochrona przed petla: restart tylko gdy usluga dziala > 300 s.
set -eu

if curl -s -m 10 http://127.0.0.1:38081/get_info >/dev/null 2>&1; then
    exit 0
fi

started=$(systemctl show -p ActiveEnterTimestamp --value nxms-monerod-a 2>/dev/null || true)
[ -n "$started" ] || exit 0
start_epoch=$(date -d "$started" +%s 2>/dev/null || echo 0)
now_epoch=$(date +%s)
[ "$((now_epoch - start_epoch))" -gt 300 ] || exit 0

logger -t nxms-watchdog 'monerod RPC nie odpowiada (>300 s od startu) — restart nxms-monerod-a'
systemctl restart nxms-monerod-a
