#!/usr/bin/env bash
set -euo pipefail

if ! command -v ausearch >/dev/null 2>&1; then
    echo "ausearch not found; install audit userspace first." >&2
    exit 1
fi

since="${1:-today}"
shift || true

keys=(
    nxms-repo
    nxms-archive
    nxms-bundle
    nxms-shell-trace
    nxms-runtime-config
    nxms-runtime-bin
    nxms-runtime-init
    nxms-identity
    nxms-audit-config
    nxms-audit-log
    nxms-tor
    nxms-monero
    nxms-exec
)

for key in "${keys[@]}"; do
    echo "== $key =="
    ausearch -i -k "$key" -ts "$since" "$@" || true
    echo
done
