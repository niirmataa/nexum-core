#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  tools/sync-vm.sh [--once]

Environment:
  NXMS_SYNC_SRC        Source repo path on local host.
                       Default: current repo root
  NXMS_SYNC_DEST       Destination repo path on VM.
                       Default: /home/operator/nexum-core
  NXMS_SYNC_USER       SSH user for VM.
                       Default: operator
  NXMS_SYNC_HOST       VM host or IP.
                       Default: 192.168.160.128
  NXMS_SYNC_KEY        SSH private key path.
                       Default: /home/nxms-server/.ssh/id_ed25519_codex_vm
  NXMS_SYNC_INTERVAL   Seconds between sync runs.
                       Default: 600
  NXMS_SYNC_DELETE     Set to 0 to disable --delete.
                       Default: 1

Examples:
  tools/sync-vm.sh
  NXMS_SYNC_INTERVAL=60 tools/sync-vm.sh
  NXMS_SYNC_HOST=10.0.0.5 NXMS_SYNC_DEST=/srv/nexum-core tools/sync-vm.sh --once
EOF
}

once=0
if [[ "${1:-}" == "--once" ]]; then
    once=1
elif [[ $# -gt 0 ]]; then
    usage >&2
    exit 1
fi

if ! command -v rsync >/dev/null 2>&1; then
    echo "rsync not found." >&2
    exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
    echo "ssh not found." >&2
    exit 1
fi

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
src="${NXMS_SYNC_SRC:-$repo_root}"
dest="${NXMS_SYNC_DEST:-/home/operator/nexum-core}"
user="${NXMS_SYNC_USER:-operator}"
host="${NXMS_SYNC_HOST:-192.168.160.128}"
key="${NXMS_SYNC_KEY:-/home/nxms-server/.ssh/id_ed25519_codex_vm}"
interval="${NXMS_SYNC_INTERVAL:-600}"
delete_flag="${NXMS_SYNC_DELETE:-1}"

if [[ ! -d "$src" ]]; then
    echo "source directory not found: $src" >&2
    exit 1
fi

if [[ ! -f "$key" ]]; then
    echo "ssh key not found: $key" >&2
    exit 1
fi

if ! [[ "$interval" =~ ^[0-9]+$ ]] || [[ "$interval" -lt 1 ]]; then
    echo "invalid NXMS_SYNC_INTERVAL: $interval" >&2
    exit 1
fi

ssh_cmd=(
    ssh
    -i "$key"
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=accept-new
)

rsync_cmd=(
    rsync
    -az
    --itemize-changes
    --human-readable
    --exclude 'target/'
    --exclude '.cargo-home/'
    --exclude '.rustup/'
    -e "${ssh_cmd[*]}"
)

if [[ "$delete_flag" == "1" ]]; then
    rsync_cmd+=(--delete)
fi

sync_once() {
    echo "== $(date -u +%Y-%m-%dT%H:%M:%SZ) sync start =="
    "${ssh_cmd[@]}" "${user}@${host}" "mkdir -p '$dest'"
    "${rsync_cmd[@]}" "${src%/}/" "${user}@${host}:${dest}/"
    echo "== $(date -u +%Y-%m-%dT%H:%M:%SZ) sync done =="
}

trap 'echo; echo "sync loop stopped"; exit 0' INT TERM

if [[ "$once" -eq 1 ]]; then
    sync_once
    exit 0
fi

while true; do
    sync_once
    sleep "$interval"
done
