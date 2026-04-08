#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  tools/tar-sync-vm.sh [--once]

Environment:
  NXMS_TAR_SRC         Source repo path on local host.
                       Default: current repo root
  NXMS_TAR_DEST        Destination repo path on VM.
                       Default: /home/codex/nexum-core
  NXMS_TAR_USER        SSH user for VM.
                       Default: codex
  NXMS_TAR_HOST        VM host or IP.
                       Default: 192.168.160.128
  NXMS_TAR_KEY         SSH private key path.
                       Default: $HOME/.ssh/id_ed25519_codex_a3
  NXMS_TAR_REMOTE_TMP  Remote archive path.
                       Default: /tmp/nexum-core-sync.tgz
  NXMS_TAR_CLEAN_DEST  Set to 1 to wipe destination contents before unpacking.
                       Default: 0

Examples:
  tools/tar-sync-vm.sh
  NXMS_TAR_HOST=192.168.160.129 tools/tar-sync-vm.sh
  NXMS_TAR_DEST=/srv/nexum-core NXMS_TAR_CLEAN_DEST=1 tools/tar-sync-vm.sh
EOF
}

if [[ "${1:-}" == "--help" ]]; then
    usage
    exit 0
elif [[ $# -gt 0 ]]; then
    usage >&2
    exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
    echo "ssh not found." >&2
    exit 1
fi

if ! command -v scp >/dev/null 2>&1; then
    echo "scp not found." >&2
    exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
    echo "tar not found." >&2
    exit 1
fi

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
src="${NXMS_TAR_SRC:-$repo_root}"
dest="${NXMS_TAR_DEST:-/home/codex/nexum-core}"
user="${NXMS_TAR_USER:-codex}"
host="${NXMS_TAR_HOST:-192.168.160.128}"
key="${NXMS_TAR_KEY:-$HOME/.ssh/id_ed25519_codex_a3}"
remote_tmp="${NXMS_TAR_REMOTE_TMP:-/tmp/nexum-core-sync.tgz}"
clean_dest="${NXMS_TAR_CLEAN_DEST:-0}"

if [[ ! -d "$src" ]]; then
    echo "source directory not found: $src" >&2
    exit 1
fi

if [[ ! -f "$key" ]]; then
    echo "ssh key not found: $key" >&2
    exit 1
fi

if [[ "$clean_dest" != "0" && "$clean_dest" != "1" ]]; then
    echo "invalid NXMS_TAR_CLEAN_DEST: $clean_dest" >&2
    exit 1
fi

ssh_cmd=(
    ssh
    -i "$key"
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=accept-new
)

scp_cmd=(
    scp
    -i "$key"
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=accept-new
)

archive="$(mktemp /tmp/nexum-core-sync.XXXXXX.tgz)"
cleanup() {
    rm -f "$archive"
}
trap cleanup EXIT

echo "== $(date -u +%Y-%m-%dT%H:%M:%SZ) pack start =="
tar \
    --exclude='.git' \
    --exclude='target' \
    --exclude='.cargo-home' \
    --exclude='.rustup' \
    --exclude='*.pyc' \
    --exclude='.DS_Store' \
    -C "$src" \
    -czf "$archive" .
echo "archive: $archive"

echo "== $(date -u +%Y-%m-%dT%H:%M:%SZ) upload start =="
"${ssh_cmd[@]}" "${user}@${host}" "mkdir -p \"$(dirname "$dest")\""
"${scp_cmd[@]}" "$archive" "${user}@${host}:${remote_tmp}"

read -r -d '' remote_script <<'EOF' || true
set -euo pipefail
dest="$1"
archive="$2"
clean_dest="$3"

mkdir -p "$dest"
if [ "$clean_dest" = "1" ]; then
    find "$dest" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
fi
tar -xzf "$archive" -C "$dest"
rm -f "$archive"
EOF

"${ssh_cmd[@]}" "${user}@${host}" "sh -s -- '$dest' '$remote_tmp' '$clean_dest'" <<<"$remote_script"
echo "== $(date -u +%Y-%m-%dT%H:%M:%SZ) sync done =="
