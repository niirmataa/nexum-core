#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  tools/nxms-alpine-reset-runtime.sh [--repo-root PATH] [--operator-home PATH] [--purge-bare-repo]

Canonical cleanup path for Alpine NXMS hosts before rebuilding/installing from the current synced repo.

Removes:
  - <repo-root>/target
  - /opt/nxms/bin/{nxms-mailbox,nxms-signer,nxms-escrow-orchestrator,nxms-host-bootstrap}
  - legacy snapshot checkouts matching <operator-home>/nexum-core.snapshot.*

Optional:
  --purge-bare-repo
    Also remove <operator-home>/repos/nexum-core.git if it exists.

Does NOT remove:
  - /etc/nxms
  - /var/lib/nxms*
  - /run/secrets/nxms

Run this as root on the target Alpine host. After cleanup, rebuild from the canonical repo checkout
as the checkout owner (for example `operator`), then rerun tools/nxms-alpine-openrc-install.sh.
EOF
}

repo_root=""
operator_home="/home/operator"
purge_bare_repo=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo-root)
            [[ $# -ge 2 ]] || { usage >&2; exit 1; }
            repo_root="$2"
            shift 2
            ;;
        --operator-home)
            [[ $# -ge 2 ]] || { usage >&2; exit 1; }
            operator_home="$2"
            shift 2
            ;;
        --purge-bare-repo)
            purge_bare_repo=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

if [[ -z "$repo_root" ]]; then
    repo_root="$(git rev-parse --show-toplevel)"
fi

repo_root="$(cd "$repo_root" && pwd)"
operator_home="$(cd "$operator_home" && pwd)"

if [[ ! -d "$repo_root/.git" ]]; then
    echo "repo root does not look like a git checkout: $repo_root" >&2
    exit 1
fi

remove_path() {
    local path="$1"
    if [[ -e "$path" ]]; then
        echo "removing: $path"
        rm -rf -- "$path"
    fi
}

remove_path "$repo_root/target"
remove_path /opt/nxms/bin/nxms-mailbox
remove_path /opt/nxms/bin/nxms-signer
remove_path /opt/nxms/bin/nxms-escrow-orchestrator
remove_path /opt/nxms/bin/nxms-host-bootstrap

for snapshot in "$operator_home"/nexum-core.snapshot.*; do
    [[ -e "$snapshot" ]] || continue
    remove_path "$snapshot"
done

if [[ "$purge_bare_repo" -eq 1 ]]; then
    remove_path "$operator_home/repos/nexum-core.git"
fi

cat <<EOF
cleanup complete
canonical_repo: $repo_root
next:
  1. rebuild as checkout owner:
     cd $repo_root
     cargo build --release -p nxms-mailbox -p nxms-signer -p nxms-escrow-orchestrator -p nxms-host-bootstrap
  2. migrate stale signer config if needed:
     $repo_root/tools/nxms-alpine-migrate-signer-config.sh --input /etc/nxms/signer.toml --output /etc/nxms/signer.toml
  3. reinstall runtime baseline:
     $repo_root/tools/nxms-alpine-openrc-install.sh --profile release --install-config-examples-if-missing
EOF
