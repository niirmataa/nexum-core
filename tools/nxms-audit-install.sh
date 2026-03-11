#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  tools/nxms-audit-install.sh <profile>

Profiles:
  wsl-repo
  alpine-vm

This command must run as root on the target host.
EOF
}

if [[ $# -ne 1 ]]; then
    usage >&2
    exit 1
fi

profile="$1"
repo_root="$(git rev-parse --show-toplevel)"

case "$profile" in
    wsl-repo)
        rules_src="$repo_root/deploy/audit/wsl-repo.rules"
        ;;
    alpine-vm)
        rules_src="$repo_root/deploy/audit/alpine-vm.rules"
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
fi

if ! command -v auditctl >/dev/null 2>&1; then
    echo "audit userspace is not installed." >&2
    exit 1
fi

install -d -m 0750 /etc/audit
install -m 0640 "$rules_src" /etc/audit/audit.rules

if [[ -d /etc/audit/rules.d ]]; then
    install -m 0640 "$rules_src" /etc/audit/rules.d/nxms.rules
fi

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
else
    auditctl -R /etc/audit/audit.rules
fi

auditctl -l
