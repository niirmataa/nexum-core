#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  tools/nxms-alpine-openrc-install.sh [--profile release|debug] [--install-config-examples-if-missing]

Canonical Alpine/OpenRC install path for NXMS runtime artifacts from the current repo checkout.

Installs:
  - /opt/nxms/bin/{nxms-mailbox,nxms-signer,nxms-escrow-orchestrator,nxms-host-bootstrap}
  - /etc/init.d/{nxms-mailbox,nxms-signer}
  - /etc/conf.d/{nxms-mailbox,nxms-signer}

Optional:
  --install-config-examples-if-missing
    Install repo example configs to /etc/nxms only when the target file does not already exist.

The installer refuses stale /etc/nxms/signer.toml configs that still use `keys_path`.
Migrate them first with:
  tools/nxms-alpine-migrate-signer-config.sh --input /etc/nxms/signer.toml --output /etc/nxms/signer.toml

This command must run as root on the target Alpine host.
EOF
}

profile="release"
install_config_examples_if_missing=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            [[ $# -ge 2 ]] || { usage >&2; exit 1; }
            profile="$2"
            shift 2
            ;;
        --install-config-examples-if-missing)
            install_config_examples_if_missing=1
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

case "$profile" in
    release|debug) ;;
    *)
        echo "invalid --profile: $profile" >&2
        exit 1
        ;;
esac

if [[ "$(id -u)" -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
target_dir="$repo_root/target/$profile"

require_executable() {
    local path="$1"
    [[ -x "$path" ]] || {
        echo "missing executable: $path" >&2
        exit 1
    }
}

require_non_stale_signer_config() {
    local cfg="/etc/nxms/signer.toml"
    [[ -e "$cfg" ]] || return 0

    if grep -Eq '^[[:space:]]*keys_path[[:space:]]*=' "$cfg"; then
        cat >&2 <<EOF
stale signer config detected: $cfg still uses legacy keys_path
run:
  $repo_root/tools/nxms-alpine-migrate-signer-config.sh --input $cfg --output $cfg
then rerun this installer
EOF
        exit 1
    fi

    for field in host_vault_dir host_vault_passphrase runtime_trust_bundle_path; do
        if ! grep -Eq "^[[:space:]]*$field[[:space:]]*=" "$cfg"; then
            cat >&2 <<EOF
incomplete signer config detected: missing $field in $cfg
use the canonical signer config baseline from:
  $repo_root/docs/reference/NXMS_SIGNER_CONFIG.example.toml
EOF
            exit 1
        fi
    done
}

install_if_missing() {
    local src="$1"
    local dest="$2"
    local mode="$3"
    local owner="$4"
    if [[ -e "$dest" ]]; then
        return 0
    fi
    install -D -m "$mode" "$src" "$dest"
    chown "$owner" "$dest"
}

require_executable "$target_dir/nxms-mailbox"
require_executable "$target_dir/nxms-signer"
require_executable "$target_dir/nxms-escrow-orchestrator"
require_executable "$target_dir/nxms-host-bootstrap"

addgroup -S nxms >/dev/null 2>&1 || true
adduser -S -D -H -h /var/lib/nxms -s /sbin/nologin -G nxms nxms >/dev/null 2>&1 || true

install -d -m 0755 /opt/nxms/bin
install -d -m 0755 /etc/nxms
install -d -m 0750 -o nxms -g nxms /var/lib/nxms
install -d -m 0750 -o nxms -g nxms /var/lib/nxms/mailbox
install -d -m 0750 -o nxms -g nxms /var/lib/nxms/orchestrator
install -d -m 0750 -o nxms -g nxms /var/lib/nxms/bootstrap
install -d -m 0750 -o nxms -g nxms /var/lib/nxms-signer
install -d -m 0750 -o nxms -g nxms /var/log/nxms
install -d -m 0750 -o root -g nxms /run/secrets/nxms

install -m 0755 "$target_dir/nxms-mailbox" /opt/nxms/bin/nxms-mailbox
install -m 0755 "$target_dir/nxms-signer" /opt/nxms/bin/nxms-signer
install -m 0755 "$target_dir/nxms-escrow-orchestrator" /opt/nxms/bin/nxms-escrow-orchestrator
install -m 0755 "$target_dir/nxms-host-bootstrap" /opt/nxms/bin/nxms-host-bootstrap

install -m 0755 "$repo_root/deploy/openrc/nxms-mailbox" /etc/init.d/nxms-mailbox
install -m 0644 "$repo_root/deploy/openrc/nxms-mailbox.confd" /etc/conf.d/nxms-mailbox
install -m 0755 "$repo_root/deploy/openrc/nxms-signer" /etc/init.d/nxms-signer
install -m 0644 "$repo_root/deploy/openrc/nxms-signer.confd" /etc/conf.d/nxms-signer

if [[ "$install_config_examples_if_missing" -eq 1 ]]; then
    install_if_missing \
        "$repo_root/docs/reference/NXMS_MAILBOX_CONFIG.example.toml" \
        /etc/nxms/mailbox.toml \
        0640 \
        root:nxms
    install_if_missing \
        "$repo_root/docs/reference/NXMS_SIGNER_CONFIG.example.toml" \
        /etc/nxms/signer.toml \
        0640 \
        root:nxms
    install_if_missing \
        "$repo_root/docs/reference/NXMS_ORCHESTRATOR_CONFIG.example.toml" \
        /etc/nxms/orchestrator.toml \
        0640 \
        root:nxms
fi

require_non_stale_signer_config

cat <<EOF
installed profile: $profile
repo_root: $repo_root
target_dir: $target_dir
binaries:
  /opt/nxms/bin/nxms-mailbox
  /opt/nxms/bin/nxms-signer
  /opt/nxms/bin/nxms-escrow-orchestrator
  /opt/nxms/bin/nxms-host-bootstrap
openrc:
  /etc/init.d/nxms-mailbox
  /etc/conf.d/nxms-mailbox
  /etc/init.d/nxms-signer
  /etc/conf.d/nxms-signer
EOF
