#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  tools/nxms-alpine-migrate-signer-config.sh [--input PATH] [--output PATH]
                                            [--host-vault-dir PATH]
                                            [--host-vault-passphrase REF]
                                            [--runtime-trust-bundle-path PATH]
                                            [--wallet-cli-path PATH]

Canonical one-shot migration from legacy signer config (`keys_path`) to the
current host-vault + runtime-trust schema.

Defaults:
  --input  /etc/nxms/signer.toml
  --output /etc/nxms/signer.toml
  --host-vault-dir /var/lib/nxms-signer/host-vault
  --host-vault-passphrase vault:/run/secrets/nxms/host_vault_passphrase
  --runtime-trust-bundle-path /var/lib/nxms/bootstrap/runtime-trust.final.json
  --wallet-cli-path /opt/monero/current/monero-wallet-cli

This command is intended to run as root on the target Alpine host.
EOF
}

input="/etc/nxms/signer.toml"
output="/etc/nxms/signer.toml"
host_vault_dir="/var/lib/nxms-signer/host-vault"
host_vault_passphrase="vault:/run/secrets/nxms/host_vault_passphrase"
runtime_trust_bundle_path="/var/lib/nxms/bootstrap/runtime-trust.final.json"
wallet_cli_path="/opt/monero/current/monero-wallet-cli"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --input)
            [[ $# -ge 2 ]] || { usage >&2; exit 1; }
            input="$2"
            shift 2
            ;;
        --output)
            [[ $# -ge 2 ]] || { usage >&2; exit 1; }
            output="$2"
            shift 2
            ;;
        --host-vault-dir)
            [[ $# -ge 2 ]] || { usage >&2; exit 1; }
            host_vault_dir="$2"
            shift 2
            ;;
        --host-vault-passphrase)
            [[ $# -ge 2 ]] || { usage >&2; exit 1; }
            host_vault_passphrase="$2"
            shift 2
            ;;
        --runtime-trust-bundle-path)
            [[ $# -ge 2 ]] || { usage >&2; exit 1; }
            runtime_trust_bundle_path="$2"
            shift 2
            ;;
        --wallet-cli-path)
            [[ $# -ge 2 ]] || { usage >&2; exit 1; }
            wallet_cli_path="$2"
            shift 2
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

[[ -r "$input" ]] || {
    echo "config not readable: $input" >&2
    exit 1
}

has_field() {
    local field="$1"
    grep -Eq "^[[:space:]]*$field[[:space:]]*=" "$input"
}

has_keys_path=0
if has_field "keys_path"; then
    has_keys_path=1
fi

if [[ "$has_keys_path" -eq 0 ]]; then
    if has_field "host_vault_dir" && has_field "host_vault_passphrase" && has_field "runtime_trust_bundle_path"; then
        echo "signer config already uses host-vault schema: $input"
        exit 0
    fi
    echo "refusing to migrate ambiguous signer config without keys_path: $input" >&2
    exit 1
fi

if has_field "host_vault_dir" || has_field "host_vault_passphrase" || has_field "runtime_trust_bundle_path"; then
    echo "refusing to migrate mixed signer config containing both keys_path and host-vault fields: $input" >&2
    exit 1
fi

tmp="$(mktemp)"
backup=""
cleanup() {
    rm -f "$tmp"
}
trap cleanup EXIT

awk \
    -v host_vault_dir="$host_vault_dir" \
    -v host_vault_passphrase="$host_vault_passphrase" \
    -v runtime_trust_bundle_path="$runtime_trust_bundle_path" \
    -v wallet_cli_path="$wallet_cli_path" \
    '
    BEGIN {
        replaced_keys_path = 0
    }
    /^[[:space:]]*keys_path[[:space:]]*=/ {
        print "host_vault_dir = \"" host_vault_dir "\""
        print "host_vault_passphrase = \"" host_vault_passphrase "\""
        print "runtime_trust_bundle_path = \"" runtime_trust_bundle_path "\""
        replaced_keys_path = 1
        next
    }
    /^[[:space:]]*wallet_cli_path[[:space:]]*=[[:space:]]*"\/usr\/local\/bin\/monero-wallet-cli"[[:space:]]*$/ {
        print "wallet_cli_path = \"" wallet_cli_path "\""
        next
    }
    {
        print
    }
    END {
        if (replaced_keys_path != 1) {
            exit 12
        }
    }
    ' "$input" >"$tmp"

if [[ "$input" == "$output" ]]; then
    backup="${input}.bak.$(date -u +%Y%m%d%H%M%S)"
    cp "$input" "$backup"
fi

install -D -m 0640 "$tmp" "$output"
chown root:nxms "$output"

grep -Eq '^[[:space:]]*host_vault_dir[[:space:]]*=' "$output" || {
    echo "migration failed: host_vault_dir missing in $output" >&2
    exit 1
}
grep -Eq '^[[:space:]]*host_vault_passphrase[[:space:]]*=' "$output" || {
    echo "migration failed: host_vault_passphrase missing in $output" >&2
    exit 1
}
grep -Eq '^[[:space:]]*runtime_trust_bundle_path[[:space:]]*=' "$output" || {
    echo "migration failed: runtime_trust_bundle_path missing in $output" >&2
    exit 1
}
if grep -Eq '^[[:space:]]*keys_path[[:space:]]*=' "$output"; then
    echo "migration failed: legacy keys_path still present in $output" >&2
    exit 1
fi

echo "migrated signer config: $output"
if [[ -n "$backup" ]]; then
    echo "backup: $backup"
fi
