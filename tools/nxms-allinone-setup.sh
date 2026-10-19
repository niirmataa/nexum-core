#!/bin/bash
# OPS: all-in-one logical split — one-shot host setup (roadmapa sekcja C).
# Tworzy konta systemowe, katalogi, sekrety bazowe i konfiguracje per rola
# zgodnie z docs/reference/NXMS_ALL_IN_ONE_LOGICAL_LAYOUT.md (sekcje 3-4, 7).
#
# Usage: sudo bash tools/nxms-allinone-setup.sh [--bin-dir /sciezka/do/binariow]
#
# --bin-dir opcjonalnie instaluje binarki nxms-mailbox, nxms-signer,
# nxms-escrow-orchestrator, nxms-host-bootstrap do /opt/nxms/bin.
# Bez tej flagi instalowany jest tylko helper unseal.
#
# Etap all-in-one (przejściowy, zgodnie z SoT sekcja 9 — baseline /run):
# - sekrety leżą w root-owned /etc/nxms/secrets-src/<rola>,
# - przy starcie usługi helper nxms-allinone-unseal instaluje ich kopie
#   do tmpfs /run/secrets/nxms-<rola> (właściciel = konto roli, 0700),
# - docelowo mechanizm zastąpi TPM2-sealed unseal.
#
# Nie uruchamia usług (start jest osobnym krokiem po ceremonii guardów).
set -eu
die() { printf 'nxms-allinone-setup: %s\n' "$*" >&2; exit 1; }

[ $# -le 2 ] || die 'Unexpected arguments.'
bin_dir=''
while [ $# -gt 0 ]; do
    case "$1" in
        --bin-dir) [ $# -ge 2 ] || die '--bin-dir needs a path.'; bin_dir=$2; shift 2 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

[ "$(id -u)" = 0 ] || die 'Run as root (sudo bash ...) from your regular account.'
[ "${SUDO_UID:-0}" -gt 0 ] || die 'Run sudo from your regular user account.'

self=$(readlink -f -- "$0")
workspace=$(cd -- "$(dirname -- "$self")/.." && pwd -P)
units_src="$workspace/deploy/allinone/systemd"
[ -d "$units_src" ] || die "Missing unit sources: $units_src"

# slug:user — zgodnie z NXMS_ALL_IN_ONE_LOGICAL_LAYOUT.md sekcja 3.
ROLES=(
    'ag01:nxms-ag01'
    'ag02:nxms-ag02'
    'orch:nxms-orch'
    'mailbox:nxms-mailbox'
    'signer-a:nxms-signer-a'
    'signer-b:nxms-signer-b'
    'monero-a:monero-a'
    'monero-b:monero-b'
)

for entry in "${ROLES[@]}"; do
    slug=${entry%%:*} user=${entry##*:}
    if ! id -u "$user" >/dev/null 2>&1; then
        adduser --system --group --no-create-home \
            --home "/var/lib/nxms-$slug" --shell /usr/sbin/nologin "$user" >/dev/null
        printf 'account %s created\n' "$user"
    fi
    install -d -m 0750 -o "$user" -g "$user" "/var/lib/nxms-$slug"
    install -d -m 0751 -o "$user" -g "$user" "/var/log/nxms-$slug"
    install -d -m 0750 -o root -g "$user" "/etc/nxms/$slug"
    install -d -m 0750 -o root -g root "/etc/nxms/secrets-src/$slug"
    install -d -m 0700 -o "$user" -g "$user" "/run/secrets/nxms-$slug"
done
install -d -m 0755 -o root -g root /etc/nxms/trust

# /run jest na tmpfs — odtwarzaj katalogi sekretów przy każdym boocie.
{
    for entry in "${ROLES[@]}"; do
        slug=${entry%%:*} user=${entry##*:}
        printf 'd /run/secrets/nxms-%s 0700 %s %s -\n' "$slug" "$user" "$user"
    done
} > /etc/tmpfiles.d/nxms-allinone.conf
systemd-tmpfiles --create /etc/tmpfiles.d/nxms-allinone.conf >/dev/null 2>&1 || true

# --- Sekrety bazowe (tylko jeśli jeszcze nie istnieją; nie nadpisujemy) ---
new_secret() { # new_secret <rola> <plik>
    local slug=$1 name=$2 path="/etc/nxms/secrets-src/$1/$2"
    [ -e "$path" ] && return 0
    ( umask 077; openssl rand -hex 32 > "$path" )
    printf 'secret %s/%s generated\n' "$slug" "$name"
}

for slug in ag01 ag02 orch mailbox signer-a signer-b; do
    new_secret "$slug" host_vault_passphrase
done
for slug in signer-a signer-b; do
    new_secret "$slug" worker_service_token
    new_secret "$slug" mailbox_push_token
    new_secret "$slug" mailbox_pull_token
    new_secret "$slug" mailbox_ack_token
    new_secret "$slug" mailbox_admin_token
    new_secret "$slug" wallet_rpc_password
    new_secret "$slug" wallet_rpc_wallet_password
    new_secret "$slug" orch_bridge_token
done
new_secret mailbox mailbox_push_token
new_secret mailbox mailbox_admin_token
for id in orchestrator signer-a signer-b; do
    new_secret mailbox "mailbox_pull_token_$id"
    new_secret mailbox "mailbox_ack_token_$id"
done
new_secret orch action-token-issuer.passphrase

# --- Konfiguracje per rola (idempotentnie: nie nadpisujemy istniejących) ---
write_once() { # write_once <sciezka> <wlasciciel:grupa>
    local path=$1 owner=$2
    [ -e "$path" ] && { printf 'config %s kept\n' "$path"; return 0; }
    cat > "$path"
    chown "$owner" "$path"
    chmod 0640 "$path"
    printf 'config %s written\n' "$path"
}

write_once /etc/nxms/mailbox/mailbox.toml root:nxms-mailbox <<'EOF'
# NXMS all-in-one: rola mailbox (jedyny relay; bez logiki escrow).
bind = "127.0.0.1:4010"
db_path = "/var/lib/nxms-mailbox/nxms_mailbox.db"
max_body_bytes = 16777216
default_ttl_secs = 86400
max_ttl_secs = 604800
lease_secs = 60
max_wait_ms = 20000
cleanup_secs = 30
checkpoint_secs = 300
max_messages_per_inbox = 10000
max_bytes_per_inbox = 67108864
max_rows_global = 1000000
rate_limit_ip_per_min = 300
rate_limit_to_per_min = 600
production_hardening = true

push_token = "vault:/run/secrets/nxms-mailbox/mailbox_push_token"
admin_token = "vault:/run/secrets/nxms-mailbox/mailbox_admin_token"

[pull_tokens]
orchestrator = "vault:/run/secrets/nxms-mailbox/mailbox_pull_token_orchestrator"
signer-a = "vault:/run/secrets/nxms-mailbox/mailbox_pull_token_signer-a"
signer-b = "vault:/run/secrets/nxms-mailbox/mailbox_pull_token_signer-b"

[ack_tokens]
orchestrator = "vault:/run/secrets/nxms-mailbox/mailbox_ack_token_orchestrator"
signer-a = "vault:/run/secrets/nxms-mailbox/mailbox_ack_token_signer-a"
signer-b = "vault:/run/secrets/nxms-mailbox/mailbox_ack_token_signer-b"
EOF

for X in a b; do
    write_once "/etc/nxms/signer-$X/signer.toml" "root:nxms-signer-$X" <<EOF
# NXMS all-in-one: rola signer-$X (capability node; nie control-plane).
local_id = "signer_$X"
signer_role = "arbiter" # TODO(C5): finalne mapowanie z polityka multisig 2-of-3
sandbox_id = "sandbox-signer-$X"
wallet_id = "wallet-signer-$X"
nettype = "stagenet"
peers_path = "/etc/nxms/signer-$X/peers.json"
host_vault_dir = "/var/lib/nxms-signer-$X/host-vault"
host_vault_passphrase = "vault:/run/secrets/nxms-signer-$X/host_vault_passphrase"
runtime_trust_bundle_path = "/etc/nxms/signer-$X/runtime-trust.final.json"
db_path = "/var/lib/nxms-signer-$X/signer.db"

mailbox_url = "http://REPLACE-WITH-MAILBOX-ONION" # podmiana w kroku C4 (Tor; adres zawiera .onion)
mailbox_push_token = "vault:/run/secrets/nxms-signer-$X/mailbox_push_token"
mailbox_pull_token = "vault:/run/secrets/nxms-signer-$X/mailbox_pull_token"
mailbox_ack_token = "vault:/run/secrets/nxms-signer-$X/mailbox_ack_token"
mailbox_admin_token = "vault:/run/secrets/nxms-signer-$X/mailbox_admin_token"
worker_service_token = "vault:/run/secrets/nxms-signer-$X/worker_service_token"
tor_socks5h = "socks5h://127.0.0.1:9050"
allow_remote_wallet_rpc = false
# ETAP D: realna granica Monero (monerod + wallet-rpc na loopback).
production_hardening = true

snapshot_quorum = 3
pull_max = 20
pull_wait_ms = 20000
poll_interval_ms = 800
default_ttl_secs = 86400
max_txset_hex_len = 16777216

[wallet_rpc]
# Granica monero-a/monero-b jest w sekcji C stubem; realne wallet-rpc
# domyka roadmapa D ("Potwierdzic wallet-rpc loopback-only").
endpoint = "http://127.0.0.1:3808$([ $X = a ] && echo 8 || echo 9)"
wallet_name = "escrow_wallet_$X"
wallet_password = "vault:/run/secrets/nxms-signer-$X/wallet_rpc_wallet_password"
username = "wallet-rpc-user-$X"
password = "vault:/run/secrets/nxms-signer-$X/wallet_rpc_password"

[wallet_provision]
# Realna granica Monero (sekcja D) — monero-wallet-cli z pakietu Debiana.
enabled = true # realna granica Monero (sekcja D)
wallet_cli_path = "/usr/bin/monero-wallet-cli"
wallet_dir = "/var/lib/nxms-monero-$X/wallets"
daemon_address = "127.0.0.1:38081"
trusted_daemon = true
extra_args = []
timeout_secs = 60

[action_token]
required = true
issuer = "nxms-auth"
audience = "sandbox:sandbox-signer-$X"
algorithm = "EDDSA"
public_key_pem_path = "/etc/nxms/signer-$X/action_token_pub.pem"
clock_skew_secs = 5
max_ttl_secs = 120
EOF
done

# Migracja do profilu D: realna granica Monero — production_hardening=true,
# wallet_provision wlaczone, realny monero-wallet-cli i katalog portfeli pary.
for X in a b; do
    cfg="/etc/nxms/signer-$X/signer.toml"
    [ -f "$cfg" ] || continue
    sed -i 's/^production_hardening = false$/production_hardening = true/' "$cfg"
    sed -i 's/^enabled = false # odroczone do roadmapy D$/enabled = true # realna granica Monero (sekcja D)/' "$cfg"
    sed -i 's|^wallet_cli_path = .*|wallet_cli_path = "/usr/bin/monero-wallet-cli"|' "$cfg"
    sed -i "s|^wallet_dir = .*|wallet_dir = \"/var/lib/nxms-monero-$X/wallets\"|" "$cfg"
    sed -i 's/\.onion\.onion/.onion/g' "$cfg"
done

write_once /etc/nxms/orch/orchestrator.toml root:nxms-orch <<'EOF'
# NXMS all-in-one: rola orchestrator (control-plane; nie trust root).
db_path = "/var/lib/nxms-orch/nxms_orchestrator.db"
runtime_trust_bundle_path = "/etc/nxms/orch/runtime-trust.final.json"

[action_token]
issuer_vault_dir = "/var/lib/nxms-orch/action-token-issuer-vault"
issuer_vault_passphrase_file = "/run/secrets/nxms-orch/action-token-issuer.passphrase"
default_ttl_secs = 60
EOF

# --- Helper unseal + binarki ---
install -m 0755 -o root -g root "$workspace/tools/wallet-rpc-stub.py" \
    /opt/nxms/bin/wallet-rpc-stub.py
install -m 0755 -o root -g root "$workspace/tools/nxms-allinone-unseal.sh" \
    /opt/nxms/bin/nxms-allinone-unseal 2>/dev/null || {
    install -d -m 0755 -o root -g root /opt/nxms/bin
    install -m 0755 -o root -g root "$workspace/tools/nxms-allinone-unseal.sh" \
        /opt/nxms/bin/nxms-allinone-unseal
}

if [ -n "$bin_dir" ]; then
    [ -d "$bin_dir" ] || die "bin-dir does not exist: $bin_dir"
    for bin in nxms-mailbox nxms-signer nxms-escrow-orchestrator nxms-host-bootstrap; do
        [ -f "$bin_dir/$bin" ] || die "Missing binary: $bin_dir/$bin"
        install -m 0755 -o root -g root "$bin_dir/$bin" "/opt/nxms/bin/$bin"
    done
    printf 'binaries installed from %s\n' "$bin_dir"
else
    printf 'note: binaries not installed (no --bin-dir); services cannot start yet\n'
fi

# --- Jednostki systemd (instalacja bez wlaczania; start jest krokiem C5) ---
for unit in nxms-mailbox.service nxms-signer-a.service nxms-signer-b.service \
            nxms-wallet-stub-a.service nxms-wallet-stub-b.service; do
    [ -f "$units_src/$unit" ] || die "Missing unit: $units_src/$unit"
    install -m 0644 -o root -g root "$units_src/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload

cat <<'EOF'

nxms-allinone-setup: done.

Kolejne kroki (zgodnie z planem sekcji C):
  C3  ceremonia guardow: nxms-host-bootstrap init-bundle/sign-bundle x2
      -> /etc/nxms/trust/runtime-trust.final.json -> materialize-local per rola
  C4  Tor: hidden service dla mailboxa, podmiana mailbox_url na .onion
  C5  start: systemctl start nxms-mailbox nxms-signer-a nxms-signer-b

Role bez daemona w tym etapie (jawne luki, nie pominięcia):
  ag-01/ag-02   — ceremonia + klucze (brak implementacji nxms-auth-guard)
  orchestrator  — CLI + baza (brak trybu daemona)
  monero-a/-b   — konta i katalogi; granica wykonawcza odroczona do roadmapy D
EOF
