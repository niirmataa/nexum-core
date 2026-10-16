#!/bin/bash
# OPS: all-in-one — ceremonia guardow i bootstrap trustu (roadmapa sekcja C, krok C3).
# Kazdy krok jest wykonywany jako konto docelowej roli (runuser), wiec separacja
# kont jest realna nawet na jednym hoście. Kolejnosc wg SoT sekcja 9a:
#   1. host vaulty per rola (sekret lokalny, nigdy nie opuszcza roli),
#   2. publiczne bundle tozsamosci,
#   3. action token issuer vault (orchestrator),
#   4. init-bundle -> sign-bundle ag-01 -> sign-bundle ag-02 -> verify-bundle,
#   5. materialize-local per rola (peers.json + action_token_pub.pem),
#   6. check-local per rola (fail-closed verification).
#
# Usage: sudo bash tools/nxms-allinone-ceremony.sh
# Epoch: NXMS_TRUST_EPOCH=<nazwa> (domyślnie allinone-<data>).
set -eu
die() { printf 'nxms-allinone-ceremony: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die 'Run as root (sudo bash ...).'
[ "${SUDO_UID:-0}" -gt 0 ] || die 'Run sudo from your regular user account.'
BOOT=/opt/nxms/bin/nxms-host-bootstrap
[ -x "$BOOT" ] || die "Missing $BOOT; run nxms-allinone-setup.sh --bin-dir first."
[ -f /etc/nxms/trust/mailbox.onion ] || die 'Missing mailbox.onion; run nxms-allinone-tor.sh first.'

epoch=${NXMS_TRUST_EPOCH:-allinone-$(date +%Y%m%d)}
trust=/etc/nxms/trust

# rola|user|local_id|role-string|port (host = .onion z C4, obowiazkowy wg nxms-transport)
ENTRIES=(
    'ag01|nxms-ag01|ag-01|ag-01|28081'
    'ag02|nxms-ag02|ag-02|ag-02|28082'
    'orch|nxms-orch|orchestrator|orchestrator|28083'
    'mailbox|nxms-mailbox|mailbox|mailbox|80'
    'signer-a|nxms-signer-a|signer_a|signer-a|28090'
    'signer-b|nxms-signer-b|signer_b|signer-b|28091'
)
for entry in "${ENTRIES[@]}"; do
    slug=${entry%%|*}
    [ -f "$trust/$slug.onion" ] || die "Missing $trust/$slug.onion; run nxms-allinone-tor.sh first."
done

as_role() { # as_role <user> <cmd...>
    local user=$1; shift
    runuser -u "$user" -- "$@"
}

# 0. Unseal passphrasow do /run (etap przejsciowy, SoT sekcja 9).
for entry in "${ENTRIES[@]}"; do
    slug=${entry%%|*}
    /opt/nxms/bin/nxms-allinone-unseal "$slug" >/dev/null
done

# 1-2. Host vault + publiczna tozsamosc per rola.
for entry in "${ENTRIES[@]}"; do
    IFS='|' read -r slug user local_id role port <<< "$entry"
    host=$(cat "$trust/$slug.onion")
    vault="/var/lib/nxms-$slug/host-vault"
    pass="/run/secrets/nxms-$slug/host_vault_passphrase"
    if [ ! -f "$vault/vault.bin" ]; then
        as_role "$user" "$BOOT" generate-host-vault \
            --local-id "$local_id" --host-vault-dir "$vault" \
            --host-vault-passphrase-file "$pass" >/dev/null
        printf 'vault %s generated\n' "$slug"
    else
        printf 'vault %s kept\n' "$slug"
    fi
    as_role "$user" "$BOOT" export-host-identity \
        --local-id "$local_id" --role "$role" --host "$host" --port "$port" \
        --host-vault-dir "$vault" --host-vault-passphrase-file "$pass" \
        --out "/var/lib/nxms-$slug/identity.json" >/dev/null
    install -m 0644 -o root -g root "/var/lib/nxms-$slug/identity.json" \
        "$trust/identity-$slug.json"
    printf 'identity %s exported (%s %s:%s)\n' "$slug" "$role" "$host" "$port"
done

# 3. Action token issuer vault (orchestrator).
issuer_vault=/var/lib/nxms-orch/action-token-issuer-vault
issuer_pass=/run/secrets/nxms-orch/action-token-issuer.passphrase
if [ ! -f "$issuer_vault/vault.bin" ]; then
    as_role nxms-orch "$BOOT" generate-action-token-issuer-vault \
        --issuer nxms-auth --algorithm EDDSA \
        --action-token-issuer-vault-dir "$issuer_vault" \
        --action-token-issuer-vault-passphrase-file "$issuer_pass" >/dev/null
    printf 'action-token issuer vault generated\n'
fi
as_role nxms-orch "$BOOT" export-action-token-issuer \
    --action-token-issuer-vault-dir "$issuer_vault" \
    --action-token-issuer-vault-passphrase-file "$issuer_pass" \
    --out /var/lib/nxms-orch/action-token-issuer.json >/dev/null
install -m 0644 -o root -g root /var/lib/nxms-orch/action-token-issuer.json \
    "$trust/action-token-issuer.json"

# 4. Bundle: init -> podpis ag-01 -> podpis ag-02 -> verify.
identities=()
for entry in "${ENTRIES[@]}"; do
    slug=${entry%%|*}
    identities+=(--host-identity "$trust/identity-$slug.json")
done
if [ ! -f "$trust/runtime-trust.final.json" ]; then
    "$BOOT" init-bundle --trust-epoch "$epoch" "${identities[@]}" \
        --action-token-issuer-bundle "$trust/action-token-issuer.json" \
        --out "$trust/runtime-trust.unsigned.json" >/dev/null
    # Guardowie podpisuja w swoich katalogach (brak zapisu do /etc/root-owned);
    # root przenosi wynik miedzy krokami.
    as_role nxms-ag01 "$BOOT" sign-bundle \
        --bundle "$trust/runtime-trust.unsigned.json" \
        --signer-id ag-01 --signer-role ag-01 \
        --host-vault-dir /var/lib/nxms-ag01/host-vault \
        --host-vault-passphrase-file /run/secrets/nxms-ag01/host_vault_passphrase \
        --out "/var/lib/nxms-ag01/runtime-trust.s1.json" >/dev/null
    install -m 0644 -o root -g root "/var/lib/nxms-ag01/runtime-trust.s1.json" \
        "$trust/runtime-trust.s1.json"
    as_role nxms-ag02 "$BOOT" sign-bundle \
        --bundle "$trust/runtime-trust.s1.json" \
        --signer-id ag-02 --signer-role ag-02 \
        --host-vault-dir /var/lib/nxms-ag02/host-vault \
        --host-vault-passphrase-file /run/secrets/nxms-ag02/host_vault_passphrase \
        --out "/var/lib/nxms-ag02/runtime-trust.final.json" >/dev/null
    install -m 0644 -o root -g root "/var/lib/nxms-ag02/runtime-trust.final.json" \
        "$trust/runtime-trust.final.json"
    printf 'bundle signed by ag-01 + ag-02 (epoch %s)\n' "$epoch"
else
    printf 'bundle kept (epoch %s)\n' "$epoch"
fi
"$BOOT" verify-bundle --bundle "$trust/runtime-trust.final.json" >/dev/null
printf 'bundle verify: OK\n'

# 5-6. Projekcje per rola + kontrola fail-closed.
for entry in "${ENTRIES[@]}"; do
    IFS='|' read -r slug user local_id role port <<< "$entry"
    vault="/var/lib/nxms-$slug/host-vault"
    pass="/run/secrets/nxms-$slug/host_vault_passphrase"
    as_role "$user" "$BOOT" materialize-local \
        --bundle "$trust/runtime-trust.final.json" --local-id "$local_id" \
        --host-vault-dir "$vault" --host-vault-passphrase-file "$pass" \
        --peers-out "/var/lib/nxms-$slug/peers.json" \
        --action-token-public-key-pem-out "/var/lib/nxms-$slug/action_token_pub.pem" >/dev/null
    for f in peers.json action_token_pub.pem runtime-trust.final.json; do
        if [ "$f" = runtime-trust.final.json ]; then
            install -m 0640 -o root -g "$user" "$trust/runtime-trust.final.json" \
                "/etc/nxms/$slug/$f"
        else
            install -m 0640 -o root -g "$user" "/var/lib/nxms-$slug/$f" \
                "/etc/nxms/$slug/$f"
        fi
    done
    as_role "$user" "$BOOT" check-local \
        --bundle "$trust/runtime-trust.final.json" --local-id "$local_id" \
        --host-vault-dir "$vault" --host-vault-passphrase-file "$pass" \
        --peers-path "/etc/nxms/$slug/peers.json" \
        --action-token-public-key-pem-path "/etc/nxms/$slug/action_token_pub.pem" >/dev/null
    printf 'materialize + check-local %s: OK\n' "$slug"
done

cat <<EOF

nxms-allinone-ceremony: done (epoch $epoch).
Bundle: $trust/runtime-trust.final.json
Kolejny krok (C5): sudo systemctl start nxms-mailbox nxms-signer-a nxms-signer-b
EOF
