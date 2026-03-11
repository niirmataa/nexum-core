# NXMS Mailbox + Signer Runbook

Last update: 2026-03-10

## Topology (recommended)
- Host A: `nxms-mailbox` only.
- Host B: `monerod-stagenet` over Tor-only + local `monero-wallet-rpc` loopback-only + `nxms-signer`.
- Escrow API stays separate (informational only).

## Escrow HTTP Integration
Legacy/operator-only note:
- `escrow_http`, `worker-route`, env-template routing do `nxms-signer serve` i podobne HTTP adapter paths nie należą do kanonicznego NXMS runtime.
- Kanoniczny cross-host runtime path to tylko `nxms-transport -> nxms-mailbox -> nxms-signer` over Tor hidden service.
- Poniższa sekcja zostaje wyłącznie jako zapis legacy/operator interoperability, nie jako rekomendowany model docelowy.

- `monero-arbitra` `ServeEscrow` (`escrow_http`) jest northbound ingress dla UI/klienta.
- `escrow_http` obsługuje state/API i idempotency, ale nie powinien trzymać sekretów signer sandboxów.
- Legacy routing operatorski:
  - `escrow_http` -> `nxms-escrow-orchestrator` (stan workflow + proposal blob metadata)
  - `nxms-escrow-orchestrator` -> lokalne worker API (`nxms-signer serve`) per sandbox/rola
- Orchestrator CLI dla proposal persistence (opaque blob):
  - `nxms-escrow-orchestrator proposal store --db-path ... --escrow-id-hex ... --action release|refund --tx-data-hex-file /run/nxms/proposal.hex --txset-hash-hex ...`
  - `nxms-escrow-orchestrator proposal show --db-path ... --escrow-id-hex ...`
- Legacy orchestrator CLI dla routingu sandbox workerów:
  - `nxms-escrow-orchestrator worker-route set --db-path ... --escrow-id-hex ... --role seller|arbiter|buyer --endpoint http://127.0.0.1:28090`
  - `nxms-escrow-orchestrator worker-route show --db-path ... --escrow-id-hex ... --role seller|arbiter|buyer`
  - `nxms-escrow-orchestrator integrity check --db-path ... --fail-on-findings` waliduje m.in. izolację ról przez wykrywanie `worker_routes.endpoint_role_collision` (ten sam endpoint przypisany do wielu ról w jednym escrow).
  - `worker-route set` odrzuca endpointy wallet-rpc (`.../json_rpc`) i porty wallet-rpc (`18088/28088/38088/38083/38084`) żeby orchestrator nie mógł routować bezpośrednio do wallet-rpc.
- Orchestrator CLI dla cross-sandbox quorum proof:
  - `nxms-escrow-orchestrator quorum-proof set --db-path ... --escrow-id-hex ... --role seller|arbiter --sign-round seller_second|arbiter_first --txset-hash-hex ... --jti ... --req-id ...`
  - `nxms-escrow-orchestrator quorum-proof show --db-path ... --escrow-id-hex ... --role seller|arbiter --sign-round seller_second|arbiter_first --txset-hash-hex ...`
- Legacy `escrow_http` adapter flags:
  - `NXMS_ESCROW_HTTP_ORCH_PROPOSAL_STORE=true` włącza write-through do orchestratora dla `tx_data_hex` (release/refund).
  - `NXMS_ESCROW_HTTP_ORCH_PROPOSAL_REQUIRED=true` wymusza fail-closed przy błędzie zapisu.
  - `NXMS_ORCH_BIN` (domyślnie `nxms-escrow-orchestrator`) i `NXMS_ESCROW_HTTP_ORCH_TIMEOUT_SECS` sterują wywołaniem CLI.
  - `GET /escrows/:id/xmr/proposal?nick=<arbiter>&token=<token>` zwraca ostatni blob proposal z orchestratora.
  - `GET /escrows/:id/xmr/status-sync?nick=<arbiter>&token=<token>` zwraca read-only agregat stanu z orchestratora (`workflow.show`, `proposal.show`, `worker-route.show` dla `buyer/seller/arbiter`) do UI/operatora.
  - `NXMS_ESCROW_HTTP_SELLER_WORKER_SIGN_SUBMIT=true` przełącza seller release sign+submit na worker capability flow (`nxms-signer` API) zamiast direct wallet-rpc.
  - `NXMS_SELLER_SIGNER_WORKER_URL=http://127.0.0.1:28090` wskazuje endpoint worker API (static).
  - `NXMS_SELLER_SIGNER_WORKER_URL_TEMPLATE=http://127.0.0.1:28{escrow_id}` pozwala routować per escrow/sandbox (`{escrow_id}`, `{escrow_id_hex}`).
  - `NXMS_SELLER_SIGNER_WORKER_TIMEOUT_SECS=20` ustawia timeout requestu z `escrow_http` do worker API.
  - `NXMS_ESCROW_HTTP_ARBITER_WORKER_SUBMIT=true` przełącza arbiter release submit na worker capability flow.
  - `NXMS_ESCROW_HTTP_ARBITER_WORKER_SUBMIT_REQUIRED=true` wymusza fail-closed dla release arbitra: brak worker submit lub brak `tx_data_hex` = reject; out-of-band `txid` jest blokowane.
  - `NXMS_ARBITER_SIGNER_WORKER_URL=http://127.0.0.1:28091` i `NXMS_ARBITER_SIGNER_WORKER_TIMEOUT_SECS=20` konfigurują endpoint/timeouts submit dla sandboxa arbitra.
  - `NXMS_ARBITER_SIGNER_WORKER_URL_TEMPLATE=http://127.0.0.1:29{escrow_id}` pozwala routować submit per escrow/sandbox (`{escrow_id}`, `{escrow_id_hex}`).
  - `NXMS_ESCROW_HTTP_ORCH_WORKER_ROUTE_LOOKUP=true` włącza lookup endpointu workera przez orchestrator (`worker-route show`) przed fallbackiem do env/template.
  - `NXMS_ESCROW_HTTP_ORCH_WORKER_ROUTE_REQUIRED=true` wymusza fail-closed: brak route w orchestratorze albo błąd lookup = reject (bez fallbacku).
  - `NXMS_ESCROW_HTTP_REQUIRE_WORKER_PATH=true` wymusza fail-closed: brak aktywnego worker path dla seller/arbiter release submit = reject (bez legacy fallbacku direct wallet).
  - `NXMS_ESCROW_HTTP_WORKER_ROUTE_STRICT=true` to profil produkcyjny 1-switch:
    - wymusza worker path,
    - wymusza seller/arbiter worker flow,
    - wymusza arbiter release submit przez worker (`tx_data_hex` wymagane, bez out-of-band `txid`),
    - wymusza orchestrator route lookup (`worker-route`) i route required,
    - blokuje fallback env/template oraz fallback direct wallet w seller auto-sign release.
  - `NXMS_ESCROW_HTTP_PRODUCTION_HARDENING=true` dodaje startup fail-closed gate:
    - wymaga `ESCROW_ALLOW_INSECURE=false`,
    - wymaga strict worker-route flags (`...WORKER_ROUTE_STRICT`, `...ORCH_WORKER_ROUTE_LOOKUP`, `...ORCH_WORKER_ROUTE_REQUIRED`, `...ARBITER_WORKER_SUBMIT_REQUIRED`),
    - wymaga loopback `XMR_WALLET_RPC_HOST`.

## Mailbox Hardening
1. Bind mailbox to localhost only:
`NXMS_MAILBOX_BIND=127.0.0.1:4010`
2. Use separate bearer tokens for push/admin and scoped token maps for pull/ack:
`NXMS_MAILBOX_PUSH_TOKEN=...`
`NXMS_MAILBOX_PULL_TOKENS=buyer=...,seller=...,arbiter=...`
`NXMS_MAILBOX_ACK_TOKENS=buyer=...,seller=...,arbiter=...`
`NXMS_MAILBOX_ADMIN_TOKEN=...`
3. `pull` and `ack` are fail-closed per inbox scope:
- a token for one inbox must not authorize another inbox,
- `ack` must delete only `(receipt, to_id)` for the authorized inbox,
- do not reuse the same token value across inbox scopes.
4. Enforce quotas/rate limits:
- `NXMS_MAILBOX_MAX_MESSAGES_PER_INBOX`
- `NXMS_MAILBOX_MAX_BYTES_PER_INBOX`
- `NXMS_MAILBOX_MAX_ROWS_GLOBAL`
- `NXMS_MAILBOX_RATE_LIMIT_IP_PER_MIN`
- `NXMS_MAILBOX_RATE_LIMIT_TO_PER_MIN`
5. Keep periodic cleanup + checkpoint enabled:
- `NXMS_MAILBOX_CLEANUP_SECS`
- `NXMS_MAILBOX_CHECKPOINT_SECS`

## Tor Onion Service
Minimal `torrc` fragment for mailbox:
```text
HiddenServiceDir /var/lib/tor/nxms-mailbox/
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:4010
```

Preferred: enable client authorization (v3 auth) so only known clients can connect.

## Signer Config
`nxms-signer` reads TOML (`NXMS_SIGNER_CONFIG`, default `nxms-signer.toml`).
Minimum required fields:
- `local_id`, `peers_path`, `keys_path`, `db_path`
- `signer_role`, `sandbox_id`, `wallet_id`, `nettype`
- `mailbox_url`, `mailbox_push_token`, `mailbox_pull_token`, `mailbox_ack_token`, `worker_service_token`, `tor_socks5h`
- `allow_remote_wallet_rpc=false` (required; remote wallet-rpc is not a supported runtime mode)
- `production_hardening=true` (recommended in production)
- `[wallet_rpc]`: endpoint + wallet credentials + digest auth credentials
- `[wallet_provision]` (production): `enabled=true`, `wallet_cli_path`, `wallet_dir`, `daemon_address`, `timeout_secs`
- `snapshot_quorum`, `max_txset_hex_len`
- `[action_token]` (production): `required=true`, `issuer`, `audience`, `algorithm=EDDSA|ES256`, `public_key_pem_path`, `clock_skew_secs`, `max_ttl_secs`

Action token `snapshot_hash` must be canonical snapshot JSON hash:
`sha256(canonical_json(sorted_keys(snapshot)))`.
Secrets can be referenced as `vault:/path/to/secret`, `file:/path/to/secret`, or `env:VAR_NAME`.
When `production_hardening=true`, `vault:` refs are mandatory for:
- `mailbox_push_token`, `mailbox_pull_token`, `mailbox_ack_token` (and `mailbox_admin_token` if set),
- `worker_service_token`,
- `wallet_rpc.wallet_password`,
- `wallet_rpc.password`.
Signer provisioning flow (`wallet_provision.enabled=true`) runs server-side CLI:
`set enable-multisig-experimental 1` -> `save` before signer opens wallet through wallet-rpc.
`production_hardening=true` wymusza `wallet_provision.enabled=true`.
Cross-sandbox quorum proof bridge (signer <-> orchestrator):
- `NXMS_SIGNER_ORCH_QUORUM_PROOF_STORE=true` zapisuje `sign_event` do orchestratora (`quorum-proof set`) po `sign_multisig`.
- `NXMS_SIGNER_ORCH_QUORUM_PROOF_STORE_REQUIRED=true` wymusza fail-closed, gdy zapis proof do orchestratora nie powiedzie się.
- `NXMS_SIGNER_ORCH_QUORUM_PROOF_VERIFY=true` wymusza przy `submit_multisig` zgodność token proof sellera (`proof_seller_jti`, `proof_seller_req_id`) z rekordem orchestratora (`quorum-proof show`).
- `NXMS_SIGNER_ORCH_BRIDGE_TOKEN_REF=vault:/run/secrets/nxms/orch_bridge_token` ustawia bridge token do wywołań CLI orchestratora bez trzymania sekretu w argv; przy `production_hardening=true` wymagany jest właśnie `vault:` reference (legacy `NXMS_SIGNER_ORCH_BRIDGE_TOKEN` jest odrzucany).
- `NXMS_ORCH_ARGV_HARDENING=true` wymusza brak sekretów/blobów w argv orchestratora:
  - `quorum-proof` odrzuca `--bridge-token` i akceptuje tylko `NXMS_ORCH_BRIDGE_TOKEN_INPUT`,
  - `proposal store` odrzuca inline `--tx-data-hex` i wymaga `--tx-data-hex-file`.
- `NXMS_SIGNER_ORCH_TIMEOUT_SECS` steruje timeoutem wywołań CLI orchestratora z poziomu signera.
- `NXMS_ORCH_BIN` i `NXMS_ORCH_DB_PATH` muszą wskazywać ten sam binary/DB co routing orchestratora.
- `production_hardening=true` wymusza `NXMS_SIGNER_ORCH_QUORUM_PROOF_VERIFY=true` już na starcie signera (fail-fast).

## Snapshot Lifecycle
1. Create draft:
`nxms-signer snapshot new ... --out snapshot.json`
2. Hash:
`nxms-signer snapshot hash --snapshot snapshot.json`
3. Sign (each signer):
`nxms-signer snapshot sign --snapshot snapshot.json --keys keys.json --signer-id <id> --out sig.json`
4. Verify:
`nxms-signer snapshot verify --snapshot snapshot.json --signature sig.json`
5. Activate with quorum:
`nxms-signer snapshot activate --config nxms-signer.toml --snapshot snapshot.json --signatures sig1.json sig2.json ...`

## Pending Queue Workflow
- Run agent:
`nxms-signer run --config nxms-signer.toml`
- List pending:
`nxms-signer pending list --config nxms-signer.toml`
- Show item:
`nxms-signer pending show --config nxms-signer.toml --id <id>`
- Approve/sign:
`nxms-signer pending approve --config nxms-signer.toml --id <id> --action-token <jwt>`
- Submit (release/refund):
`nxms-signer pending submit --config nxms-signer.toml --escrow-id-hex <id> --tx-data-hex <hex> --action release --action-token <jwt>`
- Reject:
`nxms-signer pending reject --config nxms-signer.toml --id <id> --reason "policy violation"`
- Audit metrics summary (event counters):
`nxms-signer audit metrics --config nxms-signer.toml`
- Audit metrics security breakdown (reject reasons):
`nxms-signer audit metrics --config nxms-signer.toml --security-breakdown`

## Worker API Workflow (capability mode)
- Run local worker API:
`nxms-signer serve --config nxms-signer.toml --bind 127.0.0.1:28090`
- Worker API is loopback-only; non-loopback bind is rejected.
- Health check:
`curl -sS http://127.0.0.1:28090/healthz`
- Sign endpoint:
`POST /v1/sign_multisig`
- Submit endpoint:
`POST /v1/submit_multisig`
- Proposal endpoint (arbiter sandbox source of txset):
`POST /v1/propose_multisig`
- Service auth:
  - every `/v1/*` call requires `X-NXMS-Service-Authorization: Bearer <worker_service_token>`
- Action token transport:
  - `sign_multisig` and `submit_multisig` still require business auth via action token
  - preferred: `Authorization: Bearer <action_token>`
  - fallback: JSON field `action_token`
- Request body (sign/submit):
```json
{
  "escrow_id_hex": "00112233445566778899aabbccddeeff",
  "action": "release",
  "tx_data_hex": "aa11...",
  "action_token": "optional_if_header_present"
}
```
- Request body (proposal):
```json
{
  "escrow_id_hex": "00112233445566778899aabbccddeeff",
  "action": "release",
  "amount_override_atomic": null
}
```
- Proposal call:
```bash
curl -sS -X POST http://127.0.0.1:28090/v1/propose_multisig \
  -H 'Content-Type: application/json' \
  -d '{"escrow_id_hex":"00112233445566778899aabbccddeeff","action":"release"}'
```
- Minimal sign call:
```bash
curl -sS -X POST http://127.0.0.1:28090/v1/sign_multisig \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${ACTION_TOKEN}" \
  -d '{"escrow_id_hex":"00112233445566778899aabbccddeeff","action":"release","tx_data_hex":"aa11"}'
```
- Minimal submit call:
```bash
curl -sS -X POST http://127.0.0.1:28090/v1/submit_multisig \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${SUBMIT_TOKEN}" \
  -d '{"escrow_id_hex":"00112233445566778899aabbccddeeff","action":"release","tx_data_hex":"aa11"}'
```

When `[action_token].required=true`, missing or invalid token causes hard reject before `sign_multisig`.
`max_ttl_secs` enforces short-lived capability tokens (`exp-iat` and `exp-nbf` bounds).
Formal contract reference:
- `docs/NXMS_ACTION_TOKEN_CONTRACT_V1.md`

Security posture check:
`nxms-signer security check --config nxms-signer.toml`

Strict argv-hardening reject evidence:
`scripts/nxms_orch_argv_hardening_check.sh`

Strict fail-closed reject matrix evidence (legacy worker-route strict + split token rejects):
`scripts/nxms_strict_failclosed_rejects.sh`

Governance references:
- `docs/NXMS_POLICY_BOUNDARY.md`
- `docs/NXMS_AUTO_APPROVE_POLICY.md`
- `docs/NXMS_WORKFLOW_DB_DR_PLAYBOOK.md`
- `docs/NXMS_RUNTIME_HARDENING_RUNBOOK.md`

## Firewall Baseline
- Mailbox host: allow inbound only Tor listener; deny direct mailbox port externally.
- Signer host: allow outbound only to mailbox onion via Tor + local wallet-rpc.
- Wallet-rpc bind localhost only.
- Run network isolation verifier:
`WALLET_RPC_PORT=18088 scripts/verify_nxms_network_isolation.sh`
- Run production preflight (includes fail-closed loopback check for `XMR_WALLET_RPC_HOST`):
`scripts/escrow_prod_preflight.sh --strict-daemon-sync`
- Detailed policy profile:
`docs/NXMS_SANDBOX_NETWORK_POLICY.md`

## Logging
- Keep envelope metadata and decisions only.
- Never log plaintext txset blobs, private keys, wallet passwords, or decrypted payload dumps.
