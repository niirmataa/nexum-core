# NXMS Action Token Contract v1

Last update: 2026-02-18
Scope: Falcon challenge -> capability token -> signer worker verification.

## 1. Challenge Input for `nexum-cli`
`nexum respond --challenge <file>` expects challenge JSON compatible with `ff_challenge_pkt` parsing in `nexum_cli/src/auth.c`.

Required JSON fields:
- `flow` (string)
- `kem_id` (string)
- `sid` (base64url, 16 raw bytes)
- `ts` (unix timestamp, integer)
- `ct_b64` (base64)
- `payload_b64` (base64)

Optional JSON fields:
- `nick` (if missing, CLI fills from vault nick)
- `tag_b64` (AAD v1 MAC)
- `aad_ver` (defaults to `1`)
- `tag2_b64` (AAD v2 MAC)

CLI output:
- stdout: Falcon signature in base64 (`sig_b64`), for the recovered transcript.

## 2. Capability Token Claims (JWT/JWS)
Signer verifies these required claims (`escrow/nxms-signer/src/action_token.rs`):
- `iss`
- `aud`
- `sub`
- `scope`
- `op`
- `role`
- `sign_round`
- `escrow_id`
- `wallet_id`
- `sandbox_id`
- `txset_hash`
- `snapshot_hash`
- `nettype`
- `exp`
- `nbf`
- `iat`
- `jti`

Submit token (op=`submit_multisig`) additionally requires:
- `proof_arbiter_jti`
- `proof_seller_jti`
- `proof_arbiter_req_id`
- `proof_seller_req_id`

## 3. Worker Verification Rules (Fail-Closed)
Token is rejected unless all checks pass:
1. Signature algorithm matches config (`EDDSA` or `ES256`).
2. `iss` matches configured issuer.
3. `aud` matches configured audience (production: exact `sandbox:<sandbox_id>`).
4. `scope` and `op` exact match (`sign_multisig` or `submit_multisig`).
5. `role` and `sign_round` match signer role expectations.
6. `escrow_id`, `wallet_id`, `sandbox_id`, `nettype` exact match local signer context.
7. `txset_hash` and `snapshot_hash` exact 64-hex match.
8. `jti` non-empty, max length 256.
9. Time gates:
   - `exp >= iat`
   - `exp >= nbf`
   - `iat` not in future (respecting `clock_skew_secs`)
   - token TTL bounded by config `max_ttl_secs` (`exp-iat` and `exp-nbf`)
10. Replay/idempotency gates in signer flow:
   - consume-first `jti` (`consumed_action_jti`)
   - request dedup by `req_id` (`sign_request_dedup`)

## 4. Config Requirements
`[action_token]` signer config keys:
- `required`
- `issuer`
- `audience` (production: required and must equal `sandbox:<sandbox_id>`)
- `algorithm`
- `public_key_pem_path`
- `clock_skew_secs`
- `max_ttl_secs` (production hardening: `<= 120`)

## 5. Falcon Challenge -> Token Issue Binding
Contract split:
1. CLI (`nexum respond`) proves key possession by signing recovered challenge transcript.
2. Auth/orchestrator layer verifies `sig_b64` against user Falcon public key.
3. Auth/orchestrator layer mints short-lived action token with bound context:
   - escrow and tx intent (`escrow_id`, `txset_hash`, `snapshot_hash`)
   - execution scope (`op`, `role`, `sign_round`)
   - sandbox binding (`aud`, `sandbox_id`, `wallet_id`)
4. Worker accepts only this bound token; no direct fallback in hard-fail mode.
