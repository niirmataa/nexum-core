# Escrow Protocol v1 (Rust Native API)

Last update: 2026-02-17
Source of truth: `escrow/monero-arbitra/src/escrow_http`

## Scope
This document freezes v1 behavior of the Rust escrow API transport and state machine.
Asset scope in v1 is XMR only.

## Versioning and compatibility
1. v1 is frozen as of 2026-02-17.
2. Any breaking change to auth transport, route shape, or state transition rules requires v2.
3. Non-breaking additions in v1:
 - optional response fields
 - additive audit metadata
 - internal performance/hardening changes without contract impact

## Actors and auth
1. Buyer: `nick == buyer_nick` and escrow `buyer_token`.
2. Seller: `nick == seller_nick` and escrow `seller_token`.
3. Arbiter: `nick == arbiter_nick` and global `ESCROW_ARBITER_TOKEN`.

Auth transport in v1:
1. `GET` routes use query params: `?nick=<nick>&token=<token>`.
2. `POST` routes use JSON body fields: `nick`, `token`.
3. Token compare is timing-safe.

## Escrow object (public response)
Public escrow response includes:
1. `id`, `asset`, `state`.
2. `buyer_nick`, `seller_nick`, `arbiter_nick`.
3. `deposit_address`, refund addresses, `amount_atomic`, `memo`.
4. dispute metadata (`dispute_opened_by`, `dispute_reason`, `dispute_opened_at`).
5. `buyer_token` is returned only on create response.
6. `seller_token` is not returned by the create flow.

## API routes (v1)
1. `GET /health`
2. `POST /escrows`
3. `GET /escrows/:id`
4. `POST /escrows/:id/dispute`
5. `POST /escrows/:id/xmr/r1`
6. `GET /escrows/:id/xmr/r1`
7. `POST /escrows/:id/xmr/r2`
8. `GET /escrows/:id/xmr/r2`
9. `POST /escrows/:id/xmr/r3`
10. `GET /escrows/:id/xmr/r3`
11. `POST /escrows/:id/xmr/finalize` (arbiter-only)
12. `POST /escrows/:id/xmr/export-info` (arbiter-only)
13. `POST /escrows/:id/xmr/import-info` (arbiter-only)
14. `POST /escrows/:id/xmr/sign` (arbiter-only)
15. `POST /escrows/:id/xmr/submit` (arbiter-only)
16. `POST /escrows/:id/xmr/release`
17. `POST /escrows/:id/xmr/refund`

## Response envelope and error format
1. Success responses are JSON bodies specific to the endpoint.
2. Error responses use JSON:
```json
{"detail":"<message>"}
```

## HTTP status / error code mapping (v1)
1. `200 OK`: successful operation (including idempotent replay success).
2. `400 Bad Request`: payload validation failure (nick/token shape, txid/hex format, invalid address, etc.).
3. `403 Forbidden`: auth failure (wrong token, missing token, nick not in escrow, arbiter role required).
4. `404 Not Found`: escrow ID does not exist.
5. `409 Conflict`: state conflict/domain conflict (invalid transition, idempotency payload mismatch, in-progress idempotency key, txid conflict).
6. `429 Too Many Requests`: rate limit exceeded.
7. `502 Bad Gateway`: upstream wallet-rpc failure.
8. `500 Internal Server Error`: unexpected internal/storage/runtime failure.

## Create contract
`POST /escrows` request:
1. `asset` must be `XMR`.
2. `buyer_nick` and `seller_nick` must be non-empty, <=64 chars, and different.
3. `buyer_nick` and `seller_nick` must be different than arbiter nick.
4. `amount_atomic > 0`.
5. `amount_atomic >= ESCROW_MIN_AMOUNT_ATOMIC` (fail-closed).
6. Funding reserve is derived by policy:
 - `escrow_fee_atomic = max(ESCROW_FEE_FLOOR_ATOMIC, ceil(amount_atomic * ESCROW_FEE_BPS / 10000))`
 - `required_funding_atomic = amount_atomic + escrow_fee_atomic`.
5. `memo` max length: 2000.
6. `buyer_refund_address` optional; validated as base58-like Monero address format.

Create behavior:
1. Escrow row is created with random buyer/seller tokens.
2. Arbiter `prepare_r1` is executed via wallet-rpc.
3. On success: state becomes `XMR_MSIG_R1`.
4. On failure: state becomes `CLOSED` and `create_failed` audit event is stored.

## State machine v1
States:
1. `NEW`
2. `XMR_MSIG_R1`
3. `XMR_MSIG_R2`
4. `XMR_MSIG_R3`
5. `READY`
6. `FUNDED`
7. `DISPUTE`
8. `RELEASED`
9. `REFUNDED`
10. `CLOSED`

Primary transitions:
1. `NEW -> XMR_MSIG_R1` after create + arbiter R1 prepared.
2. `XMR_MSIG_R1 -> XMR_MSIG_R2` after complete R1 + arbiter R2 set.
3. `XMR_MSIG_R2 -> XMR_MSIG_R3` after complete R2 + arbiter R3 set.
4. `XMR_MSIG_R3 -> READY` after complete R3 + deposit address set/finalized.
5. `READY -> FUNDED` by funded watcher when unlocked wallet balance >= `required_funding_atomic` (`amount_atomic + fee reserve`).
6. `READY|FUNDED|DISPUTE -> DISPUTE` when dispute opened.
7. `FUNDED|DISPUTE -> RELEASED` after 2-of-3 release confirmations.
8. `FUNDED|DISPUTE -> REFUNDED` after 2-of-3 refund confirmations.

Settlement invariants:
1. `RELEASED` and `REFUNDED` are mutually exclusive.
2. If settlement verification is enabled (`ESCROW_VERIFY_TXID_CHAIN=true` or `ESCROW_VERIFY_SETTLEMENT_WALLET=true`), `txid` is required.
3. `txid` must be 64 hex.
4. With `ESCROW_VERIFY_TXID_CHAIN=true`, txid must exist on chain with required confirmations.
5. With `ESCROW_VERIFY_SETTLEMENT_WALLET=true`, wallet-rpc `get_transfer_by_txid` must confirm outgoing transfer and no double spend.
6. With `ESCROW_VERIFY_SETTLEMENT_STRICT=true`, destination + payout amount checks are enforced against expected escrow payout address and amount.

## Role permissions (v1)
1. Buyer and seller can submit own R1/R2/R3 data.
2. Arbiter can submit arbiter R1/R2/R3, finalize, export/import multisig info, sign, and submit tx.
3. Buyer/seller/arbiter can open dispute (allowed states: `READY`, `FUNDED`, `DISPUTE`).
4. Buyer/seller/arbiter can confirm release/refund (2 confirmations required).

## Validation and limits
1. `nick`: non-empty, <=64, no control chars.
2. `token`: required, max 512 chars.
3. `memo`: <=2000 chars.
4. `reason`: <=2000 chars.
5. `multisig_info` item: non-empty, <=20000 chars.
6. `tx_data_hex`: required hex, even length, max `XMR_TX_HEX_MAX_LEN` (default 2,000,000; clamped to 200,000..20,000,000).
7. `txid`: if present, exactly 64 hex.

## Rate limiting
1. Backend supports `redis` and `memory`; in secure production mode Redis is required.
2. Keys are hashed and scoped as `label:tok|nick|ip:<hash>`.
3. Connection IP is default source.
4. Forwarded headers are honored only when:
 - `ESCROW_TRUST_PROXY_HEADERS=true`
 - peer IP is in `ESCROW_TRUSTED_PROXY_IPS`.

## Idempotency
Idempotency header:
1. `x-idempotency-key`, max 128 chars, charset `[A-Za-z0-9-_.:]`.

Covered routes:
1. `POST /escrows`
2. `POST /escrows/:id/dispute`
3. `POST /escrows/:id/xmr/submit`
4. `POST /escrows/:id/xmr/release`
5. `POST /escrows/:id/xmr/refund`

Behavior:
1. Same key + same payload returns replayed response.
2. Same key + different payload returns conflict.
3. In-progress claims use TTL (`ESCROW_IDEMPOTENCY_IN_PROGRESS_TTL_S`, default 300s).
4. Replay after `ESCROW_IDEMPOTENCY_REPLAY_WINDOW_S` (default 86400s) is rejected.
5. When `ESCROW_REQUIRE_IDEMPOTENCY_FINANCIAL=true`, covered routes require `x-idempotency-key`.

## Environment switches relevant to protocol
1. `ESCROW_ALLOW_INSECURE` must be disabled in production.
2. `ESCROW_VERIFY_TXID_CHAIN` should be enabled in production.
3. `ESCROW_MIN_TX_CONFIRMATIONS` defaults to `1`.
4. `XMR_DAEMON_RPC_HOST/PORT` define daemon endpoint for txid verification.
5. `ESCROW_REQUIRE_IDEMPOTENCY_FINANCIAL` should be `true` in production.
6. `ESCROW_IDEMPOTENCY_REPLAY_WINDOW_S` defaults to `86400`.
7. `ESCROW_RATE_LIMIT_BACKEND` must be `redis` in production.
8. `ESCROW_RATE_LIMIT_REDIS_URL` is required for Redis backend.
9. `ESCROW_MIN_AMOUNT_ATOMIC` defines minimal escrow amount accepted by `POST /escrows`.
10. `ESCROW_FEE_FLOOR_ATOMIC` defines fixed minimal fee reserve.
11. `ESCROW_FEE_BPS` defines percentage fee in basis points (`0..10000`).

## Non-goals for v1
1. No admin backdoor endpoints in protocol contract.
2. No multi-asset settlement behavior beyond XMR.
3. No distributed rate-limit backend in this version.

## Step 1 sign-off
1. Protocol v1 freeze status: DONE.
2. Freeze date: 2026-02-17.
3. Next production step: Step 2 (DB migrations and constraints).
