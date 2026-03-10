# NXMS Multisig Auto Escrow Flow State Machine (Frozen v1)

Last update: 2026-02-18

This document freezes the v1 workflow contract for production orchestration over NXMS.

## States
1. `new`
2. `prepare_collected`
3. `make_collected`
4. `exchange_r1_collected`
5. `exchange_r2_collected`
6. `finalized_ready`
7. `funded`
8. `tx_sign_pending`
9. `tx_signed_quorum`
10. `submitted`
11. `confirmed`
12. `failed_dead_letter`

## Allowed Transitions
- `new -> prepare_collected`
- `prepare_collected -> make_collected`
- `make_collected -> exchange_r1_collected`
- `exchange_r1_collected -> exchange_r2_collected`
- `exchange_r2_collected -> finalized_ready`
- `finalized_ready -> funded`
- `funded -> tx_sign_pending`
- `tx_sign_pending -> tx_signed_quorum`
- `tx_signed_quorum -> submitted`
- `submitted -> confirmed`
- Any non-terminal state may transition to `failed_dead_letter` on unrecoverable error.

## Message Contract Per Stage

### Stage: Prepare
- Required inbound type: `prepare_info`
- Required fields:
`escrow_id_hex`, `from`, `to`, `seq`, `app_proto=ESCROW/1`, payload body
- Invariant:
exactly one `prepare_info` per participant id for given `escrow_id_hex`.

### Stage: Make
- Required inbound type: `make_info`
- Invariant:
must not execute until all expected `prepare_info` are present.

### Stage: Exchange Round 1
- Required inbound type: `exchange_round1`
- Invariant:
must not execute until all expected `make_info` are present.

### Stage: Exchange Round 2
- Required inbound type: `exchange_round2`
- Invariant:
must not execute until all expected `exchange_round1` are present.

### Stage: Finalize
- Required condition:
wallet reports multisig ready and address bound to escrow context.

### Stage: Funded
- Required condition:
wallet balance/unlocked policy threshold reached.

### Stage: Sign
- Required inbound type: `tx_sign_req`
- Invariant:
active snapshot exists, replay guard passes, describe_transfer passes policy.

### Stage: Submit
- Required condition:
quorum signatures assembled in tx data.

### Stage: Confirm
- Required condition:
confirmation watcher reaches configured depth without conflicting reorg outcome.

## Idempotency Keys
Every persisted step event MUST carry idempotency key:
- `idem_key = sha3-256(escrow_id_hex || ":" || stage || ":" || from_id || ":" || seq)`

Rules:
- If `idem_key` already exists with same payload hash: treat as duplicate success.
- If `idem_key` exists with different payload hash: hard fail -> `failed_dead_letter`.

## Retry Policy
- Transient transport errors: exponential backoff (base 1s, cap 60s, jitter).
- Transient wallet errors (timeout, 5xx): retry up to 10 attempts per step.
- Non-transient validation errors: no retry, emit error and dead-letter.
- Replay/out-of-order detection: no retry, audit as rejected.

## Dead-Letter Policy
- Terminal reason categories:
`policy_violation`, `replay_violation`, `wallet_nonrecoverable`, `peer_protocol_violation`, `timeout_exhausted`.
- Dead-letter record must include:
`escrow_id_hex`, `stage`, `last_error_code`, `last_error_detail_redacted`, `attempts`, `created_at`.
- Dead-letter items require explicit operator action to replay or abandon.

## Timeouts
- Stage message wait timeout: default 120s (configurable).
- Funded wait timeout: configurable business policy window.
- Confirmation wait timeout: configurable by network target.

## Protocol Lock
- Wire proto: `NXMS/1`.
- App proto: `ESCROW/1`.
- Message type key source of truth: `nxms_transport::wire::msg_type_key()`.
