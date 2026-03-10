# NXMS Mailbox P0 Truth Test Matrix

Last update: 2026-03-10
Scope: `nxms-mailbox` truth-guarding tests for the canonical relay/store-and-forward runtime.

## Rule
- P0 mailbox behavior is not considered real unless a concrete test covers it.
- Mailbox is only relay/store-and-forward. It must not silently widen auth or alter transport semantics.
- Cross-host security still belongs to `Tor + nxms-transport`; mailbox must stay fail-closed as a scoped relay.
- Local `HTTP/axum` in mailbox is only a process adapter boundary on loopback.
- Tests using local `HTTP/axum` prove the real mailbox process API and client integration.
- These tests do not claim that HTTP is the runtime security layer; that role remains `Tor + nxms-transport`.

## Runtime Truths Guarded Here
- `push` requires its own bearer token.
- `pull` is authorized per inbox scope, not by a global bearer.
- `ack` is authorized per inbox scope and can delete only a leased receipt for that inbox.
- Dedupe is scoped by `(to_id, from_id, escrow_id_hex, seq)`.
- Lease expiry and process restart must preserve redelivery semantics.
- Quota and rate-limit failures must fail closed.

## P0 Coverage
- `smoke`
  `api::tests::smoke_push_pull_ack_roundtrip_via_api`
- `auth fail-closed`
  `api::tests::push_rejects_missing_bearer_token`
  `api::tests::pull_rejects_push_token`
  `api::tests::ack_rejects_pull_token`
  `api::tests::pull_rejects_unconfigured_inbox_even_with_valid_other_scope_token`
  `api::tests::pull_rejects_token_for_other_inbox`
  `api::tests::pull_accepts_only_matching_inbox_token`
  `api::tests::ack_is_scoped_to_receipt_inbox`
- `dedup / replay-like invariants`
  `db::tests::push_is_idempotent_while_message_exists`
  `db::tests::dedup_key_is_scoped_by_sender_and_escrow_and_seq`
- `quota / pressure`
  `api::tests::push_quota_returns_507`
  `api::tests::push_rate_limit_returns_429_with_retry_after`
  `tests::max_body_limit_rejects_oversized_push_request`
- `malformed input`
  `api::tests::push_rejects_malformed_envelope`
- `lease / recovery`
  `db::tests::lease_expiry_redelivers_message`
  `db::tests::restart_recovery_redelivers_leased_message_after_reopen`
  `db::tests::ttl_expiry_cleanup_deletes_message`
- `ack scope`
  `db::tests::ack_requires_matching_inbox_scope`
  `api::tests::ack_is_scoped_to_receipt_inbox`
- `mailbox-client <-> mailbox local adapter boundary`
  `tests::mailbox_client_smoke_roundtrip_against_real_mailbox_app`
  `tests::mailbox_client_fail_closed_on_wrong_pull_scope_against_real_mailbox_app`

## Real Gate For This Stage
Run at minimum:

```bash
cargo test -p nxms-mailbox smoke_push_pull_ack_roundtrip_via_api -- --nocapture
cargo test -p nxms-mailbox pull_rejects_unconfigured_inbox_even_with_valid_other_scope_token -- --nocapture
cargo test -p nxms-mailbox ack_is_scoped_to_receipt_inbox -- --nocapture
cargo test -p nxms-mailbox restart_recovery_redelivers_leased_message_after_reopen -- --nocapture
cargo test -p nxms-mailbox mailbox_client_smoke_roundtrip_against_real_mailbox_app -- --nocapture
cargo test -p nxms-mailbox mailbox_client_fail_closed_on_wrong_pull_scope_against_real_mailbox_app -- --nocapture
```

Preferred full mailbox gate:

```bash
cargo test -p nxms-mailbox -- --nocapture
```
