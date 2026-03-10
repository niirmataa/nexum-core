# NXMS Signer P0 Truth Test Matrix

Last update: 2026-03-10
Scope: `nxms-signer` truth-guarding tests for the canonical `nxms-transport -> nxms-mailbox -> nxms-signer` flow.

## Rule
- P0 behavior is not considered real unless it is covered by a concrete test.
- These tests guard current implementation truth, not wishful future behavior.
- Cross-host runtime model remains `nxms-transport` over Tor hidden service, with `nxms-mailbox` as relay/store-and-forward.
- Local `HTTP/axum` boundaries used in tests are only process-adapter checks on loopback.
- These tests prove signer integration with the real mailbox process API.
- These tests do not redefine runtime security; that remains `Tor + nxms-transport`.

## Current Dead-Letter Truth
- In signer runtime, unrecoverable pending approval failures terminate as `pending_tx_sign.status = failed_dead_letter`.
- Legacy rows with `status = error` are migrated to `failed_dead_letter` during DB init.
- Audit trail for this path remains `event_kind = decision_error` with `decision = dead_letter`.

## P0 Coverage
- `smoke`
  `agent::tests::smoke_process_then_approve_roundtrip`
- `sign`
  `agent::tests::approve_pending_happy_path_has_expected_side_effects`
  `agent::tests::sign_multisig_flow_duplicate_req_id_returns_cached_without_second_sign`
  `agent::tests::sign_multisig_flow_rejects_unexpected_recipient_before_wallet_sign`
- `submit`
  `agent::tests::submit_multisig_flow_duplicate_req_id_returns_cached_without_second_submit`
  `agent::tests::submit_multisig_flow_rejects_fee_cap_violation_before_wallet_submit`
  `agent::tests::submit_multisig_flow_rejects_unlock_time_violation_before_wallet_submit`
  `agent::tests::submit_multisig_flow_rejects_dummy_outputs_violation_before_wallet_submit`
  `agent::tests::submit_multisig_flow_rejects_when_arbiter_proof_does_not_match_local_event`
- `replay`
  `db::tests::replay_guard_rejects_equal_or_lower_seq`
  `agent::tests::process_envelope_rejects_out_of_order_seq_and_audits_replay`
- `duplicate req_id`
  `agent::tests::approve_pending_start_sign_request_failure_stops_before_consume_and_sign`
  `agent::tests::sign_multisig_flow_duplicate_req_id_returns_cached_without_second_sign`
  `agent::tests::submit_multisig_flow_duplicate_req_id_returns_cached_without_second_submit`
  `db::tests::sign_request_dedup_blocks_completed_duplicate`
- `out-of-order seq`
  `agent::tests::process_envelope_rejects_out_of_order_seq_and_audits_replay`
  `db::tests::out_seq_is_monotonic_per_scope`
- `dead-letter`
  `agent::tests::dead_letter_truth_uses_failed_dead_letter_status_and_decision_error_audit`
  `db::tests::init_migrates_pending_status_constraint_and_normalizes_approved`
- `restart / recovery`
  `agent::tests::approve_pending_retry_from_approved_sending_resends_without_resign`
  `agent::tests::approve_pending_retry_from_approved_sending_recovers_after_restart`
  `agent::tests::reject_pending_retry_from_rejected_sending_resends_with_staged_seq`
- `signer <-> mailbox local adapter boundary`
  `agent::tests::signer_delivers_approved_response_to_real_mailbox_app`
- `nxms-transport -> mailbox -> signer -> mailbox smoke`
  `agent::tests::transport_mailbox_signer_smoke_flow_uses_real_mailbox_app`
- `nxms-transport -> mailbox -> signer sign+submit smoke`
  `agent::tests::transport_sign_submit_smoke_flow_uses_real_mailbox_app`
- `workspace-level local adapter/component gate`
  `tests/e2e_transport_mailbox.rs::workspace_e2e_transport_mailbox_smoke_roundtrip`
  This test uses the real workspace crates and the real signer startup path.
  It is still a local boundary gate, not proof of cross-host Tor/onion deployment.
- `workspace-level sign+submit local adapter/component gate`
  `tests/e2e_sign_submit.rs::workspace_e2e_sign_submit_roundtrip`
  This test extends the same workspace boundary to the real submit path.
  It is still a local boundary gate, not proof of cross-host Tor/onion deployment.

## Real Gate For This Stage
Run at minimum:

```bash
cargo test -p nxms-signer smoke_process_then_approve_roundtrip -- --nocapture
cargo test -p nxms-signer process_envelope_rejects_out_of_order_seq_and_audits_replay -- --nocapture
cargo test -p nxms-signer dead_letter_truth_uses_failed_dead_letter_status_and_decision_error_audit -- --nocapture
cargo test -p nxms-signer approve_pending_retry_from_approved_sending_recovers_after_restart -- --nocapture
cargo test -p nxms-signer init_migrates_pending_status_constraint_and_normalizes_approved -- --nocapture
cargo test -p nxms-signer signer_delivers_approved_response_to_real_mailbox_app -- --nocapture
cargo test -p nxms-signer transport_mailbox_signer_smoke_flow_uses_real_mailbox_app -- --nocapture
cargo test -p nxms-signer transport_sign_submit_smoke_flow_uses_real_mailbox_app -- --nocapture
cargo test --test e2e_transport_mailbox -- --nocapture
cargo test --test e2e_sign_submit -- --nocapture
```

Preferred full signer gate:

```bash
cargo test -p nxms-signer -- --nocapture
```
