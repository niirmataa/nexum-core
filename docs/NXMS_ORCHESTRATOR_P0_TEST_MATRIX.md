# NXMS Orchestrator P0 Truth Test Matrix

Last update: 2026-03-10
Scope: `nxms-escrow-orchestrator` truth-guarding tests for the canonical control-plane and workflow state.

## Rule
- P0 orchestrator behavior is not considered real unless a concrete test covers it.
- Orchestrator is control-plane only. It must not silently recreate runtime execution paths.
- Cross-host runtime security still belongs to `Tor + nxms-transport`; these tests guard workflow truth, action-token issuance and control-plane invariants.
- Local DB and workspace tests here prove control-plane correctness, not cross-host Tor/onion deployment.
- Dead letters must represent real delivery or workflow failures, not normal workflow progress notes.

## Runtime Truths Guarded Here
- Workflow transitions must follow the frozen state machine only.
- Step idempotency and inbox offsets must reject replay and out-of-order progress.
- Proposal blobs and quorum proofs must be bound to the correct workflow state and txset hash.
- Submit action tokens must be issued from real orchestrator state, not ad-hoc input detached from quorum proof truth.
- Dead-letter metrics must reflect real failure pressure, not routine transitions.
- Integrity and SLO reports must expose real corruption/pressure signals.

## P0 Coverage
- `workflow state machine`
  `flow::tests::state_machine_allows_only_frozen_path`
  `db::tests::workflow_creation_and_transition`
  `db::tests::record_step_rejects_workflow_state_jump`
- `replay / out-of-order`
  `flow::tests::idem_key_is_stable`
  `db::tests::step_idempotency_duplicate_is_replay`
  `db::tests::inbox_offset_rejects_reset`
- `proposal / quorum proof truth`
  `db::tests::proposal_blob_roundtrip`
  `db::tests::proposal_blob_rejects_non_funded_state`
  `db::tests::quorum_sign_proof_roundtrip`
  `db::tests::quorum_sign_proof_rejects_invalid_req_id`
  `db::tests::quorum_sign_proof_rejects_without_workflow`
  `db::tests::quorum_sign_proof_rejects_role_round_mismatch`
  `db::tests::submit_multisig_proof_bundle_roundtrip`
  `db::tests::submit_multisig_proof_bundle_rejects_missing_seller_proof`
- `action token issuance`
  `action_token::tests::issue_sign_multisig_token_from_db_state`
  `action_token::tests::issue_submit_multisig_token_includes_quorum_proofs`
  `action_token::tests::read_private_key_rejects_symlink_path`
  `action_token::tests::build_issue_params_rejects_ttl_over_hard_limit`
- `delivery pressure / dead-letter truth`
  `db::tests::outbox_lifecycle_sent_retry_acked`
  `db::tests::outbox_retry_dead_letters_and_records_error`
  `db::tests::transition_reason_is_not_recorded_as_dead_letter`
  `db::tests::delivery_guarantee_report_tracks_stale_sent_and_dedup_proof`
  `db::tests::slo_metrics_and_alerts_capture_operational_pressure`
- `integrity`
  `db::tests::integrity_check_reports_orphan_and_invalid_rows`
- `workspace-level orchestrated control-plane gate`
  `tests/e2e_orchestrated_flow.rs::workspace_e2e_orchestrated_flow_issues_submit_token_from_control_plane`
  This test proves that real orchestrator control-plane state can issue a real submit token accepted by the signer runtime.
  It also proves that normal workflow progress does not poison dead-letter truth.
  It is still a local component/control-plane gate, not proof of cross-host Tor/onion deployment.

## Real Gate For This Stage
Run at minimum:

```bash
cargo test -p nxms-escrow-orchestrator workflow_creation_and_transition -- --nocapture
cargo test -p nxms-escrow-orchestrator step_idempotency_duplicate_is_replay -- --nocapture
cargo test -p nxms-escrow-orchestrator proposal_blob_roundtrip -- --nocapture
cargo test -p nxms-escrow-orchestrator submit_multisig_proof_bundle_roundtrip -- --nocapture
cargo test -p nxms-escrow-orchestrator issue_submit_multisig_token_includes_quorum_proofs -- --nocapture
cargo test -p nxms-escrow-orchestrator transition_reason_is_not_recorded_as_dead_letter -- --nocapture
cargo test -p nxms-escrow-orchestrator integrity_check_reports_orphan_and_invalid_rows -- --nocapture
cargo test --test e2e_orchestrated_flow -- --nocapture
```

Preferred full orchestrator gate:

```bash
cargo test -p nxms-escrow-orchestrator -- --nocapture
```
