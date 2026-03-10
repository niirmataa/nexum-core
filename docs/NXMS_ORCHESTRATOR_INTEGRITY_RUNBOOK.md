# NXMS Orchestrator Integrity Runbook

Last update: 2026-02-18
Scope: periodic integrity verification of orchestrator DB records

## Goal
Detect DB drift/corruption/orphan rows before release/submit flow is affected.

## Command
```sh
nxms-escrow-orchestrator integrity check \
  --db-path /var/lib/nxms/orchestrator.db \
  --limit 500 \
  --fail-on-findings
```

## Output
- JSON array of findings:
  - `table`
  - `escrow_id_hex`
  - `issue`
  - `detail`

## Current Integrity Rules
- `workflow_instances`
  - `escrow_id_hex` must be 32 hex chars.
  - `snapshot_hash_hex` must be 64 hex chars.
  - `participants_json` must parse and contain non-empty unique participants.
- `proposal_blobs`
  - must reference existing workflow (`orphan_workflow` check),
  - `tx_data_hex` must be non-empty even-length hex,
  - `txset_hash_hex` must be 64 hex chars.
- `worker_routes`
  - must reference existing workflow,
  - endpoint must be non-empty normalized URL-like value.
- `quorum_sign_proofs`
  - must reference existing workflow,
  - `txset_hash_hex` and `req_id` must be 64 hex chars,
  - `jti` must be non-empty and bounded.
- `submission_watch`
  - must reference existing workflow,
  - `txid` must be 64 hex chars,
  - `required_confirmations` must be > 0,
  - `confirmed` status must satisfy `last_confirmations >= required_confirmations`.

## Scheduling
- Recommended: run every 5 minutes in production.
- Recommended: run before canary/full rollout transitions.

## On-Call Actions
1. `orphan_workflow`
- Freeze affected escrow IDs.
- Reconstruct expected workflow lineage from signer/orchestrator logs.
- Reinsert missing workflow row or quarantine orphan row after review.

2. `invalid_tx_data_hex` / `invalid_txset_hash` / `invalid_req_id`
- Treat as data-integrity incident.
- Block submit path for affected escrow IDs.
- Regenerate proposal/proof via trusted signer path.

3. `invalid_txid` / `invalid_required_confirmations`
- Disable watch-based confirmation transitions for affected escrow IDs.
- Repair submission_watch row from canonical tx source.

4. High finding count burst
- Escalate to incident channel immediately.
- Capture DB snapshot and service logs before remediation.
