use crate::flow::{WorkflowState, expected_msg_type_for_state, outbox_idem_key, step_idem_key};
use anyhow::{Result, anyhow};
use rusqlite::{Connection, ErrorCode, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct OrchestratorDb {
    path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowInstance {
    pub escrow_id_hex: String,
    pub state: WorkflowState,
    pub snapshot_hash_hex: String,
    pub participants: Vec<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepInput {
    pub escrow_id_hex: String,
    pub state: WorkflowState,
    pub from_id: String,
    pub seq: u64,
    pub msg_type: String,
    pub payload_hash_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StepOutcome {
    Accepted,
    ReplayDuplicate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboxInput {
    pub escrow_id_hex: String,
    pub state: WorkflowState,
    pub to_id: String,
    pub msg_type: String,
    pub envelope_json: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboxItem {
    pub id: i64,
    pub escrow_id_hex: String,
    pub state: WorkflowState,
    pub to_id: String,
    pub msg_type: String,
    pub envelope_json: String,
    pub idem_key: String,
    pub status: String,
    pub attempts: u32,
    pub next_attempt_at_ms: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryGuaranteeReport {
    pub generated_at_ms: u64,
    pub window_ms: u64,
    pub sent_stale_ms: u64,
    pub outbox_pending: u64,
    pub outbox_sent: u64,
    pub outbox_acked: u64,
    pub outbox_dead_letter: u64,
    pub outbox_retrying: u64,
    pub outbox_sent_stale: u64,
    pub step_accepted_window: u64,
    pub step_replay_duplicate_window: u64,
    pub idem_payload_conflict_window: u64,
    pub duplicate_step_idem_keys: u64,
    pub duplicate_outbox_idem_keys: u64,
    pub inbox_offsets_total: u64,
    pub dedup_proof_ok: bool,
    pub findings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeadLetterItem {
    pub id: i64,
    pub escrow_id_hex: String,
    pub stage: String,
    pub last_error_code: String,
    pub last_error_detail_redacted: String,
    pub attempts: u32,
    pub payload_hash_hex: Option<String>,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalBlob {
    pub escrow_id_hex: String,
    pub action: String,
    pub tx_data_hex: String,
    pub txset_hash_hex: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumSignProof {
    pub escrow_id_hex: String,
    pub role: String,
    pub sign_round: String,
    pub txset_hash_hex: String,
    pub jti: String,
    pub req_id: String,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitMultisigProofBundle {
    pub escrow_id_hex: String,
    pub txset_hash_hex: String,
    pub proof_arbiter_jti: String,
    pub proof_arbiter_req_id: String,
    pub proof_seller_jti: String,
    pub proof_seller_req_id: String,
    pub arbiter_proof_updated_at_ms: u64,
    pub seller_proof_updated_at_ms: u64,
    pub generated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntegrityFinding {
    pub table: String,
    pub escrow_id_hex: Option<String>,
    pub issue: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WorkflowSloStageLatency {
    pub count: u64,
    pub avg_age_ms: u64,
    pub max_age_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowSloMetrics {
    pub generated_at_ms: u64,
    pub window_ms: u64,
    pub stuck_after_ms: u64,
    pub workflows_total: u64,
    pub workflows_active: u64,
    pub workflows_stuck: u64,
    pub active_workflow_avg_age_ms: u64,
    pub active_workflow_max_age_ms: u64,
    pub outbox_pending: u64,
    pub outbox_sent_unacked: u64,
    pub outbox_dead_letter: u64,
    pub outbox_retrying: u64,
    pub step_replay_duplicate_window: u64,
    pub dead_letter_window: u64,
    pub stage_latency: BTreeMap<String, WorkflowSloStageLatency>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SloAlertThresholds {
    pub workflows_stuck_total: u64,
    pub active_workflow_max_age_ms: u64,
    pub outbox_pending_total: u64,
    pub outbox_sent_unacked_total: u64,
    pub dead_letter_window_total: u64,
    pub replay_duplicate_window_total: u64,
}

impl Default for SloAlertThresholds {
    fn default() -> Self {
        Self {
            workflows_stuck_total: 0,
            active_workflow_max_age_ms: 900_000,
            outbox_pending_total: 250,
            outbox_sent_unacked_total: 50,
            dead_letter_window_total: 0,
            replay_duplicate_window_total: 25,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SloAlertItem {
    pub metric: String,
    pub observed: u64,
    pub threshold: u64,
    pub severity: String,
    pub action: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SloAlertReport {
    pub generated_at_ms: u64,
    pub metrics: WorkflowSloMetrics,
    pub thresholds: SloAlertThresholds,
    pub alerts: Vec<SloAlertItem>,
    pub ok: bool,
}

impl OrchestratorDb {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub async fn init(&self) -> Result<()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || init_sync(&path)).await??;
        Ok(())
    }

    pub async fn create_workflow(
        &self,
        escrow_id_hex: &str,
        snapshot_hash_hex: &str,
        participants: &[String],
    ) -> Result<()> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        let snapshot_hash_hex = snapshot_hash_hex.to_string();
        let participants = participants.to_vec();
        tokio::task::spawn_blocking(move || {
            create_workflow_sync(&path, &escrow_id_hex, &snapshot_hash_hex, &participants)
        })
        .await??;
        Ok(())
    }

    pub async fn transition_workflow(
        &self,
        escrow_id_hex: &str,
        to_state: WorkflowState,
        reason: Option<&str>,
    ) -> Result<()> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        let reason = reason.map(ToOwned::to_owned);
        tokio::task::spawn_blocking(move || {
            transition_workflow_sync(&path, &escrow_id_hex, to_state, reason.as_deref())
        })
        .await??;
        Ok(())
    }

    pub async fn record_step(&self, input: StepInput) -> Result<StepOutcome> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || record_step_sync(&path, &input)).await?
    }

    pub async fn enqueue_outbox(&self, input: OutboxInput) -> Result<()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || enqueue_outbox_sync(&path, &input)).await??;
        Ok(())
    }

    pub async fn list_outbox(&self, status: Option<&str>, limit: u32) -> Result<Vec<OutboxItem>> {
        let path = self.path.clone();
        let status = status.map(ToOwned::to_owned);
        tokio::task::spawn_blocking(move || list_outbox_sync(&path, status.as_deref(), limit))
            .await?
    }

    pub async fn mark_outbox_sent(&self, id: i64) -> Result<()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || mark_outbox_sent_sync(&path, id)).await??;
        Ok(())
    }

    pub async fn mark_outbox_acked(&self, id: i64) -> Result<()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || mark_outbox_acked_sync(&path, id)).await??;
        Ok(())
    }

    pub async fn mark_outbox_retry(
        &self,
        id: i64,
        backoff_ms: u64,
        error_code: &str,
        error_detail_redacted: &str,
        dead_letter_after_attempts: u32,
    ) -> Result<()> {
        let path = self.path.clone();
        let error_code = error_code.to_string();
        let error_detail_redacted = error_detail_redacted.to_string();
        tokio::task::spawn_blocking(move || {
            mark_outbox_retry_sync(
                &path,
                id,
                backoff_ms,
                &error_code,
                &error_detail_redacted,
                dead_letter_after_attempts,
            )
        })
        .await??;
        Ok(())
    }

    pub async fn advance_inbox_offset(
        &self,
        peer_id: &str,
        escrow_id_hex: &str,
        seq: u64,
    ) -> Result<()> {
        let path = self.path.clone();
        let peer_id = peer_id.to_string();
        let escrow_id_hex = escrow_id_hex.to_string();
        tokio::task::spawn_blocking(move || {
            advance_inbox_offset_sync(&path, &peer_id, &escrow_id_hex, seq)
        })
        .await??;
        Ok(())
    }

    pub async fn add_dead_letter(
        &self,
        escrow_id_hex: &str,
        stage: &str,
        last_error_code: &str,
        last_error_detail_redacted: &str,
        attempts: u32,
        payload_hash_hex: Option<&str>,
    ) -> Result<()> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        let stage = stage.to_string();
        let last_error_code = last_error_code.to_string();
        let last_error_detail_redacted = last_error_detail_redacted.to_string();
        let payload_hash_hex = payload_hash_hex.map(ToOwned::to_owned);
        tokio::task::spawn_blocking(move || {
            add_dead_letter_sync(
                &path,
                &escrow_id_hex,
                &stage,
                &last_error_code,
                &last_error_detail_redacted,
                attempts,
                payload_hash_hex.as_deref(),
            )
        })
        .await??;
        Ok(())
    }

    pub async fn list_dead_letters(&self, limit: u32) -> Result<Vec<DeadLetterItem>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || list_dead_letters_sync(&path, limit)).await?
    }

    pub async fn list_workflows(&self, limit: u32) -> Result<Vec<WorkflowInstance>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || list_workflows_sync(&path, limit)).await?
    }

    pub async fn step_count_for_state(
        &self,
        escrow_id_hex: &str,
        state: WorkflowState,
    ) -> Result<u64> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        tokio::task::spawn_blocking(move || step_count_for_state_sync(&path, &escrow_id_hex, state))
            .await?
    }

    pub async fn get_workflow(&self, escrow_id_hex: &str) -> Result<Option<WorkflowInstance>> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        tokio::task::spawn_blocking(move || get_workflow_sync(&path, &escrow_id_hex)).await?
    }

    pub async fn upsert_proposal_blob(
        &self,
        escrow_id_hex: &str,
        action: &str,
        tx_data_hex: &str,
        txset_hash_hex: &str,
    ) -> Result<()> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        let action = action.to_string();
        let tx_data_hex = tx_data_hex.to_string();
        let txset_hash_hex = txset_hash_hex.to_string();
        tokio::task::spawn_blocking(move || {
            upsert_proposal_blob_sync(
                &path,
                &escrow_id_hex,
                &action,
                &tx_data_hex,
                &txset_hash_hex,
            )
        })
        .await??;
        Ok(())
    }

    pub async fn get_proposal_blob(&self, escrow_id_hex: &str) -> Result<Option<ProposalBlob>> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        tokio::task::spawn_blocking(move || get_proposal_blob_sync(&path, &escrow_id_hex)).await?
    }

    pub async fn get_proposal_blob_by_txset_hash(
        &self,
        escrow_id_hex: &str,
        txset_hash_hex: &str,
    ) -> Result<Option<ProposalBlob>> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        let txset_hash_hex = txset_hash_hex.to_string();
        tokio::task::spawn_blocking(move || {
            get_proposal_blob_by_txset_hash_sync(&path, &escrow_id_hex, &txset_hash_hex)
        })
        .await?
    }

    pub async fn upsert_quorum_sign_proof(
        &self,
        escrow_id_hex: &str,
        role: &str,
        sign_round: &str,
        txset_hash_hex: &str,
        jti: &str,
        req_id: &str,
    ) -> Result<()> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        let role = role.to_string();
        let sign_round = sign_round.to_string();
        let txset_hash_hex = txset_hash_hex.to_string();
        let jti = jti.to_string();
        let req_id = req_id.to_string();
        tokio::task::spawn_blocking(move || {
            upsert_quorum_sign_proof_sync(
                &path,
                &escrow_id_hex,
                &role,
                &sign_round,
                &txset_hash_hex,
                &jti,
                &req_id,
            )
        })
        .await??;
        Ok(())
    }

    pub async fn get_quorum_sign_proof(
        &self,
        escrow_id_hex: &str,
        role: &str,
        sign_round: &str,
        txset_hash_hex: &str,
    ) -> Result<Option<QuorumSignProof>> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        let role = role.to_string();
        let sign_round = sign_round.to_string();
        let txset_hash_hex = txset_hash_hex.to_string();
        tokio::task::spawn_blocking(move || {
            get_quorum_sign_proof_sync(&path, &escrow_id_hex, &role, &sign_round, &txset_hash_hex)
        })
        .await?
    }

    pub async fn get_submit_multisig_proof_bundle(
        &self,
        escrow_id_hex: &str,
        txset_hash_hex: &str,
    ) -> Result<SubmitMultisigProofBundle> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        let txset_hash_hex = txset_hash_hex.to_string();
        tokio::task::spawn_blocking(move || {
            get_submit_multisig_proof_bundle_sync(&path, &escrow_id_hex, &txset_hash_hex)
        })
        .await?
    }

    pub async fn check_integrity(&self, limit: u32) -> Result<Vec<IntegrityFinding>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || integrity_check_sync(&path, limit)).await?
    }

    pub async fn delivery_guarantee_report(
        &self,
        window_ms: u64,
        sent_stale_ms: u64,
    ) -> Result<DeliveryGuaranteeReport> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            delivery_guarantee_report_sync(&path, window_ms, sent_stale_ms)
        })
        .await?
    }

    pub async fn slo_metrics(
        &self,
        window_ms: u64,
        stuck_after_ms: u64,
    ) -> Result<WorkflowSloMetrics> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || slo_metrics_sync(&path, window_ms, stuck_after_ms))
            .await?
    }

    pub async fn slo_alert_report(
        &self,
        window_ms: u64,
        stuck_after_ms: u64,
        thresholds: SloAlertThresholds,
    ) -> Result<SloAlertReport> {
        let metrics = self.slo_metrics(window_ms, stuck_after_ms).await?;
        Ok(build_slo_alert_report(metrics, thresholds))
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn open(path: &PathBuf) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

fn init_sync(path: &PathBuf) -> Result<()> {
    let conn = open(path)?;
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = MEMORY;

        CREATE TABLE IF NOT EXISTS workflow_instances (
            escrow_id_hex        TEXT PRIMARY KEY,
            state                TEXT NOT NULL,
            snapshot_hash_hex    TEXT NOT NULL,
            participants_json    TEXT NOT NULL,
            created_at_ms        INTEGER NOT NULL,
            updated_at_ms        INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS workflow_steps (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            escrow_id_hex        TEXT NOT NULL,
            state                TEXT NOT NULL,
            from_id              TEXT NOT NULL,
            seq                  INTEGER NOT NULL,
            msg_type             TEXT NOT NULL,
            idem_key             TEXT NOT NULL UNIQUE,
            payload_hash_hex     TEXT NOT NULL,
            status               TEXT NOT NULL CHECK(status IN ('accepted', 'replay_duplicate')),
            detail               TEXT,
            created_at_ms        INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_workflow_steps_escrow ON workflow_steps(escrow_id_hex, id);

        CREATE TABLE IF NOT EXISTS outbox (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            escrow_id_hex        TEXT NOT NULL,
            state                TEXT NOT NULL,
            to_id                TEXT NOT NULL,
            msg_type             TEXT NOT NULL,
            envelope_json        TEXT NOT NULL,
            idem_key             TEXT NOT NULL UNIQUE,
            status               TEXT NOT NULL CHECK(status IN ('pending', 'sent', 'acked', 'dead_letter')),
            attempts             INTEGER NOT NULL,
            next_attempt_at_ms   INTEGER NOT NULL,
            created_at_ms        INTEGER NOT NULL,
            updated_at_ms        INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_outbox_status_next ON outbox(status, next_attempt_at_ms);

        CREATE TABLE IF NOT EXISTS inbox_offsets (
            peer_id              TEXT NOT NULL,
            escrow_id_hex        TEXT NOT NULL,
            last_seq             INTEGER NOT NULL,
            updated_at_ms        INTEGER NOT NULL,
            PRIMARY KEY (peer_id, escrow_id_hex)
        );

        CREATE TABLE IF NOT EXISTS proposal_blobs (
            escrow_id_hex        TEXT PRIMARY KEY,
            action               TEXT NOT NULL CHECK(action IN ('release', 'refund')),
            tx_data_hex          TEXT NOT NULL,
            txset_hash_hex       TEXT NOT NULL,
            created_at_ms        INTEGER NOT NULL,
            updated_at_ms        INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_proposal_blobs_hash ON proposal_blobs(txset_hash_hex, updated_at_ms);

        CREATE TABLE IF NOT EXISTS quorum_sign_proofs (
            escrow_id_hex        TEXT NOT NULL,
            role                 TEXT NOT NULL CHECK(role IN ('buyer', 'seller', 'arbiter')),
            sign_round           TEXT NOT NULL,
            txset_hash_hex       TEXT NOT NULL,
            jti                  TEXT NOT NULL,
            req_id               TEXT NOT NULL,
            updated_at_ms        INTEGER NOT NULL,
            PRIMARY KEY (escrow_id_hex, role, sign_round, txset_hash_hex),
            UNIQUE(req_id)
        );
        CREATE INDEX IF NOT EXISTS idx_quorum_sign_proofs_lookup
            ON quorum_sign_proofs(escrow_id_hex, txset_hash_hex, role, sign_round, updated_at_ms DESC);

        CREATE TABLE IF NOT EXISTS dead_letters (
            id                         INTEGER PRIMARY KEY AUTOINCREMENT,
            escrow_id_hex              TEXT NOT NULL,
            stage                      TEXT NOT NULL,
            last_error_code            TEXT NOT NULL,
            last_error_detail_redacted TEXT NOT NULL,
            attempts                   INTEGER NOT NULL,
            payload_hash_hex           TEXT,
            created_at_ms              INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_dead_letters_escrow ON dead_letters(escrow_id_hex, id);
        "#,
    )?;
    Ok(())
}

fn create_workflow_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    snapshot_hash_hex: &str,
    participants: &[String],
) -> Result<()> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let snapshot_hash_hex = normalize_hex_exact(snapshot_hash_hex, 64, "snapshot_hash_hex")?;
    let participants = normalize_participants(participants)?;
    let conn = open(path)?;
    let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    let state = WorkflowState::New.as_str();
    let participants_json = serde_json::to_string(&participants)?;
    conn.execute(
        r#"
        INSERT INTO workflow_instances(
            escrow_id_hex, state, snapshot_hash_hex, participants_json, created_at_ms, updated_at_ms
        ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)
        "#,
        params![
            escrow_id_hex,
            state,
            snapshot_hash_hex,
            participants_json,
            now,
            now
        ],
    )?;
    Ok(())
}

fn transition_workflow_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    to_state: WorkflowState,
    reason: Option<&str>,
) -> Result<()> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let mut conn = open(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let wf = get_workflow_tx(&tx, &escrow_id_hex)?
        .ok_or_else(|| anyhow!("workflow not found for escrow_id_hex={escrow_id_hex}"))?;
    if !wf.state.can_transition_to(to_state) {
        return Err(anyhow!(
            "invalid workflow transition: {:?} -> {:?}",
            wf.state,
            to_state
        ));
    }
    let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    tx.execute(
        "UPDATE workflow_instances SET state=?1, updated_at_ms=?2 WHERE escrow_id_hex=?3",
        params![to_state.as_str(), now, &escrow_id_hex],
    )?;
    let _ = reason;
    tx.commit()?;
    Ok(())
}

fn record_step_sync(path: &PathBuf, input: &StepInput) -> Result<StepOutcome> {
    let escrow_id_hex = normalize_hex_exact(&input.escrow_id_hex, 32, "escrow_id_hex")?;
    let from_id = normalize_non_empty(&input.from_id, "from_id")?;
    let msg_type = normalize_non_empty(&input.msg_type, "msg_type")?;
    let payload_hash_hex = normalize_hex_exact(&input.payload_hash_hex, 64, "payload_hash_hex")?;
    let mut conn = open(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let wf = get_workflow_tx(&tx, &escrow_id_hex)?
        .ok_or_else(|| anyhow!("workflow not found for escrow_id_hex={}", escrow_id_hex))?;

    // Strict peer allowlist + escrow binding check.
    if !wf.participants.iter().any(|p| p == &from_id) {
        return Err(anyhow!(
            "from_id '{}' is not allowlisted for escrow '{}'",
            from_id,
            escrow_id_hex
        ));
    }

    if wf.state != input.state && !wf.state.can_transition_to(input.state) {
        return Err(anyhow!(
            "workflow precondition failed: current state {:?} does not allow step state {:?}",
            wf.state,
            input.state
        ));
    }

    if let Some(expected_msg_type) = expected_msg_type_for_state(input.state)
        && expected_msg_type != msg_type
    {
        return Err(anyhow!(
            "state {:?} expects msg_type '{}', got '{}'",
            input.state,
            expected_msg_type,
            msg_type
        ));
    }

    let idem_key = step_idem_key(&escrow_id_hex, input.state, &from_id, input.seq);
    let existing: Option<String> = tx
        .query_row(
            "SELECT payload_hash_hex FROM workflow_steps WHERE idem_key=?1",
            params![&idem_key],
            |row| row.get(0),
        )
        .optional()?;
    match existing {
        Some(hash) if hash.eq_ignore_ascii_case(&payload_hash_hex) => {
            tx.commit()?;
            return Ok(StepOutcome::ReplayDuplicate);
        }
        Some(_) => {
            add_dead_letter_tx(
                &tx,
                &escrow_id_hex,
                "step_record",
                "idem_payload_conflict",
                "same idempotency key with different payload hash",
                1,
                Some(&payload_hash_hex),
            )?;
            tx.commit()?;
            return Err(anyhow!(
                "idempotency conflict for escrow={} from={} seq={}",
                escrow_id_hex,
                from_id,
                input.seq
            ));
        }
        None => {}
    }

    tx.execute(
        r#"
        INSERT INTO workflow_steps(
            escrow_id_hex, state, from_id, seq, msg_type, idem_key, payload_hash_hex, status, detail, created_at_ms
        ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, 'accepted', NULL, ?8)
        "#,
        params![
            escrow_id_hex,
            input.state.as_str(),
            from_id,
            i64::try_from(input.seq).unwrap_or(i64::MAX),
            msg_type,
            idem_key,
            payload_hash_hex,
            i64::try_from(now_ms()).unwrap_or(i64::MAX)
        ],
    )?;
    tx.commit()?;
    Ok(StepOutcome::Accepted)
}

fn enqueue_outbox_sync(path: &PathBuf, input: &OutboxInput) -> Result<()> {
    let escrow_id_hex = normalize_hex_exact(&input.escrow_id_hex, 32, "escrow_id_hex")?;
    let to_id = normalize_non_empty(&input.to_id, "to_id")?;
    let msg_type = normalize_non_empty(&input.msg_type, "msg_type")?;
    let mut conn = open(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let wf = get_workflow_tx(&tx, &escrow_id_hex)?
        .ok_or_else(|| anyhow!("workflow not found for escrow_id_hex={}", escrow_id_hex))?;
    if !wf.participants.iter().any(|p| p == &to_id) {
        return Err(anyhow!(
            "to_id '{}' is not allowlisted for escrow '{}'",
            to_id,
            escrow_id_hex
        ));
    }
    if wf.state != input.state && !wf.state.can_transition_to(input.state) {
        return Err(anyhow!(
            "workflow precondition failed: current state {:?} does not allow outbox state {:?}",
            wf.state,
            input.state
        ));
    }
    if let Some(expected_msg_type) = expected_msg_type_for_state(input.state)
        && expected_msg_type != msg_type
    {
        return Err(anyhow!(
            "state {:?} expects msg_type '{}', got '{}'",
            input.state,
            expected_msg_type,
            msg_type
        ));
    }
    let payload_hash_hex = sha3_hex(input.envelope_json.as_bytes());
    let idem_key = outbox_idem_key(
        &escrow_id_hex,
        input.state,
        &to_id,
        &msg_type,
        &payload_hash_hex,
    );
    let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    let insert_res = tx.execute(
        r#"
        INSERT INTO outbox(
            escrow_id_hex, state, to_id, msg_type, envelope_json, idem_key,
            status, attempts, next_attempt_at_ms, created_at_ms, updated_at_ms
        ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'pending', 0, ?7, ?8, ?9)
        "#,
        params![
            escrow_id_hex,
            input.state.as_str(),
            to_id,
            msg_type,
            input.envelope_json,
            idem_key,
            now,
            now,
            now
        ],
    );
    match insert_res {
        Ok(_) => {
            tx.commit()?;
            Ok(())
        }
        Err(err) if is_unique_violation(&err) => {
            tx.commit()?;
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

fn list_outbox_sync(path: &PathBuf, status: Option<&str>, limit: u32) -> Result<Vec<OutboxItem>> {
    let conn = open(path)?;
    let mut out: Vec<OutboxItem> = Vec::new();
    let limit_i64 = i64::from(limit.max(1).min(5000));
    if let Some(status) = status.map(str::trim).filter(|v| !v.is_empty()) {
        let status = normalize_outbox_status(status)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, escrow_id_hex, state, to_id, msg_type, envelope_json, idem_key,
                   status, attempts, next_attempt_at_ms, created_at_ms, updated_at_ms
            FROM outbox
            WHERE status=?1
            ORDER BY id DESC
            LIMIT ?2
            "#,
        )?;
        let mut rows = stmt.query(params![status, limit_i64])?;
        while let Some(row) = rows.next()? {
            out.push(row_to_outbox(row)?);
        }
        return Ok(out);
    }

    let mut stmt = conn.prepare(
        r#"
        SELECT id, escrow_id_hex, state, to_id, msg_type, envelope_json, idem_key,
               status, attempts, next_attempt_at_ms, created_at_ms, updated_at_ms
        FROM outbox
        ORDER BY id DESC
        LIMIT ?1
        "#,
    )?;
    let mut rows = stmt.query(params![limit_i64])?;
    while let Some(row) = rows.next()? {
        out.push(row_to_outbox(row)?);
    }
    Ok(out)
}

fn mark_outbox_sent_sync(path: &PathBuf, id: i64) -> Result<()> {
    if id <= 0 {
        return Err(anyhow!("outbox id must be > 0"));
    }
    let conn = open(path)?;
    let n = conn.execute(
        r#"
        UPDATE outbox
        SET status='sent',
            attempts=attempts + 1,
            updated_at_ms=?1
        WHERE id=?2 AND status IN ('pending', 'sent')
        "#,
        params![i64::try_from(now_ms()).unwrap_or(i64::MAX), id],
    )?;
    if n == 0 {
        return Err(anyhow!(
            "outbox row {} not found or not in pending/sent state",
            id
        ));
    }
    Ok(())
}

fn mark_outbox_acked_sync(path: &PathBuf, id: i64) -> Result<()> {
    if id <= 0 {
        return Err(anyhow!("outbox id must be > 0"));
    }
    let conn = open(path)?;
    let n = conn.execute(
        r#"
        UPDATE outbox
        SET status='acked',
            updated_at_ms=?1
        WHERE id=?2 AND status IN ('pending', 'sent')
        "#,
        params![i64::try_from(now_ms()).unwrap_or(i64::MAX), id],
    )?;
    if n == 0 {
        return Err(anyhow!(
            "outbox row {} not found or not in pending/sent state",
            id
        ));
    }
    Ok(())
}

fn mark_outbox_retry_sync(
    path: &PathBuf,
    id: i64,
    backoff_ms: u64,
    error_code: &str,
    error_detail_redacted: &str,
    dead_letter_after_attempts: u32,
) -> Result<()> {
    if id <= 0 {
        return Err(anyhow!("outbox id must be > 0"));
    }
    let error_code = normalize_non_empty(error_code, "error_code")?;
    let error_detail_redacted =
        normalize_non_empty(error_detail_redacted, "error_detail_redacted")?;
    let dead_letter_after_attempts = dead_letter_after_attempts.max(1);
    let backoff_ms = backoff_ms.max(100);

    let mut conn = open(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(String, String, i64, String)> = tx
        .query_row(
            r#"
            SELECT escrow_id_hex, status, attempts, envelope_json
            FROM outbox
            WHERE id=?1
            "#,
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((escrow_id_hex, status, attempts, envelope_json)) = row else {
        return Err(anyhow!("outbox row {} not found", id));
    };
    if status == "acked" || status == "dead_letter" {
        return Err(anyhow!(
            "outbox row {} is in terminal state '{}'",
            id,
            status
        ));
    }

    let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    let next_attempt_at_ms = now.saturating_add(i64::try_from(backoff_ms).unwrap_or(i64::MAX));
    let next_attempts = attempts.saturating_add(1);
    let payload_hash_hex = sha3_hex(envelope_json.as_bytes());
    if next_attempts >= i64::from(dead_letter_after_attempts) {
        tx.execute(
            r#"
            UPDATE outbox
            SET status='dead_letter',
                attempts=?1,
                next_attempt_at_ms=?2,
                updated_at_ms=?3
            WHERE id=?4
            "#,
            params![next_attempts, next_attempt_at_ms, now, id],
        )?;
        add_dead_letter_tx(
            &tx,
            &escrow_id_hex,
            "outbox_delivery",
            &error_code,
            &error_detail_redacted,
            u32::try_from(next_attempts).unwrap_or(u32::MAX),
            Some(&payload_hash_hex),
        )?;
        tx.commit()?;
        return Ok(());
    }

    tx.execute(
        r#"
        UPDATE outbox
        SET status='pending',
            attempts=?1,
            next_attempt_at_ms=?2,
            updated_at_ms=?3
        WHERE id=?4
        "#,
        params![next_attempts, next_attempt_at_ms, now, id],
    )?;
    tx.commit()?;
    Ok(())
}

fn advance_inbox_offset_sync(
    path: &PathBuf,
    peer_id: &str,
    escrow_id_hex: &str,
    seq: u64,
) -> Result<()> {
    let peer_id = normalize_non_empty(peer_id, "peer_id")?;
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let mut conn = open(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current: Option<i64> = tx
        .query_row(
            "SELECT last_seq FROM inbox_offsets WHERE peer_id=?1 AND escrow_id_hex=?2",
            params![&peer_id, &escrow_id_hex],
            |row| row.get(0),
        )
        .optional()?;
    let seq_i64 = i64::try_from(seq).unwrap_or(i64::MAX);
    if let Some(current) = current
        && seq_i64 <= current
    {
        return Err(anyhow!(
            "inbox offset replay/reset for peer={} escrow={} seq={} <= {}",
            peer_id,
            escrow_id_hex,
            seq_i64,
            current
        ));
    }
    tx.execute(
        r#"
        INSERT INTO inbox_offsets(peer_id, escrow_id_hex, last_seq, updated_at_ms)
        VALUES(?1, ?2, ?3, ?4)
        ON CONFLICT(peer_id, escrow_id_hex) DO UPDATE SET
            last_seq=excluded.last_seq,
            updated_at_ms=excluded.updated_at_ms
        "#,
        params![
            &peer_id,
            &escrow_id_hex,
            seq_i64,
            i64::try_from(now_ms()).unwrap_or(i64::MAX)
        ],
    )?;
    tx.commit()?;
    Ok(())
}

fn add_dead_letter_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    stage: &str,
    last_error_code: &str,
    last_error_detail_redacted: &str,
    attempts: u32,
    payload_hash_hex: Option<&str>,
) -> Result<()> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let conn = open(path)?;
    add_dead_letter_tx(
        &conn,
        &escrow_id_hex,
        stage,
        last_error_code,
        last_error_detail_redacted,
        attempts,
        payload_hash_hex,
    )
}

fn add_dead_letter_tx(
    conn: &Connection,
    escrow_id_hex: &str,
    stage: &str,
    last_error_code: &str,
    last_error_detail_redacted: &str,
    attempts: u32,
    payload_hash_hex: Option<&str>,
) -> Result<()> {
    conn.execute(
        r#"
        INSERT INTO dead_letters(
            escrow_id_hex, stage, last_error_code, last_error_detail_redacted, attempts, payload_hash_hex, created_at_ms
        ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
        params![
            escrow_id_hex,
            stage,
            last_error_code,
            last_error_detail_redacted,
            i64::from(attempts),
            payload_hash_hex,
            i64::try_from(now_ms()).unwrap_or(i64::MAX)
        ],
    )?;
    Ok(())
}

fn list_dead_letters_sync(path: &PathBuf, limit: u32) -> Result<Vec<DeadLetterItem>> {
    let conn = open(path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT id, escrow_id_hex, stage, last_error_code, last_error_detail_redacted, attempts, payload_hash_hex, created_at_ms
        FROM dead_letters
        ORDER BY id DESC
        LIMIT ?1
        "#,
    )?;
    let mut rows = stmt.query(params![i64::from(limit.max(1).min(5000))])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(DeadLetterItem {
            id: row.get(0)?,
            escrow_id_hex: row.get(1)?,
            stage: row.get(2)?,
            last_error_code: row.get(3)?,
            last_error_detail_redacted: row.get(4)?,
            attempts: u32::try_from(row.get::<_, i64>(5)?).unwrap_or(0),
            payload_hash_hex: row.get(6)?,
            created_at_ms: u64::try_from(row.get::<_, i64>(7)?).unwrap_or(0),
        });
    }
    Ok(out)
}

fn list_workflows_sync(path: &PathBuf, limit: u32) -> Result<Vec<WorkflowInstance>> {
    let conn = open(path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT escrow_id_hex, state, snapshot_hash_hex, participants_json, created_at_ms, updated_at_ms
        FROM workflow_instances
        ORDER BY updated_at_ms ASC
        LIMIT ?1
        "#,
    )?;
    let mut rows = stmt.query(params![i64::from(limit.max(1).min(5000))])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_workflow(row)?);
    }
    Ok(out)
}

fn step_count_for_state_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    state: WorkflowState,
) -> Result<u64> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let conn = open(path)?;
    let count: i64 = conn.query_row(
        r#"
        SELECT COUNT(DISTINCT from_id)
        FROM workflow_steps
        WHERE escrow_id_hex=?1 AND state=?2 AND status='accepted'
        "#,
        params![escrow_id_hex, state.as_str()],
        |row| row.get(0),
    )?;
    Ok(u64::try_from(count).unwrap_or(0))
}

fn get_workflow_sync(path: &PathBuf, escrow_id_hex: &str) -> Result<Option<WorkflowInstance>> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let conn = open(path)?;
    get_workflow_tx(&conn, &escrow_id_hex)
}

fn upsert_proposal_blob_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    action: &str,
    tx_data_hex: &str,
    txset_hash_hex: &str,
) -> Result<()> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let action = normalize_action(action)?;
    let tx_data_hex = normalize_even_hex(tx_data_hex, "tx_data_hex")?;
    let txset_hash_hex = normalize_hex_exact(txset_hash_hex, 64, "txset_hash_hex")?;

    let mut conn = open(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let wf = get_workflow_tx(&tx, &escrow_id_hex)?
        .ok_or_else(|| anyhow!("workflow not found for escrow_id_hex={}", escrow_id_hex))?;
    let allowed_state = matches!(
        wf.state,
        WorkflowState::Funded | WorkflowState::TxSignPending | WorkflowState::TxSignedQuorum
    );
    if !allowed_state {
        return Err(anyhow!(
            "workflow state {:?} does not allow proposal blob storage",
            wf.state
        ));
    }

    let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    tx.execute(
        r#"
        INSERT INTO proposal_blobs(
            escrow_id_hex, action, tx_data_hex, txset_hash_hex, created_at_ms, updated_at_ms
        ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(escrow_id_hex) DO UPDATE SET
            action=excluded.action,
            tx_data_hex=excluded.tx_data_hex,
            txset_hash_hex=excluded.txset_hash_hex,
            updated_at_ms=excluded.updated_at_ms
        "#,
        params![escrow_id_hex, action, tx_data_hex, txset_hash_hex, now, now],
    )?;
    tx.commit()?;
    Ok(())
}

fn get_proposal_blob_sync(path: &PathBuf, escrow_id_hex: &str) -> Result<Option<ProposalBlob>> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let conn = open(path)?;
    conn.query_row(
        r#"
        SELECT escrow_id_hex, action, tx_data_hex, txset_hash_hex, created_at_ms, updated_at_ms
        FROM proposal_blobs
        WHERE escrow_id_hex=?1
        "#,
        params![escrow_id_hex],
        row_to_proposal_blob,
    )
    .optional()
    .map_err(Into::into)
}

fn get_proposal_blob_by_txset_hash_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    txset_hash_hex: &str,
) -> Result<Option<ProposalBlob>> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let txset_hash_hex = normalize_hex_exact(txset_hash_hex, 64, "txset_hash_hex")?;
    let conn = open(path)?;
    conn.query_row(
        r#"
        SELECT escrow_id_hex, action, tx_data_hex, txset_hash_hex, created_at_ms, updated_at_ms
        FROM proposal_blobs
        WHERE escrow_id_hex=?1 AND txset_hash_hex=?2
        "#,
        params![escrow_id_hex, txset_hash_hex],
        row_to_proposal_blob,
    )
    .optional()
    .map_err(Into::into)
}

fn upsert_quorum_sign_proof_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    role: &str,
    sign_round: &str,
    txset_hash_hex: &str,
    jti: &str,
    req_id: &str,
) -> Result<()> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let role = normalize_worker_role(role)?;
    let sign_round = normalize_quorum_sign_round_for_role(&role, sign_round)?;
    let txset_hash_hex = normalize_hex_exact(txset_hash_hex, 64, "txset_hash_hex")?;
    let jti = normalize_jti(jti, "jti")?;
    let req_id = normalize_hex_exact(req_id, 64, "req_id")?;
    let mut conn = open(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let wf = get_workflow_tx(&tx, &escrow_id_hex)?
        .ok_or_else(|| anyhow!("workflow not found for escrow_id_hex={}", escrow_id_hex))?;
    if !workflow_allows_quorum_proof_state(wf.state) {
        return Err(anyhow!(
            "workflow state {:?} does not allow quorum proof storage",
            wf.state
        ));
    }
    tx.execute(
        r#"
        INSERT INTO quorum_sign_proofs(
            escrow_id_hex, role, sign_round, txset_hash_hex, jti, req_id, updated_at_ms
        ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(escrow_id_hex, role, sign_round, txset_hash_hex) DO UPDATE SET
            jti=excluded.jti,
            req_id=excluded.req_id,
            updated_at_ms=excluded.updated_at_ms
        "#,
        params![
            escrow_id_hex,
            role,
            sign_round,
            txset_hash_hex,
            jti,
            req_id,
            i64::try_from(now_ms()).unwrap_or(i64::MAX),
        ],
    )?;
    tx.commit()?;
    Ok(())
}

fn get_quorum_sign_proof_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    role: &str,
    sign_round: &str,
    txset_hash_hex: &str,
) -> Result<Option<QuorumSignProof>> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let role = normalize_worker_role(role)?;
    let sign_round = normalize_quorum_sign_round_for_role(&role, sign_round)?;
    let txset_hash_hex = normalize_hex_exact(txset_hash_hex, 64, "txset_hash_hex")?;
    let conn = open(path)?;
    get_quorum_sign_proof_tx(&conn, &escrow_id_hex, &role, &sign_round, &txset_hash_hex)
}

fn get_quorum_sign_proof_tx(
    conn: &Connection,
    escrow_id_hex: &str,
    role: &str,
    sign_round: &str,
    txset_hash_hex: &str,
) -> Result<Option<QuorumSignProof>> {
    conn.query_row(
        r#"
        SELECT escrow_id_hex, role, sign_round, txset_hash_hex, jti, req_id, updated_at_ms
        FROM quorum_sign_proofs
        WHERE escrow_id_hex=?1 AND role=?2 AND sign_round=?3 AND txset_hash_hex=?4
        "#,
        params![escrow_id_hex, role, sign_round, txset_hash_hex],
        row_to_quorum_sign_proof,
    )
    .optional()
    .map_err(Into::into)
}

fn get_submit_multisig_proof_bundle_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    txset_hash_hex: &str,
) -> Result<SubmitMultisigProofBundle> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let txset_hash_hex = normalize_hex_exact(txset_hash_hex, 64, "txset_hash_hex")?;
    let conn = open(path)?;
    let wf = get_workflow_tx(&conn, &escrow_id_hex)?
        .ok_or_else(|| anyhow!("workflow not found for escrow_id_hex={}", escrow_id_hex))?;
    if !workflow_allows_submit_multisig_proof_bundle_state(wf.state) {
        return Err(anyhow!(
            "workflow state {:?} does not allow submit_multisig proof bundle",
            wf.state
        ));
    }
    let arbiter = get_quorum_sign_proof_tx(
        &conn,
        &escrow_id_hex,
        "arbiter",
        "arbiter_first",
        &txset_hash_hex,
    )?
    .ok_or_else(|| anyhow!("missing quorum proof: arbiter_first"))?;
    let seller = get_quorum_sign_proof_tx(
        &conn,
        &escrow_id_hex,
        "seller",
        "seller_second",
        &txset_hash_hex,
    )?
    .ok_or_else(|| anyhow!("missing quorum proof: seller_second"))?;
    if arbiter.jti == seller.jti {
        return Err(anyhow!(
            "invalid quorum proof bundle: proof_arbiter_jti and proof_seller_jti must differ"
        ));
    }
    if arbiter.req_id == seller.req_id {
        return Err(anyhow!(
            "invalid quorum proof bundle: proof_arbiter_req_id and proof_seller_req_id must differ"
        ));
    }
    Ok(SubmitMultisigProofBundle {
        escrow_id_hex,
        txset_hash_hex,
        proof_arbiter_jti: arbiter.jti,
        proof_arbiter_req_id: arbiter.req_id,
        proof_seller_jti: seller.jti,
        proof_seller_req_id: seller.req_id,
        arbiter_proof_updated_at_ms: arbiter.updated_at_ms,
        seller_proof_updated_at_ms: seller.updated_at_ms,
        generated_at_ms: now_ms(),
    })
}

fn get_workflow_tx(conn: &Connection, escrow_id_hex: &str) -> Result<Option<WorkflowInstance>> {
    conn.query_row(
        r#"
        SELECT escrow_id_hex, state, snapshot_hash_hex, participants_json, created_at_ms, updated_at_ms
        FROM workflow_instances
        WHERE escrow_id_hex=?1
        "#,
        params![escrow_id_hex],
        row_to_workflow,
    )
    .optional()
    .map_err(Into::into)
}

fn row_to_workflow(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkflowInstance> {
    let participants_json: String = row.get(3)?;
    let participants: Vec<String> = serde_json::from_str(&participants_json).unwrap_or_default();
    let state_raw: String = row.get(1)?;
    Ok(WorkflowInstance {
        escrow_id_hex: row.get(0)?,
        state: state_raw
            .parse::<WorkflowState>()
            .unwrap_or(WorkflowState::FailedDeadLetter),
        snapshot_hash_hex: row.get(2)?,
        participants,
        created_at_ms: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
        updated_at_ms: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(0),
    })
}

fn row_to_outbox(row: &rusqlite::Row<'_>) -> rusqlite::Result<OutboxItem> {
    let state_raw: String = row.get(2)?;
    Ok(OutboxItem {
        id: row.get(0)?,
        escrow_id_hex: row.get(1)?,
        state: state_raw
            .parse::<WorkflowState>()
            .unwrap_or(WorkflowState::FailedDeadLetter),
        to_id: row.get(3)?,
        msg_type: row.get(4)?,
        envelope_json: row.get(5)?,
        idem_key: row.get(6)?,
        status: row.get(7)?,
        attempts: u32::try_from(row.get::<_, i64>(8)?).unwrap_or(0),
        next_attempt_at_ms: u64::try_from(row.get::<_, i64>(9)?).unwrap_or(0),
        created_at_ms: u64::try_from(row.get::<_, i64>(10)?).unwrap_or(0),
        updated_at_ms: u64::try_from(row.get::<_, i64>(11)?).unwrap_or(0),
    })
}

fn row_to_proposal_blob(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProposalBlob> {
    Ok(ProposalBlob {
        escrow_id_hex: row.get(0)?,
        action: row.get(1)?,
        tx_data_hex: row.get(2)?,
        txset_hash_hex: row.get(3)?,
        created_at_ms: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
        updated_at_ms: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(0),
    })
}

fn row_to_quorum_sign_proof(row: &rusqlite::Row<'_>) -> rusqlite::Result<QuorumSignProof> {
    Ok(QuorumSignProof {
        escrow_id_hex: row.get(0)?,
        role: row.get(1)?,
        sign_round: row.get(2)?,
        txset_hash_hex: row.get(3)?,
        jti: row.get(4)?,
        req_id: row.get(5)?,
        updated_at_ms: u64::try_from(row.get::<_, i64>(6)?).unwrap_or(0),
    })
}

fn sha3_hex(input: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

fn is_unique_violation(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(e, _) => matches!(e.code, ErrorCode::ConstraintViolation),
        _ => false,
    }
}

fn normalize_non_empty(value: &str, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("{label} must not be empty"));
    }
    Ok(trimmed.to_string())
}

fn normalize_hex_exact(value: &str, expected_len: usize, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.len() != expected_len || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("{label} must be {expected_len} hex chars"));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn normalize_even_hex(value: &str, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() % 2 != 0
        || !trimmed.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(anyhow!("{label} must be non-empty even-length hex"));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn normalize_action(value: &str) -> Result<String> {
    let action = value.trim().to_ascii_lowercase();
    match action.as_str() {
        "release" | "refund" => Ok(action),
        _ => Err(anyhow!("action must be one of: release|refund")),
    }
}

fn normalize_outbox_status(value: &str) -> Result<String> {
    let status = value.trim().to_ascii_lowercase();
    match status.as_str() {
        "pending" | "sent" | "acked" | "dead_letter" => Ok(status),
        _ => Err(anyhow!(
            "outbox status must be one of: pending|sent|acked|dead_letter"
        )),
    }
}

fn normalize_worker_role(value: &str) -> Result<String> {
    let role = value.trim().to_ascii_lowercase();
    match role.as_str() {
        "buyer" | "seller" | "arbiter" => Ok(role),
        _ => Err(anyhow!("role must be one of: buyer|seller|arbiter")),
    }
}

fn normalize_quorum_sign_round_for_role(role: &str, sign_round: &str) -> Result<String> {
    let sign_round = sign_round.trim().to_ascii_lowercase();
    if sign_round.is_empty() {
        return Err(anyhow!("sign_round must not be empty"));
    }
    let expected = match role {
        "arbiter" => "arbiter_first",
        "seller" => "seller_second",
        "buyer" => "buyer_second",
        _ => return Err(anyhow!("role must be one of: buyer|seller|arbiter")),
    };
    if sign_round != expected {
        return Err(anyhow!(
            "sign_round '{}' does not match role '{}' (expected '{}')",
            sign_round,
            role,
            expected
        ));
    }
    Ok(sign_round)
}

fn normalize_jti(value: &str, label: &str) -> Result<String> {
    let v = normalize_non_empty(value, label)?;
    if v.len() > 256 {
        return Err(anyhow!("{label} too long (max 256 chars)"));
    }
    Ok(v)
}

fn workflow_allows_quorum_proof_state(state: WorkflowState) -> bool {
    matches!(
        state,
        WorkflowState::Funded
            | WorkflowState::TxSignPending
            | WorkflowState::TxSignedQuorum
            | WorkflowState::Submitted
    )
}

fn workflow_allows_submit_multisig_proof_bundle_state(state: WorkflowState) -> bool {
    workflow_allows_quorum_proof_state(state)
}

fn normalize_participants(participants: &[String]) -> Result<Vec<String>> {
    if participants.is_empty() {
        return Err(anyhow!("participants must not be empty"));
    }
    let mut out = Vec::with_capacity(participants.len());
    let mut seen = BTreeSet::new();
    for raw in participants {
        let p = normalize_non_empty(raw, "participant")?;
        if !seen.insert(p.clone()) {
            return Err(anyhow!("duplicate participant '{}'", p));
        }
        out.push(p);
    }
    Ok(out)
}

fn push_integrity_finding(
    out: &mut Vec<IntegrityFinding>,
    limit: usize,
    table: &str,
    escrow_id_hex: Option<&str>,
    issue: &str,
    detail: impl Into<String>,
) {
    if out.len() >= limit {
        return;
    }
    out.push(IntegrityFinding {
        table: table.to_string(),
        escrow_id_hex: escrow_id_hex.map(ToOwned::to_owned),
        issue: issue.to_string(),
        detail: detail.into(),
    });
}

fn integrity_check_sync(path: &PathBuf, limit: u32) -> Result<Vec<IntegrityFinding>> {
    let conn = open(path)?;
    let limit = usize::try_from(limit.max(1).min(10_000)).unwrap_or(10_000);
    let mut findings = Vec::<IntegrityFinding>::new();
    let mut workflow_ids = BTreeSet::<String>::new();

    {
        let mut stmt = conn.prepare(
            r#"
            SELECT escrow_id_hex, snapshot_hash_hex, participants_json
            FROM workflow_instances
            ORDER BY created_at_ms DESC
            "#,
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let escrow_id_hex: String = row.get(0)?;
            let snapshot_hash_hex: String = row.get(1)?;
            let participants_json: String = row.get(2)?;
            workflow_ids.insert(escrow_id_hex.clone());
            if normalize_hex_exact(&escrow_id_hex, 32, "escrow_id_hex").is_err() {
                push_integrity_finding(
                    &mut findings,
                    limit,
                    "workflow_instances",
                    Some(&escrow_id_hex),
                    "invalid_escrow_id",
                    "workflow escrow_id_hex is not 32 hex chars",
                );
            }
            if normalize_hex_exact(&snapshot_hash_hex, 64, "snapshot_hash_hex").is_err() {
                push_integrity_finding(
                    &mut findings,
                    limit,
                    "workflow_instances",
                    Some(&escrow_id_hex),
                    "invalid_snapshot_hash",
                    "snapshot_hash_hex is not 64 hex chars",
                );
            }
            match serde_json::from_str::<Vec<String>>(&participants_json) {
                Ok(participants) => {
                    if let Err(err) = normalize_participants(&participants) {
                        push_integrity_finding(
                            &mut findings,
                            limit,
                            "workflow_instances",
                            Some(&escrow_id_hex),
                            "invalid_participants",
                            err.to_string(),
                        );
                    }
                }
                Err(err) => {
                    push_integrity_finding(
                        &mut findings,
                        limit,
                        "workflow_instances",
                        Some(&escrow_id_hex),
                        "invalid_participants_json",
                        err.to_string(),
                    );
                }
            }
        }
    }

    {
        let mut stmt = conn.prepare(
            r#"
            SELECT escrow_id_hex, action, tx_data_hex, txset_hash_hex
            FROM proposal_blobs
            ORDER BY updated_at_ms DESC
            "#,
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let escrow_id_hex: String = row.get(0)?;
            let action: String = row.get(1)?;
            let tx_data_hex: String = row.get(2)?;
            let txset_hash_hex: String = row.get(3)?;
            if !workflow_ids.contains(&escrow_id_hex) {
                push_integrity_finding(
                    &mut findings,
                    limit,
                    "proposal_blobs",
                    Some(&escrow_id_hex),
                    "orphan_workflow",
                    "proposal row has no matching workflow_instances row",
                );
            }
            if normalize_action(&action).is_err() {
                push_integrity_finding(
                    &mut findings,
                    limit,
                    "proposal_blobs",
                    Some(&escrow_id_hex),
                    "invalid_action",
                    "proposal action must be release|refund",
                );
            }
            if normalize_even_hex(&tx_data_hex, "tx_data_hex").is_err() {
                push_integrity_finding(
                    &mut findings,
                    limit,
                    "proposal_blobs",
                    Some(&escrow_id_hex),
                    "invalid_tx_data_hex",
                    "proposal tx_data_hex is not even-length hex",
                );
            }
            if normalize_hex_exact(&txset_hash_hex, 64, "txset_hash_hex").is_err() {
                push_integrity_finding(
                    &mut findings,
                    limit,
                    "proposal_blobs",
                    Some(&escrow_id_hex),
                    "invalid_txset_hash",
                    "proposal txset_hash_hex is not 64 hex chars",
                );
            }
        }
    }

    {
        let mut stmt = conn.prepare(
            r#"
            SELECT escrow_id_hex, role, sign_round, txset_hash_hex, jti, req_id
            FROM quorum_sign_proofs
            ORDER BY updated_at_ms DESC
            "#,
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let escrow_id_hex: String = row.get(0)?;
            let role: String = row.get(1)?;
            let sign_round: String = row.get(2)?;
            let txset_hash_hex: String = row.get(3)?;
            let jti: String = row.get(4)?;
            let req_id: String = row.get(5)?;
            if !workflow_ids.contains(&escrow_id_hex) {
                push_integrity_finding(
                    &mut findings,
                    limit,
                    "quorum_sign_proofs",
                    Some(&escrow_id_hex),
                    "orphan_workflow",
                    format!(
                        "quorum proof sign_round '{}' has no matching workflow",
                        sign_round
                    ),
                );
            }
            if normalize_worker_role(&role).is_err() {
                push_integrity_finding(
                    &mut findings,
                    limit,
                    "quorum_sign_proofs",
                    Some(&escrow_id_hex),
                    "invalid_role",
                    "role must be buyer|seller|arbiter",
                );
            }
            if let Ok(role_norm) = normalize_worker_role(&role) {
                if normalize_quorum_sign_round_for_role(&role_norm, &sign_round).is_err() {
                    push_integrity_finding(
                        &mut findings,
                        limit,
                        "quorum_sign_proofs",
                        Some(&escrow_id_hex),
                        "invalid_sign_round",
                        format!(
                            "sign_round '{}' does not match role '{}'",
                            sign_round, role_norm
                        ),
                    );
                }
            }
            if normalize_hex_exact(&txset_hash_hex, 64, "txset_hash_hex").is_err() {
                push_integrity_finding(
                    &mut findings,
                    limit,
                    "quorum_sign_proofs",
                    Some(&escrow_id_hex),
                    "invalid_txset_hash",
                    "txset_hash_hex is not 64 hex chars",
                );
            }
            if normalize_jti(&jti, "jti").is_err() {
                push_integrity_finding(
                    &mut findings,
                    limit,
                    "quorum_sign_proofs",
                    Some(&escrow_id_hex),
                    "invalid_jti",
                    "jti is empty or too long",
                );
            }
            if normalize_hex_exact(&req_id, 64, "req_id").is_err() {
                push_integrity_finding(
                    &mut findings,
                    limit,
                    "quorum_sign_proofs",
                    Some(&escrow_id_hex),
                    "invalid_req_id",
                    "req_id is not 64 hex chars",
                );
            }
        }
    }

    Ok(findings)
}

fn delivery_guarantee_report_sync(
    path: &PathBuf,
    window_ms: u64,
    sent_stale_ms: u64,
) -> Result<DeliveryGuaranteeReport> {
    let conn = open(path)?;
    let now = now_ms();
    let window_ms = window_ms.max(1);
    let sent_stale_ms = sent_stale_ms.max(1);
    let since_ms = now.saturating_sub(window_ms);
    let sent_stale_before_ms = now.saturating_sub(sent_stale_ms);
    let since_i64 = i64::try_from(since_ms).unwrap_or(i64::MAX);
    let sent_stale_before_i64 = i64::try_from(sent_stale_before_ms).unwrap_or(i64::MAX);

    let outbox_pending = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM outbox WHERE status='pending'",
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);
    let outbox_sent = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM outbox WHERE status='sent'",
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);
    let outbox_acked = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM outbox WHERE status='acked'",
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);
    let outbox_dead_letter = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM outbox WHERE status='dead_letter'",
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);
    let outbox_retrying = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM outbox WHERE status='pending' AND attempts > 0",
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);
    let outbox_sent_stale = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM outbox WHERE status='sent' AND updated_at_ms < ?1",
        params![sent_stale_before_i64],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);

    let step_accepted_window = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM workflow_steps WHERE status='accepted' AND created_at_ms >= ?1",
        params![since_i64],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);
    let step_replay_duplicate_window = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM workflow_steps WHERE status='replay_duplicate' AND created_at_ms >= ?1",
        params![since_i64],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);
    let idem_payload_conflict_window = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM dead_letters WHERE created_at_ms >= ?1 AND last_error_code='idem_payload_conflict'",
        params![since_i64],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);

    let duplicate_step_idem_keys = u64::try_from(conn.query_row(
        r#"
        SELECT COUNT(1)
        FROM (
            SELECT idem_key
            FROM workflow_steps
            GROUP BY idem_key
            HAVING COUNT(1) > 1
        ) t
        "#,
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);
    let duplicate_outbox_idem_keys = u64::try_from(conn.query_row(
        r#"
        SELECT COUNT(1)
        FROM (
            SELECT idem_key
            FROM outbox
            GROUP BY idem_key
            HAVING COUNT(1) > 1
        ) t
        "#,
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);
    let inbox_offsets_total = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM inbox_offsets",
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);

    let mut findings: Vec<String> = Vec::new();
    if duplicate_step_idem_keys > 0 {
        findings.push(format!(
            "workflow_steps duplicate idem_key entries detected: {}",
            duplicate_step_idem_keys
        ));
    }
    if duplicate_outbox_idem_keys > 0 {
        findings.push(format!(
            "outbox duplicate idem_key entries detected: {}",
            duplicate_outbox_idem_keys
        ));
    }
    if outbox_sent_stale > 0 {
        findings.push(format!(
            "sent-but-unacked outbox rows older than sent_stale_ms: {}",
            outbox_sent_stale
        ));
    }
    if outbox_dead_letter > 0 {
        findings.push(format!(
            "outbox dead-letter rows present: {}",
            outbox_dead_letter
        ));
    }
    if step_accepted_window > 0 && outbox_acked == 0 {
        findings.push(
            "accepted workflow steps observed in window but no outbox ack evidence".to_string(),
        );
    }

    let dedup_proof_ok = duplicate_step_idem_keys == 0 && duplicate_outbox_idem_keys == 0;
    Ok(DeliveryGuaranteeReport {
        generated_at_ms: now,
        window_ms,
        sent_stale_ms,
        outbox_pending,
        outbox_sent,
        outbox_acked,
        outbox_dead_letter,
        outbox_retrying,
        outbox_sent_stale,
        step_accepted_window,
        step_replay_duplicate_window,
        idem_payload_conflict_window,
        duplicate_step_idem_keys,
        duplicate_outbox_idem_keys,
        inbox_offsets_total,
        dedup_proof_ok,
        findings,
    })
}

fn slo_metrics_sync(
    path: &PathBuf,
    window_ms: u64,
    stuck_after_ms: u64,
) -> Result<WorkflowSloMetrics> {
    #[derive(Default)]
    struct StageAgg {
        count: u64,
        age_sum: u128,
        max_age: u64,
    }

    let conn = open(path)?;
    let now = now_ms();
    let window_ms = window_ms.max(1);
    let stuck_after_ms = stuck_after_ms.max(1);
    let since_ms = now.saturating_sub(window_ms);

    let workflows_total = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM workflow_instances",
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);

    let mut workflows_active: u64 = 0;
    let mut workflows_stuck: u64 = 0;
    let mut active_age_sum: u128 = 0;
    let mut active_age_max: u64 = 0;
    let mut stage_aggs = BTreeMap::<String, StageAgg>::new();
    {
        let mut stmt = conn.prepare(
            r#"
            SELECT state, updated_at_ms
            FROM workflow_instances
            WHERE state NOT IN ('confirmed', 'failed_dead_letter')
            "#,
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let state: String = row.get(0)?;
            let updated_at_ms_i64: i64 = row.get(1)?;
            let updated_at_ms = u64::try_from(updated_at_ms_i64).unwrap_or(0);
            let age_ms = now.saturating_sub(updated_at_ms);

            workflows_active = workflows_active.saturating_add(1);
            if age_ms > stuck_after_ms {
                workflows_stuck = workflows_stuck.saturating_add(1);
            }
            active_age_sum = active_age_sum.saturating_add(u128::from(age_ms));
            active_age_max = active_age_max.max(age_ms);

            let agg = stage_aggs.entry(state).or_default();
            agg.count = agg.count.saturating_add(1);
            agg.age_sum = agg.age_sum.saturating_add(u128::from(age_ms));
            agg.max_age = agg.max_age.max(age_ms);
        }
    }
    let active_workflow_avg_age_ms = if workflows_active == 0 {
        0
    } else {
        u64::try_from(active_age_sum / u128::from(workflows_active)).unwrap_or(u64::MAX)
    };
    let stage_latency = stage_aggs
        .into_iter()
        .map(|(state, agg)| {
            let avg = if agg.count == 0 {
                0
            } else {
                u64::try_from(agg.age_sum / u128::from(agg.count)).unwrap_or(u64::MAX)
            };
            (
                state,
                WorkflowSloStageLatency {
                    count: agg.count,
                    avg_age_ms: avg,
                    max_age_ms: agg.max_age,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    let outbox_pending = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM outbox WHERE status='pending'",
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);
    let outbox_sent_unacked = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM outbox WHERE status='sent'",
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);
    let outbox_dead_letter = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM outbox WHERE status='dead_letter'",
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);
    let outbox_retrying = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM outbox WHERE status='pending' AND attempts > 0",
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);

    let since_i64 = i64::try_from(since_ms).unwrap_or(i64::MAX);
    let step_replay_duplicate_window = u64::try_from(
        conn.query_row(
            "SELECT COUNT(1) FROM workflow_steps WHERE status='replay_duplicate' AND created_at_ms >= ?1",
            params![since_i64],
            |row| row.get::<_, i64>(0),
        )?,
    )
    .unwrap_or(0);
    let dead_letter_window = u64::try_from(conn.query_row(
        "SELECT COUNT(1) FROM dead_letters WHERE created_at_ms >= ?1",
        params![since_i64],
        |row| row.get::<_, i64>(0),
    )?)
    .unwrap_or(0);
    Ok(WorkflowSloMetrics {
        generated_at_ms: now,
        window_ms,
        stuck_after_ms,
        workflows_total,
        workflows_active,
        workflows_stuck,
        active_workflow_avg_age_ms,
        active_workflow_max_age_ms: active_age_max,
        outbox_pending,
        outbox_sent_unacked,
        outbox_dead_letter,
        outbox_retrying,
        step_replay_duplicate_window,
        dead_letter_window,
        stage_latency,
    })
}

fn build_slo_alert_report(
    metrics: WorkflowSloMetrics,
    thresholds: SloAlertThresholds,
) -> SloAlertReport {
    let mut alerts: Vec<SloAlertItem> = Vec::new();

    if metrics.workflows_stuck > thresholds.workflows_stuck_total {
        alerts.push(SloAlertItem {
            metric: "workflows_stuck_total".to_string(),
            observed: metrics.workflows_stuck,
            threshold: thresholds.workflows_stuck_total,
            severity: "critical".to_string(),
            action: "inspect stale workflows and unblock stage transitions immediately".to_string(),
        });
    }
    if metrics.active_workflow_max_age_ms > thresholds.active_workflow_max_age_ms {
        alerts.push(SloAlertItem {
            metric: "active_workflow_max_age_ms".to_string(),
            observed: metrics.active_workflow_max_age_ms,
            threshold: thresholds.active_workflow_max_age_ms,
            severity: "high".to_string(),
            action: "check orchestration worker and dependent services for stalled progress"
                .to_string(),
        });
    }
    if metrics.outbox_pending > thresholds.outbox_pending_total {
        alerts.push(SloAlertItem {
            metric: "outbox_pending_total".to_string(),
            observed: metrics.outbox_pending,
            threshold: thresholds.outbox_pending_total,
            severity: "high".to_string(),
            action: "drain outbox backlog and verify downstream mailbox availability".to_string(),
        });
    }
    if metrics.outbox_sent_unacked > thresholds.outbox_sent_unacked_total {
        alerts.push(SloAlertItem {
            metric: "outbox_sent_unacked_total".to_string(),
            observed: metrics.outbox_sent_unacked,
            threshold: thresholds.outbox_sent_unacked_total,
            severity: "high".to_string(),
            action: "investigate acknowledgement path; possible delivery gap or mailbox lag"
                .to_string(),
        });
    }
    if metrics.dead_letter_window > thresholds.dead_letter_window_total {
        alerts.push(SloAlertItem {
            metric: "dead_letter_window_total".to_string(),
            observed: metrics.dead_letter_window,
            threshold: thresholds.dead_letter_window_total,
            severity: "critical".to_string(),
            action: "triage dead letters and execute workflow recovery or rollback".to_string(),
        });
    }
    if metrics.step_replay_duplicate_window > thresholds.replay_duplicate_window_total {
        alerts.push(SloAlertItem {
            metric: "replay_duplicate_window_total".to_string(),
            observed: metrics.step_replay_duplicate_window,
            threshold: thresholds.replay_duplicate_window_total,
            severity: "medium".to_string(),
            action: "investigate replay spikes (network retries or abuse patterns)".to_string(),
        });
    }
    SloAlertReport {
        generated_at_ms: now_ms(),
        metrics,
        thresholds,
        ok: alerts.is_empty(),
        alerts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::WorkflowState;
    use rusqlite::params;

    fn unique_db_path(label: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "nxms_orchestrator_test_{label}_{}_{}.db",
            std::process::id(),
            ts
        ))
    }

    #[tokio::test]
    async fn workflow_creation_and_transition() {
        let db_path = unique_db_path("workflow");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        db.create_workflow(
            "00112233445566778899aabbccddeeff",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[
                "alice".to_string(),
                "bob".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create");
        db.transition_workflow(
            "00112233445566778899aabbccddeeff",
            WorkflowState::PrepareCollected,
            None,
        )
        .await
        .expect("transition");
        let wf = db
            .get_workflow("00112233445566778899aabbccddeeff")
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(wf.state, WorkflowState::PrepareCollected);
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn transition_reason_is_not_recorded_as_dead_letter() {
        let db_path = unique_db_path("workflow_transition_reason");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        db.create_workflow(
            escrow_id_hex,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[
                "alice".to_string(),
                "bob".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create");
        db.transition_workflow(
            escrow_id_hex,
            WorkflowState::PrepareCollected,
            Some("expected progress note"),
        )
        .await
        .expect("transition");

        let dead_letters = db.list_dead_letters(50).await.expect("dead letters");
        assert!(
            dead_letters.is_empty(),
            "workflow transition notes must not poison dead-letter metrics"
        );

        let metrics = db.slo_metrics(60_000, 60_000).await.expect("slo metrics");
        assert_eq!(metrics.dead_letter_window, 0);
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn step_idempotency_duplicate_is_replay() {
        let db_path = unique_db_path("step_replay");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        db.create_workflow(
            "00112233445566778899aabbccddeeff",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[
                "alice".to_string(),
                "bob".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create");

        let input = StepInput {
            escrow_id_hex: "00112233445566778899aabbccddeeff".to_string(),
            state: WorkflowState::PrepareCollected,
            from_id: "alice".to_string(),
            seq: 1,
            msg_type: "prepare_info".to_string(),
            payload_hash_hex: "aa".repeat(32),
        };
        let o1 = db.record_step(input.clone()).await.expect("first");
        assert!(matches!(o1, StepOutcome::Accepted));
        let o2 = db.record_step(input).await.expect("second");
        assert!(matches!(o2, StepOutcome::ReplayDuplicate));
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn inbox_offset_rejects_reset() {
        let db_path = unique_db_path("offset");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        db.advance_inbox_offset("alice", "00112233445566778899aabbccddeeff", 10)
            .await
            .expect("seq10");
        let err = db
            .advance_inbox_offset("alice", "00112233445566778899aabbccddeeff", 9)
            .await
            .expect_err("must reject reset");
        assert!(err.to_string().contains("replay/reset"));
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn outbox_lifecycle_sent_retry_acked() {
        let db_path = unique_db_path("outbox_lifecycle");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        db.create_workflow(
            escrow_id_hex,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[
                "buyer".to_string(),
                "seller".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create");
        db.enqueue_outbox(OutboxInput {
            escrow_id_hex: escrow_id_hex.to_string(),
            state: WorkflowState::New,
            to_id: "seller".to_string(),
            msg_type: "prepare_info".to_string(),
            envelope_json: "{\"m\":\"hello\"}".to_string(),
        })
        .await
        .expect("enqueue");

        let pending = db
            .list_outbox(Some("pending"), 50)
            .await
            .expect("list pending");
        assert_eq!(pending.len(), 1);
        let outbox_id = pending[0].id;
        assert_eq!(pending[0].attempts, 0);

        db.mark_outbox_sent(outbox_id).await.expect("mark sent");
        let sent = db.list_outbox(Some("sent"), 50).await.expect("list sent");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].id, outbox_id);
        assert_eq!(sent[0].attempts, 1);

        db.mark_outbox_retry(outbox_id, 500, "mailbox_timeout", "retry later", 5)
            .await
            .expect("mark retry");
        let pending_retry = db
            .list_outbox(Some("pending"), 50)
            .await
            .expect("list pending after retry");
        assert_eq!(pending_retry.len(), 1);
        assert_eq!(pending_retry[0].id, outbox_id);
        assert_eq!(pending_retry[0].attempts, 2);

        db.mark_outbox_acked(outbox_id).await.expect("mark acked");
        let acked = db.list_outbox(Some("acked"), 50).await.expect("list acked");
        assert_eq!(acked.len(), 1);
        assert_eq!(acked[0].id, outbox_id);
        assert_eq!(acked[0].attempts, 2);

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn outbox_retry_dead_letters_and_records_error() {
        let db_path = unique_db_path("outbox_dead_letter");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        db.create_workflow(
            escrow_id_hex,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[
                "buyer".to_string(),
                "seller".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create");
        db.enqueue_outbox(OutboxInput {
            escrow_id_hex: escrow_id_hex.to_string(),
            state: WorkflowState::New,
            to_id: "seller".to_string(),
            msg_type: "prepare_info".to_string(),
            envelope_json: "{\"m\":\"hello\"}".to_string(),
        })
        .await
        .expect("enqueue");

        let pending = db
            .list_outbox(Some("pending"), 50)
            .await
            .expect("list pending");
        assert_eq!(pending.len(), 1);
        let outbox_id = pending[0].id;

        db.mark_outbox_retry(
            outbox_id,
            1_000,
            "mailbox_timeout",
            "timeout while delivering",
            1,
        )
        .await
        .expect("dead-letter on retry");

        let dead_rows = db
            .list_outbox(Some("dead_letter"), 50)
            .await
            .expect("list dead-letter");
        assert_eq!(dead_rows.len(), 1);
        assert_eq!(dead_rows[0].id, outbox_id);
        assert_eq!(dead_rows[0].attempts, 1);

        let dead_letters = db.list_dead_letters(50).await.expect("dead letters");
        assert!(
            dead_letters.iter().any(|row| {
                row.escrow_id_hex == escrow_id_hex
                    && row.stage == "outbox_delivery"
                    && row.last_error_code == "mailbox_timeout"
            }),
            "expected outbox_delivery dead-letter entry"
        );

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn delivery_guarantee_report_tracks_stale_sent_and_dedup_proof() {
        let db_path = unique_db_path("delivery_guarantee_report");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        db.create_workflow(
            escrow_id_hex,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[
                "buyer".to_string(),
                "seller".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create");

        let step = db
            .record_step(StepInput {
                escrow_id_hex: escrow_id_hex.to_string(),
                state: WorkflowState::PrepareCollected,
                from_id: "buyer".to_string(),
                seq: 1,
                msg_type: "prepare_info".to_string(),
                payload_hash_hex: "11".repeat(32),
            })
            .await
            .expect("record step");
        assert!(matches!(step, StepOutcome::Accepted));

        db.enqueue_outbox(OutboxInput {
            escrow_id_hex: escrow_id_hex.to_string(),
            state: WorkflowState::New,
            to_id: "seller".to_string(),
            msg_type: "prepare_info".to_string(),
            envelope_json: "{\"m\":\"hello\"}".to_string(),
        })
        .await
        .expect("enqueue");
        let outbox_id = db
            .list_outbox(Some("pending"), 10)
            .await
            .expect("list pending")[0]
            .id;
        db.mark_outbox_sent(outbox_id).await.expect("mark sent");

        let conn = open(&db_path).expect("open");
        conn.execute(
            "UPDATE outbox SET updated_at_ms=1 WHERE id=?1",
            params![outbox_id],
        )
        .expect("force stale sent outbox");

        db.add_dead_letter(
            escrow_id_hex,
            "step_record",
            "idem_payload_conflict",
            "same idem key with different payload hash",
            1,
            None,
        )
        .await
        .expect("add dead letter");
        db.advance_inbox_offset("buyer", escrow_id_hex, 1)
            .await
            .expect("advance inbox offset");

        let report = db
            .delivery_guarantee_report(60_000, 100)
            .await
            .expect("delivery report");
        assert_eq!(report.outbox_sent, 1);
        assert_eq!(report.outbox_sent_stale, 1);
        assert_eq!(report.step_accepted_window, 1);
        assert_eq!(report.idem_payload_conflict_window, 1);
        assert_eq!(report.inbox_offsets_total, 1);
        assert!(report.dedup_proof_ok);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.contains("sent-but-unacked outbox rows older"))
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.contains("accepted workflow steps observed in window"))
        );

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn record_step_rejects_workflow_state_jump() {
        let db_path = unique_db_path("state_jump");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        db.create_workflow(
            "00112233445566778899aabbccddeeff",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[
                "alice".to_string(),
                "bob".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create");

        let err = db
            .record_step(StepInput {
                escrow_id_hex: "00112233445566778899aabbccddeeff".to_string(),
                state: WorkflowState::TxSignedQuorum,
                from_id: "alice".to_string(),
                seq: 1,
                msg_type: "tx_sign_resp".to_string(),
                payload_hash_hex: "11".repeat(32),
            })
            .await
            .expect_err("must reject state jump");
        assert!(err.to_string().contains("precondition"));
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn create_workflow_rejects_invalid_snapshot_hash() {
        let db_path = unique_db_path("invalid_snapshot_hash");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        let err = db
            .create_workflow(
                "00112233445566778899aabbccddeeff",
                "not_hex",
                &["alice".to_string()],
            )
            .await
            .expect_err("must reject invalid snapshot hash");
        assert!(err.to_string().contains("snapshot_hash_hex"));
        let _ = std::fs::remove_file(db_path);
    }

    async fn transition_to_funded(db: &OrchestratorDb, escrow_id_hex: &str) {
        let path = [
            WorkflowState::PrepareCollected,
            WorkflowState::MakeCollected,
            WorkflowState::ExchangeR1Collected,
            WorkflowState::ExchangeR2Collected,
            WorkflowState::FinalizedReady,
            WorkflowState::Funded,
        ];
        for s in path {
            db.transition_workflow(escrow_id_hex, s, None)
                .await
                .expect("transition");
        }
    }

    #[tokio::test]
    async fn proposal_blob_roundtrip() {
        let db_path = unique_db_path("proposal_blob");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        db.create_workflow(
            escrow_id_hex,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[
                "alice".to_string(),
                "bob".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create");
        transition_to_funded(&db, escrow_id_hex).await;

        db.upsert_proposal_blob(
            escrow_id_hex,
            "release",
            "aa11",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .await
        .expect("upsert proposal");
        let p = db
            .get_proposal_blob(escrow_id_hex)
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(p.action, "release");
        assert_eq!(p.tx_data_hex, "aa11");
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn proposal_blob_rejects_non_funded_state() {
        let db_path = unique_db_path("proposal_state_gate");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        db.create_workflow(
            escrow_id_hex,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[
                "alice".to_string(),
                "bob".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create");

        let err = db
            .upsert_proposal_blob(
                escrow_id_hex,
                "release",
                "aa11",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .await
            .expect_err("state gate must fail");
        assert!(
            err.to_string()
                .contains("does not allow proposal blob storage")
        );
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn quorum_sign_proof_roundtrip() {
        let db_path = unique_db_path("quorum_sign_proof");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        db.create_workflow(
            escrow_id_hex,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[
                "alice".to_string(),
                "bob".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create");
        transition_to_funded(&db, escrow_id_hex).await;

        db.upsert_quorum_sign_proof(
            escrow_id_hex,
            "seller",
            "seller_second",
            "aa".repeat(32).as_str(),
            "seller-jti-1",
            "11".repeat(32).as_str(),
        )
        .await
        .expect("upsert quorum proof");

        let row = db
            .get_quorum_sign_proof(
                escrow_id_hex,
                "seller",
                "seller_second",
                "aa".repeat(32).as_str(),
            )
            .await
            .expect("get quorum proof")
            .expect("proof exists");
        assert_eq!(row.role, "seller");
        assert_eq!(row.sign_round, "seller_second");
        assert_eq!(row.jti, "seller-jti-1");
        assert_eq!(row.req_id, "11".repeat(32));
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn quorum_sign_proof_rejects_invalid_req_id() {
        let db_path = unique_db_path("quorum_sign_proof_req_id");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");

        let err = db
            .upsert_quorum_sign_proof(
                "00112233445566778899aabbccddeeff",
                "seller",
                "seller_second",
                "aa".repeat(32).as_str(),
                "seller-jti-1",
                "not_hex_req_id",
            )
            .await
            .expect_err("invalid req_id must fail");
        assert!(err.to_string().contains("req_id"));
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn quorum_sign_proof_rejects_without_workflow() {
        let db_path = unique_db_path("quorum_sign_proof_missing_workflow");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        let err = db
            .upsert_quorum_sign_proof(
                "00112233445566778899aabbccddeeff",
                "seller",
                "seller_second",
                "aa".repeat(32).as_str(),
                "seller-jti-1",
                "11".repeat(32).as_str(),
            )
            .await
            .expect_err("missing workflow must fail");
        assert!(err.to_string().contains("workflow not found"));
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn quorum_sign_proof_rejects_role_round_mismatch() {
        let db_path = unique_db_path("quorum_sign_proof_role_round_mismatch");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        db.create_workflow(
            escrow_id_hex,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[
                "alice".to_string(),
                "bob".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create");
        transition_to_funded(&db, escrow_id_hex).await;
        let err = db
            .upsert_quorum_sign_proof(
                escrow_id_hex,
                "seller",
                "arbiter_first",
                "aa".repeat(32).as_str(),
                "seller-jti-1",
                "11".repeat(32).as_str(),
            )
            .await
            .expect_err("round mismatch must fail");
        assert!(err.to_string().contains("does not match role"));
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn submit_multisig_proof_bundle_roundtrip() {
        let db_path = unique_db_path("submit_multisig_proof_bundle_roundtrip");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        let txset_hash_hex = "aa".repeat(32);
        db.create_workflow(
            escrow_id_hex,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[
                "alice".to_string(),
                "bob".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create");
        transition_to_funded(&db, escrow_id_hex).await;

        db.upsert_quorum_sign_proof(
            escrow_id_hex,
            "arbiter",
            "arbiter_first",
            &txset_hash_hex,
            "arbiter-jti-1",
            "11".repeat(32).as_str(),
        )
        .await
        .expect("arbiter proof");
        db.upsert_quorum_sign_proof(
            escrow_id_hex,
            "seller",
            "seller_second",
            &txset_hash_hex,
            "seller-jti-1",
            "22".repeat(32).as_str(),
        )
        .await
        .expect("seller proof");

        let bundle = db
            .get_submit_multisig_proof_bundle(escrow_id_hex, &txset_hash_hex)
            .await
            .expect("bundle");
        assert_eq!(bundle.escrow_id_hex, escrow_id_hex);
        assert_eq!(bundle.txset_hash_hex, txset_hash_hex);
        assert_eq!(bundle.proof_arbiter_jti, "arbiter-jti-1");
        assert_eq!(bundle.proof_seller_jti, "seller-jti-1");
        assert_eq!(bundle.proof_arbiter_req_id, "11".repeat(32));
        assert_eq!(bundle.proof_seller_req_id, "22".repeat(32));
        assert!(bundle.generated_at_ms > 0);
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn submit_multisig_proof_bundle_rejects_missing_seller_proof() {
        let db_path = unique_db_path("submit_multisig_proof_bundle_missing_seller");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        let txset_hash_hex = "aa".repeat(32);
        db.create_workflow(
            escrow_id_hex,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[
                "alice".to_string(),
                "bob".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create");
        transition_to_funded(&db, escrow_id_hex).await;

        db.upsert_quorum_sign_proof(
            escrow_id_hex,
            "arbiter",
            "arbiter_first",
            &txset_hash_hex,
            "arbiter-jti-1",
            "11".repeat(32).as_str(),
        )
        .await
        .expect("arbiter proof");

        let err = db
            .get_submit_multisig_proof_bundle(escrow_id_hex, &txset_hash_hex)
            .await
            .expect_err("missing seller proof must fail");
        assert!(
            err.to_string()
                .contains("missing quorum proof: seller_second")
        );
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn integrity_check_reports_orphan_and_invalid_rows() {
        let db_path = unique_db_path("integrity_check");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");

        db.create_workflow(
            "00112233445566778899aabbccddeeff",
            &"11".repeat(32),
            &[
                "buyer".to_string(),
                "seller".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("workflow");

        let conn = Connection::open(&db_path).expect("open db");
        let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
        conn.execute(
            r#"
            INSERT INTO proposal_blobs(
                escrow_id_hex, action, tx_data_hex, txset_hash_hex, created_at_ms, updated_at_ms
            ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                "ffeeddccbbaa99887766554433221100",
                "release",
                "zz11",
                "11",
                now,
                now
            ],
        )
        .expect("insert orphan invalid proposal");
        conn.execute(
            r#"
            INSERT INTO submission_watch(
                escrow_id_hex, txid, required_confirmations, status,
                last_confirmations, double_spend_seen, created_at_ms, updated_at_ms
            ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                "00112233445566778899aabbccddeeff",
                "abc",
                0_i64,
                "pending",
                0_i64,
                0_i64,
                now,
                now
            ],
        )
        .expect("insert invalid submission_watch");

        let findings = db.check_integrity(50).await.expect("integrity");
        assert!(
            findings
                .iter()
                .any(|f| f.table == "proposal_blobs" && f.issue == "orphan_workflow")
        );
        assert!(
            findings
                .iter()
                .any(|f| f.table == "proposal_blobs" && f.issue == "invalid_tx_data_hex")
        );
        assert!(
            findings
                .iter()
                .any(|f| f.table == "proposal_blobs" && f.issue == "invalid_txset_hash")
        );
        assert!(
            findings
                .iter()
                .any(|f| f.table == "submission_watch" && f.issue == "invalid_txid")
        );
        assert!(
            findings
                .iter()
                .any(|f| f.table == "submission_watch"
                    && f.issue == "invalid_required_confirmations")
        );

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn slo_metrics_and_alerts_capture_operational_pressure() {
        let db_path = unique_db_path("slo_metrics");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");

        let escrow_a = "00112233445566778899aabbccddeeff";
        let escrow_b = "ffeeddccbbaa99887766554433221100";
        let snapshot_hash = "aa".repeat(32);
        let participants = vec![
            "buyer".to_string(),
            "seller".to_string(),
            "arbiter".to_string(),
        ];
        db.create_workflow(escrow_a, &snapshot_hash, &participants)
            .await
            .expect("create workflow a");
        db.create_workflow(escrow_b, &snapshot_hash, &participants)
            .await
            .expect("create workflow b");

        db.enqueue_outbox(OutboxInput {
            escrow_id_hex: escrow_a.to_string(),
            state: WorkflowState::New,
            to_id: "buyer".to_string(),
            msg_type: "prepare_info".to_string(),
            envelope_json: "{\"id\":1}".to_string(),
        })
        .await
        .expect("enqueue outbox pending");
        db.enqueue_outbox(OutboxInput {
            escrow_id_hex: escrow_a.to_string(),
            state: WorkflowState::New,
            to_id: "seller".to_string(),
            msg_type: "prepare_info".to_string(),
            envelope_json: "{\"id\":2}".to_string(),
        })
        .await
        .expect("enqueue outbox pending retry");

        let conn = open(&db_path).expect("open");
        let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
        conn.execute(
            "UPDATE workflow_instances SET updated_at_ms=1 WHERE escrow_id_hex=?1",
            params![escrow_b],
        )
        .expect("force stale workflow");
        conn.execute(
            "UPDATE outbox SET attempts=3 WHERE status='pending' AND to_id='seller'",
            [],
        )
        .expect("mark retrying outbox");
        conn.execute(
            r#"
            INSERT INTO outbox(
                escrow_id_hex, state, to_id, msg_type, envelope_json, idem_key,
                status, attempts, next_attempt_at_ms, created_at_ms, updated_at_ms
            ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'sent', ?7, ?8, ?9, ?10)
            "#,
            params![
                escrow_a,
                "new",
                "arbiter",
                "prepare_info",
                "{\"id\":3}",
                "idem-sent-1",
                1_i64,
                now,
                now,
                now
            ],
        )
        .expect("insert sent outbox");
        conn.execute(
            r#"
            INSERT INTO outbox(
                escrow_id_hex, state, to_id, msg_type, envelope_json, idem_key,
                status, attempts, next_attempt_at_ms, created_at_ms, updated_at_ms
            ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'dead_letter', ?7, ?8, ?9, ?10)
            "#,
            params![
                escrow_a,
                "new",
                "buyer",
                "prepare_info",
                "{\"id\":4}",
                "idem-dead-1",
                4_i64,
                now,
                now,
                now
            ],
        )
        .expect("insert dead-letter outbox");
        conn.execute(
            r#"
            INSERT INTO workflow_steps(
                escrow_id_hex, state, from_id, seq, msg_type, idem_key, payload_hash_hex, status, detail, created_at_ms
            ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, 'replay_duplicate', ?8, ?9)
            "#,
            params![
                escrow_a,
                "prepare_collected",
                "buyer",
                1_i64,
                "prepare_info",
                "replay-idem-1",
                "11".repeat(32),
                "duplicate frame",
                now
            ],
        )
        .expect("insert replay duplicate");
        conn.execute(
            r#"
            INSERT INTO dead_letters(
                escrow_id_hex, stage, last_error_code, last_error_detail_redacted, attempts, payload_hash_hex, created_at_ms
            ) VALUES(?1, ?2, ?3, ?4, ?5, NULL, ?6)
            "#,
            params![
                escrow_a,
                "worker_tick",
                "wallet_rpc_unreachable",
                "wallet-rpc timed out",
                2_i64,
                now
            ],
        )
        .expect("insert wallet dead letter");
        conn.execute(
            r#"
            INSERT INTO dead_letters(
                escrow_id_hex, stage, last_error_code, last_error_detail_redacted, attempts, payload_hash_hex, created_at_ms
            ) VALUES(?1, ?2, ?3, ?4, ?5, NULL, ?6)
            "#,
            params![
                escrow_b,
                "step_record",
                "idem_payload_conflict",
                "same idempotency key with different payload hash",
                1_i64,
                now
            ],
        )
        .expect("insert generic dead letter");

        let metrics = db.slo_metrics(60_000, 100).await.expect("metrics");
        assert_eq!(metrics.workflows_total, 2);
        assert_eq!(metrics.workflows_active, 2);
        assert!(metrics.workflows_stuck >= 1);
        assert_eq!(metrics.outbox_pending, 2);
        assert_eq!(metrics.outbox_sent_unacked, 1);
        assert_eq!(metrics.outbox_dead_letter, 1);
        assert_eq!(metrics.outbox_retrying, 1);
        assert_eq!(metrics.step_replay_duplicate_window, 1);
        assert_eq!(metrics.dead_letter_window, 2);
        assert!(metrics.stage_latency.contains_key("new"));

        let report = db
            .slo_alert_report(60_000, 100, SloAlertThresholds::default())
            .await
            .expect("slo alerts");
        assert!(!report.ok);
        assert!(
            report
                .alerts
                .iter()
                .any(|a| a.metric == "workflows_stuck_total")
        );
        assert!(
            report
                .alerts
                .iter()
                .any(|a| a.metric == "dead_letter_window_total")
        );
        let _ = std::fs::remove_file(db_path);
    }
}
