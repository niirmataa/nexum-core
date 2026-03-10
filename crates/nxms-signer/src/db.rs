use crate::agent_support::now_ms;
use crate::audit_event::validate_known_audit_event_kind;
use anyhow::{Result, anyhow};
use rusqlite::{Connection, ErrorCode, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct SignerDb {
    path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingTxSign {
    pub id: i64,
    pub escrow_id_hex: String,
    pub from_id: String,
    pub to_id: String,
    pub seq: u64,
    pub action: String,
    pub snapshot_hash_hex: String,
    pub multisig_txset_hex: String,
    pub txset_hash_hex: String,
    pub describe_transfer_json: String,
    pub status: String,
    pub decision_reason: Option<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SnapshotRow {
    pub hash_hex: String,
    pub snapshot_json: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SignEventAuditRow {
    pub role: String,
    pub sign_round: String,
    pub txset_hash_hex: String,
    pub jti: String,
    pub req_id: String,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditLogRow {
    pub id: i64,
    pub event_kind: String,
    pub escrow_id_hex: String,
    pub from_id: Option<String>,
    pub to_id: Option<String>,
    pub seq: Option<u64>,
    pub envelope_hash_hex: Option<String>,
    pub payload_hash_hex: Option<String>,
    pub decision: Option<String>,
    pub detail: Option<String>,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditMetricRow {
    pub event_kind: String,
    pub count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SecurityMetricRow {
    pub metric: String,
    pub count: u64,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct SecurityMetricBucket {
    pub total: u64,
    pub reasons: std::collections::BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct SecurityDashboard {
    pub token_reject: SecurityMetricBucket,
    pub replay_reject: SecurityMetricBucket,
    pub policy_reject: SecurityMetricBucket,
    pub rpc_fail: SecurityMetricBucket,
    pub shadow_allow: SecurityMetricBucket,
}

#[derive(Clone, Debug, Serialize)]
pub struct SecurityAlertThresholds {
    pub token_reject_total: u64,
    pub replay_reject_total: u64,
    pub policy_reject_total: u64,
    pub rpc_fail_total: u64,
    pub shadow_allow_total: u64,
}

impl Default for SecurityAlertThresholds {
    fn default() -> Self {
        Self {
            token_reject_total: 5,
            replay_reject_total: 3,
            policy_reject_total: 1,
            rpc_fail_total: 2,
            shadow_allow_total: 1,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SecurityAlertItem {
    pub metric: String,
    pub observed: u64,
    pub threshold: u64,
    pub severity: String,
    pub action: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SecurityAlertReport {
    pub generated_at_ms: u64,
    pub window_ms: u64,
    pub thresholds: SecurityAlertThresholds,
    pub dashboard: SecurityDashboard,
    pub alerts: Vec<SecurityAlertItem>,
    pub ok: bool,
}

#[derive(Clone, Debug)]
pub struct AuditLogInsert<'a> {
    pub event_kind: &'a str,
    pub escrow_id_hex: &'a str,
    pub from_id: Option<&'a str>,
    pub to_id: Option<&'a str>,
    pub seq: Option<u64>,
    pub envelope_hash_hex: Option<&'a str>,
    pub payload_hash_hex: Option<&'a str>,
    pub decision: Option<&'a str>,
    pub detail: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct SnapshotSigRow {
    pub signer_id: String,
    pub sig_pk_b64: String,
    pub sig_b64: String,
    pub hash_hex: String,
    pub alg: String,
    pub created_at_unix_ms: u64,
}

#[derive(Clone, Debug)]
pub struct SignRequestRow {
    pub req_id: String,
    pub escrow_id_hex: String,
    pub op: String,
    pub sign_round: String,
    pub txset_hash_hex: String,
    pub status: String,
}

#[derive(Clone, Debug)]
pub struct SignEventRow {
    pub jti: String,
    pub req_id: String,
}

impl SignerDb {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub async fn init(&self) -> Result<()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || init_sync(&path)).await??;
        Ok(())
    }

    pub async fn record_incoming_seq(
        &self,
        escrow_id_hex: &str,
        from_id: &str,
        seq: u64,
    ) -> Result<()> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        let from_id = from_id.to_string();
        tokio::task::spawn_blocking(move || {
            record_incoming_seq_sync(&path, &escrow_id_hex, &from_id, seq)
        })
        .await??;
        Ok(())
    }

    pub async fn next_out_seq(&self, escrow_id_hex: &str, from_id: &str) -> Result<u64> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        let from_id = from_id.to_string();
        tokio::task::spawn_blocking(move || next_out_seq_sync(&path, &escrow_id_hex, &from_id))
            .await?
    }

    pub async fn put_snapshot_pending(
        &self,
        escrow_id_hex: &str,
        hash_hex: &str,
        snapshot_json: &str,
    ) -> Result<()> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        let hash_hex = hash_hex.to_string();
        let snapshot_json = snapshot_json.to_string();
        tokio::task::spawn_blocking(move || {
            put_snapshot_pending_sync(&path, &escrow_id_hex, &hash_hex, &snapshot_json)
        })
        .await??;
        Ok(())
    }

    pub async fn put_snapshot_signature(&self, sig: &SnapshotSigRow) -> Result<()> {
        let path = self.path.clone();
        let sig = sig.clone();
        tokio::task::spawn_blocking(move || put_snapshot_signature_sync(&path, &sig)).await??;
        Ok(())
    }

    pub async fn activate_snapshot(&self, hash_hex: &str, quorum: u32) -> Result<()> {
        let path = self.path.clone();
        let hash_hex = hash_hex.to_string();
        tokio::task::spawn_blocking(move || activate_snapshot_sync(&path, &hash_hex, quorum))
            .await??;
        Ok(())
    }

    pub async fn active_snapshot_for_escrow(
        &self,
        escrow_id_hex: &str,
    ) -> Result<Option<SnapshotRow>> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        tokio::task::spawn_blocking(move || active_snapshot_for_escrow_sync(&path, &escrow_id_hex))
            .await?
    }

    pub async fn enqueue_pending_tx(&self, pending: &PendingTxSign) -> Result<()> {
        let path = self.path.clone();
        let pending = pending.clone();
        tokio::task::spawn_blocking(move || enqueue_pending_tx_sync(&path, &pending)).await??;
        Ok(())
    }

    pub async fn list_pending(&self) -> Result<Vec<PendingTxSign>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || list_pending_sync(&path)).await?
    }

    pub async fn get_pending(&self, id: i64) -> Result<Option<PendingTxSign>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || get_pending_sync(&path, id)).await?
    }

    pub async fn set_pending_status(
        &self,
        id: i64,
        status: &str,
        decision_reason: Option<&str>,
    ) -> Result<()> {
        let path = self.path.clone();
        let status = status.to_string();
        let decision_reason = decision_reason.map(ToOwned::to_owned);
        tokio::task::spawn_blocking(move || {
            set_pending_status_sync(&path, id, &status, decision_reason.as_deref())
        })
        .await??;
        Ok(())
    }

    pub async fn start_sign_request(
        &self,
        req_id: &str,
        escrow_id_hex: &str,
        op: &str,
        sign_round: &str,
        txset_hash_hex: &str,
    ) -> Result<()> {
        let path = self.path.clone();
        let req_id = req_id.to_string();
        let escrow_id_hex = escrow_id_hex.to_string();
        let op = op.to_string();
        let sign_round = sign_round.to_string();
        let txset_hash_hex = txset_hash_hex.to_string();
        tokio::task::spawn_blocking(move || {
            start_sign_request_sync(
                &path,
                &req_id,
                &escrow_id_hex,
                &op,
                &sign_round,
                &txset_hash_hex,
            )
        })
        .await??;
        Ok(())
    }

    pub async fn get_sign_request(&self, req_id: &str) -> Result<Option<SignRequestRow>> {
        let path = self.path.clone();
        let req_id = req_id.to_string();
        tokio::task::spawn_blocking(move || get_sign_request_sync(&path, &req_id)).await?
    }

    pub async fn complete_sign_request(&self, req_id: &str) -> Result<()> {
        let path = self.path.clone();
        let req_id = req_id.to_string();
        tokio::task::spawn_blocking(move || complete_sign_request_sync(&path, &req_id)).await??;
        Ok(())
    }

    pub async fn complete_sign_request_with_result(
        &self,
        req_id: &str,
        op: &str,
        response_json: &str,
    ) -> Result<()> {
        let path = self.path.clone();
        let req_id = req_id.to_string();
        let op = op.to_string();
        let response_json = response_json.to_string();
        tokio::task::spawn_blocking(move || {
            complete_sign_request_with_result_sync(&path, &req_id, &op, &response_json)
        })
        .await??;
        Ok(())
    }

    pub async fn get_sign_request_result(&self, req_id: &str) -> Result<Option<String>> {
        let path = self.path.clone();
        let req_id = req_id.to_string();
        tokio::task::spawn_blocking(move || get_sign_request_result_sync(&path, &req_id)).await?
    }

    pub async fn abort_sign_request(&self, req_id: &str) -> Result<()> {
        let path = self.path.clone();
        let req_id = req_id.to_string();
        tokio::task::spawn_blocking(move || abort_sign_request_sync(&path, &req_id)).await??;
        Ok(())
    }

    pub async fn consume_action_jti(
        &self,
        jti: &str,
        escrow_id_hex: &str,
        op: &str,
        sign_round: &str,
        req_id: &str,
        exp_unix_s: u64,
    ) -> Result<()> {
        let path = self.path.clone();
        let jti = jti.to_string();
        let escrow_id_hex = escrow_id_hex.to_string();
        let op = op.to_string();
        let sign_round = sign_round.to_string();
        let req_id = req_id.to_string();
        tokio::task::spawn_blocking(move || {
            consume_action_jti_sync(
                &path,
                &jti,
                &escrow_id_hex,
                &op,
                &sign_round,
                &req_id,
                exp_unix_s,
            )
        })
        .await??;
        Ok(())
    }

    pub async fn record_sign_event(
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
            record_sign_event_sync(
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

    pub async fn has_sign_event(
        &self,
        escrow_id_hex: &str,
        role: &str,
        sign_round: &str,
        txset_hash_hex: &str,
    ) -> Result<bool> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        let role = role.to_string();
        let sign_round = sign_round.to_string();
        let txset_hash_hex = txset_hash_hex.to_string();
        tokio::task::spawn_blocking(move || {
            has_sign_event_sync(&path, &escrow_id_hex, &role, &sign_round, &txset_hash_hex)
        })
        .await?
    }

    pub async fn get_sign_event(
        &self,
        escrow_id_hex: &str,
        role: &str,
        sign_round: &str,
        txset_hash_hex: &str,
    ) -> Result<Option<SignEventRow>> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        let role = role.to_string();
        let sign_round = sign_round.to_string();
        let txset_hash_hex = txset_hash_hex.to_string();
        tokio::task::spawn_blocking(move || {
            get_sign_event_sync(&path, &escrow_id_hex, &role, &sign_round, &txset_hash_hex)
        })
        .await?
    }

    pub async fn append_audit_log(&self, event: AuditLogInsert<'_>) -> Result<()> {
        let path = self.path.clone();
        let event = AuditLogOwned::from(event);
        tokio::task::spawn_blocking(move || append_audit_log_sync(&path, &event)).await??;
        Ok(())
    }

    pub async fn list_audit_logs(&self, limit: u32) -> Result<Vec<AuditLogRow>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || list_audit_logs_sync(&path, limit)).await?
    }

    pub async fn list_audit_logs_for_escrow(
        &self,
        escrow_id_hex: &str,
        limit: u32,
    ) -> Result<Vec<AuditLogRow>> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        tokio::task::spawn_blocking(move || {
            list_audit_logs_for_escrow_sync(&path, &escrow_id_hex, limit)
        })
        .await?
    }

    pub async fn audit_metrics(&self) -> Result<Vec<AuditMetricRow>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || audit_metrics_sync(&path)).await?
    }

    pub async fn audit_security_metrics(&self) -> Result<Vec<SecurityMetricRow>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || audit_security_metrics_sync(&path, None)).await?
    }

    pub async fn audit_security_dashboard(&self) -> Result<SecurityDashboard> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || audit_security_dashboard_sync(&path, None)).await?
    }

    pub async fn audit_security_dashboard_window(
        &self,
        window_ms: u64,
    ) -> Result<SecurityDashboard> {
        let path = self.path.clone();
        let since_ms = now_ms().saturating_sub(window_ms.max(1));
        tokio::task::spawn_blocking(move || audit_security_dashboard_sync(&path, Some(since_ms)))
            .await?
    }

    pub async fn audit_security_alert_report(
        &self,
        window_ms: u64,
        thresholds: SecurityAlertThresholds,
    ) -> Result<SecurityAlertReport> {
        let dashboard = self.audit_security_dashboard_window(window_ms).await?;
        Ok(build_security_alert_report(
            window_ms, thresholds, dashboard,
        ))
    }

    pub async fn list_pending_for_escrow(&self, escrow_id_hex: &str) -> Result<Vec<PendingTxSign>> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        tokio::task::spawn_blocking(move || list_pending_for_escrow_sync(&path, &escrow_id_hex))
            .await?
    }

    pub async fn list_sign_events_for_escrow(
        &self,
        escrow_id_hex: &str,
    ) -> Result<Vec<SignEventAuditRow>> {
        let path = self.path.clone();
        let escrow_id_hex = escrow_id_hex.to_string();
        tokio::task::spawn_blocking(move || list_sign_events_for_escrow_sync(&path, &escrow_id_hex))
            .await?
    }
}

#[derive(Clone, Debug)]
struct AuditLogOwned {
    event_kind: String,
    escrow_id_hex: String,
    from_id: Option<String>,
    to_id: Option<String>,
    seq: Option<u64>,
    envelope_hash_hex: Option<String>,
    payload_hash_hex: Option<String>,
    decision: Option<String>,
    detail: Option<String>,
}

impl<'a> From<AuditLogInsert<'a>> for AuditLogOwned {
    fn from(value: AuditLogInsert<'a>) -> Self {
        Self {
            event_kind: value.event_kind.to_string(),
            escrow_id_hex: value.escrow_id_hex.to_string(),
            from_id: value.from_id.map(ToOwned::to_owned),
            to_id: value.to_id.map(ToOwned::to_owned),
            seq: value.seq,
            envelope_hash_hex: value.envelope_hash_hex.map(ToOwned::to_owned),
            payload_hash_hex: value.payload_hash_hex.map(ToOwned::to_owned),
            decision: value.decision.map(ToOwned::to_owned),
            detail: value.detail.map(ToOwned::to_owned),
        }
    }
}

fn open(path: &PathBuf) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    #[cfg(unix)]
    harden_sqlite_permissions(path.as_path())?;
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    #[cfg(unix)]
    harden_sqlite_permissions(path.as_path())?;
    Ok(conn)
}

#[cfg(unix)]
fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut out = path.as_os_str().to_os_string();
    out.push(suffix);
    PathBuf::from(out)
}

#[cfg(unix)]
fn harden_sqlite_permissions(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && parent.exists()
    {
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    for p in [
        path.to_path_buf(),
        sqlite_sidecar_path(path, "-wal"),
        sqlite_sidecar_path(path, "-shm"),
    ] {
        if p.exists() {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

fn init_sync(path: &PathBuf) -> Result<()> {
    let mut conn = open(path)?;
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = MEMORY;

        CREATE TABLE IF NOT EXISTS incoming_seen (
            escrow_id_hex        TEXT NOT NULL,
            from_id              TEXT NOT NULL,
            seq                  INTEGER NOT NULL,
            seen_at_ms           INTEGER NOT NULL,
            PRIMARY KEY (escrow_id_hex, from_id, seq)
        );

        CREATE TABLE IF NOT EXISTS out_seq (
            escrow_id_hex        TEXT NOT NULL,
            from_id              TEXT NOT NULL,
            last_seq             INTEGER NOT NULL,
            updated_at_ms        INTEGER NOT NULL,
            PRIMARY KEY (escrow_id_hex, from_id)
        );

        CREATE TABLE IF NOT EXISTS snapshots (
            hash_hex             TEXT PRIMARY KEY,
            escrow_id_hex        TEXT NOT NULL,
            snapshot_json        TEXT NOT NULL,
            status               TEXT NOT NULL CHECK(status IN ('pending', 'active')),
            created_at_ms        INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_snapshots_escrow_status ON snapshots(escrow_id_hex, status);

        CREATE TABLE IF NOT EXISTS snapshot_sigs (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            hash_hex             TEXT NOT NULL,
            signer_id            TEXT NOT NULL,
            sig_pk_b64           TEXT NOT NULL,
            sig_b64              TEXT NOT NULL,
            alg                  TEXT NOT NULL,
            created_at_unix_ms   INTEGER NOT NULL,
            UNIQUE(hash_hex, signer_id)
        );
        CREATE INDEX IF NOT EXISTS idx_snapshot_sigs_hash ON snapshot_sigs(hash_hex);

        CREATE TABLE IF NOT EXISTS pending_tx_sign (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            escrow_id_hex        TEXT NOT NULL,
            from_id              TEXT NOT NULL,
            to_id                TEXT NOT NULL,
            seq                  INTEGER NOT NULL,
            action               TEXT NOT NULL,
            snapshot_hash_hex    TEXT NOT NULL,
            multisig_txset_hex   TEXT NOT NULL,
            txset_hash_hex       TEXT NOT NULL,
            describe_transfer_json TEXT NOT NULL,
            status               TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'approved_sending', 'approved_sent', 'rejected_sending', 'rejected', 'error')),
            decision_reason      TEXT,
            created_at_ms        INTEGER NOT NULL,
            updated_at_ms        INTEGER NOT NULL,
            UNIQUE(escrow_id_hex, from_id, seq)
        );
        CREATE INDEX IF NOT EXISTS idx_pending_status_created ON pending_tx_sign(status, created_at_ms);

        CREATE TABLE IF NOT EXISTS sign_request_dedup (
            req_id                TEXT PRIMARY KEY,
            escrow_id_hex         TEXT NOT NULL,
            op                    TEXT NOT NULL,
            sign_round            TEXT NOT NULL,
            txset_hash_hex        TEXT NOT NULL,
            status                TEXT NOT NULL CHECK(status IN ('in_progress', 'completed')),
            created_at_ms         INTEGER NOT NULL,
            updated_at_ms         INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sign_request_dedup_escrow ON sign_request_dedup(escrow_id_hex, created_at_ms DESC);

        CREATE TABLE IF NOT EXISTS sign_request_result (
            req_id                TEXT PRIMARY KEY,
            op                    TEXT NOT NULL,
            response_json         TEXT NOT NULL,
            created_at_ms         INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sign_request_result_op_created ON sign_request_result(op, created_at_ms DESC);

        CREATE TABLE IF NOT EXISTS consumed_action_jti (
            jti                   TEXT PRIMARY KEY,
            escrow_id_hex         TEXT NOT NULL,
            op                    TEXT NOT NULL,
            sign_round            TEXT NOT NULL,
            req_id                TEXT NOT NULL,
            exp_unix_s            INTEGER NOT NULL,
            consumed_at_ms        INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_consumed_action_jti_escrow ON consumed_action_jti(escrow_id_hex, consumed_at_ms DESC);

        CREATE TABLE IF NOT EXISTS sign_events (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            escrow_id_hex         TEXT NOT NULL,
            role                  TEXT NOT NULL,
            sign_round            TEXT NOT NULL,
            txset_hash_hex        TEXT NOT NULL,
            jti                   TEXT NOT NULL,
            req_id                TEXT NOT NULL,
            created_at_ms         INTEGER NOT NULL,
            UNIQUE(escrow_id_hex, role, sign_round, txset_hash_hex),
            UNIQUE(jti),
            UNIQUE(req_id)
        );
        CREATE INDEX IF NOT EXISTS idx_sign_events_lookup ON sign_events(escrow_id_hex, txset_hash_hex, role, sign_round);

        CREATE TABLE IF NOT EXISTS audit_log (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            event_kind           TEXT NOT NULL,
            escrow_id_hex        TEXT NOT NULL,
            from_id              TEXT,
            to_id                TEXT,
            seq                  INTEGER,
            envelope_hash_hex    TEXT,
            payload_hash_hex     TEXT,
            decision             TEXT,
            detail               TEXT,
            created_at_ms        INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at_ms DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_log_escrow ON audit_log(escrow_id_hex, created_at_ms DESC);
        "#,
    )?;
    migrate_pending_tx_sign_schema_sync(&mut conn)?;
    Ok(())
}

fn migrate_pending_tx_sign_schema_sync(conn: &mut Connection) -> Result<()> {
    let create_sql: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='pending_tx_sign'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let Some(create_sql) = create_sql else {
        return Ok(());
    };
    let create_sql_lc = create_sql.to_ascii_lowercase();
    if create_sql_lc.contains("approved_sending")
        && create_sql_lc.contains("approved_sent")
        && create_sql_lc.contains("rejected_sending")
    {
        return Ok(());
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        r#"
        CREATE TABLE pending_tx_sign_new (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            escrow_id_hex        TEXT NOT NULL,
            from_id              TEXT NOT NULL,
            to_id                TEXT NOT NULL,
            seq                  INTEGER NOT NULL,
            action               TEXT NOT NULL,
            snapshot_hash_hex    TEXT NOT NULL,
            multisig_txset_hex   TEXT NOT NULL,
            txset_hash_hex       TEXT NOT NULL,
            describe_transfer_json TEXT NOT NULL,
            status               TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'approved_sending', 'approved_sent', 'rejected_sending', 'rejected', 'error')),
            decision_reason      TEXT,
            created_at_ms        INTEGER NOT NULL,
            updated_at_ms        INTEGER NOT NULL,
            UNIQUE(escrow_id_hex, from_id, seq)
        );
        INSERT INTO pending_tx_sign_new(
            id, escrow_id_hex, from_id, to_id, seq, action,
            snapshot_hash_hex, multisig_txset_hex, txset_hash_hex, describe_transfer_json,
            status, decision_reason, created_at_ms, updated_at_ms
        )
        SELECT
            id, escrow_id_hex, from_id, to_id, seq, action,
            snapshot_hash_hex, multisig_txset_hex, txset_hash_hex, describe_transfer_json,
            CASE
                WHEN status='approved' THEN 'approved_sent'
                ELSE status
            END,
            decision_reason, created_at_ms, updated_at_ms
        FROM pending_tx_sign;
        DROP TABLE pending_tx_sign;
        ALTER TABLE pending_tx_sign_new RENAME TO pending_tx_sign;
        CREATE INDEX IF NOT EXISTS idx_pending_status_created ON pending_tx_sign(status, created_at_ms);
        "#,
    )?;
    tx.commit()?;
    Ok(())
}

fn record_incoming_seq_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    from_id: &str,
    seq: u64,
) -> Result<()> {
    let mut conn = open(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let seq_i64 = i64::try_from(seq).unwrap_or(i64::MAX);

    let max_seen: Option<i64> = tx
        .query_row(
            "SELECT MAX(seq) FROM incoming_seen WHERE escrow_id_hex=?1 AND from_id=?2",
            params![escrow_id_hex, from_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();

    if let Some(max_seen) = max_seen
        && seq_i64 <= max_seen
    {
        return Err(anyhow!(
            "replay/out-of-order seq detected for ({}, {}): {} <= {}",
            escrow_id_hex,
            from_id,
            seq_i64,
            max_seen
        ));
    }

    let insert_res = tx.execute(
        "INSERT INTO incoming_seen(escrow_id_hex, from_id, seq, seen_at_ms) VALUES(?1, ?2, ?3, ?4)",
        params![
            escrow_id_hex,
            from_id,
            seq_i64,
            i64::try_from(now_ms()).unwrap_or(i64::MAX)
        ],
    );
    match insert_res {
        Ok(_) => {}
        Err(err) if is_unique_violation(&err) => {
            return Err(anyhow!(
                "replay seq detected for ({}, {}, {})",
                escrow_id_hex,
                from_id,
                seq
            ));
        }
        Err(err) => return Err(err.into()),
    }

    tx.commit()?;
    Ok(())
}

fn next_out_seq_sync(path: &PathBuf, escrow_id_hex: &str, from_id: &str) -> Result<u64> {
    let mut conn = open(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let current: Option<i64> = tx
        .query_row(
            "SELECT last_seq FROM out_seq WHERE escrow_id_hex=?1 AND from_id=?2",
            params![escrow_id_hex, from_id],
            |row| row.get(0),
        )
        .optional()?;
    let next = current.unwrap_or(0).saturating_add(1).max(1);
    tx.execute(
        r#"
        INSERT INTO out_seq(escrow_id_hex, from_id, last_seq, updated_at_ms)
        VALUES(?1, ?2, ?3, ?4)
        ON CONFLICT(escrow_id_hex, from_id) DO UPDATE SET
            last_seq=excluded.last_seq,
            updated_at_ms=excluded.updated_at_ms
        "#,
        params![
            escrow_id_hex,
            from_id,
            next,
            i64::try_from(now_ms()).unwrap_or(i64::MAX)
        ],
    )?;
    tx.commit()?;
    Ok(u64::try_from(next).unwrap_or(u64::MAX))
}

fn put_snapshot_pending_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    hash_hex: &str,
    snapshot_json: &str,
) -> Result<()> {
    let conn = open(path)?;
    conn.execute(
        r#"
        INSERT INTO snapshots(hash_hex, escrow_id_hex, snapshot_json, status, created_at_ms)
        VALUES(?1, ?2, ?3, 'pending', ?4)
        ON CONFLICT(hash_hex) DO UPDATE SET
            snapshot_json=excluded.snapshot_json
        "#,
        params![
            hash_hex,
            escrow_id_hex,
            snapshot_json,
            i64::try_from(now_ms()).unwrap_or(i64::MAX)
        ],
    )?;
    Ok(())
}

fn put_snapshot_signature_sync(path: &PathBuf, sig: &SnapshotSigRow) -> Result<()> {
    let conn = open(path)?;
    conn.execute(
        r#"
        INSERT INTO snapshot_sigs(hash_hex, signer_id, sig_pk_b64, sig_b64, alg, created_at_unix_ms)
        VALUES(?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(hash_hex, signer_id) DO UPDATE SET
            sig_pk_b64=excluded.sig_pk_b64,
            sig_b64=excluded.sig_b64,
            alg=excluded.alg,
            created_at_unix_ms=excluded.created_at_unix_ms
        "#,
        params![
            sig.hash_hex,
            sig.signer_id,
            sig.sig_pk_b64,
            sig.sig_b64,
            sig.alg,
            i64::try_from(sig.created_at_unix_ms).unwrap_or(i64::MAX),
        ],
    )?;
    Ok(())
}

fn activate_snapshot_sync(path: &PathBuf, hash_hex: &str, quorum: u32) -> Result<()> {
    let mut conn = open(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let sig_count: i64 = tx.query_row(
        "SELECT COUNT(1) FROM snapshot_sigs WHERE hash_hex=?1",
        params![hash_hex],
        |row| row.get(0),
    )?;
    if sig_count < i64::from(quorum) {
        return Err(anyhow!(
            "snapshot {} has {} signatures but quorum is {}",
            hash_hex,
            sig_count,
            quorum
        ));
    }

    let escrow_id_hex: String = tx
        .query_row(
            "SELECT escrow_id_hex FROM snapshots WHERE hash_hex=?1",
            params![hash_hex],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| anyhow!("snapshot {} not found", hash_hex))?;

    tx.execute(
        "UPDATE snapshots SET status='pending' WHERE escrow_id_hex=?1",
        params![escrow_id_hex],
    )?;
    tx.execute(
        "UPDATE snapshots SET status='active' WHERE hash_hex=?1",
        params![hash_hex],
    )?;
    tx.commit()?;
    Ok(())
}

fn active_snapshot_for_escrow_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
) -> Result<Option<SnapshotRow>> {
    let conn = open(path)?;
    conn.query_row(
        r#"
        SELECT hash_hex, escrow_id_hex, snapshot_json, status, created_at_ms
        FROM snapshots
        WHERE escrow_id_hex=?1 AND status='active'
        ORDER BY created_at_ms DESC
        LIMIT 1
        "#,
        params![escrow_id_hex],
        |row| {
            Ok(SnapshotRow {
                hash_hex: row.get(0)?,
                snapshot_json: row.get(2)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn enqueue_pending_tx_sync(path: &PathBuf, pending: &PendingTxSign) -> Result<()> {
    let conn = open(path)?;
    conn.execute(
        r#"
        INSERT INTO pending_tx_sign(
            escrow_id_hex, from_id, to_id, seq, action,
            snapshot_hash_hex, multisig_txset_hex, txset_hash_hex, describe_transfer_json,
            status, decision_reason, created_at_ms, updated_at_ms
        ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
        ON CONFLICT(escrow_id_hex, from_id, seq) DO UPDATE SET
            action=excluded.action,
            snapshot_hash_hex=excluded.snapshot_hash_hex,
            multisig_txset_hex=excluded.multisig_txset_hex,
            txset_hash_hex=excluded.txset_hash_hex,
            describe_transfer_json=excluded.describe_transfer_json,
            status=excluded.status,
            decision_reason=excluded.decision_reason,
            updated_at_ms=excluded.updated_at_ms
        "#,
        params![
            pending.escrow_id_hex,
            pending.from_id,
            pending.to_id,
            i64::try_from(pending.seq).unwrap_or(i64::MAX),
            pending.action,
            pending.snapshot_hash_hex,
            pending.multisig_txset_hex,
            pending.txset_hash_hex,
            pending.describe_transfer_json,
            pending.status,
            pending.decision_reason,
            i64::try_from(pending.created_at_ms).unwrap_or(i64::MAX),
            i64::try_from(pending.updated_at_ms).unwrap_or(i64::MAX),
        ],
    )?;
    Ok(())
}

fn list_pending_sync(path: &PathBuf) -> Result<Vec<PendingTxSign>> {
    let conn = open(path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT id, escrow_id_hex, from_id, to_id, seq, action, snapshot_hash_hex,
               multisig_txset_hex, txset_hash_hex, describe_transfer_json, status, decision_reason,
               created_at_ms, updated_at_ms
        FROM pending_tx_sign
        ORDER BY created_at_ms DESC
        "#,
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_pending(row)?);
    }
    Ok(out)
}

fn get_pending_sync(path: &PathBuf, id: i64) -> Result<Option<PendingTxSign>> {
    let conn = open(path)?;
    conn.query_row(
        r#"
        SELECT id, escrow_id_hex, from_id, to_id, seq, action, snapshot_hash_hex,
               multisig_txset_hex, txset_hash_hex, describe_transfer_json, status, decision_reason,
               created_at_ms, updated_at_ms
        FROM pending_tx_sign
        WHERE id=?1
        "#,
        params![id],
        row_to_pending,
    )
    .optional()
    .map_err(Into::into)
}

fn set_pending_status_sync(
    path: &PathBuf,
    id: i64,
    status: &str,
    decision_reason: Option<&str>,
) -> Result<()> {
    let conn = open(path)?;
    let n = conn.execute(
        "UPDATE pending_tx_sign SET status=?1, decision_reason=?2, updated_at_ms=?3 WHERE id=?4",
        params![
            status,
            decision_reason,
            i64::try_from(now_ms()).unwrap_or(i64::MAX),
            id
        ],
    )?;
    if n == 0 {
        return Err(anyhow!("pending id {} not found", id));
    }
    Ok(())
}

fn start_sign_request_sync(
    path: &PathBuf,
    req_id: &str,
    escrow_id_hex: &str,
    op: &str,
    sign_round: &str,
    txset_hash_hex: &str,
) -> Result<()> {
    let conn = open(path)?;
    let insert_res = conn.execute(
        r#"
        INSERT INTO sign_request_dedup(
            req_id, escrow_id_hex, op, sign_round, txset_hash_hex, status, created_at_ms, updated_at_ms
        ) VALUES(?1, ?2, ?3, ?4, ?5, 'in_progress', ?6, ?7)
        "#,
        params![
            req_id,
            escrow_id_hex,
            op,
            sign_round,
            txset_hash_hex,
            i64::try_from(now_ms()).unwrap_or(i64::MAX),
            i64::try_from(now_ms()).unwrap_or(i64::MAX)
        ],
    );
    match insert_res {
        Ok(_) => Ok(()),
        Err(err) if is_unique_violation(&err) => Err(anyhow!("duplicate req_id: {}", req_id)),
        Err(err) => Err(err.into()),
    }
}

fn get_sign_request_sync(path: &PathBuf, req_id: &str) -> Result<Option<SignRequestRow>> {
    let conn = open(path)?;
    conn.query_row(
        r#"
        SELECT req_id, escrow_id_hex, op, sign_round, txset_hash_hex, status
        FROM sign_request_dedup
        WHERE req_id=?1
        LIMIT 1
        "#,
        params![req_id],
        |row| {
            Ok(SignRequestRow {
                req_id: row.get(0)?,
                escrow_id_hex: row.get(1)?,
                op: row.get(2)?,
                sign_round: row.get(3)?,
                txset_hash_hex: row.get(4)?,
                status: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn complete_sign_request_sync(path: &PathBuf, req_id: &str) -> Result<()> {
    let conn = open(path)?;
    let n = conn.execute(
        r#"
        UPDATE sign_request_dedup
        SET status='completed', updated_at_ms=?1
        WHERE req_id=?2 AND status='in_progress'
        "#,
        params![i64::try_from(now_ms()).unwrap_or(i64::MAX), req_id],
    )?;
    if n == 0 {
        return Err(anyhow!(
            "sign request {} not found or not in progress",
            req_id
        ));
    }
    Ok(())
}

fn complete_sign_request_with_result_sync(
    path: &PathBuf,
    req_id: &str,
    op: &str,
    response_json: &str,
) -> Result<()> {
    let mut conn = open(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let n = tx.execute(
        r#"
        UPDATE sign_request_dedup
        SET status='completed', updated_at_ms=?1
        WHERE req_id=?2 AND status='in_progress'
        "#,
        params![i64::try_from(now_ms()).unwrap_or(i64::MAX), req_id],
    )?;
    if n == 0 {
        return Err(anyhow!(
            "sign request {} not found or not in progress",
            req_id
        ));
    }
    tx.execute(
        r#"
        INSERT INTO sign_request_result(req_id, op, response_json, created_at_ms)
        VALUES(?1, ?2, ?3, ?4)
        "#,
        params![
            req_id,
            op,
            response_json,
            i64::try_from(now_ms()).unwrap_or(i64::MAX),
        ],
    )?;
    tx.commit()?;
    Ok(())
}

fn get_sign_request_result_sync(path: &PathBuf, req_id: &str) -> Result<Option<String>> {
    let conn = open(path)?;
    conn.query_row(
        "SELECT response_json FROM sign_request_result WHERE req_id=?1 LIMIT 1",
        params![req_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

fn abort_sign_request_sync(path: &PathBuf, req_id: &str) -> Result<()> {
    let conn = open(path)?;
    conn.execute(
        "DELETE FROM sign_request_dedup WHERE req_id=?1 AND status='in_progress'",
        params![req_id],
    )?;
    Ok(())
}

fn consume_action_jti_sync(
    path: &PathBuf,
    jti: &str,
    escrow_id_hex: &str,
    op: &str,
    sign_round: &str,
    req_id: &str,
    exp_unix_s: u64,
) -> Result<()> {
    let conn = open(path)?;
    let insert_res = conn.execute(
        r#"
        INSERT INTO consumed_action_jti(
            jti, escrow_id_hex, op, sign_round, req_id, exp_unix_s, consumed_at_ms
        ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
        params![
            jti,
            escrow_id_hex,
            op,
            sign_round,
            req_id,
            i64::try_from(exp_unix_s).unwrap_or(i64::MAX),
            i64::try_from(now_ms()).unwrap_or(i64::MAX)
        ],
    );
    match insert_res {
        Ok(_) => Ok(()),
        Err(err) if is_unique_violation(&err) => Err(anyhow!("replayed jti: {}", jti)),
        Err(err) => Err(err.into()),
    }
}

fn record_sign_event_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    role: &str,
    sign_round: &str,
    txset_hash_hex: &str,
    jti: &str,
    req_id: &str,
) -> Result<()> {
    let conn = open(path)?;
    conn.execute(
        r#"
        INSERT OR IGNORE INTO sign_events(
            escrow_id_hex, role, sign_round, txset_hash_hex, jti, req_id, created_at_ms
        ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
        params![
            escrow_id_hex,
            role,
            sign_round,
            txset_hash_hex,
            jti,
            req_id,
            i64::try_from(now_ms()).unwrap_or(i64::MAX)
        ],
    )?;
    Ok(())
}

fn has_sign_event_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    role: &str,
    sign_round: &str,
    txset_hash_hex: &str,
) -> Result<bool> {
    let conn = open(path)?;
    let exists: Option<i64> = conn
        .query_row(
            r#"
            SELECT 1 FROM sign_events
            WHERE escrow_id_hex=?1 AND role=?2 AND sign_round=?3 AND txset_hash_hex=?4
            LIMIT 1
            "#,
            params![escrow_id_hex, role, sign_round, txset_hash_hex],
            |row| row.get(0),
        )
        .optional()?;
    Ok(exists.is_some())
}

fn get_sign_event_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    role: &str,
    sign_round: &str,
    txset_hash_hex: &str,
) -> Result<Option<SignEventRow>> {
    let conn = open(path)?;
    conn.query_row(
        r#"
        SELECT jti, req_id
        FROM sign_events
        WHERE escrow_id_hex=?1 AND role=?2 AND sign_round=?3 AND txset_hash_hex=?4
        LIMIT 1
        "#,
        params![escrow_id_hex, role, sign_round, txset_hash_hex],
        |row| {
            Ok(SignEventRow {
                jti: row.get(0)?,
                req_id: row.get(1)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn append_audit_log_sync(path: &PathBuf, event: &AuditLogOwned) -> Result<()> {
    validate_known_audit_event_kind(&event.event_kind)?;
    let conn = open(path)?;
    conn.execute(
        r#"
        INSERT INTO audit_log(
            event_kind, escrow_id_hex, from_id, to_id, seq,
            envelope_hash_hex, payload_hash_hex, decision, detail, created_at_ms
        ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
        params![
            event.event_kind,
            event.escrow_id_hex,
            event.from_id,
            event.to_id,
            event.seq.map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
            event.envelope_hash_hex,
            event.payload_hash_hex,
            event.decision,
            event.detail,
            i64::try_from(now_ms()).unwrap_or(i64::MAX),
        ],
    )?;
    Ok(())
}

fn list_audit_logs_sync(path: &PathBuf, limit: u32) -> Result<Vec<AuditLogRow>> {
    let conn = open(path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT id, event_kind, escrow_id_hex, from_id, to_id, seq,
               envelope_hash_hex, payload_hash_hex, decision, detail, created_at_ms
        FROM audit_log
        ORDER BY id DESC
        LIMIT ?1
        "#,
    )?;
    let mut rows = stmt.query(params![i64::from(limit.max(1).min(5000))])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(AuditLogRow {
            id: row.get(0)?,
            event_kind: row.get(1)?,
            escrow_id_hex: row.get(2)?,
            from_id: row.get(3)?,
            to_id: row.get(4)?,
            seq: row
                .get::<_, Option<i64>>(5)?
                .and_then(|v| u64::try_from(v).ok()),
            envelope_hash_hex: row.get(6)?,
            payload_hash_hex: row.get(7)?,
            decision: row.get(8)?,
            detail: row.get(9)?,
            created_at_ms: u64::try_from(row.get::<_, i64>(10)?).unwrap_or(0),
        });
    }
    Ok(out)
}

fn list_audit_logs_for_escrow_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
    limit: u32,
) -> Result<Vec<AuditLogRow>> {
    let conn = open(path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT id, event_kind, escrow_id_hex, from_id, to_id, seq,
               envelope_hash_hex, payload_hash_hex, decision, detail, created_at_ms
        FROM audit_log
        WHERE escrow_id_hex = ?1
        ORDER BY id DESC
        LIMIT ?2
        "#,
    )?;
    let mut rows = stmt.query(params![escrow_id_hex, i64::from(limit.max(1).min(20000))])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(AuditLogRow {
            id: row.get(0)?,
            event_kind: row.get(1)?,
            escrow_id_hex: row.get(2)?,
            from_id: row.get(3)?,
            to_id: row.get(4)?,
            seq: row
                .get::<_, Option<i64>>(5)?
                .and_then(|v| u64::try_from(v).ok()),
            envelope_hash_hex: row.get(6)?,
            payload_hash_hex: row.get(7)?,
            decision: row.get(8)?,
            detail: row.get(9)?,
            created_at_ms: u64::try_from(row.get::<_, i64>(10)?).unwrap_or(0),
        });
    }
    Ok(out)
}

fn audit_metrics_sync(path: &PathBuf) -> Result<Vec<AuditMetricRow>> {
    let conn = open(path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT event_kind, COUNT(1) AS c
        FROM audit_log
        GROUP BY event_kind
        ORDER BY c DESC, event_kind ASC
        "#,
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(AuditMetricRow {
            event_kind: row.get(0)?,
            count: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
        });
    }
    Ok(out)
}

fn audit_security_metrics_sync(
    path: &PathBuf,
    since_ms: Option<u64>,
) -> Result<Vec<SecurityMetricRow>> {
    let conn = open(path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT event_kind, detail
        FROM audit_log
        WHERE (?1 IS NULL OR created_at_ms >= ?1)
        ORDER BY id ASC
        "#,
    )?;
    let since_i64 = since_ms.map(|v| i64::try_from(v).unwrap_or(i64::MAX));
    let mut rows = stmt.query(params![since_i64])?;
    let mut out = std::collections::BTreeMap::<String, u64>::new();
    while let Some(row) = rows.next()? {
        let event_kind: String = row.get(0)?;
        let detail: Option<String> = row.get(1)?;
        for metric in classify_security_metric_labels(&event_kind, detail.as_deref()) {
            *out.entry(metric).or_insert(0) += 1;
        }
    }
    Ok(out
        .into_iter()
        .map(|(metric, count)| SecurityMetricRow { metric, count })
        .collect())
}

fn list_pending_for_escrow_sync(path: &PathBuf, escrow_id_hex: &str) -> Result<Vec<PendingTxSign>> {
    let conn = open(path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT id, escrow_id_hex, from_id, to_id, seq, action, snapshot_hash_hex,
               multisig_txset_hex, txset_hash_hex, describe_transfer_json, status, decision_reason,
               created_at_ms, updated_at_ms
        FROM pending_tx_sign
        WHERE escrow_id_hex=?1
        ORDER BY created_at_ms DESC, id DESC
        "#,
    )?;
    let mut rows = stmt.query(params![escrow_id_hex])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_pending(row)?);
    }
    Ok(out)
}

fn list_sign_events_for_escrow_sync(
    path: &PathBuf,
    escrow_id_hex: &str,
) -> Result<Vec<SignEventAuditRow>> {
    let conn = open(path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT role, sign_round, txset_hash_hex, jti, req_id, created_at_ms
        FROM sign_events
        WHERE escrow_id_hex=?1
        ORDER BY created_at_ms DESC, id DESC
        "#,
    )?;
    let mut rows = stmt.query(params![escrow_id_hex])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(SignEventAuditRow {
            role: row.get(0)?,
            sign_round: row.get(1)?,
            txset_hash_hex: row.get(2)?,
            jti: row.get(3)?,
            req_id: row.get(4)?,
            created_at_ms: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(0),
        });
    }
    Ok(out)
}

fn audit_security_dashboard_sync(
    path: &PathBuf,
    since_ms: Option<u64>,
) -> Result<SecurityDashboard> {
    let rows = audit_security_metrics_sync(path, since_ms)?;
    let mut dashboard = SecurityDashboard::default();
    for row in rows {
        let (prefix, reason) = match row.metric.split_once('.') {
            Some((p, r)) => (p, r),
            None => continue,
        };
        let bucket = match prefix {
            "token_reject_reason" => &mut dashboard.token_reject,
            "replay_reject" => &mut dashboard.replay_reject,
            "policy_reject" => &mut dashboard.policy_reject,
            "rpc_fail" => &mut dashboard.rpc_fail,
            "shadow_allow" => &mut dashboard.shadow_allow,
            _ => continue,
        };
        bucket.total = bucket.total.saturating_add(row.count);
        bucket
            .reasons
            .entry(reason.to_string())
            .and_modify(|v| *v = v.saturating_add(row.count))
            .or_insert(row.count);
    }
    Ok(dashboard)
}

fn build_security_alert_report(
    window_ms: u64,
    thresholds: SecurityAlertThresholds,
    dashboard: SecurityDashboard,
) -> SecurityAlertReport {
    let mut alerts = Vec::<SecurityAlertItem>::new();
    if dashboard.token_reject.total >= thresholds.token_reject_total {
        alerts.push(SecurityAlertItem {
            metric: "token_reject_total".to_string(),
            observed: dashboard.token_reject.total,
            threshold: thresholds.token_reject_total,
            severity: "high".to_string(),
            action:
                "Investigate capability-token issuance/validation drift and clock skew; rotate auth keys if suspicious"
                    .to_string(),
        });
    }
    if dashboard.replay_reject.total >= thresholds.replay_reject_total {
        alerts.push(SecurityAlertItem {
            metric: "replay_reject_total".to_string(),
            observed: dashboard.replay_reject.total,
            threshold: thresholds.replay_reject_total,
            severity: "high".to_string(),
            action:
                "Investigate replay attempts (jti/req_id/seq), block offending actors, verify single-use token enforcement"
                    .to_string(),
        });
    }
    if dashboard.policy_reject.total >= thresholds.policy_reject_total {
        alerts.push(SecurityAlertItem {
            metric: "policy_reject_total".to_string(),
            observed: dashboard.policy_reject.total,
            threshold: thresholds.policy_reject_total,
            severity: "critical".to_string(),
            action:
                "Pause release/refund automation for affected escrow IDs and review snapshot vs txset policy mismatches"
                    .to_string(),
        });
    }
    if dashboard.rpc_fail.total >= thresholds.rpc_fail_total {
        alerts.push(SecurityAlertItem {
            metric: "rpc_fail_total".to_string(),
            observed: dashboard.rpc_fail.total,
            threshold: thresholds.rpc_fail_total,
            severity: "critical".to_string(),
            action:
                "Check wallet-rpc/node health, transport path, and sandbox connectivity before resuming submit flow"
                    .to_string(),
        });
    }
    if dashboard.shadow_allow.total >= thresholds.shadow_allow_total {
        alerts.push(SecurityAlertItem {
            metric: "shadow_allow_total".to_string(),
            observed: dashboard.shadow_allow.total,
            threshold: thresholds.shadow_allow_total,
            severity: "high".to_string(),
            action:
                "Complete Stage-2 shadow window and force hard-fail action-token mode for sign/submit paths"
                    .to_string(),
        });
    }

    SecurityAlertReport {
        generated_at_ms: now_ms(),
        window_ms,
        thresholds,
        dashboard,
        ok: alerts.is_empty(),
        alerts,
    }
}

fn classify_security_metric_labels(event_kind: &str, detail: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let detail_lc = detail.unwrap_or_default().to_ascii_lowercase();
    if let Some(reason) = classify_token_reject_reason(&detail_lc) {
        out.push(format!("token_reject_reason.{reason}"));
    }
    if let Some(reason) = classify_replay_reject_reason(event_kind, &detail_lc) {
        out.push(format!("replay_reject.{reason}"));
    }
    if let Some(reason) = classify_policy_reject_reason(&detail_lc) {
        out.push(format!("policy_reject.{reason}"));
    }
    if let Some(reason) = classify_rpc_fail_reason(&detail_lc) {
        out.push(format!("rpc_fail.{reason}"));
    }
    if let Some(reason) = classify_shadow_allow_reason(event_kind) {
        out.push(format!("shadow_allow.{reason}"));
    }
    out
}

fn classify_token_reject_reason(detail_lc: &str) -> Option<&'static str> {
    let has_token_context = detail_lc.contains("action token")
        || detail_lc.contains("token required")
        || detail_lc.contains("issuer mismatch")
        || detail_lc.contains("audience mismatch")
        || detail_lc.contains("scope/op mismatch")
        || detail_lc.contains("sign_round mismatch")
        || detail_lc.contains("role mismatch")
        || detail_lc.contains("wallet_id mismatch")
        || detail_lc.contains("sandbox_id mismatch")
        || detail_lc.contains("escrow_id mismatch")
        || detail_lc.contains("nettype mismatch");
    if !has_token_context {
        return None;
    }
    if detail_lc.contains("replayed jti") {
        return Some("replayed_jti");
    }
    if detail_lc.contains("scope/op mismatch") {
        return Some("scope_op_mismatch");
    }
    if detail_lc.contains("sign_round mismatch") {
        return Some("sign_round_mismatch");
    }
    if detail_lc.contains("role mismatch") {
        return Some("role_mismatch");
    }
    if detail_lc.contains("issuer mismatch") {
        return Some("issuer_mismatch");
    }
    if detail_lc.contains("audience mismatch") {
        return Some("audience_mismatch");
    }
    if detail_lc.contains("wallet_id mismatch") {
        return Some("wallet_id_mismatch");
    }
    if detail_lc.contains("sandbox_id mismatch") {
        return Some("sandbox_id_mismatch");
    }
    if detail_lc.contains("escrow_id mismatch") {
        return Some("escrow_id_mismatch");
    }
    if detail_lc.contains("nettype mismatch") {
        return Some("nettype_mismatch");
    }
    if detail_lc.contains("required") {
        return Some("missing_token");
    }
    Some("other")
}

fn classify_replay_reject_reason(event_kind: &str, detail_lc: &str) -> Option<&'static str> {
    if event_kind == "rx_rejected_replay" {
        return Some("seq_replay");
    }
    if detail_lc.contains("replayed jti") {
        return Some("jti_replay");
    }
    if detail_lc.contains("duplicate req_id") {
        return Some("req_id_duplicate");
    }
    None
}

fn classify_policy_reject_reason(detail_lc: &str) -> Option<&'static str> {
    if detail_lc.contains("submit denied: missing local quorum proof") {
        return Some("missing_local_quorum");
    }
    if detail_lc.contains("submit denied: missing seller quorum proof") {
        return Some("missing_seller_quorum");
    }
    if detail_lc.contains("describe_transfer") {
        return Some("describe_transfer");
    }
    if detail_lc.contains("snapshot mismatch") || detail_lc.contains("no active snapshot") {
        return Some("snapshot_mismatch");
    }
    if detail_lc.contains("policy check failed") || detail_lc.contains("policy") {
        return Some("policy_mismatch");
    }
    None
}

fn classify_rpc_fail_reason(detail_lc: &str) -> Option<&'static str> {
    if !(detail_lc.contains("wallet-rpc")
        || detail_lc.contains("wallet rpc")
        || detail_lc.contains("connection refused")
        || detail_lc.contains("timed out")
        || detail_lc.contains("rpc"))
    {
        return None;
    }
    if detail_lc.contains("timed out") {
        return Some("timeout");
    }
    if detail_lc.contains("connection") || detail_lc.contains("refused") {
        return Some("transport");
    }
    if detail_lc.contains("http status") {
        return Some("http_status");
    }
    Some("other")
}

fn classify_shadow_allow_reason(event_kind: &str) -> Option<&'static str> {
    match event_kind {
        "sign_shadow_allow" => Some("sign_multisig"),
        "submit_shadow_allow" => Some("submit_multisig"),
        _ => None,
    }
}

fn row_to_pending(row: &rusqlite::Row<'_>) -> rusqlite::Result<PendingTxSign> {
    Ok(PendingTxSign {
        id: row.get(0)?,
        escrow_id_hex: row.get(1)?,
        from_id: row.get(2)?,
        to_id: row.get(3)?,
        seq: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
        action: row.get(5)?,
        snapshot_hash_hex: row.get(6)?,
        multisig_txset_hex: row.get(7)?,
        txset_hash_hex: row.get(8)?,
        describe_transfer_json: row.get(9)?,
        status: row.get(10)?,
        decision_reason: row.get(11)?,
        created_at_ms: u64::try_from(row.get::<_, i64>(12)?).unwrap_or(0),
        updated_at_ms: u64::try_from(row.get::<_, i64>(13)?).unwrap_or(0),
    })
}

fn is_unique_violation(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(e, _) => matches!(e.code, ErrorCode::ConstraintViolation),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_db_path(label: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "nxms_signer_test_{label}_{}_{}.db",
            std::process::id(),
            ts
        ))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn init_hardens_sqlite_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base = std::env::temp_dir().join(format!(
            "nxms_signer_test_perm_{}_{}",
            std::process::id(),
            ts
        ));
        std::fs::create_dir_all(&base).expect("create base dir");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755))
            .expect("set loose dir mode");

        let db_path = base.join("audit.db");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        let db_mode = std::fs::metadata(&db_path)
            .expect("db metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(db_mode, 0o600, "sqlite db must be owner-only");

        let dir_mode = std::fs::metadata(&base)
            .expect("dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "db parent dir must be owner-only");

        for suffix in ["-wal", "-shm"] {
            let p = sqlite_sidecar_path(db_path.as_path(), suffix);
            if p.exists() {
                let mode = std::fs::metadata(&p)
                    .expect("sidecar metadata")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600, "sqlite sidecar must be owner-only");
                let _ = std::fs::remove_file(&p);
            }
        }
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&base);
    }

    #[tokio::test]
    async fn replay_guard_rejects_equal_or_lower_seq() {
        let db_path = unique_db_path("replay");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        db.record_incoming_seq("aabbccddeeff00112233445566778899", "alice", 10)
            .await
            .expect("seq10 ok");

        let err_equal = db
            .record_incoming_seq("aabbccddeeff00112233445566778899", "alice", 10)
            .await
            .expect_err("equal seq must fail");
        assert!(err_equal.to_string().contains("replay"));

        let err_lower = db
            .record_incoming_seq("aabbccddeeff00112233445566778899", "alice", 9)
            .await
            .expect_err("lower seq must fail");
        assert!(err_lower.to_string().contains("out-of-order"));

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn out_seq_is_monotonic_per_scope() {
        let db_path = unique_db_path("outseq");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        let s1 = db
            .next_out_seq("00112233445566778899aabbccddeeff", "arbiter")
            .await
            .expect("s1");
        let s2 = db
            .next_out_seq("00112233445566778899aabbccddeeff", "arbiter")
            .await
            .expect("s2");
        let s3 = db
            .next_out_seq("00112233445566778899aabbccddeeff", "arbiter")
            .await
            .expect("s3");
        assert_eq!((s1, s2, s3), (1, 2, 3));

        let other_scope = db
            .next_out_seq("00112233445566778899aabbccddeeff", "other")
            .await
            .expect("other scope");
        assert_eq!(other_scope, 1);

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn action_jti_consume_is_single_use() {
        let db_path = unique_db_path("jti_single_use");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        db.consume_action_jti(
            "jti-1",
            "00112233445566778899aabbccddeeff",
            "sign_multisig",
            "arbiter_first",
            "req-1",
            4_000_000_000,
        )
        .await
        .expect("first consume");
        let err = db
            .consume_action_jti(
                "jti-1",
                "00112233445566778899aabbccddeeff",
                "sign_multisig",
                "arbiter_first",
                "req-1",
                4_000_000_000,
            )
            .await
            .expect_err("replay must fail");
        assert!(err.to_string().contains("replayed jti"));

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn sign_request_dedup_blocks_completed_duplicate() {
        let db_path = unique_db_path("req_dedup");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        db.start_sign_request(
            "req-1",
            "00112233445566778899aabbccddeeff",
            "sign_multisig",
            "arbiter_first",
            &"11".repeat(32),
        )
        .await
        .expect("start");
        db.complete_sign_request("req-1").await.expect("complete");
        let err = db
            .start_sign_request(
                "req-1",
                "00112233445566778899aabbccddeeff",
                "sign_multisig",
                "arbiter_first",
                &"11".repeat(32),
            )
            .await
            .expect_err("duplicate req_id must fail");
        assert!(err.to_string().contains("duplicate req_id"));

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn complete_sign_request_with_result_roundtrip() {
        let db_path = unique_db_path("req_result");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        db.start_sign_request(
            "req-1",
            "00112233445566778899aabbccddeeff",
            "sign_multisig",
            "arbiter_first",
            &"11".repeat(32),
        )
        .await
        .expect("start");
        db.complete_sign_request_with_result(
            "req-1",
            "sign_multisig",
            r#"{"op":"sign_multisig","tx_data_hex":"aa11","tx_hash_list":["abcd"]}"#,
        )
        .await
        .expect("complete with result");

        let row = db
            .get_sign_request("req-1")
            .await
            .expect("get row")
            .expect("row exists");
        assert_eq!(row.req_id, "req-1");
        assert_eq!(row.status, "completed");
        assert_eq!(row.op, "sign_multisig");

        let result = db
            .get_sign_request_result("req-1")
            .await
            .expect("result")
            .expect("result exists");
        assert!(result.contains("\"tx_data_hex\":\"aa11\""));

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn sign_events_roundtrip() {
        let db_path = unique_db_path("sign_events");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        db.record_sign_event(
            "00112233445566778899aabbccddeeff",
            "arbiter",
            "arbiter_first",
            &"11".repeat(32),
            "jti-a",
            "req-a",
        )
        .await
        .expect("record");

        let row = db
            .get_sign_event(
                "00112233445566778899aabbccddeeff",
                "arbiter",
                "arbiter_first",
                &"11".repeat(32),
            )
            .await
            .expect("get event row")
            .expect("event row exists");
        assert_eq!(row.jti, "jti-a");
        assert_eq!(row.req_id, "req-a");

        let has = db
            .has_sign_event(
                "00112233445566778899aabbccddeeff",
                "arbiter",
                "arbiter_first",
                &"11".repeat(32),
            )
            .await
            .expect("has event");
        assert!(has);

        let missing = db
            .has_sign_event(
                "00112233445566778899aabbccddeeff",
                "seller",
                "seller_second",
                &"11".repeat(32),
            )
            .await
            .expect("missing");
        assert!(!missing);

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn escrow_scoped_queries_return_only_requested_escrow_records() {
        let db_path = unique_db_path("escrow_scoped_queries");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        let pending_a = PendingTxSign {
            id: 0,
            escrow_id_hex: "00112233445566778899aabbccddeeff".to_string(),
            from_id: "peer1".to_string(),
            to_id: "local".to_string(),
            seq: 1,
            action: "\"release\"".to_string(),
            snapshot_hash_hex: "11".repeat(32),
            multisig_txset_hex: "aa11".to_string(),
            txset_hash_hex: "22".repeat(32),
            describe_transfer_json: "{}".to_string(),
            status: "pending".to_string(),
            decision_reason: None,
            created_at_ms: now_ms(),
            updated_at_ms: now_ms(),
        };
        let pending_b = PendingTxSign {
            escrow_id_hex: "ffeeddccbbaa99887766554433221100".to_string(),
            ..pending_a.clone()
        };
        db.enqueue_pending_tx(&pending_a).await.expect("enqueue A");
        db.enqueue_pending_tx(&pending_b).await.expect("enqueue B");

        db.record_sign_event(
            "00112233445566778899aabbccddeeff",
            "arbiter",
            "arbiter_first",
            &"11".repeat(32),
            "jti-a",
            "req-a",
        )
        .await
        .expect("sign event A");
        db.record_sign_event(
            "ffeeddccbbaa99887766554433221100",
            "seller",
            "seller_second",
            &"22".repeat(32),
            "jti-b",
            "req-b",
        )
        .await
        .expect("sign event B");

        db.append_audit_log(AuditLogInsert {
            event_kind: "sign_attempt",
            escrow_id_hex: "00112233445566778899aabbccddeeff",
            from_id: Some("peer1"),
            to_id: Some("local"),
            seq: Some(1),
            envelope_hash_hex: None,
            payload_hash_hex: None,
            decision: Some("attempt"),
            detail: Some("escrow A"),
        })
        .await
        .expect("audit A");
        db.append_audit_log(AuditLogInsert {
            event_kind: "sign_attempt",
            escrow_id_hex: "ffeeddccbbaa99887766554433221100",
            from_id: Some("peer1"),
            to_id: Some("local"),
            seq: Some(1),
            envelope_hash_hex: None,
            payload_hash_hex: None,
            decision: Some("attempt"),
            detail: Some("escrow B"),
        })
        .await
        .expect("audit B");

        let pending = db
            .list_pending_for_escrow("00112233445566778899aabbccddeeff")
            .await
            .expect("pending for escrow");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].escrow_id_hex, "00112233445566778899aabbccddeeff");

        let sign_events = db
            .list_sign_events_for_escrow("00112233445566778899aabbccddeeff")
            .await
            .expect("sign events for escrow");
        assert_eq!(sign_events.len(), 1);
        assert_eq!(sign_events[0].jti, "jti-a");

        let audit = db
            .list_audit_logs_for_escrow("00112233445566778899aabbccddeeff", 50)
            .await
            .expect("audit for escrow");
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].escrow_id_hex, "00112233445566778899aabbccddeeff");

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn audit_log_roundtrip() {
        let db_path = unique_db_path("audit");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        let env_hash = "ee".repeat(32);
        let payload_hash = "ff".repeat(32);

        db.append_audit_log(AuditLogInsert {
            event_kind: "pending_enqueued",
            escrow_id_hex: "00112233445566778899aabbccddeeff",
            from_id: Some("alice"),
            to_id: Some("arbiter"),
            seq: Some(7),
            envelope_hash_hex: Some(&env_hash),
            payload_hash_hex: Some(&payload_hash),
            decision: None,
            detail: Some("queued"),
        })
        .await
        .expect("append");

        let rows = db.list_audit_logs(10).await.expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_kind, "pending_enqueued");
        assert_eq!(rows[0].seq, Some(7));

        let metrics = db.audit_metrics().await.expect("metrics");
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].event_kind, "pending_enqueued");
        assert_eq!(metrics[0].count, 1);

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn audit_log_rejects_unknown_event_kind() {
        let db_path = unique_db_path("audit_unknown_kind");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        let err = db
            .append_audit_log(AuditLogInsert {
                event_kind: "unknown_event_kind",
                escrow_id_hex: "00112233445566778899aabbccddeeff",
                from_id: None,
                to_id: None,
                seq: None,
                envelope_hash_hex: None,
                payload_hash_hex: None,
                decision: None,
                detail: None,
            })
            .await
            .expect_err("unknown event kind must fail");
        assert!(err.to_string().contains("unknown audit event kind"));

        let rows = db.list_audit_logs(10).await.expect("list");
        assert!(rows.is_empty());
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn audit_security_metrics_breakdown() {
        let db_path = unique_db_path("audit_security_metrics");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        let payload_hash = "aa".repeat(32);

        let events = vec![
            (
                "sign_reject",
                "op=sign_multisig reason=action token sign_round mismatch",
            ),
            (
                "sign_reject",
                "op=sign_multisig reason=replayed jti: abcdef",
            ),
            (
                "submit_reject",
                "op=submit_multisig reason=submit denied: missing local quorum proof event arbiter_first",
            ),
            (
                "submit_reject",
                "op=submit_multisig reason=wallet-rpc transport error: connection refused",
            ),
            ("sign_shadow_allow", "op=sign_multisig shadow mode allow"),
            ("rx_rejected_replay", "replay/out-of-order seq detected"),
        ];
        for (event_kind, detail) in events {
            db.append_audit_log(AuditLogInsert {
                event_kind,
                escrow_id_hex,
                from_id: Some("alice"),
                to_id: Some("arbiter"),
                seq: Some(1),
                envelope_hash_hex: None,
                payload_hash_hex: Some(&payload_hash),
                decision: Some("rejected"),
                detail: Some(detail),
            })
            .await
            .expect("append");
        }

        let rows = db
            .audit_security_metrics()
            .await
            .expect("audit security metrics");
        let mut by_name = std::collections::BTreeMap::<String, u64>::new();
        for row in rows {
            by_name.insert(row.metric, row.count);
        }
        assert_eq!(
            by_name.get("token_reject_reason.sign_round_mismatch"),
            Some(&1)
        );
        assert_eq!(by_name.get("replay_reject.jti_replay"), Some(&1));
        assert_eq!(by_name.get("replay_reject.seq_replay"), Some(&1));
        assert_eq!(by_name.get("policy_reject.missing_local_quorum"), Some(&1));
        assert_eq!(by_name.get("rpc_fail.transport"), Some(&1));
        assert_eq!(by_name.get("shadow_allow.sign_multisig"), Some(&1));

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn audit_security_dashboard_groups_metrics_by_bucket() {
        let db_path = unique_db_path("audit_security_dashboard");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        let payload_hash = "aa".repeat(32);
        let events = vec![
            (
                "sign_reject",
                "op=sign_multisig reason=action token role mismatch",
            ),
            (
                "sign_reject",
                "op=sign_multisig reason=replayed jti: abcdef",
            ),
            (
                "submit_reject",
                "op=submit_multisig reason=policy check failed during submit",
            ),
            (
                "submit_reject",
                "op=submit_multisig reason=wallet-rpc transport error: connection refused",
            ),
            ("sign_shadow_allow", "op=sign_multisig shadow mode allow"),
            ("rx_rejected_replay", "replay/out-of-order seq detected"),
        ];
        for (event_kind, detail) in events {
            db.append_audit_log(AuditLogInsert {
                event_kind,
                escrow_id_hex,
                from_id: Some("alice"),
                to_id: Some("arbiter"),
                seq: Some(1),
                envelope_hash_hex: None,
                payload_hash_hex: Some(&payload_hash),
                decision: Some("rejected"),
                detail: Some(detail),
            })
            .await
            .expect("append");
        }

        let dashboard = db.audit_security_dashboard().await.expect("dashboard");
        assert_eq!(dashboard.token_reject.total, 1);
        assert_eq!(dashboard.replay_reject.total, 2);
        assert_eq!(dashboard.policy_reject.total, 1);
        assert_eq!(dashboard.rpc_fail.total, 1);
        assert_eq!(dashboard.shadow_allow.total, 1);
        assert_eq!(
            dashboard.token_reject.reasons.get("role_mismatch"),
            Some(&1)
        );
        assert_eq!(dashboard.replay_reject.reasons.get("jti_replay"), Some(&1));
        assert_eq!(dashboard.replay_reject.reasons.get("seq_replay"), Some(&1));
        assert_eq!(
            dashboard.policy_reject.reasons.get("policy_mismatch"),
            Some(&1)
        );
        assert_eq!(dashboard.rpc_fail.reasons.get("transport"), Some(&1));
        assert_eq!(
            dashboard.shadow_allow.reasons.get("sign_multisig"),
            Some(&1)
        );

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn audit_security_alert_report_triggers_threshold_alerts() {
        let db_path = unique_db_path("audit_security_alerts");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        let payload_hash = "aa".repeat(32);
        let events = vec![
            (
                "sign_reject",
                "op=sign_multisig reason=action token role mismatch",
            ),
            (
                "sign_reject",
                "op=sign_multisig reason=replayed jti: abcdef",
            ),
            (
                "submit_reject",
                "op=submit_multisig reason=policy check failed during submit",
            ),
            (
                "submit_reject",
                "op=submit_multisig reason=wallet-rpc transport error: connection refused",
            ),
            ("sign_shadow_allow", "op=sign_multisig shadow mode allow"),
        ];
        for (event_kind, detail) in events {
            db.append_audit_log(AuditLogInsert {
                event_kind,
                escrow_id_hex,
                from_id: Some("alice"),
                to_id: Some("arbiter"),
                seq: Some(1),
                envelope_hash_hex: None,
                payload_hash_hex: Some(&payload_hash),
                decision: Some("rejected"),
                detail: Some(detail),
            })
            .await
            .expect("append");
        }

        let report = db
            .audit_security_alert_report(
                300_000,
                SecurityAlertThresholds {
                    token_reject_total: 1,
                    replay_reject_total: 1,
                    policy_reject_total: 1,
                    rpc_fail_total: 1,
                    shadow_allow_total: 1,
                },
            )
            .await
            .expect("alert report");
        assert!(!report.ok);
        assert_eq!(report.alerts.len(), 5);
        assert!(
            report
                .alerts
                .iter()
                .any(|a| a.metric == "policy_reject_total" && a.severity == "critical")
        );
        assert!(
            report
                .alerts
                .iter()
                .any(|a| a.metric == "rpc_fail_total" && a.severity == "critical")
        );
        assert!(
            report
                .alerts
                .iter()
                .any(|a| a.metric == "shadow_allow_total" && a.severity == "high")
        );

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn audit_security_alert_report_window_ignores_old_events() {
        let db_path = unique_db_path("audit_security_alerts_window");
        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init");

        let now = now_ms();
        let old_ms = now.saturating_sub(3_600_000);
        let conn = Connection::open(&db_path).expect("open db");
        conn.execute(
            r#"
            INSERT INTO audit_log(
                event_kind, escrow_id_hex, from_id, to_id, seq,
                envelope_hash_hex, payload_hash_hex, decision, detail, created_at_ms
            ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                "submit_reject",
                "00112233445566778899aabbccddeeff",
                "alice",
                "arbiter",
                1_i64,
                Option::<String>::None,
                Option::<String>::None,
                "rejected",
                "op=submit_multisig reason=wallet-rpc transport error: connection refused",
                i64::try_from(old_ms).unwrap_or(i64::MAX),
            ],
        )
        .expect("insert old audit row");

        db.append_audit_log(AuditLogInsert {
            event_kind: "submit_reject",
            escrow_id_hex: "00112233445566778899aabbccddeeff",
            from_id: Some("alice"),
            to_id: Some("arbiter"),
            seq: Some(1),
            envelope_hash_hex: None,
            payload_hash_hex: None,
            decision: Some("rejected"),
            detail: Some(
                "op=submit_multisig reason=wallet-rpc transport error: connection refused",
            ),
        })
        .await
        .expect("append recent");

        let report = db
            .audit_security_alert_report(
                120_000,
                SecurityAlertThresholds {
                    token_reject_total: 10,
                    replay_reject_total: 10,
                    policy_reject_total: 10,
                    rpc_fail_total: 2,
                    shadow_allow_total: 10,
                },
            )
            .await
            .expect("window report");
        assert!(report.ok, "recent window should not include old rpc error");
        assert_eq!(report.dashboard.rpc_fail.total, 1);

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn init_migrates_pending_status_constraint_and_normalizes_approved() {
        let db_path = unique_db_path("pending_status_migration");
        {
            let conn = Connection::open(&db_path).expect("open legacy db");
            conn.execute_batch(
                r#"
                CREATE TABLE pending_tx_sign (
                    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                    escrow_id_hex        TEXT NOT NULL,
                    from_id              TEXT NOT NULL,
                    to_id                TEXT NOT NULL,
                    seq                  INTEGER NOT NULL,
                    action               TEXT NOT NULL,
                    snapshot_hash_hex    TEXT NOT NULL,
                    multisig_txset_hex   TEXT NOT NULL,
                    txset_hash_hex       TEXT NOT NULL,
                    describe_transfer_json TEXT NOT NULL,
                    status               TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected', 'error')),
                    decision_reason      TEXT,
                    created_at_ms        INTEGER NOT NULL,
                    updated_at_ms        INTEGER NOT NULL,
                    UNIQUE(escrow_id_hex, from_id, seq)
                );
                INSERT INTO pending_tx_sign(
                    escrow_id_hex, from_id, to_id, seq, action,
                    snapshot_hash_hex, multisig_txset_hex, txset_hash_hex, describe_transfer_json,
                    status, decision_reason, created_at_ms, updated_at_ms
                ) VALUES(
                    '00112233445566778899aabbccddeeff', 'peer1', 'local', 1, '\"release\"',
                    '11', 'aa11', '22', '{}',
                    'approved', NULL, 1, 1
                );
                "#,
            )
            .expect("seed legacy table");
        }

        let db = SignerDb::new(db_path.clone());
        db.init().await.expect("init with migration");
        let row = db.get_pending(1).await.expect("get pending").expect("row");
        assert_eq!(row.status, "approved_sent");

        db.set_pending_status(1, "approved_sending", Some("{\"k\":\"v\"}"))
            .await
            .expect("new status should be accepted after migration");
        let row = db.get_pending(1).await.expect("get pending").expect("row");
        assert_eq!(row.status, "approved_sending");

        db.set_pending_status(1, "rejected_sending", Some("{\"k\":\"v\"}"))
            .await
            .expect("rejected_sending should be accepted after migration");
        let row = db.get_pending(1).await.expect("get pending").expect("row");
        assert_eq!(row.status, "rejected_sending");

        let _ = std::fs::remove_file(db_path);
    }
}
