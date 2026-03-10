use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use nxms_transport::wire::{NxmsEnvelope, msg_type_key};
use rand::RngCore;
use rusqlite::{Connection, ErrorCode, OptionalExtension, TransactionBehavior, params};

#[derive(Clone)]
pub(crate) struct SqliteMailboxDb {
    path: PathBuf,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MailboxLimits {
    pub max_messages_per_inbox: u64,
    pub max_bytes_per_inbox: u64,
    pub max_rows_global: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct PushResult {
    pub dedup: bool,
    pub rejection: Option<PushRejection>,
}

#[derive(Clone, Debug)]
pub(crate) struct LeasedMessage {
    pub receipt: String,
    pub envelope: NxmsEnvelope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PushRejection {
    InboxMessageLimit,
    InboxBytesLimit,
    GlobalRowsLimit,
}

#[derive(Clone, Debug)]
pub(crate) struct MailboxStats {
    pub total_rows: u64,
    pub db_bytes: u64,
    pub wal_bytes: u64,
    pub inboxes: Vec<InboxStats>,
}

#[derive(Clone, Debug)]
pub(crate) struct InboxStats {
    pub to: String,
    pub backlog_count: u64,
    pub oldest_age_secs: u64,
    pub bytes: u64,
}

impl SqliteMailboxDb {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) async fn init(&self) -> Result<(), String> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || init_sync(&path))
            .await
            .map_err(|e| e.to_string())?
    }

    pub(crate) async fn push(
        &self,
        env: &NxmsEnvelope,
        ttl_secs: u64,
        limits: MailboxLimits,
    ) -> Result<PushResult, String> {
        let path = self.path.clone();
        let env = env.clone();
        tokio::task::spawn_blocking(move || push_sync(&path, &env, ttl_secs, limits))
            .await
            .map_err(|e| e.to_string())?
    }

    pub(crate) async fn pull(
        &self,
        to: &str,
        max: u32,
        lease_secs: u64,
    ) -> Result<Vec<LeasedMessage>, String> {
        let path = self.path.clone();
        let to = to.to_string();
        tokio::task::spawn_blocking(move || pull_sync(&path, &to, max, lease_secs))
            .await
            .map_err(|e| e.to_string())?
    }

    pub(crate) async fn ack(&self, receipt: &str) -> Result<bool, String> {
        let path = self.path.clone();
        let receipt = receipt.to_string();
        tokio::task::spawn_blocking(move || ack_sync(&path, &receipt))
            .await
            .map_err(|e| e.to_string())?
    }

    pub(crate) async fn cleanup_expired(&self) -> Result<(), String> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || cleanup_expired_sync(&path))
            .await
            .map_err(|e| e.to_string())?
    }

    pub(crate) async fn stats(&self) -> Result<MailboxStats, String> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || stats_sync(&path))
            .await
            .map_err(|e| e.to_string())?
    }

    pub(crate) async fn wal_checkpoint_truncate(&self) -> Result<(), String> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || wal_checkpoint_truncate_sync(&path))
            .await
            .map_err(|e| e.to_string())?
    }

    pub(crate) async fn vacuum(&self) -> Result<(), String> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || vacuum_sync(&path))
            .await
            .map_err(|e| e.to_string())?
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn init_sync(path: &PathBuf) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }

    let conn = open(path)?;

    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = MEMORY;
        PRAGMA foreign_keys = ON;
        "#,
    )
    .map_err(|e| e.to_string())?;

    // Schema guard: if an older development schema is detected, drop it.
    // Mailbox messages are ephemeral; destructive migration is acceptable here.
    let cols = table_columns(&conn, "messages").map_err(|e| e.to_string())?;
    if !cols.is_empty()
        && (cols.contains(&"msg_id_hex".to_string()) || !cols.contains(&"seq".to_string()))
    {
        conn.execute_batch(
            r#"
            DROP TABLE IF EXISTS messages;
            DROP INDEX IF EXISTS idx_messages_to_msgid;
            DROP INDEX IF EXISTS idx_messages_to_lease;
            DROP INDEX IF EXISTS idx_messages_expires;
            "#,
        )
        .map_err(|e| e.to_string())?;
    }

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS messages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            to_id           TEXT NOT NULL,
            from_id         TEXT NOT NULL,
            escrow_id_hex   TEXT NOT NULL,
            msg_type        TEXT NOT NULL,
            seq             INTEGER NOT NULL,
            envelope_json   TEXT NOT NULL,
            received_at_ms  INTEGER NOT NULL,
            expires_at_ms   INTEGER NOT NULL,
            lease_id        TEXT,
            lease_until_ms  INTEGER
        );

        -- Dedupe/idempotency while the message exists in the mailbox.
        CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_to_from_escrow_seq
            ON messages(to_id, from_id, escrow_id_hex, seq);

        CREATE INDEX IF NOT EXISTS idx_messages_to_lease ON messages(to_id, lease_until_ms, id);
        CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at_ms);
        "#,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn open(path: &PathBuf) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    Ok(conn)
}

fn push_sync(
    path: &PathBuf,
    env: &NxmsEnvelope,
    ttl_secs: u64,
    limits: MailboxLimits,
) -> Result<PushResult, String> {
    let mut conn = open(path)?;
    let now = now_ms();

    let ttl_ms = i64::try_from(ttl_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
    let expires_at_ms = now.saturating_add(ttl_ms.max(1));

    let envelope_json = serde_json::to_string(env).map_err(|e| e.to_string())?;
    let envelope_bytes = u64::try_from(envelope_json.len()).unwrap_or(u64::MAX);
    let seq = i64::try_from(env.seq).unwrap_or(i64::MAX);

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;

    // Keep quota calculations bounded to active rows.
    tx.execute(
        "DELETE FROM messages WHERE expires_at_ms <= ?1",
        params![now],
    )
    .map_err(|e| e.to_string())?;

    let exists: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM messages WHERE to_id=?1 AND from_id=?2 AND escrow_id_hex=?3 AND seq=?4 LIMIT 1",
            params![env.to, env.from, env.escrow_id_hex, seq],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if exists.is_some() {
        tx.commit().map_err(|e| e.to_string())?;
        return Ok(PushResult {
            dedup: true,
            rejection: None,
        });
    }

    let global_rows: u64 = tx
        .query_row("SELECT COUNT(1) FROM messages", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if global_rows >= limits.max_rows_global {
        tx.commit().map_err(|e| e.to_string())?;
        return Ok(PushResult {
            dedup: false,
            rejection: Some(PushRejection::GlobalRowsLimit),
        });
    }

    let (inbox_rows, inbox_bytes): (u64, u64) = tx
        .query_row(
            "SELECT COUNT(1), COALESCE(SUM(LENGTH(envelope_json)), 0) FROM messages WHERE to_id=?1",
            params![env.to],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| e.to_string())?;

    if inbox_rows >= limits.max_messages_per_inbox {
        tx.commit().map_err(|e| e.to_string())?;
        return Ok(PushResult {
            dedup: false,
            rejection: Some(PushRejection::InboxMessageLimit),
        });
    }

    if inbox_bytes.saturating_add(envelope_bytes) > limits.max_bytes_per_inbox {
        tx.commit().map_err(|e| e.to_string())?;
        return Ok(PushResult {
            dedup: false,
            rejection: Some(PushRejection::InboxBytesLimit),
        });
    }

    let insert_res = tx.execute(
        r#"
        INSERT INTO messages (
            to_id, from_id, escrow_id_hex, msg_type, seq,
            envelope_json, received_at_ms, expires_at_ms, lease_id, lease_until_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL)
        "#,
        params![
            env.to,
            env.from,
            env.escrow_id_hex,
            msg_type_key(&env.msg_type),
            seq,
            envelope_json,
            now,
            expires_at_ms,
        ],
    );
    match insert_res {
        Ok(_) => {}
        Err(err) if is_unique_violation(&err) => {
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(PushResult {
                dedup: true,
                rejection: None,
            });
        }
        Err(err) => return Err(err.to_string()),
    }

    tx.commit().map_err(|e| e.to_string())?;
    Ok(PushResult {
        dedup: false,
        rejection: None,
    })
}

fn pull_sync(
    path: &PathBuf,
    to: &str,
    max: u32,
    lease_secs: u64,
) -> Result<Vec<LeasedMessage>, String> {
    let mut conn = open(path)?;
    let now = now_ms();
    let lease_ms = i64::try_from(lease_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
    let lease_until_ms = now.saturating_add(lease_ms.max(1));

    // Best-effort prune expired rows (keeps DB bounded without a separate vacuum strategy).
    let _ = conn.execute(
        "DELETE FROM messages WHERE expires_at_ms <= ?1",
        params![now],
    );

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    {
        let mut selected: Vec<(i64, String)> = Vec::new();

        let mut stmt = tx
            .prepare(
                r#"
                SELECT id, envelope_json
                FROM messages
                WHERE to_id = ?1
                  AND expires_at_ms > ?2
                  AND (lease_until_ms IS NULL OR lease_until_ms < ?2)
                ORDER BY id
                LIMIT ?3
                "#,
            )
            .map_err(|e| e.to_string())?;

        let mut rows = stmt
            .query(params![to, now, i64::from(max)])
            .map_err(|e| e.to_string())?;

        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let id: i64 = row.get(0).map_err(|e| e.to_string())?;
            let envelope_json: String = row.get(1).map_err(|e| e.to_string())?;
            selected.push((id, envelope_json));
        }

        for (id, envelope_json) in selected {
            let envelope: NxmsEnvelope =
                serde_json::from_str(&envelope_json).map_err(|e| e.to_string())?;
            let receipt = random_hex_16();
            tx.execute(
                "UPDATE messages SET lease_id=?1, lease_until_ms=?2 WHERE id=?3",
                params![receipt, lease_until_ms, id],
            )
            .map_err(|e| e.to_string())?;
            out.push(LeasedMessage { receipt, envelope });
        }
    }

    tx.commit().map_err(|e| e.to_string())?;
    Ok(out)
}

fn ack_sync(path: &PathBuf, receipt: &str) -> Result<bool, String> {
    let conn = open(path)?;
    let n = conn
        .execute("DELETE FROM messages WHERE lease_id=?1", params![receipt])
        .map_err(|e| e.to_string())?;
    Ok(n > 0)
}

fn cleanup_expired_sync(path: &PathBuf) -> Result<(), String> {
    let conn = open(path)?;
    let now = now_ms();
    let n = conn
        .execute(
            "DELETE FROM messages WHERE expires_at_ms <= ?1",
            params![now],
        )
        .map_err(|e| e.to_string())?;
    if n > 0 {
        tracing::debug!("cleanup: deleted {} expired messages", n);
    }
    Ok(())
}

fn stats_sync(path: &PathBuf) -> Result<MailboxStats, String> {
    let conn = open(path)?;
    let now = now_ms();

    let total_rows: u64 = conn
        .query_row(
            "SELECT COUNT(1) FROM messages WHERE expires_at_ms > ?1",
            params![now],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                to_id,
                COUNT(1) AS backlog_count,
                MIN(received_at_ms) AS oldest_ms,
                COALESCE(SUM(LENGTH(envelope_json)), 0) AS total_bytes
            FROM messages
            WHERE expires_at_ms > ?1
            GROUP BY to_id
            ORDER BY backlog_count DESC
            "#,
        )
        .map_err(|e| e.to_string())?;

    let mut rows = stmt.query(params![now]).map_err(|e| e.to_string())?;
    let mut inboxes = Vec::new();
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let to: String = row.get(0).map_err(|e| e.to_string())?;
        let backlog_count: u64 = row.get(1).map_err(|e| e.to_string())?;
        let oldest_ms: i64 = row.get(2).map_err(|e| e.to_string())?;
        let bytes: u64 = row.get(3).map_err(|e| e.to_string())?;
        let oldest_age_secs = if oldest_ms <= 0 || oldest_ms > now {
            0
        } else {
            u64::try_from((now - oldest_ms) / 1000).unwrap_or(0)
        };
        inboxes.push(InboxStats {
            to,
            backlog_count,
            oldest_age_secs,
            bytes,
        });
    }

    let db_bytes = file_size(path);
    let wal_bytes = file_size(&wal_path(path));
    Ok(MailboxStats {
        total_rows,
        db_bytes,
        wal_bytes,
        inboxes,
    })
}

fn wal_checkpoint_truncate_sync(path: &PathBuf) -> Result<(), String> {
    let conn = open(path)?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn vacuum_sync(path: &PathBuf) -> Result<(), String> {
    let conn = open(path)?;
    conn.execute_batch("VACUUM;").map_err(|e| e.to_string())?;
    Ok(())
}

fn is_unique_violation(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(e, _) => {
            matches!(e.code, ErrorCode::ConstraintViolation)
        }
        _ => false,
    }
}

fn random_hex_16() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn file_size(path: &PathBuf) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn wal_path(path: &PathBuf) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push("-wal");
    PathBuf::from(os)
}

fn is_safe_sqlite_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b == b'_' || b.is_ascii_alphanumeric())
}

fn table_columns(conn: &Connection, table: &str) -> rusqlite::Result<Vec<String>> {
    if !is_safe_sqlite_identifier(table) {
        return Err(rusqlite::Error::InvalidParameterName(table.to_string()));
    }
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        // PRAGMA table_info: cid, name, type, notnull, dflt_value, pk
        let name: String = row.get(1)?;
        out.push(name);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nxms_transport::wire::MsgType;
    use nxms_transport::wire::NXMS_PROTO_V1;
    use tokio::time::{Duration, sleep};

    fn unique_db_path(label: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "nxms_mailbox_test_{label}_{}_{}.db",
            std::process::id(),
            ts
        ))
    }

    fn sample_env(to: &str, seq: u64) -> NxmsEnvelope {
        NxmsEnvelope {
            proto: NXMS_PROTO_V1.to_string(),
            kem_id: "FrodoKEM-640-SHAKE".to_string(),
            sig_id: "Falcon-1024-CT".to_string(),
            msg_type: MsgType::PrepareInfo,
            escrow_id_hex: "0".repeat(32),
            from: "alice".to_string(),
            to: to.to_string(),
            seq,
            kem_ct_b64: "x".to_string(),
            nonce_b64: "x".to_string(),
            ciphertext_b64: "x".to_string(),
            tag_b64: "x".to_string(),
            sig_b64: "x".to_string(),
        }
    }

    fn default_limits() -> MailboxLimits {
        MailboxLimits {
            max_messages_per_inbox: 10_000,
            max_bytes_per_inbox: 64 * 1024 * 1024,
            max_rows_global: 1_000_000,
        }
    }

    #[tokio::test]
    async fn push_pull_ack_roundtrip() {
        let db_path = unique_db_path("roundtrip");
        let db = SqliteMailboxDb::new(db_path.clone());
        db.init().await.expect("init");

        let env = sample_env("bob", 1);
        let r1 = db.push(&env, 60, default_limits()).await.expect("push");
        assert!(!r1.dedup);

        let leased = db.pull("bob", 10, 60).await.expect("pull");
        assert_eq!(leased.len(), 1);
        assert_eq!(leased[0].envelope.seq, env.seq);

        // While leased, a second pull returns empty.
        let leased2 = db.pull("bob", 10, 60).await.expect("pull2");
        assert!(leased2.is_empty());

        db.ack(&leased[0].receipt).await.expect("ack");

        let leased3 = db.pull("bob", 10, 60).await.expect("pull3");
        assert!(leased3.is_empty());

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn push_is_idempotent_while_message_exists() {
        let db_path = unique_db_path("dedup");
        let db = SqliteMailboxDb::new(db_path.clone());
        db.init().await.expect("init");

        let env = sample_env("bob", 1);
        let r1 = db.push(&env, 60, default_limits()).await.expect("push1");
        assert!(!r1.dedup);
        let r2 = db.push(&env, 60, default_limits()).await.expect("push2");
        assert!(r2.dedup);

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn lease_expiry_redelivers_message() {
        let db_path = unique_db_path("lease_expiry");
        let db = SqliteMailboxDb::new(db_path.clone());
        db.init().await.expect("init");

        db.push(&sample_env("bob", 1), 60, default_limits())
            .await
            .expect("push");

        let first = db.pull("bob", 10, 1).await.expect("pull1");
        assert_eq!(first.len(), 1);

        sleep(Duration::from_millis(1200)).await;

        let second = db.pull("bob", 10, 1).await.expect("pull2");
        assert_eq!(second.len(), 1);
        assert_ne!(first[0].receipt, second[0].receipt);
        assert_eq!(second[0].envelope.seq, 1);

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn ttl_expiry_cleanup_deletes_message() {
        let db_path = unique_db_path("ttl_expiry");
        let db = SqliteMailboxDb::new(db_path.clone());
        db.init().await.expect("init");

        db.push(&sample_env("bob", 1), 1, default_limits())
            .await
            .expect("push");
        sleep(Duration::from_millis(1200)).await;
        db.cleanup_expired().await.expect("cleanup");

        let leased = db.pull("bob", 10, 60).await.expect("pull");
        assert!(leased.is_empty());

        let stats = db.stats().await.expect("stats");
        assert_eq!(stats.total_rows, 0);

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn dedup_key_is_scoped_by_sender_and_escrow_and_seq() {
        let db_path = unique_db_path("dedup_scope");
        let db = SqliteMailboxDb::new(db_path.clone());
        db.init().await.expect("init");

        let mut env1 = sample_env("bob", 1);
        env1.from = "alice".to_string();
        let mut env2 = sample_env("bob", 1);
        env2.from = "charlie".to_string();
        let mut env3 = sample_env("bob", 1);
        env3.from = "alice".to_string();
        env3.escrow_id_hex = "1".repeat(32);

        let r1 = db.push(&env1, 60, default_limits()).await.expect("push1");
        assert!(!r1.dedup);
        let r2 = db.push(&env2, 60, default_limits()).await.expect("push2");
        assert!(!r2.dedup);
        let r3 = db.push(&env3, 60, default_limits()).await.expect("push3");
        assert!(!r3.dedup);
        let r4 = db.push(&env1, 60, default_limits()).await.expect("push4");
        assert!(r4.dedup);

        let _ = std::fs::remove_file(db_path);
    }
}
