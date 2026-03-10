use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use nxms_mailbox::{AppState, api, build_app, db};
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "nxms-mailbox",
    version,
    about = "NXMS mailbox (Tor onion service)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the mailbox HTTP server.
    Serve {
        /// HTTP bind address (Tor onion service should forward to this).
        #[arg(long, env = "NXMS_MAILBOX_BIND", default_value = "127.0.0.1:4010")]
        bind: String,

        /// SQLite DB path.
        #[arg(long, env = "NXMS_MAILBOX_DB_PATH", default_value = "nxms_mailbox.db")]
        db_path: String,

        /// Maximum request body size in bytes.
        #[arg(long, env = "NXMS_MAILBOX_MAX_BODY_BYTES", default_value_t = 16 * 1024 * 1024)]
        max_body_bytes: usize,

        /// Default message TTL in seconds.
        #[arg(long, env = "NXMS_MAILBOX_DEFAULT_TTL_SECS", default_value_t = 24 * 60 * 60)]
        default_ttl_secs: u64,

        /// Maximum allowed TTL in seconds (server clamps larger values).
        #[arg(long, env = "NXMS_MAILBOX_MAX_TTL_SECS", default_value_t = 7 * 24 * 60 * 60)]
        max_ttl_secs: u64,

        /// Lease time in seconds for pulled messages.
        #[arg(long, env = "NXMS_MAILBOX_LEASE_SECS", default_value_t = 60)]
        lease_secs: u64,

        /// Maximum long-poll wait in milliseconds.
        #[arg(long, env = "NXMS_MAILBOX_MAX_WAIT_MS", default_value_t = 20_000)]
        max_wait_ms: u64,

        /// Bearer token required for /v1/push.
        #[arg(long, env = "NXMS_MAILBOX_PUSH_TOKEN")]
        push_token: Option<String>,

        /// Comma-separated inbox=token map required for /v1/pull.
        #[arg(long, env = "NXMS_MAILBOX_PULL_TOKENS")]
        pull_tokens: Option<String>,

        /// Comma-separated inbox=token map required for /v1/ack.
        #[arg(long, env = "NXMS_MAILBOX_ACK_TOKENS")]
        ack_tokens: Option<String>,

        /// Bearer token required for /v1/admin/* endpoints.
        #[arg(long, env = "NXMS_MAILBOX_ADMIN_TOKEN")]
        admin_token: Option<String>,

        /// Periodic cleanup interval in seconds (expired messages).
        #[arg(long, env = "NXMS_MAILBOX_CLEANUP_SECS", default_value_t = 30)]
        cleanup_secs: u64,

        /// Periodic WAL checkpoint interval in seconds.
        #[arg(long, env = "NXMS_MAILBOX_CHECKPOINT_SECS", default_value_t = 300)]
        checkpoint_secs: u64,

        /// Hard cap of queued messages per inbox.
        #[arg(
            long,
            env = "NXMS_MAILBOX_MAX_MESSAGES_PER_INBOX",
            default_value_t = 10_000
        )]
        max_messages_per_inbox: u64,

        /// Hard cap of queued envelope bytes per inbox.
        #[arg(long, env = "NXMS_MAILBOX_MAX_BYTES_PER_INBOX", default_value_t = 64 * 1024 * 1024)]
        max_bytes_per_inbox: u64,

        /// Hard cap of queued messages across all inboxes.
        #[arg(
            long,
            env = "NXMS_MAILBOX_MAX_ROWS_GLOBAL",
            default_value_t = 1_000_000
        )]
        max_rows_global: u64,

        /// Push request limit per minute for a source IP (0 disables).
        #[arg(
            long,
            env = "NXMS_MAILBOX_RATE_LIMIT_IP_PER_MIN",
            default_value_t = 300
        )]
        rate_limit_ip_per_min: u32,

        /// Push request limit per minute for target inbox id (0 disables).
        #[arg(
            long,
            env = "NXMS_MAILBOX_RATE_LIMIT_TO_PER_MIN",
            default_value_t = 600
        )]
        rate_limit_to_per_min: u32,
    },

    /// Run WAL checkpoint(TRUNCATE) once and exit.
    Checkpoint {
        /// SQLite DB path.
        #[arg(long, env = "NXMS_MAILBOX_DB_PATH", default_value = "nxms_mailbox.db")]
        db_path: String,
    },

    /// Run VACUUM once and exit.
    Vacuum {
        /// SQLite DB path.
        #[arg(long, env = "NXMS_MAILBOX_DB_PATH", default_value = "nxms_mailbox.db")]
        db_path: String,
    },
}

fn require_token(name: &str, value: Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    let token = value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{name} must be set and non-empty"))?;
    Ok(token)
}

fn require_scoped_tokens(
    name: &str,
    value: Option<String>,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let raw = value
        .ok_or_else(|| format!("{name} must be set and non-empty"))?
        .trim()
        .to_string();
    if raw.is_empty() {
        return Err(format!("{name} must be set and non-empty").into());
    }

    let mut tokens = HashMap::new();
    let mut seen_token_values = std::collections::HashSet::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(format!("{name} contains an empty entry").into());
        }
        let (inbox, token) = entry
            .split_once('=')
            .ok_or_else(|| format!("{name} entries must have inbox=token format"))?;
        let inbox = inbox.trim();
        let token = token.trim();
        if inbox.is_empty() || token.is_empty() {
            return Err(format!("{name} entries must have non-empty inbox and token").into());
        }
        if tokens.insert(inbox.to_string(), token.to_string()).is_some() {
            return Err(format!("{name} contains duplicate inbox `{inbox}`").into());
        }
        if !seen_token_values.insert(token.to_string()) {
            return Err(format!("{name} reuses the same token across inbox scopes").into());
        }
    }

    if tokens.is_empty() {
        return Err(format!("{name} must define at least one inbox token").into());
    }

    Ok(tokens)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Command::Serve {
            bind,
            db_path,
            max_body_bytes,
            default_ttl_secs,
            max_ttl_secs,
            lease_secs,
            max_wait_ms,
            push_token,
            pull_tokens,
            ack_tokens,
            admin_token,
            cleanup_secs,
            checkpoint_secs,
            max_messages_per_inbox,
            max_bytes_per_inbox,
            max_rows_global,
            rate_limit_ip_per_min,
            rate_limit_to_per_min,
        } => {
            let bind_addr: SocketAddr = bind.parse()?;
            let db_path = PathBuf::from(db_path);
            let db = db::SqliteMailboxDb::new(db_path);
            db.init().await?;
            let push_token = require_token("NXMS_MAILBOX_PUSH_TOKEN", push_token)?;
            let pull_tokens = require_scoped_tokens("NXMS_MAILBOX_PULL_TOKENS", pull_tokens)?;
            let ack_tokens = require_scoped_tokens("NXMS_MAILBOX_ACK_TOKENS", ack_tokens)?;
            let admin_token = require_token("NXMS_MAILBOX_ADMIN_TOKEN", admin_token)?;

            let cfg = api::ApiConfig {
                push_token: Some(push_token),
                pull_tokens,
                ack_tokens,
                admin_token: Some(admin_token),
                max_body_bytes,
                default_ttl_secs,
                max_ttl_secs,
                lease_secs,
                max_wait_ms,
                limits: db::MailboxLimits {
                    max_messages_per_inbox: max_messages_per_inbox.max(1),
                    max_bytes_per_inbox: max_bytes_per_inbox.max(1024),
                    max_rows_global: max_rows_global.max(1),
                },
                rate_limit_ip_per_min,
                rate_limit_to_per_min,
            };

            let state = AppState::new(db.clone(), cfg);

            // Periodic cleanup loop (expired messages).
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(cleanup_secs.max(1)));
                let mut last_checkpoint = std::time::Instant::now();
                loop {
                    interval.tick().await;
                    if let Err(err) = db.cleanup_expired().await {
                        tracing::warn!("cleanup failed: {}", err);
                    }
                    if last_checkpoint.elapsed() >= Duration::from_secs(checkpoint_secs.max(1)) {
                        if let Err(err) = db.wal_checkpoint_truncate().await {
                            tracing::warn!("checkpoint failed: {}", err);
                        }
                        last_checkpoint = std::time::Instant::now();
                    }
                }
            });

            let app = build_app(state, max_body_bytes);

            info!("nxms-mailbox listening on {}", bind_addr);
            let listener = tokio::net::TcpListener::bind(bind_addr).await?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
        }
        Command::Checkpoint { db_path } => {
            let db = db::SqliteMailboxDb::new(PathBuf::from(db_path));
            db.init().await?;
            db.wal_checkpoint_truncate().await?;
            info!("wal checkpoint completed");
        }
        Command::Vacuum { db_path } => {
            let db = db::SqliteMailboxDb::new(PathBuf::from(db_path));
            db.init().await?;
            db.vacuum().await?;
            info!("vacuum completed");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use nxms_mailbox_client::MailboxClient;
    use nxms_transport::wire::{MsgType, NXMS_PROTO_V1, NxmsEnvelope};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    #[test]
    fn require_token_rejects_missing_or_blank_values() {
        assert!(require_token("NXMS_MAILBOX_PUSH_TOKEN", None).is_err());
        assert!(require_token("NXMS_MAILBOX_PUSH_TOKEN", Some("   ".to_string())).is_err());
        assert_eq!(
            require_token("NXMS_MAILBOX_PUSH_TOKEN", Some(" secret ".to_string())).unwrap(),
            "secret"
        );
    }

    #[test]
    fn require_scoped_tokens_parses_and_rejects_bad_values() {
        let parsed = require_scoped_tokens(
            "NXMS_MAILBOX_PULL_TOKENS",
            Some("alice = token-a, bob=token-b".to_string()),
        )
        .expect("scoped tokens");
        assert_eq!(parsed.get("alice"), Some(&"token-a".to_string()));
        assert_eq!(parsed.get("bob"), Some(&"token-b".to_string()));

        assert!(require_scoped_tokens("NXMS_MAILBOX_PULL_TOKENS", None).is_err());
        assert!(require_scoped_tokens(
            "NXMS_MAILBOX_PULL_TOKENS",
            Some("alice=".to_string())
        )
        .is_err());
        assert!(require_scoped_tokens(
            "NXMS_MAILBOX_PULL_TOKENS",
            Some("alice=shared,bob=shared".to_string())
        )
        .is_err());
        assert!(require_scoped_tokens(
            "NXMS_MAILBOX_PULL_TOKENS",
            Some("alice=a,alice=b".to_string())
        )
        .is_err());
    }

    fn unique_db_path(label: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "nxms_mailbox_main_test_{label}_{}_{}.db",
            std::process::id(),
            ts
        ))
    }

    fn sample_envelope(to: &str, seq: u64) -> NxmsEnvelope {
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

    async fn spawn_mailbox_server(label: &str) -> (String, PathBuf) {
        let db_path = unique_db_path(label);
        let db = db::SqliteMailboxDb::new(db_path.clone());
        db.init().await.expect("db init");

        let state = AppState::new(
            db,
            api::ApiConfig {
                push_token: Some("push-token".to_string()),
                pull_tokens: HashMap::from([
                    ("bob".to_string(), "pull-token-bob".to_string()),
                    ("carol".to_string(), "pull-token-carol".to_string()),
                ]),
                ack_tokens: HashMap::from([
                    ("bob".to_string(), "ack-token-bob".to_string()),
                    ("carol".to_string(), "ack-token-carol".to_string()),
                ]),
                admin_token: Some("admin".to_string()),
                max_body_bytes: 1024 * 1024,
                default_ttl_secs: 60,
                max_ttl_secs: 600,
                lease_secs: 1,
                max_wait_ms: 1000,
                limits: db::MailboxLimits {
                    max_messages_per_inbox: 100,
                    max_bytes_per_inbox: 1024 * 1024,
                    max_rows_global: 1000,
                },
                rate_limit_ip_per_min: 1000,
                rate_limit_to_per_min: 1000,
            },
        );
        let app = build_app(state, 1024 * 1024);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });

        (format!("http://{}", addr), db_path)
    }

    #[tokio::test]
    async fn max_body_limit_rejects_oversized_push_request() {
        let db_path = unique_db_path("max_body");
        let db = db::SqliteMailboxDb::new(db_path.clone());
        db.init().await.expect("db init");

        let state = AppState::new(
            db,
            api::ApiConfig {
                push_token: Some("push-token".to_string()),
                pull_tokens: HashMap::from([("bob".to_string(), "pull-token-bob".to_string())]),
                ack_tokens: HashMap::from([("bob".to_string(), "ack-token-bob".to_string())]),
                admin_token: Some("admin".to_string()),
                max_body_bytes: 256,
                default_ttl_secs: 60,
                max_ttl_secs: 600,
                lease_secs: 30,
                max_wait_ms: 1000,
                limits: db::MailboxLimits {
                    max_messages_per_inbox: 100,
                    max_bytes_per_inbox: 1024 * 1024,
                    max_rows_global: 1000,
                },
                rate_limit_ip_per_min: 1000,
                rate_limit_to_per_min: 1000,
            },
        );
        let app = build_app(state, 256);

        let huge = "A".repeat(2048);
        let body = json!({
            "envelope": {
                "proto": "NXMS/1",
                "kem_id": "FrodoKEM-640-SHAKE",
                "sig_id": "Falcon-1024-CT",
                "msg_type": "prepare_info",
                "escrow_id_hex": "00112233445566778899aabbccddeeff",
                "from": "alice",
                "to": "bob",
                "seq": 1,
                "kem_ct_b64": huge,
                "nonce_b64": "x",
                "ciphertext_b64": "x",
                "tag_b64": "x",
                "sig_b64": "x"
            },
            "ttl_secs": 60
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/push")
            .header("content-type", "application/json")
            .header("authorization", "Bearer push-token")
            .body(Body::from(body.to_string()))
            .expect("request");

        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn mailbox_client_smoke_roundtrip_against_real_mailbox_app() {
        let (base_url, db_path) = spawn_mailbox_server("client_smoke").await;
        let client = MailboxClient::builder(&base_url)
            .expect("builder")
            .push_token("push-token")
            .pull_token("pull-token-bob")
            .ack_token("ack-token-bob")
            .admin_token("admin")
            .build()
            .expect("client");

        client.health().await.expect("health");
        let pushed = client
            .push(&sample_envelope("bob", 1), Some(60))
            .await
            .expect("push");
        assert!(pushed.ok);
        assert!(!pushed.dedup);

        let pulled = client.pull("bob", Some(1), Some(0)).await.expect("pull");
        assert_eq!(pulled.messages.len(), 1);
        assert_eq!(pulled.messages[0].envelope.seq, 1);

        client
            .ack(&pulled.messages[0].receipt)
            .await
            .expect("ack");

        let stats = client.admin_stats().await.expect("admin stats");
        assert_eq!(stats.total_rows, 0);

        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn mailbox_client_fail_closed_on_wrong_pull_scope_against_real_mailbox_app() {
        let (base_url, db_path) = spawn_mailbox_server("client_wrong_scope").await;
        let push_client = MailboxClient::builder(&base_url)
            .expect("builder")
            .push_token("push-token")
            .build()
            .expect("push client");
        push_client
            .push(&sample_envelope("bob", 1), Some(60))
            .await
            .expect("push");

        let wrong_scope_client = MailboxClient::builder(&base_url)
            .expect("builder")
            .pull_token("pull-token-carol")
            .build()
            .expect("wrong scope client");
        let err = wrong_scope_client
            .pull("bob", Some(1), Some(0))
            .await
            .expect_err("wrong scope pull must fail closed");
        assert!(err.to_string().contains("mailbox http 401"));

        let _ = std::fs::remove_file(db_path);
    }
}
