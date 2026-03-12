use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use nxms_signer::agent::{AuthEventContext, append_auth_event};
use nxms_signer::snapshot::SnapshotSignature;
use nxms_signer::snapshot::{
    AmountRule, Asset, ContractSnapshot, PayoutPolicy, RecipientRule, canonical_hash_hex,
    canonical_json_sha256_hex, sign_snapshot, verify_snapshot_signature,
};
use nxms_signer::worker_http;
use nxms_signer::{
    AuditLogRow, PendingTxSign, SecurityAlertThresholds, SignEventAuditRow, SignerAgent,
    SignerConfig, SignerDb, SnapshotRow, SnapshotSigRow, normalize_hex_exact, now_ms,
};
use nxms_signer::trust::materialize_runtime_trust_from_config;
use nxms_transport::crypto::Keys;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "nxms-signer",
    version,
    about = "NXMS manual signer (mailbox + snapshot policy)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run pull/decrypt/replay-guard loop and enqueue tx signing requests for manual approval.
    Run {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
    },

    /// Run local worker HTTP API for sign/submit capability calls.
    Serve {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
        #[arg(long, env = "NXMS_SIGNER_BIND", default_value = "127.0.0.1:28090")]
        bind: String,
    },

    /// Contract snapshot operations.
    Snapshot {
        #[command(subcommand)]
        cmd: SnapshotCommand,
    },

    /// Pending tx-sign queue operations.
    Pending {
        #[command(subcommand)]
        cmd: PendingCommand,
    },

    /// Audit log operations.
    Audit {
        #[command(subcommand)]
        cmd: AuditCommand,
    },

    /// Security posture checks.
    Security {
        #[command(subcommand)]
        cmd: SecurityCommand,
    },

    /// Runtime trust bundle materialization and checks.
    Trust {
        #[command(subcommand)]
        cmd: TrustCommand,
    },
}

#[derive(Subcommand, Debug)]
enum SnapshotCommand {
    /// Generate a minimal snapshot JSON template.
    New {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        escrow_id_hex: String,
        #[arg(long)]
        buyer_id: String,
        #[arg(long)]
        seller_id: String,
        #[arg(long)]
        arbiter_id: String,
        #[arg(long)]
        release_address: String,
        #[arg(long)]
        release_amount: u64,
        #[arg(long)]
        refund_address: String,
        #[arg(long)]
        refund_min: u64,
        #[arg(long)]
        refund_max: u64,
        #[arg(long)]
        fee_cap_atomic: u64,
    },

    /// Compute canonical sha3-256 hash of snapshot JSON.
    Hash {
        #[arg(long)]
        snapshot: PathBuf,
    },

    /// Sign snapshot hash with Falcon secret key from keys.json.
    Sign {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        signer_id: String,
        #[arg(long)]
        out: PathBuf,
    },

    /// Verify snapshot signature JSON against snapshot JSON.
    Verify {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        signature: PathBuf,
    },

    /// Store snapshot + signatures in signer DB and activate (requires quorum).
    Activate {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long, required = true)]
        signatures: Vec<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum PendingCommand {
    List {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
    },
    Show {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
        #[arg(long)]
        id: i64,
    },
    Approve {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
        #[arg(long)]
        id: i64,
        #[arg(long)]
        action_token: Option<String>,
    },
    Reject {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
        #[arg(long)]
        id: i64,
        #[arg(long)]
        reason: String,
    },
    Submit {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
        #[arg(long)]
        escrow_id_hex: String,
        #[arg(long)]
        tx_data_hex: String,
        #[arg(long)]
        action: String,
        #[arg(long)]
        action_token: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AuditCommand {
    List {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
        #[arg(long, default_value_t = 200)]
        limit: u32,
    },
    Metrics {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
        #[arg(long, default_value_t = false)]
        security_breakdown: bool,
    },
    /// Print grouped security dashboard (token/replay/policy/rpc).
    Dashboard {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
    },
    /// Evaluate windowed security alerts against thresholds.
    Alerts {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
        #[arg(long, default_value_t = 300)]
        window_secs: u64,
        #[arg(long, default_value_t = 5)]
        token_reject_total: u64,
        #[arg(long, default_value_t = 3)]
        replay_reject_total: u64,
        #[arg(long, default_value_t = 1)]
        policy_reject_total: u64,
        #[arg(long, default_value_t = 2)]
        rpc_fail_total: u64,
        #[arg(long, default_value_t = 1)]
        shadow_allow_total: u64,
        #[arg(long, default_value_t = false)]
        fail_on_alerts: bool,
    },
    /// Append auth lifecycle audit event (challenge/token) from external auth layer.
    AuthEvent {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
        #[arg(long)]
        escrow_id_hex: String,
        #[arg(long)]
        event_kind: String,
        #[arg(long)]
        actor_id: Option<String>,
        #[arg(long)]
        detail: Option<String>,
        #[arg(long)]
        op: Option<String>,
        #[arg(long)]
        txset_hash_hex: Option<String>,
        #[arg(long)]
        proof_arbiter_jti: Option<String>,
        #[arg(long)]
        proof_arbiter_req_id: Option<String>,
        #[arg(long)]
        proof_seller_jti: Option<String>,
        #[arg(long)]
        proof_seller_req_id: Option<String>,
    },
    /// Export deterministic evidence bundle JSON for one escrow.
    EvidenceBundle {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
        #[arg(long)]
        escrow_id_hex: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 5000)]
        audit_limit: u32,
    },
}

#[derive(Subcommand, Debug)]
enum SecurityCommand {
    Check {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum TrustCommand {
    /// Materialize peers.json and action_token_pub.pem from runtime_trust_bundle.
    Materialize {
        #[arg(long, env = "NXMS_SIGNER_CONFIG", default_value = "nxms-signer.toml")]
        config: PathBuf,
    },
}

#[derive(Debug, Serialize)]
struct EvidenceSectionHashes {
    active_snapshot: Option<String>,
    sign_events: String,
    pending: String,
    audit_logs: String,
}

#[derive(Debug, Serialize)]
struct EvidenceBundlePayload {
    version: String,
    generated_at_ms: u64,
    escrow_id_hex: String,
    active_snapshot: Option<SnapshotRow>,
    sign_events: Vec<SignEventAuditRow>,
    pending: Vec<PendingTxSign>,
    audit_logs: Vec<AuditLogRow>,
    section_hashes: EvidenceSectionHashes,
}

#[derive(Debug, Serialize)]
struct EvidenceBundleEnvelope {
    format: String,
    bundle_hash_sha256: String,
    payload: EvidenceBundlePayload,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Command::Run { config } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let agent = SignerAgent::from_config(cfg).await?;
            agent.run().await?;
        }
        Command::Serve { config, bind } => handle_serve_cmd(config, &bind).await?,
        Command::Snapshot { cmd } => handle_snapshot_cmd(cmd).await?,
        Command::Pending { cmd } => handle_pending_cmd(cmd).await?,
        Command::Audit { cmd } => handle_audit_cmd(cmd).await?,
        Command::Security { cmd } => handle_security_cmd(cmd).await?,
        Command::Trust { cmd } => handle_trust_cmd(cmd).await?,
    }
    Ok(())
}

async fn handle_serve_cmd(config: PathBuf, bind: &str) -> Result<()> {
    let cfg = SignerConfig::from_toml_path(config)?;
    let agent = SignerAgent::from_config(cfg).await?;
    worker_http::serve(agent, bind).await
}

async fn handle_snapshot_cmd(cmd: SnapshotCommand) -> Result<()> {
    match cmd {
        SnapshotCommand::New {
            out,
            escrow_id_hex,
            buyer_id,
            seller_id,
            arbiter_id,
            release_address,
            release_amount,
            refund_address,
            refund_min,
            refund_max,
            fee_cap_atomic,
        } => {
            let now = now_ms();
            let snapshot = ContractSnapshot {
                app_proto: "ESCROW/1".to_string(),
                escrow_id_hex,
                asset: Asset::Xmr,
                buyer_id,
                seller_id,
                arbiter_id,
                release_policy: PayoutPolicy {
                    allowed_recipients: vec![RecipientRule {
                        address: release_address,
                        amount: AmountRule::Exact {
                            amount: release_amount,
                        },
                        required: true,
                    }],
                    allow_split_tx: false,
                    allow_dummy_outputs: false,
                },
                refund_policy: PayoutPolicy {
                    allowed_recipients: vec![RecipientRule {
                        address: refund_address,
                        amount: AmountRule::Range {
                            min: refund_min,
                            max: refund_max,
                        },
                        required: true,
                    }],
                    allow_split_tx: false,
                    allow_dummy_outputs: false,
                },
                fee_cap_atomic,
                require_unlock_time_zero: true,
                created_at_unix_ms: now,
                updated_at_unix_ms: now,
            };
            let raw = serde_json::to_vec_pretty(&snapshot)?;
            std::fs::write(&out, raw)?;
            println!("{}", out.display());
        }
        SnapshotCommand::Hash { snapshot } => {
            let snap = load_snapshot(&snapshot)?;
            println!("{}", canonical_hash_hex(&snap)?);
        }
        SnapshotCommand::Sign {
            snapshot,
            keys,
            signer_id,
            out,
        } => {
            let snap = load_snapshot(&snapshot)?;
            let keys = Keys::read_json(&keys)?;
            let sig_sk = keys.sig_sk_zeroizing()?;
            let sig = sign_snapshot(
                &snap,
                &signer_id,
                sig_sk.as_slice(),
                &keys.sig_pk()?,
                now_ms(),
            )?;
            std::fs::write(&out, serde_json::to_vec_pretty(&sig)?)?;
            println!("{}", out.display());
        }
        SnapshotCommand::Verify {
            snapshot,
            signature,
        } => {
            let snap = load_snapshot(&snapshot)?;
            let sig = load_signature(&signature)?;
            verify_snapshot_signature(&snap, &sig)?;
            println!("ok");
        }
        SnapshotCommand::Activate {
            config,
            snapshot,
            signatures,
        } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let db = SignerDb::new(cfg.db_path.clone());
            db.init().await?;

            let snap = load_snapshot(&snapshot)?;
            let hash_hex = canonical_hash_hex(&snap)?;
            let snapshot_json = serde_json::to_string(&snap)?;
            db.put_snapshot_pending(&snap.escrow_id_hex, &hash_hex, &snapshot_json)
                .await?;

            for sig_path in signatures {
                let sig = load_signature(&sig_path)?;
                verify_snapshot_signature(&snap, &sig)?;
                db.put_snapshot_signature(&SnapshotSigRow {
                    signer_id: sig.signer_id,
                    sig_pk_b64: sig.sig_pk_b64,
                    sig_b64: sig.sig_b64,
                    hash_hex: sig.hash_hex,
                    alg: sig.alg,
                    created_at_unix_ms: sig.created_at_unix_ms,
                })
                .await?;
            }
            db.activate_snapshot(&hash_hex, cfg.snapshot_quorum).await?;
            println!("activated {}", hash_hex);
        }
    }
    Ok(())
}

async fn handle_pending_cmd(cmd: PendingCommand) -> Result<()> {
    match cmd {
        PendingCommand::List { config } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let db = SignerDb::new(cfg.db_path.clone());
            db.init().await?;
            let rows = db.list_pending().await?;
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        PendingCommand::Show { config, id } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let db = SignerDb::new(cfg.db_path.clone());
            db.init().await?;
            let row = db.get_pending(id).await?;
            println!("{}", serde_json::to_string_pretty(&row)?);
        }
        PendingCommand::Approve {
            config,
            id,
            action_token,
        } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let agent = SignerAgent::from_config(cfg).await?;
            agent.approve_pending(id, action_token.as_deref()).await?;
            println!("approved {}", id);
        }
        PendingCommand::Reject { config, id, reason } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let agent = SignerAgent::from_config(cfg).await?;
            agent.reject_pending(id, &reason).await?;
            println!("rejected {}", id);
        }
        PendingCommand::Submit {
            config,
            escrow_id_hex,
            tx_data_hex,
            action,
            action_token,
        } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let agent = SignerAgent::from_config(cfg).await?;
            let action = parse_action(&action)?;
            let tx_hashes = agent
                .submit_multisig_flow(
                    &escrow_id_hex,
                    action,
                    &tx_data_hex,
                    action_token.as_deref(),
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&tx_hashes)?);
        }
    }
    Ok(())
}

async fn handle_audit_cmd(cmd: AuditCommand) -> Result<()> {
    match cmd {
        AuditCommand::List { config, limit } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let db = SignerDb::new(cfg.db_path.clone());
            db.init().await?;
            let rows = db.list_audit_logs(limit).await?;
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        AuditCommand::Metrics {
            config,
            security_breakdown,
        } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let db = SignerDb::new(cfg.db_path.clone());
            db.init().await?;
            let rows = if security_breakdown {
                serde_json::to_value(db.audit_security_metrics().await?)?
            } else {
                serde_json::to_value(db.audit_metrics().await?)?
            };
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        AuditCommand::Dashboard { config } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let db = SignerDb::new(cfg.db_path.clone());
            db.init().await?;
            let dashboard = db.audit_security_dashboard().await?;
            println!("{}", serde_json::to_string_pretty(&dashboard)?);
        }
        AuditCommand::Alerts {
            config,
            window_secs,
            token_reject_total,
            replay_reject_total,
            policy_reject_total,
            rpc_fail_total,
            shadow_allow_total,
            fail_on_alerts,
        } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let db = SignerDb::new(cfg.db_path.clone());
            db.init().await?;
            let window_ms = window_secs.max(1).saturating_mul(1000);
            let thresholds = SecurityAlertThresholds {
                token_reject_total: token_reject_total.max(1),
                replay_reject_total: replay_reject_total.max(1),
                policy_reject_total: policy_reject_total.max(1),
                rpc_fail_total: rpc_fail_total.max(1),
                shadow_allow_total: shadow_allow_total.max(1),
            };
            let report = db
                .audit_security_alert_report(window_ms, thresholds)
                .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if fail_on_alerts && !report.ok {
                return Err(anyhow!(
                    "security alerts triggered: {} item(s) over threshold",
                    report.alerts.len()
                ));
            }
        }
        AuditCommand::AuthEvent {
            config,
            escrow_id_hex,
            event_kind,
            actor_id,
            detail,
            op,
            txset_hash_hex,
            proof_arbiter_jti,
            proof_arbiter_req_id,
            proof_seller_jti,
            proof_seller_req_id,
        } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let db = SignerDb::new(cfg.db_path.clone());
            db.init().await?;
            let context = AuthEventContext {
                op,
                txset_hash_hex,
                proof_arbiter_jti,
                proof_arbiter_req_id,
                proof_seller_jti,
                proof_seller_req_id,
            };
            let has_context = context.op.is_some()
                || context.txset_hash_hex.is_some()
                || context.proof_arbiter_jti.is_some()
                || context.proof_arbiter_req_id.is_some()
                || context.proof_seller_jti.is_some()
                || context.proof_seller_req_id.is_some();
            append_auth_event(
                &cfg,
                &db,
                &cfg.local_id,
                &escrow_id_hex,
                &event_kind,
                actor_id.as_deref(),
                detail.as_deref(),
                if has_context { Some(context) } else { None },
            )
            .await?;
            println!("ok");
        }
        AuditCommand::EvidenceBundle {
            config,
            escrow_id_hex,
            out,
            audit_limit,
        } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let db = SignerDb::new(cfg.db_path.clone());
            db.init().await?;

            let escrow_id_hex = normalize_hex_exact(&escrow_id_hex, 32, "escrow_id_hex")?;
            let active_snapshot = db.active_snapshot_for_escrow(&escrow_id_hex).await?;
            let sign_events = db.list_sign_events_for_escrow(&escrow_id_hex).await?;
            let pending = db.list_pending_for_escrow(&escrow_id_hex).await?;
            let audit_logs = db
                .list_audit_logs_for_escrow(&escrow_id_hex, audit_limit.max(1))
                .await?;

            let section_hashes = EvidenceSectionHashes {
                active_snapshot: match &active_snapshot {
                    Some(v) => Some(sha256_for_serializable(v)?),
                    None => None,
                },
                sign_events: sha256_for_serializable(&sign_events)?,
                pending: sha256_for_serializable(&pending)?,
                audit_logs: sha256_for_serializable(&audit_logs)?,
            };
            let payload = EvidenceBundlePayload {
                version: "nxms_evidence_bundle_v1".to_string(),
                generated_at_ms: now_ms(),
                escrow_id_hex,
                active_snapshot,
                sign_events,
                pending,
                audit_logs,
                section_hashes,
            };
            let bundle_hash_sha256 = sha256_for_serializable(&payload)?;
            let envelope = EvidenceBundleEnvelope {
                format: "nxms_evidence_envelope_v1".to_string(),
                bundle_hash_sha256,
                payload,
            };
            if let Some(parent) = out.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&out, serde_json::to_vec_pretty(&envelope)?)?;
            println!("{}", out.display());
        }
    }
    Ok(())
}

async fn handle_security_cmd(cmd: SecurityCommand) -> Result<()> {
    match cmd {
        SecurityCommand::Check { config } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let report = cfg.security_report();
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.ok {
                return Err(anyhow!(
                    "security check failed with {} finding(s)",
                    report.findings.len()
                ));
            }
        }
    }
    Ok(())
}

async fn handle_trust_cmd(cmd: TrustCommand) -> Result<()> {
    match cmd {
        TrustCommand::Materialize { config } => {
            let cfg = SignerConfig::from_toml_path(config)?;
            let bundle = materialize_runtime_trust_from_config(&cfg)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "trust_epoch": bundle.trust_epoch,
                    "local_id": cfg.local_id,
                    "peers_path": cfg.peers_path,
                    "action_token_public_key_path": cfg.action_token.as_ref().map(|v| v.public_key_pem_path.clone()),
                }))?
            );
        }
    }
    Ok(())
}

fn load_snapshot(path: &PathBuf) -> Result<ContractSnapshot> {
    let raw = std::fs::read(path)?;
    Ok(serde_json::from_slice(&raw)?)
}

fn load_signature(path: &PathBuf) -> Result<SnapshotSignature> {
    let raw = std::fs::read(path)?;
    Ok(serde_json::from_slice(&raw)?)
}

fn parse_action(raw: &str) -> Result<nxms_transport::wire::EscrowAction> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "release" => Ok(nxms_transport::wire::EscrowAction::Release),
        "refund" => Ok(nxms_transport::wire::EscrowAction::Refund),
        _ => Err(anyhow!("action must be one of: release|refund")),
    }
}

fn sha256_for_serializable<T: serde::Serialize>(value: &T) -> Result<String> {
    let raw = serde_json::to_value(value)?;
    canonical_json_sha256_hex(&raw)
}
