use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use nxms_escrow_orchestrator::{
    ENV_ORCHESTRATOR_CONFIG_PATH, ENV_ORCHESTRATOR_DB_PATH, load_optional_orchestrator_config,
    resolve_orchestrator_db_path,
};
use serde_json::to_string_pretty;
use std::path::PathBuf;

use nxms_escrow_orchestrator::action_token::{ActionTokenCommand, handle_action_token};
use nxms_escrow_orchestrator::db::{OrchestratorDb, SloAlertThresholds};

#[derive(Debug, Parser)]
#[command(name = "nxms-escrow-orchestrator")]
#[command(about = "NXMS auto-multisig orchestrator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    QuorumProof {
        #[command(subcommand)]
        command: QuorumProofCommand,
    },

    ActionToken {
        #[command(subcommand)]
        command: ActionTokenCommand,
    },

    IntegrityCheck(IntegrityCheckArgs),

    SloReport(SloReportArgs),
}

#[derive(Debug, Subcommand)]
enum QuorumProofCommand {
    Set(QuorumProofSetArgs),
    SubmitBundle(QuorumProofSubmitBundleArgs),
}

#[derive(Debug, Args)]
struct QuorumProofSetArgs {
    #[arg(long, env = ENV_ORCHESTRATOR_DB_PATH)]
    db_path: Option<PathBuf>,

    #[arg(long, env = ENV_ORCHESTRATOR_CONFIG_PATH)]
    config_path: Option<PathBuf>,

    #[arg(long)]
    escrow_id_hex: String,

    #[arg(long)]
    role: String,

    #[arg(long)]
    sign_round: String,

    #[arg(long)]
    txset_hash_hex: String,

    #[arg(long)]
    jti: String,

    #[arg(long)]
    req_id: String,
}

#[derive(Debug, Args)]
struct QuorumProofSubmitBundleArgs {
    #[arg(long, env = ENV_ORCHESTRATOR_DB_PATH)]
    db_path: Option<PathBuf>,

    #[arg(long, env = ENV_ORCHESTRATOR_CONFIG_PATH)]
    config_path: Option<PathBuf>,

    #[arg(long)]
    escrow_id_hex: String,

    #[arg(long)]
    txset_hash_hex: String,
}

#[derive(Debug, Args)]
struct IntegrityCheckArgs {
    #[arg(long, env = ENV_ORCHESTRATOR_DB_PATH)]
    db_path: Option<PathBuf>,

    #[arg(long, env = ENV_ORCHESTRATOR_CONFIG_PATH)]
    config_path: Option<PathBuf>,

    #[arg(long, default_value_t = 100)]
    limit: u32,
}

#[derive(Debug, Args)]
struct SloReportArgs {
    #[arg(long, env = ENV_ORCHESTRATOR_DB_PATH)]
    db_path: Option<PathBuf>,

    #[arg(long, env = ENV_ORCHESTRATOR_CONFIG_PATH)]
    config_path: Option<PathBuf>,

    #[arg(long, default_value_t = 3_600_000)]
    window_ms: u64,

    #[arg(long, default_value_t = 900_000)]
    stuck_after_ms: u64,

    #[arg(long, default_value_t = 0)]
    workflows_stuck_total: u64,

    #[arg(long, default_value_t = 900_000)]
    active_workflow_max_age_ms: u64,

    #[arg(long, default_value_t = 250)]
    outbox_pending_total: u64,

    #[arg(long, default_value_t = 50)]
    outbox_sent_unacked_total: u64,

    #[arg(long, default_value_t = 0)]
    dead_letter_window_total: u64,

    #[arg(long, default_value_t = 25)]
    replay_duplicate_window_total: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match cli.command {
        Command::QuorumProof { command } => run_quorum_proof(command).await,
        Command::ActionToken { command } => handle_action_token(command).await,
        Command::IntegrityCheck(args) => run_integrity_check(args).await,
        Command::SloReport(args) => run_slo_report(args).await,
    }
}

async fn run_quorum_proof(command: QuorumProofCommand) -> Result<()> {
    match command {
        QuorumProofCommand::Set(args) => {
            let db_path = resolve_db_path(args.config_path, args.db_path)?;
            let db = OrchestratorDb::new(db_path);
            db.init().await?;
            db.upsert_quorum_sign_proof(
                &args.escrow_id_hex,
                &args.role,
                &args.sign_round,
                &args.txset_hash_hex,
                &args.jti,
                &args.req_id,
            )
            .await?;
            println!("ok");
            Ok(())
        }
        QuorumProofCommand::SubmitBundle(args) => {
            let db_path = resolve_db_path(args.config_path, args.db_path)?;
            let db = OrchestratorDb::new(db_path);
            db.init().await?;
            let bundle = db
                .get_submit_multisig_proof_bundle(&args.escrow_id_hex, &args.txset_hash_hex)
                .await?;
            println!("{}", to_string_pretty(&bundle)?);
            Ok(())
        }
    }
}

async fn run_integrity_check(args: IntegrityCheckArgs) -> Result<()> {
    let db_path = resolve_db_path(args.config_path, args.db_path)?;
    let db = OrchestratorDb::new(db_path);
    db.init().await?;
    let findings = db.check_integrity(args.limit).await?;
    println!("{}", to_string_pretty(&findings)?);
    Ok(())
}

async fn run_slo_report(args: SloReportArgs) -> Result<()> {
    let db_path = resolve_db_path(args.config_path, args.db_path)?;
    let db = OrchestratorDb::new(db_path);
    db.init().await?;

    let thresholds = SloAlertThresholds {
        workflows_stuck_total: args.workflows_stuck_total,
        active_workflow_max_age_ms: args.active_workflow_max_age_ms,
        outbox_pending_total: args.outbox_pending_total,
        outbox_sent_unacked_total: args.outbox_sent_unacked_total,
        dead_letter_window_total: args.dead_letter_window_total,
        replay_duplicate_window_total: args.replay_duplicate_window_total,
    };

    let report = db
        .slo_alert_report(args.window_ms, args.stuck_after_ms, thresholds)
        .await?;

    println!("{}", to_string_pretty(&report)?);
    Ok(())
}

fn resolve_db_path(config_path: Option<PathBuf>, db_path: Option<PathBuf>) -> Result<PathBuf> {
    let config = load_optional_orchestrator_config(config_path)?;
    Ok(resolve_orchestrator_db_path(config.as_ref(), db_path))
}
