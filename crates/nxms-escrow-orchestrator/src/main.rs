use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use nxms_transport::bootstrap::{
    export_host_identity, generate_local_host_vault, init_runtime_trust_bundle,
    now_ms as bootstrap_now_ms, sign_runtime_trust_bundle, verify_runtime_trust_bundle,
};
use nxms_transport::crypto::{suite_kem_id, suite_sig_id};
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
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },

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
enum TrustCommand {
    GenerateHostVault(TrustGenerateHostVaultArgs),
    ExportHostIdentity(TrustExportHostIdentityArgs),
    InitBundle(TrustInitBundleArgs),
    SignBundle(TrustSignBundleArgs),
    VerifyBundle(TrustVerifyBundleArgs),
}

#[derive(Debug, Args)]
struct TrustGenerateHostVaultArgs {
    #[arg(long)]
    local_id: String,

    #[arg(long)]
    host_vault_dir: PathBuf,

    #[arg(long)]
    host_vault_passphrase_file: PathBuf,
}

#[derive(Debug, Args)]
struct TrustExportHostIdentityArgs {
    #[arg(long)]
    local_id: String,

    #[arg(long)]
    role: String,

    #[arg(long)]
    host: String,

    #[arg(long)]
    port: u16,

    #[arg(long)]
    host_vault_dir: PathBuf,

    #[arg(long)]
    host_vault_passphrase_file: PathBuf,

    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct TrustInitBundleArgs {
    #[arg(long)]
    trust_epoch: String,

    #[arg(long, required = true)]
    host_identity: Vec<PathBuf>,

    #[arg(long)]
    action_token_issuer: String,

    #[arg(long)]
    action_token_algorithm: String,

    #[arg(long)]
    action_token_public_key_pem_path: PathBuf,

    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct TrustSignBundleArgs {
    #[arg(long)]
    bundle: PathBuf,

    #[arg(long)]
    signer_id: String,

    #[arg(long)]
    signer_role: String,

    #[arg(long)]
    host_vault_dir: PathBuf,

    #[arg(long)]
    host_vault_passphrase_file: PathBuf,

    #[arg(long)]
    out: PathBuf,

    #[arg(long)]
    created_at_unix_ms: Option<u64>,
}

#[derive(Debug, Args)]
struct TrustVerifyBundleArgs {
    #[arg(long)]
    bundle: PathBuf,
}

#[derive(Debug, Subcommand)]
enum QuorumProofCommand {
    Set(QuorumProofSetArgs),
    SubmitBundle(QuorumProofSubmitBundleArgs),
}

#[derive(Debug, Args)]
struct QuorumProofSetArgs {
    #[arg(long, default_value = "nxms_orchestrator.db")]
    db_path: PathBuf,

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
    #[arg(long, default_value = "nxms_orchestrator.db")]
    db_path: PathBuf,

    #[arg(long)]
    escrow_id_hex: String,

    #[arg(long)]
    txset_hash_hex: String,
}

#[derive(Debug, Args)]
struct IntegrityCheckArgs {
    #[arg(long, default_value = "nxms_orchestrator.db")]
    db_path: PathBuf,

    #[arg(long, default_value_t = 100)]
    limit: u32,
}

#[derive(Debug, Args)]
struct SloReportArgs {
    #[arg(long, default_value = "nxms_orchestrator.db")]
    db_path: PathBuf,

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
        Command::Trust { command } => run_trust(command),
        Command::QuorumProof { command } => run_quorum_proof(command).await,
        Command::ActionToken { command } => handle_action_token(command).await,
        Command::IntegrityCheck(args) => run_integrity_check(args).await,
        Command::SloReport(args) => run_slo_report(args).await,
    }
}

fn run_trust(command: TrustCommand) -> Result<()> {
    match command {
        TrustCommand::GenerateHostVault(args) => {
            let keys = generate_local_host_vault(
                &args.local_id,
                &args.host_vault_dir,
                &args.host_vault_passphrase_file,
            )?;
            println!("host_vault: {}", args.host_vault_dir.display());
            println!("local_id: {}", args.local_id);
            println!("kem: {}", suite_kem_id());
            println!("sig: {}", suite_sig_id());
            println!("pk_kem_b64: {}", keys.kem_pk_b64);
            println!("pk_sig_b64: {}", keys.sig_pk_b64);
            Ok(())
        }
        TrustCommand::ExportHostIdentity(args) => {
            let bundle = export_host_identity(
                &args.local_id,
                &args.role,
                &args.host,
                args.port,
                &args.host_vault_dir,
                &args.host_vault_passphrase_file,
                &args.out,
            )?;
            println!("{}", to_string_pretty(&bundle)?);
            Ok(())
        }
        TrustCommand::InitBundle(args) => {
            let bundle = init_runtime_trust_bundle(
                &args.trust_epoch,
                &args.host_identity,
                &args.action_token_issuer,
                &args.action_token_algorithm,
                &args.action_token_public_key_pem_path,
                &args.out,
            )?;
            println!("{}", to_string_pretty(&bundle)?);
            Ok(())
        }
        TrustCommand::SignBundle(args) => {
            let bundle = sign_runtime_trust_bundle(
                &args.bundle,
                &args.signer_id,
                &args.signer_role,
                &args.host_vault_dir,
                &args.host_vault_passphrase_file,
                &args.out,
                args.created_at_unix_ms.unwrap_or_else(bootstrap_now_ms),
            )?;
            println!("{}", to_string_pretty(&bundle)?);
            Ok(())
        }
        TrustCommand::VerifyBundle(args) => {
            let bundle = verify_runtime_trust_bundle(&args.bundle)?;
            println!(
                "{}",
                to_string_pretty(&serde_json::json!({
                    "trust_epoch": bundle.trust_epoch,
                    "peer_count": bundle.peers.len(),
                    "signature_count": bundle.signatures.len(),
                    "peer_ids": bundle.peers.iter().map(|peer| peer.id.clone()).collect::<Vec<_>>(),
                }))?
            );
            Ok(())
        }
    }
}

async fn run_quorum_proof(command: QuorumProofCommand) -> Result<()> {
    match command {
        QuorumProofCommand::Set(args) => {
            let db = OrchestratorDb::new(args.db_path);
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
            let db = OrchestratorDb::new(args.db_path);
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
    let db = OrchestratorDb::new(args.db_path);
    db.init().await?;
    let findings = db.check_integrity(args.limit).await?;
    println!("{}", to_string_pretty(&findings)?);
    Ok(())
}

async fn run_slo_report(args: SloReportArgs) -> Result<()> {
    let db = OrchestratorDb::new(args.db_path);
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
