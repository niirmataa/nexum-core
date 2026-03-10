# NXMS ROADMAP

## Cel

To repo ma być jednym spójnym rdzeniem systemu auto-multisig, bez mieszania starych flow,
eksperymentów i ścieżek awaryjnych w krytycznej ścieżce runtime.

Docelowe założenia:
- `nxms-transport` jako jedyny wire format
- `nxms-mailbox` jako relay/store-and-forward
- `nxms-signer` jako node z kluczami i lokalną logiką wykonawczą
- `nxms-escrow-orchestrator` jako automat i control-plane
- `nxms-monero-core` jako rdzeń domenowy Monero / multisig
- `tools/nexum-cli` jako narzędzie ręczne / operatorskie / recovery
- komunikacja między hostami tylko przez Tor
- deployment docelowo na Alpine Linux
- brak legacy direct flow w głównej ścieżce

## Zasady ogólne

### Tagi dla wszystkiego
Każdy moduł, plik albo feature#![forbid(unsafe_code)]

mod action_token;
mod db;
mod flow;
mod tx_profile;
mod wallet;
mod worker;

use anyhow::{Result, anyhow};
use clap::{Args, Parser, Subcommand};
use serde_json::to_string_pretty;
use std::path::PathBuf;
use std::time::Duration;

use crate::action_token::{ActionTokenCommand, handle_action_token};
use crate::db::{OrchestratorDb, SloAlertThresholds};
use crate::worker::{OrchestratorWorker, WorkerConfig};

const ENV_BRIDGE_TOKEN_INPUT: &str = "NXMS_ORCH_BRIDGE_TOKEN_INPUT";

#[derive(Debug, Parser)]
#[command(name = "nxms-escrow-orchestrator")]
#[command(about = "NXMS auto-multisig orchestrator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Worker(WorkerArgs),

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

#[derive(Debug, Args)]
struct WorkerArgs {
    #[arg(long, default_value = "nxms_orchestrator.db")]
    db_path: PathBuf,

    #[arg(long, default_value_t = 300_000)]
    stage_timeout_ms: u64,

    #[arg(long, default_value_t = 900_000)]
    submit_timeout_ms: u64,

    #[arg(long, default_value_t = 0)]
    funded_min_balance: u64,

    #[arg(long, default_value_t = 0)]
    funded_min_unlocked_balance: u64,

    #[arg(long, default_value_t = 20)]
    max_height_lag: u64,

    #[arg(long, default_value_t = 2)]
    tx_sign_quorum: u64,

    #[arg(long, default_value_t = 3)]
    confirm_required: u64,

    #[arg(long, default_value_t = 100)]
    batch_limit: u32,

    #[arg(long, default_value_t = 2_000)]
    poll_interval_ms: u64,
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

    #[arg(long, default_value_t = 0)]
    wallet_rpc_failure_window_total: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match cli.command {
        Command::Worker(args) => run_worker(args).await,
        Command::QuorumProof { command } => run_quorum_proof(command).await,
        Command::ActionToken { command } => handle_action_token(command).await,
        Command::IntegrityCheck(args) => run_integrity_check(args).await,
        Command::SloReport(args) => run_slo_report(args).await,
    }
}

pub(crate) fn require_bridge_token(bridge_token: Option<&str>) -> Result<()> {
    let cli_token_ok = bridge_token
        .map(str::trim)
        .map(|v| !v.is_empty())
        .unwrap_or(false);

    if cli_token_ok {
        return Ok(());
    }

    let env_token_ok = std::env::var(ENV_BRIDGE_TOKEN_INPUT)
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    if env_token_ok {
        return Ok(());
    }

    Err(anyhow!(
        "missing bridge token: pass --bridge-token or set {}",
        ENV_BRIDGE_TOKEN_INPUT
    ))
}

async fn run_worker(args: WorkerArgs) -> Result<()> {
    let db = OrchestratorDb::new(args.db_path.clone());
    db.init().await?;

    let cfg = WorkerConfig::from_run_args(
        args.stage_timeout_ms,
        args.submit_timeout_ms,
        args.funded_min_balance,
        args.funded_min_unlocked_balance,
        args.max_height_lag,
        args.tx_sign_quorum,
        args.confirm_required,
        args.batch_limit,
    );

    let wallet = OrchestratorWorker::wallet_from_env();
    let worker = OrchestratorWorker::new(db, wallet, cfg);

    loop {
        let report = worker.tick_once().await?;
        tracing::info!(
            scanned = report.scanned,
            transitioned = report.transitioned,
            dead_lettered = report.dead_lettered,
            confirmed = report.confirmed,
            "worker tick complete"
        );
        tokio::time::sleep(Duration::from_millis(args.poll_interval_ms.max(100))).await;
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
        wallet_rpc_failure_window_total: args.wallet_rpc_failure_window_total,
    };

    let report = db
        .slo_alert_report(args.window_ms, args.stuck_after_ms, thresholds)
        .await?;

    println!("{}", to_string_pretty(&report)?);
    Ok(())
} ma mieć jeden z tagów:
- CORE
- OPS
- MANUAL

### Twarde zasady
- Nie dodawaj drugiego równoległego flow.
- `tools/nexum-cli` nie może być dependency ścieżki krytycznej runtime.
- Break-glass i shadow mode nie mogą być domyślną drogą działania.
- Każda nowa rzecz musi mieć decyzję w docs i test.

## Etap 0 — zamrożenie starego świata
- [ ] Zamknąć stare repo jako archiwum eksperymentu.
- [ ] Utworzyć nowe repo robocze `nxms-core`.
- [ ] Dodać `README.md`.
- [ ] Dodać `docs/NXMS_STACK_SOURCE_OF_TRUTH.md`.
- [ ] Dodać `docs/DECISIONS.md`.

## Etap 1 — szkielet nowego repo
- [ ] Utworzyć `crates/`, `tools/`, `docs/`, `deploy/`, `tests/`.
- [ ] Dodać root `Cargo.toml` jako workspace.
- [ ] Dodać `docs/REPO_LAYOUT.md`.

## Etap 2 — migracja fundamentów transportu
- [ ] Przenieść `nxms-transport`.
- [ ] Przenieść `nxms-mailbox`.
- [ ] Przenieść `nxms-mailbox-client`.
- [ ] Uruchomić testy roundtrip i push/pull/ack.

## Etap 3 — wydzielenie `nxms-monero-core`
- [ ] Dodać crate `nxms-monero-core`.
- [ ] Przenieść logikę domenową Monero / multisig.
- [ ] Nie przenosić `escrow_http/*`.

## Etap 4 — migracja `nxms-signer`
- [ ] Przenieść `nxms-signer`.
- [ ] Potwierdzić action token verification.
- [ ] Potwierdzić sign i submit flow.
- [ ] Wyłączyć shadow mode domyślnie.

## Etap 5 — migracja `nxms-escrow-orchestrator`
- [ ] Przenieść orchestrator bez `http_flow.rs`.
- [ ] Zostawić tylko automat workflow.

## Etap 6 — przeniesienie `nexum-cli`
- [ ] Przenieść do `tools/nexum-cli/`.
- [ ] Zostawić jako MANUAL / recovery / operator tooling.

## Etap 7 — cięcie legacy
- [ ] Usunąć stare HTTP pathy z runtime core.
- [ ] Usunąć direct legacy sign/submit z głównego flow.
- [ ] Oznaczyć break-glass jako awaryjne.

## Etap 8 — Alpine/OpenRC
- [ ] Dodać OpenRC dla mailbox, signer, orchestrator.
- [ ] Sprawdzić build na Alpine/musl.
- [ ] Zrobić lokalne smoke testy na Alpine WSL.

## Etap 9 — testy E2E
- [ ] `tests/workspace_smoke.rs`
- [ ] `tests/e2e_transport_mailbox.rs`
- [ ] `tests/e2e_sign_submit.rs`
- [ ] `tests/e2e_orchestrated_flow.rs`

## Etap 10 — release criteria
- [ ] Każda większa zmiana ma decyzję w docs.
- [ ] Każda większa zmiana ma test.
- [ ] Żadna zmiana nie otwiera drugiego flow.