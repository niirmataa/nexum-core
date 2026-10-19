use anyhow::{Result, anyhow};
use clap::{Args, Parser, Subcommand};
use nxms_peer::{
    SignReqConfig, export_identity, init_vault, read_secret_text, sign_req,
};
use nxms_transport::crypto::{suite_kem_id, suite_sig_id};
use nxms_transport::wire::EscrowAction;
use serde_json::to_string_pretty;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "nxms-peer")]
#[command(about = "NXMS peer tool: initiates escrow tx_sign_req flows to signers over the mailbox")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a fresh peer host vault (FrodoKEM + Falcon keys).
    Init(InitArgs),
    /// Export the peer identity as a peers.json entry for signer allowlists.
    Identity(IdentityArgs),
    /// Push a tx_sign_req to a signer and wait for its tx_sign_resp.
    SignReq(SignReqArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long)]
    vault_dir: PathBuf,

    #[arg(long)]
    passphrase_file: PathBuf,

    #[arg(long)]
    local_id: String,
}

#[derive(Debug, Args)]
struct IdentityArgs {
    #[arg(long)]
    vault_dir: PathBuf,

    #[arg(long)]
    passphrase_file: PathBuf,

    #[arg(long)]
    out: PathBuf,

    /// Reachable host placeholder for the peers.json entry (mailbox-only
    /// peers do not use it for delivery).
    #[arg(long, default_value = "localhost")]
    host: String,

    #[arg(long, default_value_t = 80)]
    port: u16,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ActionArg {
    Release,
    Refund,
}

impl From<ActionArg> for EscrowAction {
    fn from(value: ActionArg) -> Self {
        match value {
            ActionArg::Release => EscrowAction::Release,
            ActionArg::Refund => EscrowAction::Refund,
        }
    }
}

#[derive(Debug, Args)]
struct SignReqArgs {
    #[arg(long)]
    vault_dir: PathBuf,

    #[arg(long)]
    passphrase_file: PathBuf,

    /// Mailbox base URL (optionally a Tor .onion endpoint).
    #[arg(long)]
    mailbox: String,

    #[arg(long)]
    push_token_file: PathBuf,

    #[arg(long)]
    pull_token_file: PathBuf,

    #[arg(long)]
    ack_token_file: PathBuf,

    /// Signer local id; must exist in the peer book and have this peer in its
    /// peers.json allowlist.
    #[arg(long)]
    to: String,

    #[arg(long)]
    escrow_id: String,

    #[arg(long)]
    action: ActionArg,

    #[arg(long)]
    txset_file: PathBuf,

    #[arg(long)]
    snapshot_hash: String,

    /// Long-poll window per /v1/pull call (server-side capped).
    #[arg(long, default_value_t = 1000)]
    wait_ms: u64,

    /// TTL of the pushed request envelope.
    #[arg(long, default_value_t = 60)]
    ttl_secs: u64,

    /// Overall deadline waiting for tx_sign_resp.
    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,

    /// Peer-side peer book with the signer entry.
    /// Defaults to <vault-dir>/peers.json.
    #[arg(long)]
    peers_file: Option<PathBuf>,

    #[arg(long)]
    human_hint: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Init(args) => {
            let passphrase = read_secret_text(&args.passphrase_file, "passphrase_file")?;
            let keys = init_vault(&args.vault_dir, &passphrase, &args.local_id)?;
            println!("vault_dir: {}", args.vault_dir.display());
            println!("local_id: {}", args.local_id);
            println!("kem: {}", suite_kem_id());
            println!("sig: {}", suite_sig_id());
            println!("pk_kem_b64: {}", keys.kem_pk_b64);
            println!("pk_sig_b64: {}", keys.sig_pk_b64);
        }
        Command::Identity(args) => {
            let passphrase = read_secret_text(&args.passphrase_file, "passphrase_file")?;
            let peer = export_identity(
                &args.vault_dir,
                &passphrase,
                &args.host,
                args.port,
                &args.out,
            )?;
            println!("out: {}", args.out.display());
            println!("{}", to_string_pretty(&peer)?);
        }
        Command::SignReq(args) => {
            let passphrase = read_secret_text(&args.passphrase_file, "passphrase_file")?;
            let push_token = read_secret_text(&args.push_token_file, "push_token_file")?;
            let pull_token = read_secret_text(&args.pull_token_file, "pull_token_file")?;
            let ack_token = read_secret_text(&args.ack_token_file, "ack_token_file")?;
            let peers_path = args
                .peers_file
                .clone()
                .unwrap_or_else(|| args.vault_dir.join("peers.json"));
            let txset_raw = std::fs::read_to_string(&args.txset_file)
                .map_err(|e| anyhow!("txset_file failed to read '{}': {}", args.txset_file.display(), e))?;
            let cfg = SignReqConfig {
                vault_dir: args.vault_dir.clone(),
                passphrase,
                peers_path,
                mailbox_url: args.mailbox.clone(),
                push_token,
                pull_token,
                ack_token,
                to: args.to.clone(),
                escrow_id_hex: args.escrow_id.clone(),
                action: args.action.into(),
                multisig_txset_hex: txset_raw,
                snapshot_hash_hex: args.snapshot_hash.clone(),
                human_hint: args.human_hint.clone(),
                ttl_secs: args.ttl_secs,
                wait_ms: args.wait_ms,
                timeout_secs: args.timeout_secs,
            };
            let outcome = sign_req(&cfg).await?;
            println!("{}", to_string_pretty(&outcome)?);
        }
    }
    Ok(())
}
