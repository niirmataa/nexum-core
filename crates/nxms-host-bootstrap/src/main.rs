use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use nxms_transport::bootstrap::{
    export_host_identity, generate_local_host_vault, init_runtime_trust_bundle,
    materialize_runtime_trust_for_local, now_ms, sign_runtime_trust_bundle,
    verify_runtime_trust_bundle,
};
use nxms_transport::crypto::{suite_kem_id, suite_sig_id};
use serde_json::to_string_pretty;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "nxms-host-bootstrap")]
#[command(about = "NXMS neutral bootstrap tool for core host identities and runtime trust")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    GenerateHostVault(GenerateHostVaultArgs),
    ExportHostIdentity(ExportHostIdentityArgs),
    InitBundle(InitBundleArgs),
    SignBundle(SignBundleArgs),
    VerifyBundle(VerifyBundleArgs),
    MaterializeLocal(MaterializeLocalArgs),
}

#[derive(Debug, Args)]
struct GenerateHostVaultArgs {
    #[arg(long)]
    local_id: String,

    #[arg(long)]
    host_vault_dir: PathBuf,

    #[arg(long)]
    host_vault_passphrase_file: PathBuf,
}

#[derive(Debug, Args)]
struct ExportHostIdentityArgs {
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
struct InitBundleArgs {
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
struct SignBundleArgs {
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
struct VerifyBundleArgs {
    #[arg(long)]
    bundle: PathBuf,
}

#[derive(Debug, Args)]
struct MaterializeLocalArgs {
    #[arg(long)]
    bundle: PathBuf,

    #[arg(long)]
    local_id: String,

    #[arg(long)]
    host_vault_dir: PathBuf,

    #[arg(long)]
    host_vault_passphrase_file: PathBuf,

    #[arg(long)]
    peers_out: PathBuf,

    #[arg(long)]
    action_token_public_key_pem_out: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::GenerateHostVault(args) => {
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
        }
        Command::ExportHostIdentity(args) => {
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
        }
        Command::InitBundle(args) => {
            let bundle = init_runtime_trust_bundle(
                &args.trust_epoch,
                &args.host_identity,
                &args.action_token_issuer,
                &args.action_token_algorithm,
                &args.action_token_public_key_pem_path,
                &args.out,
            )?;
            println!("{}", to_string_pretty(&bundle)?);
        }
        Command::SignBundle(args) => {
            let bundle = sign_runtime_trust_bundle(
                &args.bundle,
                &args.signer_id,
                &args.signer_role,
                &args.host_vault_dir,
                &args.host_vault_passphrase_file,
                &args.out,
                args.created_at_unix_ms.unwrap_or_else(now_ms),
            )?;
            println!("{}", to_string_pretty(&bundle)?);
        }
        Command::VerifyBundle(args) => {
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
        }
        Command::MaterializeLocal(args) => {
            let bundle = materialize_runtime_trust_for_local(
                &args.bundle,
                &args.local_id,
                &args.host_vault_dir,
                &args.host_vault_passphrase_file,
                &args.peers_out,
                &args.action_token_public_key_pem_out,
            )?;
            println!(
                "{}",
                to_string_pretty(&serde_json::json!({
                    "trust_epoch": bundle.trust_epoch,
                    "local_id": args.local_id,
                    "peers_path": args.peers_out,
                    "action_token_public_key_path": args.action_token_public_key_pem_out,
                }))?
            );
        }
    }
    Ok(())
}
