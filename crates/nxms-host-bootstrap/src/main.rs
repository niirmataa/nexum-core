use anyhow::{Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use nxms_transport::admission::EscrowAdmissionArtifact;
use nxms_transport::bootstrap::{
    export_action_token_issuer, export_host_identity, generate_action_token_issuer_vault,
    generate_local_host_vault, init_runtime_trust_bundle, materialize_runtime_trust_for_local,
    now_ms, read_owner_only_text, sign_runtime_trust_bundle, verify_runtime_trust_bundle,
    verify_runtime_trust_projection_for_local,
};
use nxms_transport::crypto::{suite_kem_id, suite_sig_id};
use nxms_transport::host_vault::HostVault;
use nxms_transport::trust::RuntimeTrustBundle;
use nxms_transport::wire::EscrowAction;
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
    GenerateActionTokenIssuerVault(GenerateActionTokenIssuerVaultArgs),
    ExportHostIdentity(ExportHostIdentityArgs),
    ExportActionTokenIssuer(ExportActionTokenIssuerArgs),
    InitBundle(InitBundleArgs),
    SignBundle(SignBundleArgs),
    VerifyBundle(VerifyBundleArgs),
    MaterializeLocal(MaterializeLocalArgs),
    CheckLocal(CheckLocalArgs),
    /// Build/extend an escrow admission artifact signed by the AG guards.
    Admission(AdmissionArgs),
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
struct GenerateActionTokenIssuerVaultArgs {
    #[arg(long)]
    issuer: String,

    #[arg(long)]
    algorithm: String,

    #[arg(long)]
    action_token_issuer_vault_dir: PathBuf,

    #[arg(long)]
    action_token_issuer_vault_passphrase_file: PathBuf,
}

#[derive(Debug, Args)]
struct ExportActionTokenIssuerArgs {
    #[arg(long)]
    action_token_issuer_vault_dir: PathBuf,

    #[arg(long)]
    action_token_issuer_vault_passphrase_file: PathBuf,

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
    action_token_issuer_bundle: PathBuf,

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

#[derive(Debug, Args)]
struct CheckLocalArgs {
    #[arg(long)]
    bundle: PathBuf,

    #[arg(long)]
    local_id: String,

    #[arg(long)]
    host_vault_dir: PathBuf,

    #[arg(long)]
    host_vault_passphrase_file: PathBuf,

    #[arg(long)]
    peers_path: PathBuf,

    #[arg(long)]
    action_token_public_key_pem_path: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AdmissionActionArg {
    Release,
    Refund,
}

impl From<AdmissionActionArg> for EscrowAction {
    fn from(value: AdmissionActionArg) -> Self {
        match value {
            AdmissionActionArg::Release => EscrowAction::Release,
            AdmissionActionArg::Refund => EscrowAction::Refund,
        }
    }
}

#[derive(Debug, Args)]
struct AdmissionArgs {
    /// Final runtime trust bundle (after sign-bundle/verify-bundle).
    #[arg(long)]
    bundle: PathBuf,

    #[arg(long)]
    escrow_id: String,

    /// Snapshot POLICY hash (sha256 canonical JSON) as required by the signer.
    #[arg(long)]
    snapshot_hash: String,

    #[arg(long)]
    action: AdmissionActionArg,

    #[arg(long)]
    host_vault_dir: PathBuf,

    #[arg(long)]
    host_vault_passphrase_file: PathBuf,

    /// Existing artifact to extend with this guard's signature
    /// (first guard omits it; second guard passes the first guard's --out).
    #[arg(long = "in")]
    input: Option<PathBuf>,

    #[arg(long)]
    out: PathBuf,

    /// admitted_at_unix_ms of a newly created artifact (default: now).
    #[arg(long)]
    admitted_at: Option<u64>,
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
        Command::GenerateActionTokenIssuerVault(args) => {
            let bundle = generate_action_token_issuer_vault(
                &args.issuer,
                &args.algorithm,
                &args.action_token_issuer_vault_dir,
                &args.action_token_issuer_vault_passphrase_file,
            )?;
            println!("action_token_issuer_vault: {}", args.action_token_issuer_vault_dir.display());
            println!("issuer: {}", bundle.issuer);
            println!("algorithm: {}", bundle.algorithm);
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
        Command::ExportActionTokenIssuer(args) => {
            let bundle = export_action_token_issuer(
                &args.action_token_issuer_vault_dir,
                &args.action_token_issuer_vault_passphrase_file,
                &args.out,
            )?;
            println!("{}", to_string_pretty(&bundle)?);
        }
        Command::InitBundle(args) => {
            let bundle = init_runtime_trust_bundle(
                &args.trust_epoch,
                &args.host_identity,
                &args.action_token_issuer_bundle,
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
        Command::CheckLocal(args) => {
            let bundle = verify_runtime_trust_projection_for_local(
                &args.bundle,
                &args.local_id,
                &args.host_vault_dir,
                &args.host_vault_passphrase_file,
                &args.peers_path,
                &args.action_token_public_key_pem_path,
            )?;
            println!(
                "{}",
                to_string_pretty(&serde_json::json!({
                    "trust_epoch": bundle.trust_epoch,
                    "local_id": args.local_id,
                    "peers_path": args.peers_path,
                    "action_token_public_key_path": args.action_token_public_key_pem_path,
                }))?
            );
        }
        Command::Admission(args) => handle_admission(args)?,
    }
    Ok(())
}

/// Build or extend an escrow admission artifact.
///
/// Called once per AG guard (ag-01, then ag-02): the first call creates the
/// artifact and writes `--out`; the second adds its signature via `--in`.
/// The guard identity (signer_id/signer_role) is derived from the runtime
/// trust bundle by matching the vault's Falcon public key, so it always
/// matches what `verify_against_bundle` expects.
fn handle_admission(args: AdmissionArgs) -> Result<()> {
    let bundle = RuntimeTrustBundle::load_verified(&args.bundle)?;
    let action = EscrowAction::from(args.action);
    let passphrase = read_owner_only_text(
        &args.host_vault_passphrase_file,
        "host_vault_passphrase_file",
    )?;
    let vault = HostVault::load(&args.host_vault_dir, &passphrase)?;
    let guard = bundle
        .peers
        .iter()
        .find(|peer| peer.sig_pk_b64 == vault.keys.sig_pk_b64)
        .ok_or_else(|| {
            anyhow!(
                "host vault sig_pk_b64 is not in runtime trust bundle {}",
                args.bundle.display()
            )
        })?;
    let signer_id = guard.id.clone();
    let signer_role = guard.role.clone();

    let mut artifact = match &args.input {
        Some(path) => {
            let raw = std::fs::read(path)
                .map_err(|e| anyhow!("failed to read admission artifact {}: {e}", path.display()))?;
            let artifact: EscrowAdmissionArtifact = serde_json::from_slice(&raw)
                .map_err(|e| anyhow!("invalid admission artifact {}: {e}", path.display()))?;
            // These fields are covered by the existing signature — refuse to
            // build a self-inconsistent artifact.
            if artifact.escrow_id_hex.trim() != args.escrow_id.trim() {
                bail!("admission artifact escrow_id mismatch: --in {} != --escrow-id {}",
                    artifact.escrow_id_hex, args.escrow_id);
            }
            if artifact.snapshot_hash_hex.trim() != args.snapshot_hash.trim() {
                bail!("admission artifact snapshot_hash mismatch: --in {} != --snapshot-hash {}",
                    artifact.snapshot_hash_hex, args.snapshot_hash);
            }
            if artifact.action != action {
                bail!("admission artifact action mismatch: --in {:?} != --action {:?}",
                    artifact.action, action);
            }
            if artifact.runtime_trust_epoch.trim() != bundle.trust_epoch.trim() {
                bail!("admission artifact runtime_trust_epoch mismatch: --in {} != bundle {}",
                    artifact.runtime_trust_epoch, bundle.trust_epoch);
            }
            artifact
        }
        None => EscrowAdmissionArtifact::new(
            &args.escrow_id,
            &args.snapshot_hash,
            action,
            bundle.trust_epoch.clone(),
            args.admitted_at.unwrap_or_else(now_ms),
        ),
    };

    artifact.sign_with_local_keys(&signer_id, &signer_role, &vault.keys, now_ms())?;
    artifact
        .validate_unsigned()
        .map_err(|e| anyhow!("admission artifact invalid after signing: {e}"))?;
    if artifact.runtime_trust_epoch.trim() != bundle.trust_epoch.trim() {
        bail!("escrow admission runtime_trust_epoch mismatch against bundle");
    }
    let artifact_hash_hex = artifact.hash_hex()?;
    std::fs::write(&args.out, serde_json::to_vec_pretty(&artifact)?)
        .map_err(|e| anyhow!("failed to write {}: {e}", args.out.display()))?;

    // Finalize check: a complete artifact must verify against the bundle.
    // Before the second guard signs, only the guard-signature count may fail.
    let verified = match artifact.verify_against_bundle(&bundle) {
        Ok(()) => true,
        Err(err) if artifact.signatures.len() < 2 => {
            println!(
                "admission: weryfikacja niepelna ({}/2 sygnatur): {}",
                artifact.signatures.len(),
                err
            );
            false
        }
        Err(err) => return Err(err),
    };

    println!(
        "{}",
        to_string_pretty(&serde_json::json!({
            "out": args.out.display().to_string(),
            "escrow_id_hex": artifact.escrow_id_hex,
            "snapshot_hash_hex": artifact.snapshot_hash_hex,
            "action": artifact.action,
            "runtime_trust_epoch": artifact.runtime_trust_epoch,
            "admitted_at_unix_ms": artifact.admitted_at_unix_ms,
            "artifact_hash_hex": artifact_hash_hex,
            "signatures": artifact
                .signatures
                .iter()
                .map(|sig| serde_json::json!({
                    "signer_id": sig.signer_id,
                    "signer_role": sig.signer_role,
                    "alg": sig.alg,
                }))
                .collect::<Vec<_>>(),
            "verified": verified,
        }))?
    );
    Ok(())
}
