use crate::crypto::Keys;
use crate::host_identity::HostIdentityBundle;
use crate::host_vault::{self, HostVault, load_host_keys, vault_bin_path};
use crate::trust::{RuntimeActionTokenIssuer, RuntimeTrustBundle};
use anyhow::{Context, Result, anyhow, bail};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn generate_local_host_vault(
    local_id: &str,
    host_vault_dir: &Path,
    host_vault_passphrase_file: &Path,
) -> Result<Keys> {
    let passphrase = read_owner_only_text(host_vault_passphrase_file, "host_vault_passphrase_file")?;
    let vault_path = vault_bin_path(host_vault_dir);
    if vault_path.exists() {
        bail!("host vault already exists at {}", vault_path.display());
    }
    HostVault::generate(host_vault_dir, passphrase.as_str(), local_id)
        .with_context(|| format!("failed to generate host vault {}", vault_path.display()))?;
    load_host_keys(host_vault_dir, passphrase.as_str())
        .with_context(|| format!("failed to load generated host vault {}", vault_path.display()))
}

pub fn export_host_identity(
    local_id: &str,
    role: &str,
    host: &str,
    port: u16,
    host_vault_dir: &Path,
    host_vault_passphrase_file: &Path,
    out: &Path,
) -> Result<HostIdentityBundle> {
    let passphrase = read_owner_only_text(host_vault_passphrase_file, "host_vault_passphrase_file")?;
    let keys = load_host_keys(host_vault_dir, passphrase.as_str()).with_context(|| {
        format!(
            "failed to load host vault {}",
            host_vault::vault_bin_path(host_vault_dir).display()
        )
    })?;
    let bundle = HostIdentityBundle::from_local_keys(local_id, role, host, port, &keys)?;
    bundle.write_json(out)?;
    Ok(bundle)
}

pub fn init_runtime_trust_bundle(
    trust_epoch: &str,
    host_identity_paths: &[PathBuf],
    action_token_issuer: &str,
    action_token_algorithm: &str,
    action_token_public_key_pem_path: &Path,
    out: &Path,
) -> Result<RuntimeTrustBundle> {
    if host_identity_paths.is_empty() {
        bail!("at least one --host-identity is required");
    }
    let identities = host_identity_paths
        .iter()
        .map(HostIdentityBundle::load)
        .collect::<Result<Vec<_>>>()?;
    let public_key_pem = read_public_text(action_token_public_key_pem_path, "action_token_public_key_pem_path")?;
    let issuer = normalize_non_empty(action_token_issuer, "action_token_issuer", 256)?;
    let algorithm = normalize_action_token_algorithm(action_token_algorithm)?;
    let bundle = RuntimeTrustBundle::from_host_identities(
        trust_epoch,
        &identities,
        RuntimeActionTokenIssuer {
            issuer,
            algorithm,
            public_key_pem,
        },
    )?;
    bundle.write_json(out)?;
    Ok(bundle)
}

pub fn sign_runtime_trust_bundle(
    bundle_path: &Path,
    signer_id: &str,
    signer_role: &str,
    host_vault_dir: &Path,
    host_vault_passphrase_file: &Path,
    out: &Path,
    created_at_unix_ms: u64,
) -> Result<RuntimeTrustBundle> {
    let passphrase = read_owner_only_text(host_vault_passphrase_file, "host_vault_passphrase_file")?;
    let keys = load_host_keys(host_vault_dir, passphrase.as_str()).with_context(|| {
        format!(
            "failed to load host vault {}",
            host_vault::vault_bin_path(host_vault_dir).display()
        )
    })?;
    let mut bundle = RuntimeTrustBundle::load(bundle_path)?;
    bundle.sign_with_local_keys(signer_id, signer_role, &keys, created_at_unix_ms)?;
    bundle.write_json(out)?;
    Ok(bundle)
}

pub fn verify_runtime_trust_bundle(bundle_path: &Path) -> Result<RuntimeTrustBundle> {
    let bundle = RuntimeTrustBundle::load(bundle_path)?;
    bundle.verify_guard_quorum()?;
    Ok(bundle)
}

pub fn materialize_runtime_trust_for_local(
    bundle_path: &Path,
    local_id: &str,
    host_vault_dir: &Path,
    host_vault_passphrase_file: &Path,
    peers_path: &Path,
    action_token_public_key_pem_path: &Path,
) -> Result<RuntimeTrustBundle> {
    let passphrase = read_owner_only_text(host_vault_passphrase_file, "host_vault_passphrase_file")?;
    let keys = load_host_keys(host_vault_dir, passphrase.as_str()).with_context(|| {
        format!(
            "failed to load host vault {}",
            host_vault::vault_bin_path(host_vault_dir).display()
        )
    })?;
    let bundle = verify_runtime_trust_bundle(bundle_path)?;
    bundle.validate_local_keys(local_id, &keys)?;
    bundle.materialize_for_local(local_id, peers_path, action_token_public_key_pem_path)?;
    Ok(bundle)
}

#[cfg(unix)]
fn read_owner_only_text(path: &Path, label: &str) -> Result<String> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| anyhow!("{label} failed to open '{}': {}", path.display(), e))?;
    let metadata = file
        .metadata()
        .map_err(|e| anyhow!("{label} failed to stat '{}': {}", path.display(), e))?;
    validate_owner_only_file(path, &metadata, label)?;
    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .map_err(|e| anyhow!("{label} failed to read '{}': {}", path.display(), e))?;
    let out = raw.trim().to_string();
    if out.is_empty() {
        return Err(anyhow!("{label} '{}' is empty", path.display()));
    }
    Ok(out)
}

#[cfg(not(unix))]
fn read_owner_only_text(path: &Path, label: &str) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("{label} failed to read '{}': {}", path.display(), e))?;
    let out = raw.trim().to_string();
    if out.is_empty() {
        return Err(anyhow!("{label} '{}' is empty", path.display()));
    }
    Ok(out)
}

#[cfg(unix)]
fn read_public_text(path: &Path, label: &str) -> Result<String> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| anyhow!("{label} failed to open '{}': {}", path.display(), e))?;
    let metadata = file
        .metadata()
        .map_err(|e| anyhow!("{label} failed to stat '{}': {}", path.display(), e))?;
    validate_public_file(path, &metadata, label)?;
    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .map_err(|e| anyhow!("{label} failed to read '{}': {}", path.display(), e))?;
    let out = raw.trim().to_string();
    if out.is_empty() {
        return Err(anyhow!("{label} '{}' is empty", path.display()));
    }
    Ok(format!("{out}\n"))
}

#[cfg(not(unix))]
fn read_public_text(path: &Path, label: &str) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("{label} failed to read '{}': {}", path.display(), e))?;
    let out = raw.trim().to_string();
    if out.is_empty() {
        return Err(anyhow!("{label} '{}' is empty", path.display()));
    }
    Ok(format!("{out}\n"))
}

#[cfg(unix)]
fn validate_owner_only_file(path: &Path, metadata: &std::fs::Metadata, label: &str) -> Result<()> {
    if !metadata.is_file() {
        bail!("{label} '{}' is not a regular file", path.display());
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{label} '{}' must not be group/other accessible (mode {:03o})",
            path.display(),
            mode
        );
    }
    Ok(())
}

#[cfg(unix)]
fn validate_public_file(path: &Path, metadata: &std::fs::Metadata, label: &str) -> Result<()> {
    if !metadata.is_file() {
        bail!("{label} '{}' is not a regular file", path.display());
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        bail!(
            "{label} '{}' has unsafe write permissions (mode {:03o})",
            path.display(),
            mode
        );
    }
    Ok(())
}

fn normalize_non_empty(value: &str, label: &str, max_len: usize) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_len {
        bail!("{label} must be 1..={max_len} chars");
    }
    Ok(trimmed.to_string())
}

fn normalize_action_token_algorithm(value: &str) -> Result<String> {
    let normalized = normalize_non_empty(value, "action_token_algorithm", 16)?.to_ascii_uppercase();
    match normalized.as_str() {
        "EDDSA" | "ES256" => Ok(normalized),
        _ => bail!("action_token_algorithm must be EDDSA or ES256"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAD7TxzeCSPJhJljqWs/fABRUaUBlTkJP8O1v31Z64F/I=\n-----END PUBLIC KEY-----\n";

    fn unique_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nxms_transport_bootstrap_{}_{}_{}",
            label,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    fn write_owner_only_secret(path: &Path, value: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(path, format!("{value}\n")).expect("write");
        #[cfg(unix)]
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }

    fn write_public_pem(path: &Path) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(path, ED25519_PUBLIC_PEM).expect("write pem");
        #[cfg(unix)]
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    }

    #[test]
    fn bootstrap_generate_and_export_host_identity() {
        let dir = unique_dir("export_host_identity");
        let pass_path = dir.join("run/passphrase");
        let vault_dir = dir.join("host-vault");
        let out = dir.join("ag01.pub.json");
        write_owner_only_secret(&pass_path, "correct horse battery");

        let keys = generate_local_host_vault("ag01", &vault_dir, &pass_path).expect("vault");
        let bundle = export_host_identity(
            "ag01",
            "ag-01",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
            443,
            &vault_dir,
            &pass_path,
            &out,
        )
        .expect("export");
        assert_eq!(bundle.host_id, "ag01");
        assert_eq!(bundle.role, "ag-01");
        assert_eq!(bundle.kem_pk_b64, keys.kem_pk_b64);
        assert_eq!(bundle.sig_pk_b64, keys.sig_pk_b64);
    }

    #[test]
    fn bootstrap_init_sign_verify_and_materialize_runtime_trust_bundle() {
        let dir = unique_dir("signed_bundle");
        let action_pem = dir.join("action_token_pub.pem");
        let signer_peers = dir.join("runtime/peers.json");
        let signer_action_pub = dir.join("runtime/action_token_pub.pem");
        write_public_pem(&action_pem);

        let signer_pass = dir.join("signer/run/passphrase");
        let signer_vault = dir.join("signer/host-vault");
        let signer_bundle = dir.join("signer/signer.pub.json");
        write_owner_only_secret(&signer_pass, "correct horse battery");
        generate_local_host_vault("signer-a", &signer_vault, &signer_pass).expect("signer vault");
        export_host_identity(
            "signer-a",
            "signer",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
            443,
            &signer_vault,
            &signer_pass,
            &signer_bundle,
        )
        .expect("signer bundle");

        let orch_pass = dir.join("orch/run/passphrase");
        let orch_vault = dir.join("orch/host-vault");
        let orch_bundle = dir.join("orch/orch.pub.json");
        write_owner_only_secret(&orch_pass, "correct horse battery");
        generate_local_host_vault("orchestrator", &orch_vault, &orch_pass).expect("orch vault");
        export_host_identity(
            "orchestrator",
            "orchestrator",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion",
            443,
            &orch_vault,
            &orch_pass,
            &orch_bundle,
        )
        .expect("orch bundle");

        let ag01_pass = dir.join("ag01/run/passphrase");
        let ag01_vault = dir.join("ag01/host-vault");
        let ag01_bundle = dir.join("ag01/ag01.pub.json");
        write_owner_only_secret(&ag01_pass, "correct horse battery");
        generate_local_host_vault("ag01", &ag01_vault, &ag01_pass).expect("ag01 vault");
        export_host_identity(
            "ag01",
            "ag-01",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccc.onion",
            443,
            &ag01_vault,
            &ag01_pass,
            &ag01_bundle,
        )
        .expect("ag01 bundle");

        let ag02_pass = dir.join("ag02/run/passphrase");
        let ag02_vault = dir.join("ag02/host-vault");
        let ag02_bundle = dir.join("ag02/ag02.pub.json");
        write_owner_only_secret(&ag02_pass, "correct horse battery");
        generate_local_host_vault("ag02", &ag02_vault, &ag02_pass).expect("ag02 vault");
        export_host_identity(
            "ag02",
            "ag-02",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddd.onion",
            443,
            &ag02_vault,
            &ag02_pass,
            &ag02_bundle,
        )
        .expect("ag02 bundle");

        let unsigned = dir.join("runtime-trust.unsigned.json");
        let signed_once = dir.join("runtime-trust.ag01.json");
        let signed_twice = dir.join("runtime-trust.final.json");
        init_runtime_trust_bundle(
            "epoch-1",
            &[signer_bundle, orch_bundle, ag01_bundle, ag02_bundle],
            "nxms-auth",
            "EDDSA",
            &action_pem,
            &unsigned,
        )
        .expect("init bundle");

        let err = verify_runtime_trust_bundle(&unsigned).expect_err("unsigned must fail");
        assert!(err.to_string().contains("requires exactly 2 guard signatures"));

        sign_runtime_trust_bundle(
            &unsigned,
            "ag01",
            "ag-01",
            &ag01_vault,
            &ag01_pass,
            &signed_once,
            1,
        )
        .expect("sign ag01");
        let err = verify_runtime_trust_bundle(&signed_once).expect_err("single signature must fail");
        assert!(err.to_string().contains("requires exactly 2 guard signatures"));

        sign_runtime_trust_bundle(
            &signed_once,
            "ag02",
            "ag-02",
            &ag02_vault,
            &ag02_pass,
            &signed_twice,
            2,
        )
        .expect("sign ag02");
        let bundle = verify_runtime_trust_bundle(&signed_twice).expect("verify final bundle");
        assert_eq!(bundle.trust_epoch, "epoch-1");
        assert_eq!(bundle.signatures.len(), 2);

        let materialized = materialize_runtime_trust_for_local(
            &signed_twice,
            "signer-a",
            &signer_vault,
            &signer_pass,
            &signer_peers,
            &signer_action_pub,
        )
        .expect("materialize for local");
        assert_eq!(materialized.trust_epoch, "epoch-1");
        assert!(signer_peers.exists());
        assert!(signer_action_pub.exists());
    }
}
