use crate::config::SignerConfig;
use anyhow::{Context, Result, anyhow, bail};
use nxms_transport::crypto::Keys;
use nxms_transport::host_identity::HostIdentityBundle;
use nxms_transport::host_vault::{HostVault, load_host_keys, vault_bin_path};
use nxms_transport::peers::PeerBook;
use nxms_transport::trust::RuntimeTrustBundle;
use std::path::Path;

pub fn load_runtime_trust_bundle_from_config(
    cfg: &SignerConfig,
) -> Result<Option<RuntimeTrustBundle>> {
    let Some(path) = &cfg.runtime_trust_bundle_path else {
        return Ok(None);
    };
    let bundle = RuntimeTrustBundle::load(path)?;
    bundle.verify_guard_quorum()?;
    validate_action_token_config_against_bundle(cfg, &bundle)?;
    Ok(Some(bundle))
}

pub fn materialize_runtime_trust_from_config(cfg: &SignerConfig) -> Result<RuntimeTrustBundle> {
    let bundle = load_runtime_trust_bundle_from_config(cfg)?
        .ok_or_else(|| anyhow!("runtime_trust_bundle_path is not configured"))?;
    let keys = load_host_keys(&cfg.host_vault_dir, &cfg.host_vault_passphrase).with_context(|| {
        format!(
            "failed to load host vault {}",
            vault_bin_path(&cfg.host_vault_dir).display()
        )
    })?;
    bundle.validate_local_keys(&cfg.local_id, &keys)?;
    let action_cfg = cfg
        .action_token
        .as_ref()
        .ok_or_else(|| anyhow!("runtime trust materialization requires action_token config"))?;
    bundle.materialize_for_local(
        &cfg.local_id,
        &cfg.peers_path,
        &action_cfg.public_key_pem_path,
    )?;
    Ok(bundle)
}

pub fn generate_local_host_vault(cfg: &SignerConfig) -> Result<Keys> {
    let vault_path = vault_bin_path(&cfg.host_vault_dir);
    if vault_path.exists() {
        bail!("host vault already exists at {}", vault_path.display());
    }
    HostVault::generate(&cfg.host_vault_dir, &cfg.host_vault_passphrase, &cfg.local_id)
        .with_context(|| format!("failed to generate host vault {}", vault_path.display()))?;
    load_host_keys(&cfg.host_vault_dir, &cfg.host_vault_passphrase).with_context(|| {
        format!(
            "failed to load generated host vault {}",
            vault_path.display()
        )
    })
}

pub fn export_host_identity_from_config(
    cfg: &SignerConfig,
    role: &str,
    host: &str,
    port: u16,
    out: &Path,
) -> Result<HostIdentityBundle> {
    let keys = load_host_keys(&cfg.host_vault_dir, &cfg.host_vault_passphrase).with_context(|| {
        format!(
            "failed to load host vault {}",
            vault_bin_path(&cfg.host_vault_dir).display()
        )
    })?;
    let bundle = HostIdentityBundle::from_local_keys(&cfg.local_id, role, host, port, &keys)?;
    bundle.write_json(out)?;
    Ok(bundle)
}

pub fn validate_runtime_trust_projection(
    cfg: &SignerConfig,
    keys: &Keys,
    peers: &PeerBook,
) -> Result<Option<RuntimeTrustBundle>> {
    let Some(bundle) = load_runtime_trust_bundle_from_config(cfg)? else {
        return Ok(None);
    };
    bundle.validate_local_keys(&cfg.local_id, keys)?;
    let projected = bundle.peer_book_for(&cfg.local_id)?;
    if projected != *peers {
        bail!(
            "peers.json does not match runtime trust bundle projection for local_id '{}'",
            cfg.local_id
        );
    }
    let action_cfg = cfg
        .action_token
        .as_ref()
        .ok_or_else(|| anyhow!("runtime trust bundle requires action_token config"))?;
    let actual_pem = std::fs::read_to_string(&action_cfg.public_key_pem_path).with_context(|| {
        format!(
            "failed to read action token public key {}",
            action_cfg.public_key_pem_path.display()
        )
    })?;
    if normalize_text(&actual_pem) != normalize_text(bundle.action_token_public_key_pem()) {
        bail!("action_token public key does not match runtime trust bundle projection");
    }
    Ok(Some(bundle))
}

fn validate_action_token_config_against_bundle(
    cfg: &SignerConfig,
    bundle: &RuntimeTrustBundle,
) -> Result<()> {
    let action_cfg = cfg
        .action_token
        .as_ref()
        .ok_or_else(|| anyhow!("runtime_trust_bundle_path requires action_token config"))?;
    if action_cfg.issuer.trim() != bundle.action_token.issuer.trim() {
        bail!(
            "action_token.issuer '{}' does not match runtime trust bundle issuer '{}'",
            action_cfg.issuer,
            bundle.action_token.issuer
        );
    }
    if action_cfg.algorithm.trim().to_ascii_uppercase()
        != bundle.action_token.algorithm.trim().to_ascii_uppercase()
    {
        bail!(
            "action_token.algorithm '{}' does not match runtime trust bundle algorithm '{}'",
            action_cfg.algorithm,
            bundle.action_token.algorithm
        );
    }
    Ok(())
}

fn normalize_text(value: &str) -> &str {
    value.trim_end_matches(['\r', '\n', ' ', '\t'])
}
