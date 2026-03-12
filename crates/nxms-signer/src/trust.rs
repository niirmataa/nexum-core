use crate::config::SignerConfig;
use anyhow::{Result, anyhow, bail};
use nxms_transport::bootstrap::{
    materialize_runtime_trust_for_local_with_passphrase,
    verify_runtime_trust_projection_for_local_with_passphrase,
};
use nxms_transport::trust::RuntimeTrustBundle;

pub fn load_runtime_trust_bundle_from_config(
    cfg: &SignerConfig,
) -> Result<Option<RuntimeTrustBundle>> {
    let Some(path) = &cfg.runtime_trust_bundle_path else {
        return Ok(None);
    };
    let bundle = RuntimeTrustBundle::load_verified(path)?;
    validate_action_token_config_against_bundle(cfg, &bundle)?;
    Ok(Some(bundle))
}

pub fn materialize_runtime_trust_from_config(cfg: &SignerConfig) -> Result<RuntimeTrustBundle> {
    let bundle_path = cfg
        .runtime_trust_bundle_path
        .as_ref()
        .ok_or_else(|| anyhow!("runtime_trust_bundle_path is not configured"))?;
    let action_cfg = cfg
        .action_token
        .as_ref()
        .ok_or_else(|| anyhow!("runtime trust materialization requires action_token config"))?;
    let bundle = materialize_runtime_trust_for_local_with_passphrase(
        bundle_path,
        &cfg.local_id,
        &cfg.host_vault_dir,
        &cfg.host_vault_passphrase,
        &cfg.peers_path,
        &action_cfg.public_key_pem_path,
    )?;
    validate_action_token_config_against_bundle(cfg, &bundle)?;
    Ok(bundle)
}

pub fn validate_runtime_trust_projection(cfg: &SignerConfig) -> Result<Option<RuntimeTrustBundle>> {
    let Some(bundle_path) = &cfg.runtime_trust_bundle_path else {
        return Ok(None);
    };
    let action_cfg = cfg
        .action_token
        .as_ref()
        .ok_or_else(|| anyhow!("runtime trust bundle requires action_token config"))?;
    let bundle = verify_runtime_trust_projection_for_local_with_passphrase(
        bundle_path,
        &cfg.local_id,
        &cfg.host_vault_dir,
        &cfg.host_vault_passphrase,
        &cfg.peers_path,
        &action_cfg.public_key_pem_path,
    )?;
    validate_action_token_config_against_bundle(cfg, &bundle)?;
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
