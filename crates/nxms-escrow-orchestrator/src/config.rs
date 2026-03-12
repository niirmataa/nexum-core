use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use std::path::PathBuf;

pub const ENV_ORCHESTRATOR_CONFIG_PATH: &str = "NXMS_ORCH_CONFIG_PATH";

fn default_action_token_ttl_secs() -> u64 {
    60
}

#[derive(Clone, Debug, Deserialize)]
pub struct ActionTokenRuntimeConfig {
    pub issuer_vault_dir: PathBuf,
    pub issuer_vault_passphrase_file: PathBuf,
    #[serde(default = "default_action_token_ttl_secs")]
    pub default_ttl_secs: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OrchestratorConfig {
    pub db_path: PathBuf,
    #[serde(default)]
    pub runtime_trust_bundle_path: Option<PathBuf>,
    #[serde(default)]
    pub action_token: Option<ActionTokenRuntimeConfig>,
}

impl OrchestratorConfig {
    pub fn from_toml_path(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read orchestrator config {}", path.display()))?;
        let mut cfg: OrchestratorConfig =
            toml::from_str(&raw).with_context(|| format!("invalid TOML in {}", path.display()))?;
        cfg.normalize()?;
        Ok(cfg)
    }

    fn normalize(&mut self) -> Result<()> {
        if self.db_path.as_os_str().is_empty() {
            return Err(anyhow!("db_path must not be empty"));
        }
        if let Some(path) = &self.runtime_trust_bundle_path
            && path.as_os_str().is_empty()
        {
            return Err(anyhow!("runtime_trust_bundle_path must not be empty"));
        }
        if let Some(action_token) = &self.action_token {
            if action_token.issuer_vault_dir.as_os_str().is_empty() {
                return Err(anyhow!("action_token.issuer_vault_dir must not be empty"));
            }
            if action_token
                .issuer_vault_passphrase_file
                .as_os_str()
                .is_empty()
            {
                return Err(anyhow!(
                    "action_token.issuer_vault_passphrase_file must not be empty"
                ));
            }
            if action_token.default_ttl_secs == 0 {
                return Err(anyhow!("action_token.default_ttl_secs must be > 0"));
            }
            if action_token.default_ttl_secs > 120 {
                return Err(anyhow!(
                    "action_token.default_ttl_secs exceeds hard limit (120s)"
                ));
            }
        }
        Ok(())
    }
}

pub fn load_optional_orchestrator_config(
    cli_path: Option<PathBuf>,
) -> Result<Option<OrchestratorConfig>> {
    let path = cli_path.or_else(|| {
        std::env::var(ENV_ORCHESTRATOR_CONFIG_PATH)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    });
    path.map(OrchestratorConfig::from_toml_path).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nxms_orchestrator_config_{}_{}_{}.toml",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    #[test]
    fn orchestrator_config_loads_runtime_paths() {
        let path = unique_path("load");
        std::fs::write(
            &path,
            r#"
db_path = "/var/lib/nxms/orchestrator.db"
runtime_trust_bundle_path = "/var/lib/nxms/bootstrap/runtime-trust.final.json"

[action_token]
issuer_vault_dir = "/var/lib/nxms/action-token-issuer-vault"
issuer_vault_passphrase_file = "/run/nxms/action-token-issuer.passphrase"
default_ttl_secs = 75
"#,
        )
        .expect("write config");
        let cfg = OrchestratorConfig::from_toml_path(&path).expect("load config");
        assert_eq!(cfg.db_path, PathBuf::from("/var/lib/nxms/orchestrator.db"));
        assert_eq!(
            cfg.runtime_trust_bundle_path,
            Some(PathBuf::from(
                "/var/lib/nxms/bootstrap/runtime-trust.final.json"
            ))
        );
        let action_token = cfg.action_token.expect("action token section");
        assert_eq!(
            action_token.issuer_vault_dir,
            PathBuf::from("/var/lib/nxms/action-token-issuer-vault")
        );
        assert_eq!(action_token.default_ttl_secs, 75);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn orchestrator_config_rejects_invalid_ttl() {
        let path = unique_path("ttl");
        std::fs::write(
            &path,
            r#"
db_path = "/var/lib/nxms/orchestrator.db"

[action_token]
issuer_vault_dir = "/var/lib/nxms/action-token-issuer-vault"
issuer_vault_passphrase_file = "/run/nxms/action-token-issuer.passphrase"
default_ttl_secs = 121
"#,
        )
        .expect("write config");
        let err = OrchestratorConfig::from_toml_path(&path).expect_err("ttl > 120 must fail");
        assert!(
            err.to_string()
                .contains("default_ttl_secs exceeds hard limit")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_optional_orchestrator_config_reads_cli_path() {
        let path = unique_path("optional");
        std::fs::write(
            &path,
            r#"
db_path = "/var/lib/nxms/orchestrator.db"
runtime_trust_bundle_path = "/var/lib/nxms/bootstrap/runtime-trust.final.json"

[action_token]
issuer_vault_dir = "/var/lib/nxms/action-token-issuer-vault"
issuer_vault_passphrase_file = "/run/nxms/action-token-issuer.passphrase"
"#,
        )
        .expect("write config");
        let cfg = load_optional_orchestrator_config(Some(path.clone()))
            .expect("load config")
            .expect("config from cli path");
        assert_eq!(cfg.db_path, PathBuf::from("/var/lib/nxms/orchestrator.db"));
        let _ = std::fs::remove_file(path);
    }
}
