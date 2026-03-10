use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::api::ApiConfig;
use crate::db::MailboxLimits;

fn default_bind() -> String {
    "127.0.0.1:4010".to_string()
}

fn default_db_path() -> PathBuf {
    PathBuf::from("nxms_mailbox.db")
}

fn default_max_body_bytes() -> usize {
    16 * 1024 * 1024
}

fn default_default_ttl_secs() -> u64 {
    24 * 60 * 60
}

fn default_max_ttl_secs() -> u64 {
    7 * 24 * 60 * 60
}

fn default_lease_secs() -> u64 {
    60
}

fn default_max_wait_ms() -> u64 {
    20_000
}

fn default_cleanup_secs() -> u64 {
    30
}

fn default_checkpoint_secs() -> u64 {
    300
}

fn default_max_messages_per_inbox() -> u64 {
    10_000
}

fn default_max_bytes_per_inbox() -> u64 {
    64 * 1024 * 1024
}

fn default_max_rows_global() -> u64 {
    1_000_000
}

fn default_rate_limit_ip_per_min() -> u32 {
    300
}

fn default_rate_limit_to_per_min() -> u32 {
    600
}

#[derive(Clone, Debug, Deserialize)]
pub struct MailboxConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_default_ttl_secs")]
    pub default_ttl_secs: u64,
    #[serde(default = "default_max_ttl_secs")]
    pub max_ttl_secs: u64,
    #[serde(default = "default_lease_secs")]
    pub lease_secs: u64,
    #[serde(default = "default_max_wait_ms")]
    pub max_wait_ms: u64,
    pub push_token: String,
    pub pull_tokens: HashMap<String, String>,
    pub ack_tokens: HashMap<String, String>,
    pub admin_token: String,
    #[serde(default = "default_cleanup_secs")]
    pub cleanup_secs: u64,
    #[serde(default = "default_checkpoint_secs")]
    pub checkpoint_secs: u64,
    #[serde(default = "default_max_messages_per_inbox")]
    pub max_messages_per_inbox: u64,
    #[serde(default = "default_max_bytes_per_inbox")]
    pub max_bytes_per_inbox: u64,
    #[serde(default = "default_max_rows_global")]
    pub max_rows_global: u64,
    #[serde(default = "default_rate_limit_ip_per_min")]
    pub rate_limit_ip_per_min: u32,
    #[serde(default = "default_rate_limit_to_per_min")]
    pub rate_limit_to_per_min: u32,
    #[serde(default)]
    pub production_hardening: bool,
}

impl MailboxConfig {
    pub fn from_toml_path(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let mut cfg: MailboxConfig =
            toml::from_str(&raw).with_context(|| format!("invalid TOML in {}", path.display()))?;
        cfg.normalize()?;
        Ok(cfg)
    }

    pub fn bind_addr(&self) -> Result<SocketAddr> {
        self.bind
            .parse::<SocketAddr>()
            .map_err(|e| anyhow!("invalid bind address '{}': {}", self.bind, e))
    }

    pub fn api_config(&self) -> ApiConfig {
        ApiConfig {
            push_token: Some(self.push_token.clone()),
            pull_tokens: self.pull_tokens.clone(),
            ack_tokens: self.ack_tokens.clone(),
            admin_token: Some(self.admin_token.clone()),
            max_body_bytes: self.max_body_bytes,
            default_ttl_secs: self.default_ttl_secs,
            max_ttl_secs: self.max_ttl_secs,
            lease_secs: self.lease_secs,
            max_wait_ms: self.max_wait_ms,
            limits: MailboxLimits {
                max_messages_per_inbox: self.max_messages_per_inbox,
                max_bytes_per_inbox: self.max_bytes_per_inbox,
                max_rows_global: self.max_rows_global,
            },
            rate_limit_ip_per_min: self.rate_limit_ip_per_min,
            rate_limit_to_per_min: self.rate_limit_to_per_min,
        }
    }

    fn normalize(&mut self) -> Result<()> {
        let push_token_from_vault_ref = secret_uses_vault_reference(&self.push_token);
        let admin_token_from_vault_ref = secret_uses_vault_reference(&self.admin_token);
        let pull_tokens_from_vault_refs = self
            .pull_tokens
            .iter()
            .map(|(k, v)| (k.clone(), secret_uses_vault_reference(v)))
            .collect::<HashMap<_, _>>();
        let ack_tokens_from_vault_refs = self
            .ack_tokens
            .iter()
            .map(|(k, v)| (k.clone(), secret_uses_vault_reference(v)))
            .collect::<HashMap<_, _>>();

        let bind_addr = self.bind_addr()?;
        if !bind_addr.ip().is_loopback() {
            return Err(anyhow!(
                "bind must use loopback address; got '{}'",
                self.bind
            ));
        }

        self.push_token = resolve_secret_value(&self.push_token, "push_token")?;
        self.admin_token = resolve_secret_value(&self.admin_token, "admin_token")?;
        normalize_scoped_tokens(&mut self.pull_tokens, "pull_tokens")?;
        normalize_scoped_tokens(&mut self.ack_tokens, "ack_tokens")?;

        if self.pull_tokens.is_empty() {
            return Err(anyhow!("pull_tokens must define at least one inbox scope"));
        }
        if self.ack_tokens.is_empty() {
            return Err(anyhow!("ack_tokens must define at least one inbox scope"));
        }

        let pull_keys = self.pull_tokens.keys().cloned().collect::<HashSet<_>>();
        let ack_keys = self.ack_tokens.keys().cloned().collect::<HashSet<_>>();
        if pull_keys != ack_keys {
            return Err(anyhow!(
                "pull_tokens and ack_tokens must define the same inbox scopes"
            ));
        }

        let mut seen_tokens = HashSet::new();
        for (label, token) in [
            ("push_token", self.push_token.as_str()),
            ("admin_token", self.admin_token.as_str()),
        ] {
            if !seen_tokens.insert(token.to_string()) {
                return Err(anyhow!(
                    "{label} reuses a token already assigned to another scope"
                ));
            }
        }
        for (inbox, token) in &self.pull_tokens {
            if !seen_tokens.insert(token.clone()) {
                return Err(anyhow!(
                    "pull_tokens inbox '{}' reuses a token already assigned to another scope",
                    inbox
                ));
            }
        }
        for (inbox, token) in &self.ack_tokens {
            if !seen_tokens.insert(token.clone()) {
                return Err(anyhow!(
                    "ack_tokens inbox '{}' reuses a token already assigned to another scope",
                    inbox
                ));
            }
        }

        self.max_body_bytes = self.max_body_bytes.max(1024);
        self.default_ttl_secs = self.default_ttl_secs.max(30);
        self.max_ttl_secs = self.max_ttl_secs.max(self.default_ttl_secs);
        self.lease_secs = self.lease_secs.max(1);
        self.max_wait_ms = self.max_wait_ms.clamp(1, 60_000);
        self.cleanup_secs = self.cleanup_secs.max(1);
        self.checkpoint_secs = self.checkpoint_secs.max(1);
        self.max_messages_per_inbox = self.max_messages_per_inbox.max(1);
        self.max_bytes_per_inbox = self.max_bytes_per_inbox.max(1024);
        self.max_rows_global = self.max_rows_global.max(1);

        if self.production_hardening {
            if self.push_token.len() < 16 {
                return Err(anyhow!(
                    "production_hardening=true requires push_token with min 16 chars"
                ));
            }
            if self.admin_token.len() < 16 {
                return Err(anyhow!(
                    "production_hardening=true requires admin_token with min 16 chars"
                ));
            }
            if !push_token_from_vault_ref {
                return Err(anyhow!(
                    "production_hardening=true requires push_token to use vault: secret reference"
                ));
            }
            if !admin_token_from_vault_ref {
                return Err(anyhow!(
                    "production_hardening=true requires admin_token to use vault: secret reference"
                ));
            }
            for (inbox, token) in &self.pull_tokens {
                if token.len() < 16 {
                    return Err(anyhow!(
                        "production_hardening=true requires pull_tokens.{} with min 16 chars",
                        inbox
                    ));
                }
                if !pull_tokens_from_vault_refs
                    .get(inbox)
                    .copied()
                    .unwrap_or(false)
                {
                    return Err(anyhow!(
                        "production_hardening=true requires pull_tokens.{} to use vault: secret reference",
                        inbox
                    ));
                }
            }
            for (inbox, token) in &self.ack_tokens {
                if token.len() < 16 {
                    return Err(anyhow!(
                        "production_hardening=true requires ack_tokens.{} with min 16 chars",
                        inbox
                    ));
                }
                if !ack_tokens_from_vault_refs
                    .get(inbox)
                    .copied()
                    .unwrap_or(false)
                {
                    return Err(anyhow!(
                        "production_hardening=true requires ack_tokens.{} to use vault: secret reference",
                        inbox
                    ));
                }
            }
        }

        Ok(())
    }
}

fn normalize_scoped_tokens(tokens: &mut HashMap<String, String>, label: &str) -> Result<()> {
    let raw = std::mem::take(tokens);
    let mut normalized = HashMap::new();
    for (inbox_raw, token_raw) in raw {
        let inbox = inbox_raw.trim().to_string();
        if inbox.is_empty() {
            return Err(anyhow!("{label} contains empty inbox key"));
        }
        let token = resolve_secret_value(&token_raw, &format!("{label}.{inbox}"))?;
        if normalized.insert(inbox.clone(), token).is_some() {
            return Err(anyhow!("{label} contains duplicate inbox '{}'", inbox));
        }
    }
    *tokens = normalized;
    Ok(())
}

fn resolve_secret_value(raw: &str, label: &str) -> Result<String> {
    let trimmed = raw.trim();
    if let Some(var_name) = trimmed.strip_prefix("env:") {
        let key = var_name.trim();
        if key.is_empty() {
            return Err(anyhow!("{label} env: prefix without variable name"));
        }
        let value =
            std::env::var(key).map_err(|_| anyhow!("{label} env variable '{}' is missing", key))?;
        let out = value.trim().to_string();
        if out.is_empty() {
            return Err(anyhow!("{label} env variable '{}' is empty", key));
        }
        return Ok(out);
    }
    if let Some(path_raw) = trimmed.strip_prefix("vault:") {
        let path = path_raw.trim();
        if path.is_empty() {
            return Err(anyhow!("{label} vault: prefix without path"));
        }
        return read_secret_file(path, label, true);
    }
    if let Some(path_raw) = trimmed.strip_prefix("file:") {
        let path = path_raw.trim();
        if path.is_empty() {
            return Err(anyhow!("{label} file: prefix without path"));
        }
        return read_secret_file(path, label, false);
    }
    let out = trimmed.to_string();
    if out.is_empty() {
        return Err(anyhow!("{label} must not be empty"));
    }
    Ok(out)
}

fn read_secret_file(path: &str, label: &str, require_owner_only: bool) -> Result<String> {
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow!("{label} failed to read metadata for '{}': {}", path, e))?;
    if !meta.is_file() {
        return Err(anyhow!(
            "{label} secret source '{}' is not a regular file",
            path
        ));
    }
    #[cfg(unix)]
    if require_owner_only {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(anyhow!(
                "{label} vault file '{}' must not be group/other accessible (mode {:03o})",
                path,
                mode
            ));
        }
    }
    let value = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("{label} failed to read file '{}': {}", path, e))?;
    let out = value.trim().to_string();
    if out.is_empty() {
        return Err(anyhow!("{label} file '{}' is empty", path));
    }
    Ok(out)
}

fn secret_uses_vault_reference(raw: &str) -> bool {
    let trimmed = raw.trim();
    if let Some(v) = trimmed.strip_prefix("vault:") {
        return !v.trim().is_empty();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    fn temp_secret_path(label: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "nxms_mailbox_secret_{label}_{}_{}",
            std::process::id(),
            ts
        ))
    }

    fn base_cfg() -> MailboxConfig {
        MailboxConfig {
            bind: "127.0.0.1:4010".to_string(),
            db_path: PathBuf::from("mailbox.db"),
            max_body_bytes: default_max_body_bytes(),
            default_ttl_secs: default_default_ttl_secs(),
            max_ttl_secs: default_max_ttl_secs(),
            lease_secs: default_lease_secs(),
            max_wait_ms: default_max_wait_ms(),
            push_token: "push-token-0123456789".to_string(),
            pull_tokens: HashMap::from([(
                "buyer".to_string(),
                "pull-buyer-0123456789".to_string(),
            )]),
            ack_tokens: HashMap::from([("buyer".to_string(), "ack-buyer-0123456789".to_string())]),
            admin_token: "admin-token-0123456789".to_string(),
            cleanup_secs: default_cleanup_secs(),
            checkpoint_secs: default_checkpoint_secs(),
            max_messages_per_inbox: default_max_messages_per_inbox(),
            max_bytes_per_inbox: default_max_bytes_per_inbox(),
            max_rows_global: default_max_rows_global(),
            rate_limit_ip_per_min: default_rate_limit_ip_per_min(),
            rate_limit_to_per_min: default_rate_limit_to_per_min(),
            production_hardening: false,
        }
    }

    #[test]
    fn resolve_secret_from_env_file_and_vault() {
        let _guard = env_lock().lock().expect("env lock");
        let var = "NXMS_MAILBOX_SECRET_TEST";
        unsafe {
            std::env::set_var(var, "secret-from-env");
        }
        let from_env = resolve_secret_value(&format!("env:{var}"), "x").expect("env");
        assert_eq!(from_env, "secret-from-env");
        unsafe {
            std::env::remove_var(var);
        }

        let path = temp_secret_path("file");
        std::fs::write(&path, "secret-from-file\n").expect("write file");
        let from_file =
            resolve_secret_value(&format!("file:{}", path.display()), "x").expect("file");
        assert_eq!(from_file, "secret-from-file");

        #[cfg(unix)]
        {
            let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms).expect("chmod 600");
        }
        let from_vault =
            resolve_secret_value(&format!("vault:{}", path.display()), "x").expect("vault");
        assert_eq!(from_vault, "secret-from-file");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn normalize_rejects_non_loopback_bind() {
        let mut cfg = base_cfg();
        cfg.bind = "10.0.0.2:4010".to_string();
        let err = cfg.normalize().expect_err("must reject non-loopback bind");
        assert!(err.to_string().contains("bind must use loopback address"));
    }

    #[test]
    fn normalize_rejects_pull_ack_scope_mismatch() {
        let mut cfg = base_cfg();
        cfg.ack_tokens =
            HashMap::from([("seller".to_string(), "ack-seller-0123456789".to_string())]);
        let err = cfg.normalize().expect_err("must reject scope mismatch");
        assert!(
            err.to_string()
                .contains("pull_tokens and ack_tokens must define the same inbox scopes")
        );
    }

    #[test]
    fn production_hardening_accepts_vault_secret_refs() {
        let path_push = temp_secret_path("push");
        let path_pull = temp_secret_path("pull");
        let path_ack = temp_secret_path("ack");
        let path_admin = temp_secret_path("admin");
        for (path, value) in [
            (&path_push, "push-token-0123456789"),
            (&path_pull, "pull-token-0123456789"),
            (&path_ack, "ack-token-0123456789"),
            (&path_admin, "admin-token-0123456789"),
        ] {
            std::fs::write(path, value).expect("write secret");
            #[cfg(unix)]
            {
                let mut perms = std::fs::metadata(path).expect("metadata").permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(path, perms).expect("chmod 600");
            }
        }

        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        cfg.push_token = format!("vault:{}", path_push.display());
        cfg.pull_tokens = HashMap::from([(
            "buyer".to_string(),
            format!("vault:{}", path_pull.display()),
        )]);
        cfg.ack_tokens =
            HashMap::from([("buyer".to_string(), format!("vault:{}", path_ack.display()))]);
        cfg.admin_token = format!("vault:{}", path_admin.display());

        cfg.normalize()
            .expect("vault secret refs should pass in hardening");

        for path in [path_push, path_pull, path_ack, path_admin] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn production_hardening_rejects_literal_secret_values() {
        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        let err = cfg
            .normalize()
            .expect_err("literal secrets must be rejected in hardening");
        assert!(
            err.to_string()
                .contains("push_token to use vault: secret reference")
        );
    }
}
