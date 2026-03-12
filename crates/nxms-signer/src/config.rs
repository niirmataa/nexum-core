use anyhow::{Context, Result, anyhow};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignerRole {
    Arbiter,
    Seller,
    Buyer,
}

fn default_signer_role() -> SignerRole {
    SignerRole::Arbiter
}

fn default_nettype() -> String {
    "stagenet".to_string()
}

fn default_action_token_clock_skew_secs() -> u64 {
    5
}

fn default_action_token_required() -> bool {
    true
}

fn default_action_token_max_ttl_secs() -> u64 {
    120
}

fn default_action_token_verify_rate_limit_max_attempts() -> u32 {
    8
}

fn default_action_token_verify_rate_limit_window_secs() -> u64 {
    60
}

fn default_action_token_verify_rate_limit_max_keys() -> usize {
    4096
}

fn default_wallet_provision_cli_path() -> PathBuf {
    PathBuf::from("monero-wallet-cli")
}

fn default_wallet_provision_timeout_secs() -> u64 {
    60
}

fn default_mailbox_retry_attempts() -> u32 {
    3
}

fn default_mailbox_retry_backoff_ms() -> u64 {
    250
}

#[derive(Clone, Debug, Deserialize)]
pub struct ActionTokenConfig {
    #[serde(default = "default_action_token_required")]
    pub required: bool,
    pub issuer: String,
    pub audience: Option<String>,
    pub algorithm: String,
    pub public_key_pem_path: PathBuf,
    #[serde(default = "default_action_token_clock_skew_secs")]
    pub clock_skew_secs: u64,
    #[serde(default = "default_action_token_max_ttl_secs")]
    pub max_ttl_secs: u64,
    #[serde(default = "default_action_token_verify_rate_limit_max_attempts")]
    pub verify_rate_limit_max_attempts: u32,
    #[serde(default = "default_action_token_verify_rate_limit_window_secs")]
    pub verify_rate_limit_window_secs: u64,
    #[serde(default = "default_action_token_verify_rate_limit_max_keys")]
    pub verify_rate_limit_max_keys: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignerConfig {
    pub local_id: String,
    #[serde(default = "default_signer_role")]
    pub signer_role: SignerRole,
    #[serde(default)]
    pub sandbox_id: String,
    #[serde(default)]
    pub wallet_id: String,
    #[serde(default = "default_nettype")]
    pub nettype: String,
    pub peers_path: PathBuf,
    pub host_vault_dir: PathBuf,
    pub host_vault_passphrase: String,
    #[serde(default)]
    pub runtime_trust_bundle_path: Option<PathBuf>,
    pub db_path: PathBuf,

    pub mailbox_url: String,
    pub mailbox_push_token: Option<String>,
    pub mailbox_pull_token: Option<String>,
    pub mailbox_ack_token: Option<String>,
    pub mailbox_admin_token: Option<String>,
    pub worker_service_token: Option<String>,
    pub tor_socks5h: Option<String>,
    #[serde(default = "default_mailbox_retry_attempts")]
    pub mailbox_retry_attempts: u32,
    #[serde(default = "default_mailbox_retry_backoff_ms")]
    pub mailbox_retry_backoff_ms: u64,
    #[serde(default)]
    pub allow_remote_wallet_rpc: bool,
    #[serde(default)]
    pub production_hardening: bool,

    pub wallet_rpc: WalletRpcConfig,

    pub snapshot_quorum: u32,
    pub pull_max: u32,
    pub pull_wait_ms: u64,
    pub poll_interval_ms: u64,
    pub default_ttl_secs: u64,
    pub max_txset_hex_len: usize,
    #[serde(default)]
    pub action_token: Option<ActionTokenConfig>,
    #[serde(default)]
    pub wallet_provision: Option<WalletProvisionConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WalletRpcConfig {
    pub endpoint: String,
    pub wallet_name: String,
    pub wallet_password: String,
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WalletProvisionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_wallet_provision_cli_path")]
    pub wallet_cli_path: PathBuf,
    #[serde(default)]
    pub wallet_dir: Option<PathBuf>,
    #[serde(default)]
    pub daemon_address: Option<String>,
    #[serde(default)]
    pub trusted_daemon: bool,
    #[serde(default)]
    pub extra_args: Vec<String>,
    #[serde(default = "default_wallet_provision_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SecurityCheckItem {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SecurityCheckReport {
    pub ok: bool,
    pub checks: Vec<SecurityCheckItem>,
    pub findings: Vec<String>,
}

impl SignerConfig {
    pub fn from_toml_path(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let mut cfg: SignerConfig =
            toml::from_str(&raw).with_context(|| format!("invalid TOML in {}", path.display()))?;
        cfg.normalize()?;
        Ok(cfg)
    }

    fn normalize(&mut self) -> Result<()> {
        let mailbox_push_token_from_vault_ref = self
            .mailbox_push_token
            .as_deref()
            .map(secret_uses_vault_reference)
            .unwrap_or(false);
        let mailbox_pull_token_from_vault_ref = self
            .mailbox_pull_token
            .as_deref()
            .map(secret_uses_vault_reference)
            .unwrap_or(false);
        let mailbox_ack_token_from_vault_ref = self
            .mailbox_ack_token
            .as_deref()
            .map(secret_uses_vault_reference)
            .unwrap_or(false);
        let mailbox_admin_token_from_vault_ref = self
            .mailbox_admin_token
            .as_deref()
            .map(secret_uses_vault_reference)
            .unwrap_or(false);
        let worker_service_token_from_vault_ref = self
            .worker_service_token
            .as_deref()
            .map(secret_uses_vault_reference)
            .unwrap_or(false);
        let wallet_password_from_vault_ref =
            secret_uses_vault_reference(&self.wallet_rpc.wallet_password);
        let wallet_rpc_password_from_vault_ref =
            secret_uses_vault_reference(&self.wallet_rpc.password);
        let host_vault_passphrase_from_vault_ref =
            secret_uses_vault_reference(&self.host_vault_passphrase);

        self.local_id = self.local_id.trim().to_string();
        if self.local_id.is_empty() {
            return Err(anyhow!("local_id must not be empty"));
        }
        self.sandbox_id = self.sandbox_id.trim().to_string();
        if self.sandbox_id.is_empty() {
            self.sandbox_id = self.local_id.clone();
        }
        self.wallet_id = self.wallet_id.trim().to_string();
        if self.wallet_id.is_empty() {
            self.wallet_id = self.local_id.clone();
        }
        self.nettype = self.nettype.trim().to_ascii_lowercase();
        if self.nettype.is_empty() {
            self.nettype = default_nettype();
        }
        match self.nettype.as_str() {
            "mainnet" | "stagenet" | "testnet" => {}
            _ => {
                return Err(anyhow!("nettype must be one of: mainnet|stagenet|testnet"));
            }
        }
        if self.host_vault_dir.as_os_str().is_empty() {
            return Err(anyhow!("host_vault_dir must not be empty"));
        }
        self.host_vault_passphrase =
            resolve_secret_value(&self.host_vault_passphrase, "host_vault_passphrase")?;
        if self.host_vault_passphrase.trim().len() < 12 {
            return Err(anyhow!(
                "host_vault_passphrase must resolve to at least 12 characters"
            ));
        }
        if let Some(path) = &self.runtime_trust_bundle_path
            && path.as_os_str().is_empty()
        {
            return Err(anyhow!("runtime_trust_bundle_path must not be empty"));
        }
        self.mailbox_url = self.mailbox_url.trim().trim_end_matches('/').to_string();
        if self.mailbox_url.is_empty() {
            return Err(anyhow!("mailbox_url must not be empty"));
        }
        let mailbox_url =
            Url::parse(&self.mailbox_url).map_err(|e| anyhow!("invalid mailbox_url: {}", e))?;
        if !matches!(mailbox_url.scheme(), "http" | "https") {
            return Err(anyhow!("mailbox_url scheme must be http|https"));
        }
        let mailbox_host = mailbox_url
            .host_str()
            .ok_or_else(|| anyhow!("mailbox_url missing host"))?;
        if !mailbox_host.to_ascii_lowercase().ends_with(".onion") {
            return Err(anyhow!("mailbox_url host must be .onion"));
        }
        if let Some(tok) = &mut self.mailbox_push_token {
            *tok = resolve_secret_value(tok, "mailbox_push_token")?;
        }
        if let Some(tok) = &mut self.mailbox_pull_token {
            *tok = resolve_secret_value(tok, "mailbox_pull_token")?;
        }
        if let Some(tok) = &mut self.mailbox_ack_token {
            *tok = resolve_secret_value(tok, "mailbox_ack_token")?;
        }
        if let Some(tok) = &mut self.mailbox_admin_token {
            *tok = resolve_secret_value(tok, "mailbox_admin_token")?;
        }
        if let Some(tok) = &mut self.worker_service_token {
            *tok = resolve_secret_value(tok, "worker_service_token")?;
            if tok.trim().is_empty() {
                return Err(anyhow!("worker_service_token must not be empty"));
            }
        }

        if let Some(socks) = &mut self.tor_socks5h {
            *socks = socks.trim().to_string();
            if socks.is_empty() {
                self.tor_socks5h = None;
            }
        }
        let socks = self
            .tor_socks5h
            .as_ref()
            .ok_or_else(|| anyhow!("tor_socks5h is required for onion routing"))?;
        let socks_url = Url::parse(socks).map_err(|e| anyhow!("invalid tor_socks5h URL: {}", e))?;
        if socks_url.scheme() != "socks5h" {
            return Err(anyhow!("tor_socks5h scheme must be socks5h"));
        }
        let socks_host = socks_url
            .host_str()
            .ok_or_else(|| anyhow!("tor_socks5h missing host"))?;
        let socks_loopback = socks_host.eq_ignore_ascii_case("localhost")
            || socks_host
                .parse::<IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        if !socks_loopback {
            return Err(anyhow!("tor_socks5h host must be loopback"));
        }

        for (name, token) in [
            ("mailbox_push_token", self.mailbox_push_token.as_deref()),
            ("mailbox_pull_token", self.mailbox_pull_token.as_deref()),
            ("mailbox_ack_token", self.mailbox_ack_token.as_deref()),
        ] {
            if token.unwrap_or_default().trim().is_empty() {
                return Err(anyhow!("{name} must be set and non-empty"));
            }
        }

        self.wallet_rpc.endpoint = self
            .wallet_rpc
            .endpoint
            .trim()
            .trim_end_matches('/')
            .to_string();
        if self.wallet_rpc.endpoint.is_empty() {
            return Err(anyhow!("wallet_rpc.endpoint must not be empty"));
        }
        self.wallet_rpc.wallet_password = resolve_secret_value(
            &self.wallet_rpc.wallet_password,
            "wallet_rpc.wallet_password",
        )?;
        self.wallet_rpc.password =
            resolve_secret_value(&self.wallet_rpc.password, "wallet_rpc.password")?;
        let parsed_wallet_rpc_url = Url::parse(&self.wallet_rpc.endpoint)
            .map_err(|e| anyhow!("wallet_rpc.endpoint must be valid URL: {}", e))?;
        match parsed_wallet_rpc_url.scheme() {
            "http" | "https" => {}
            other => {
                return Err(anyhow!(
                    "wallet_rpc.endpoint unsupported URL scheme '{}'",
                    other
                ));
            }
        }
        if self.allow_remote_wallet_rpc {
            return Err(anyhow!(
                "allow_remote_wallet_rpc=true is no longer supported; wallet_rpc.endpoint must stay loopback-only"
            ));
        }
        let host = parsed_wallet_rpc_url
            .host_str()
            .ok_or_else(|| anyhow!("wallet_rpc.endpoint missing host"))?;
        let is_loopback_host = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        if !is_loopback_host {
            return Err(anyhow!(
                "wallet_rpc.endpoint must use loopback host; got '{}'",
                host
            ));
        }

        self.snapshot_quorum = self.snapshot_quorum.max(1);
        self.pull_max = self.pull_max.clamp(1, 50);
        self.pull_wait_ms = self.pull_wait_ms.min(60_000);
        self.poll_interval_ms = self.poll_interval_ms.max(100);
        self.mailbox_retry_attempts = self.mailbox_retry_attempts.clamp(1, 16);
        self.mailbox_retry_backoff_ms = self.mailbox_retry_backoff_ms.clamp(50, 10_000);
        self.default_ttl_secs = self.default_ttl_secs.max(30);
        self.max_txset_hex_len = self.max_txset_hex_len.max(2048);

        if let Some(action_token) = &mut self.action_token {
            action_token.issuer = action_token.issuer.trim().to_string();
            if action_token.issuer.is_empty() {
                return Err(anyhow!("action_token.issuer must not be empty"));
            }
            action_token.algorithm = action_token.algorithm.trim().to_ascii_uppercase();
            match action_token.algorithm.as_str() {
                "EDDSA" | "ES256" => {}
                _ => {
                    return Err(anyhow!("action_token.algorithm must be EDDSA or ES256"));
                }
            }
            if action_token.public_key_pem_path.as_os_str().is_empty() {
                return Err(anyhow!(
                    "action_token.public_key_pem_path must not be empty"
                ));
            }
            if let Some(aud) = &mut action_token.audience {
                *aud = aud.trim().to_string();
                if aud.is_empty() {
                    action_token.audience = None;
                }
            }
            action_token.clock_skew_secs = action_token.clock_skew_secs.min(120);
            action_token.max_ttl_secs = action_token.max_ttl_secs.clamp(10, 900);
            action_token.verify_rate_limit_max_attempts =
                action_token.verify_rate_limit_max_attempts.clamp(1, 128);
            action_token.verify_rate_limit_window_secs =
                action_token.verify_rate_limit_window_secs.clamp(1, 3600);
            action_token.verify_rate_limit_max_keys =
                action_token.verify_rate_limit_max_keys.clamp(64, 262_144);
        }

        let action_token = self
            .action_token
            .as_ref()
            .ok_or_else(|| anyhow!("NXMS Falcon multisig mode requires [action_token] section"))?;
        if !action_token.required {
            return Err(anyhow!(
                "NXMS Falcon multisig mode requires [action_token].required=true"
            ));
        }
        if self.worker_service_token.is_none() {
            return Err(anyhow!(
                "nxms-signer worker API requires worker_service_token"
            ));
        }

        if let Some(wallet_provision) = &mut self.wallet_provision {
            if wallet_provision.wallet_cli_path.as_os_str().is_empty() {
                return Err(anyhow!(
                    "wallet_provision.wallet_cli_path must not be empty"
                ));
            }
            if let Some(dir) = &wallet_provision.wallet_dir
                && dir.as_os_str().is_empty()
            {
                wallet_provision.wallet_dir = None;
            }
            if let Some(daemon_address) = &mut wallet_provision.daemon_address {
                *daemon_address = daemon_address.trim().to_string();
                if daemon_address.is_empty() {
                    wallet_provision.daemon_address = None;
                }
            }
            wallet_provision.extra_args = wallet_provision
                .extra_args
                .iter()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>();
            if wallet_provision
                .extra_args
                .iter()
                .any(|v| v.contains('\n') || v.contains('\r'))
            {
                return Err(anyhow!(
                    "wallet_provision.extra_args must not contain newlines"
                ));
            }
            wallet_provision.timeout_secs = wallet_provision.timeout_secs.clamp(5, 600);
        }

        if self.production_hardening {
            if self.wallet_rpc.wallet_password.trim().is_empty() {
                return Err(anyhow!(
                    "production_hardening=true requires non-empty wallet_rpc.wallet_password"
                ));
            }
            if self.wallet_rpc.password.trim().is_empty() {
                return Err(anyhow!(
                    "production_hardening=true requires non-empty wallet_rpc.password"
                ));
            }
            if !wallet_password_from_vault_ref {
                return Err(anyhow!(
                    "production_hardening=true requires wallet_rpc.wallet_password to use vault: secret reference"
                ));
            }
            if !wallet_rpc_password_from_vault_ref {
                return Err(anyhow!(
                    "production_hardening=true requires wallet_rpc.password to use vault: secret reference"
                ));
            }
            if !host_vault_passphrase_from_vault_ref {
                return Err(anyhow!(
                    "production_hardening=true requires host_vault_passphrase to use vault: secret reference"
                ));
            }
            if self.mailbox_push_token.as_deref().unwrap_or_default().len() < 16 {
                return Err(anyhow!(
                    "production_hardening=true requires mailbox_push_token with min 16 chars"
                ));
            }
            if !mailbox_push_token_from_vault_ref {
                return Err(anyhow!(
                    "production_hardening=true requires mailbox_push_token to use vault: secret reference"
                ));
            }
            if self.mailbox_pull_token.as_deref().unwrap_or_default().len() < 16 {
                return Err(anyhow!(
                    "production_hardening=true requires mailbox_pull_token with min 16 chars"
                ));
            }
            if !mailbox_pull_token_from_vault_ref {
                return Err(anyhow!(
                    "production_hardening=true requires mailbox_pull_token to use vault: secret reference"
                ));
            }
            if self.mailbox_ack_token.as_deref().unwrap_or_default().len() < 16 {
                return Err(anyhow!(
                    "production_hardening=true requires mailbox_ack_token with min 16 chars"
                ));
            }
            if !mailbox_ack_token_from_vault_ref {
                return Err(anyhow!(
                    "production_hardening=true requires mailbox_ack_token to use vault: secret reference"
                ));
            }
            if self.mailbox_admin_token.is_some() && !mailbox_admin_token_from_vault_ref {
                return Err(anyhow!(
                    "production_hardening=true requires mailbox_admin_token to use vault: secret reference"
                ));
            }
            if self
                .worker_service_token
                .as_deref()
                .unwrap_or_default()
                .len()
                < 16
            {
                return Err(anyhow!(
                    "production_hardening=true requires worker_service_token with min 16 chars"
                ));
            }
            if !worker_service_token_from_vault_ref {
                return Err(anyhow!(
                    "production_hardening=true requires worker_service_token to use vault: secret reference"
                ));
            }
            let action_token = self.action_token.as_ref().ok_or_else(|| {
                anyhow!("production_hardening=true requires [action_token] section")
            })?;
            if !action_token.required {
                return Err(anyhow!(
                    "production_hardening=true requires [action_token] with required=true"
                ));
            }
            let expected_audience = format!("sandbox:{}", self.sandbox_id);
            let audience = action_token.audience.as_deref().ok_or_else(|| {
                anyhow!(
                    "production_hardening=true requires [action_token].audience='{}'",
                    expected_audience
                )
            })?;
            if audience != expected_audience {
                return Err(anyhow!(
                    "production_hardening=true requires [action_token].audience='{}' (got '{}')",
                    expected_audience,
                    audience
                ));
            }
            if action_token.max_ttl_secs > 120 {
                return Err(anyhow!(
                    "production_hardening=true requires [action_token].max_ttl_secs <= 120"
                ));
            }

            let wallet_provision = self.wallet_provision.as_ref().ok_or_else(|| {
                anyhow!("production_hardening=true requires [wallet_provision] section")
            })?;
            if !wallet_provision.enabled {
                return Err(anyhow!(
                    "production_hardening=true requires [wallet_provision] with enabled=true"
                ));
            }
        }
        Ok(())
    }

    pub fn security_report(&self) -> SecurityCheckReport {
        let mut checks: Vec<SecurityCheckItem> = Vec::new();
        let mut add = |name: &str, ok: bool, detail: String| {
            checks.push(SecurityCheckItem {
                name: name.to_string(),
                ok,
                detail,
            });
        };

        let wallet_host = parse_host(&self.wallet_rpc.endpoint, "wallet_rpc.endpoint").ok();
        let wallet_loopback = wallet_host
            .as_deref()
            .map(is_loopback_host)
            .unwrap_or(false);
        add(
            "wallet_rpc_loopback",
            wallet_loopback,
            format!(
                "wallet_rpc host={} allow_remote_wallet_rpc={}",
                wallet_host.as_deref().unwrap_or("<invalid>"),
                self.allow_remote_wallet_rpc
            ),
        );
        add(
            "action_token_required",
            self.action_token
                .as_ref()
                .map(|v| v.required)
                .unwrap_or(false),
            "requires [action_token].required=true".to_string(),
        );
        add(
            "mailbox_onion",
            parse_host(&self.mailbox_url, "mailbox_url")
                .map(|h| h.to_ascii_lowercase().ends_with(".onion"))
                .unwrap_or(false),
            format!("mailbox_url={}", self.mailbox_url),
        );
        add(
            "tor_socks5h_present",
            self.tor_socks5h.is_some(),
            format!(
                "tor_socks5h={}",
                self.tor_socks5h.as_deref().unwrap_or("<none>")
            ),
        );
        add(
            "mailbox_retry_enabled",
            self.mailbox_retry_attempts >= 2,
            format!(
                "mailbox_retry_attempts={} mailbox_retry_backoff_ms={}",
                self.mailbox_retry_attempts, self.mailbox_retry_backoff_ms
            ),
        );
        add(
            "mailbox_push_token_min_len",
            self.mailbox_push_token.as_deref().unwrap_or_default().len() >= 16,
            format!(
                "mailbox_push_token_len={}",
                self.mailbox_push_token.as_deref().unwrap_or_default().len()
            ),
        );
        add(
            "mailbox_pull_token_min_len",
            self.mailbox_pull_token.as_deref().unwrap_or_default().len() >= 16,
            format!(
                "mailbox_pull_token_len={}",
                self.mailbox_pull_token.as_deref().unwrap_or_default().len()
            ),
        );
        add(
            "mailbox_ack_token_min_len",
            self.mailbox_ack_token.as_deref().unwrap_or_default().len() >= 16,
            format!(
                "mailbox_ack_token_len={}",
                self.mailbox_ack_token.as_deref().unwrap_or_default().len()
            ),
        );
        add(
            "worker_service_token_min_len",
            self.worker_service_token
                .as_deref()
                .unwrap_or_default()
                .len()
                >= 16,
            format!(
                "worker_service_token_len={}",
                self.worker_service_token
                    .as_deref()
                    .unwrap_or_default()
                    .len()
            ),
        );
        add(
            "wallet_rpc_secrets_present",
            !self.wallet_rpc.wallet_password.trim().is_empty()
                && !self.wallet_rpc.password.trim().is_empty(),
            "wallet_rpc.{wallet_password,password} must be non-empty".to_string(),
        );
        add(
            "production_hardening_enabled",
            self.production_hardening,
            format!("production_hardening={}", self.production_hardening),
        );
        add(
            "wallet_provision_enabled",
            self.wallet_provision
                .as_ref()
                .map(|v| v.enabled)
                .unwrap_or(false),
            format!(
                "wallet_provision.enabled={}",
                self.wallet_provision
                    .as_ref()
                    .map(|v| v.enabled)
                    .unwrap_or(false)
            ),
        );
        let orch_verify = env_bool("NXMS_SIGNER_ORCH_QUORUM_PROOF_VERIFY");
        add(
            "orchestrator_quorum_verify",
            !self.production_hardening || orch_verify,
            format!(
                "production_hardening={} NXMS_SIGNER_ORCH_QUORUM_PROOF_VERIFY={}",
                self.production_hardening, orch_verify
            ),
        );

        let findings = checks
            .iter()
            .filter(|c| !c.ok)
            .map(|c| format!("{}: {}", c.name, c.detail))
            .collect::<Vec<_>>();
        SecurityCheckReport {
            ok: findings.is_empty(),
            checks,
            findings,
        }
    }
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
    Ok(trimmed.to_string())
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

fn parse_host(url: &str, label: &str) -> Result<String> {
    let parsed = Url::parse(url).map_err(|e| anyhow!("{label} must be valid URL: {}", e))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("{label} missing host"))?;
    Ok(host.to_string())
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

fn env_bool(name: &str) -> bool {
    let raw = std::env::var(name).unwrap_or_default();
    let trimmed = raw.trim();
    trimmed.eq_ignore_ascii_case("true") || trimmed == "1"
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

    fn base_cfg() -> SignerConfig {
        SignerConfig {
            local_id: "arbiter".to_string(),
            signer_role: SignerRole::Arbiter,
            sandbox_id: "sandbox-1".to_string(),
            wallet_id: "wallet-1".to_string(),
            nettype: "stagenet".to_string(),
            peers_path: PathBuf::from("peers.json"),
            host_vault_dir: PathBuf::from("host-vault"),
            host_vault_passphrase: "correct horse battery".to_string(),
            runtime_trust_bundle_path: None,
            db_path: PathBuf::from("signer.db"),
            mailbox_url: "http://mailbox.onion".to_string(),
            mailbox_push_token: Some("1234567890abcdef-push".to_string()),
            mailbox_pull_token: Some("1234567890abcdef-pull".to_string()),
            mailbox_ack_token: Some("1234567890abcdef-ack".to_string()),
            mailbox_admin_token: None,
            worker_service_token: Some("1234567890abcdef-worker".to_string()),
            tor_socks5h: Some("socks5h://127.0.0.1:9050".to_string()),
            mailbox_retry_attempts: 3,
            mailbox_retry_backoff_ms: 250,
            allow_remote_wallet_rpc: false,
            production_hardening: false,
            wallet_rpc: WalletRpcConfig {
                endpoint: "http://127.0.0.1:18088".to_string(),
                wallet_name: "wallet".to_string(),
                wallet_password: "wallet-pass".to_string(),
                username: "user".to_string(),
                password: "rpc-pass".to_string(),
            },
            snapshot_quorum: 1,
            pull_max: 10,
            pull_wait_ms: 0,
            poll_interval_ms: 100,
            default_ttl_secs: 60,
            max_txset_hex_len: 4096,
            action_token: Some(ActionTokenConfig {
                required: true,
                issuer: "nxms-auth".to_string(),
                audience: Some("sandbox:sandbox-1".to_string()),
                algorithm: "EDDSA".to_string(),
                public_key_pem_path: PathBuf::from("/tmp/pub.pem"),
                clock_skew_secs: 5,
                max_ttl_secs: 120,
                verify_rate_limit_max_attempts: 8,
                verify_rate_limit_window_secs: 60,
                verify_rate_limit_max_keys: 4096,
            }),
            wallet_provision: Some(WalletProvisionConfig {
                enabled: true,
                wallet_cli_path: PathBuf::from("/usr/bin/monero-wallet-cli"),
                wallet_dir: Some(PathBuf::from("/var/lib/monero/wallets")),
                daemon_address: Some("127.0.0.1:38081".to_string()),
                trusted_daemon: true,
                extra_args: Vec::new(),
                timeout_secs: 60,
            }),
        }
    }

    struct TestVaultSecrets {
        paths: Vec<PathBuf>,
    }

    impl Drop for TestVaultSecrets {
        fn drop(&mut self) {
            for path in self.paths.drain(..) {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    fn temp_secret_file(tag: &str, value: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "nxms_test_vault_{}_{}_{}",
            tag,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&path, format!("{value}\n")).expect("write secret file");
        #[cfg(unix)]
        {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod secret file");
        }
        path
    }

    fn apply_production_vault_secrets(cfg: &mut SignerConfig) -> TestVaultSecrets {
        let host_vault_passphrase =
            temp_secret_file("host_vault_passphrase", "correct horse battery");
        let wallet_password = temp_secret_file("wallet_password", "wallet-pass");
        let rpc_password = temp_secret_file("rpc_password", "rpc-pass");
        let mailbox_push_token = temp_secret_file("mailbox_push_token", "1234567890abcdef-push");
        let mailbox_pull_token = temp_secret_file("mailbox_pull_token", "1234567890abcdef-pull");
        let mailbox_ack_token = temp_secret_file("mailbox_ack_token", "1234567890abcdef-ack");
        let worker_service_token =
            temp_secret_file("worker_service_token", "1234567890abcdef-worker");

        cfg.host_vault_passphrase = format!("vault:{}", host_vault_passphrase.display());
        cfg.wallet_rpc.wallet_password = format!("vault:{}", wallet_password.display());
        cfg.wallet_rpc.password = format!("vault:{}", rpc_password.display());
        cfg.mailbox_push_token = Some(format!("vault:{}", mailbox_push_token.display()));
        cfg.mailbox_pull_token = Some(format!("vault:{}", mailbox_pull_token.display()));
        cfg.mailbox_ack_token = Some(format!("vault:{}", mailbox_ack_token.display()));
        cfg.worker_service_token = Some(format!("vault:{}", worker_service_token.display()));

        TestVaultSecrets {
            paths: vec![
                host_vault_passphrase,
                wallet_password,
                rpc_password,
                mailbox_push_token,
                mailbox_pull_token,
                mailbox_ack_token,
                worker_service_token,
            ],
        }
    }

    #[test]
    fn resolve_secret_from_env_file_and_vault() {
        let _guard = env_lock().lock().expect("env lock");
        let var = format!(
            "NXMS_TEST_SECRET_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        unsafe {
            std::env::set_var(&var, "secret-from-env");
        }
        let from_env = resolve_secret_value(&format!("env:{var}"), "x").expect("env");
        assert_eq!(from_env, "secret-from-env");

        let path = std::env::temp_dir().join(format!("nxms_secret_{}.txt", var));
        std::fs::write(&path, "secret-from-file\n").expect("write");
        let from_file =
            resolve_secret_value(&format!("file:{}", path.display()), "x").expect("file");
        assert_eq!(from_file, "secret-from-file");

        #[cfg(unix)]
        {
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms).expect("chmod");
        }
        let from_vault =
            resolve_secret_value(&format!("vault:{}", path.display()), "x").expect("vault");
        assert_eq!(from_vault, "secret-from-file");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[cfg(unix)]
    fn resolve_vault_secret_rejects_world_readable_file() {
        let _guard = env_lock().lock().expect("env lock");
        let path = std::env::temp_dir().join(format!(
            "nxms_vault_secret_insecure_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&path, "secret-from-vault\n").expect("write");
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(&path, perms).expect("chmod");
        let err = resolve_secret_value(&format!("vault:{}", path.display()), "x")
            .expect_err("insecure permissions must fail");
        assert!(
            err.to_string()
                .contains("must not be group/other accessible")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn production_hardening_requires_action_token_required() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        let _vault = apply_production_vault_secrets(&mut cfg);
        cfg.action_token = None;
        let err = cfg
            .normalize()
            .expect_err("must reject missing action token");
        assert!(err.to_string().contains("action_token"));
    }

    #[test]
    fn production_hardening_rejects_action_token_required_false() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        let _vault = apply_production_vault_secrets(&mut cfg);
        cfg.action_token.as_mut().expect("action token").required = false;
        let err = cfg.normalize().expect_err("must reject required=false");
        assert!(err.to_string().contains("required=true"));
    }

    #[test]
    fn production_hardening_rejects_action_token_missing_audience() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        let _vault = apply_production_vault_secrets(&mut cfg);
        cfg.action_token.as_mut().expect("action token").audience = None;
        let err = cfg.normalize().expect_err("must reject audience none");
        assert!(err.to_string().contains("action_token].audience"));
    }

    #[test]
    fn production_hardening_rejects_action_token_audience_mismatch() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        let _vault = apply_production_vault_secrets(&mut cfg);
        cfg.action_token.as_mut().expect("action token").audience =
            Some("sandbox:other".to_string());
        let err = cfg.normalize().expect_err("must reject audience mismatch");
        assert!(err.to_string().contains("sandbox:sandbox-1"));
    }

    #[test]
    fn production_hardening_rejects_action_token_ttl_too_large() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        let _vault = apply_production_vault_secrets(&mut cfg);
        cfg.action_token
            .as_mut()
            .expect("action token")
            .max_ttl_secs = 600;
        let err = cfg.normalize().expect_err("must reject large max_ttl_secs");
        assert!(err.to_string().contains("max_ttl_secs <= 120"));
    }

    #[test]
    fn production_hardening_requires_wallet_provision_enabled() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        let _vault = apply_production_vault_secrets(&mut cfg);
        cfg.wallet_provision = None;
        let err = cfg
            .normalize()
            .expect_err("must reject missing wallet provision");
        assert!(err.to_string().contains("wallet_provision"));
    }

    #[test]
    fn production_hardening_rejects_wallet_provision_disabled() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        let _vault = apply_production_vault_secrets(&mut cfg);
        cfg.wallet_provision
            .as_mut()
            .expect("wallet provision")
            .enabled = false;
        let err = cfg.normalize().expect_err("must reject enabled=false");
        assert!(err.to_string().contains("wallet_provision"));
    }

    #[test]
    fn default_mode_rejects_non_onion_mailbox() {
        let mut cfg = base_cfg();
        cfg.production_hardening = false;
        cfg.mailbox_url = "http://example.com".to_string();
        let err = cfg.normalize().expect_err("must reject non-onion mailbox");
        assert!(err.to_string().contains("mailbox_url host must be .onion"));
    }

    #[test]
    fn default_mode_rejects_non_http_mailbox_scheme() {
        let mut cfg = base_cfg();
        cfg.production_hardening = false;
        cfg.mailbox_url = "ftp://mailbox.onion".to_string();
        let err = cfg
            .normalize()
            .expect_err("must reject unsupported mailbox scheme");
        assert!(
            err.to_string()
                .contains("mailbox_url scheme must be http|https")
        );
    }

    #[test]
    fn default_mode_rejects_missing_tor_socks() {
        let mut cfg = base_cfg();
        cfg.production_hardening = false;
        cfg.tor_socks5h = None;
        let err = cfg.normalize().expect_err("must reject missing tor socks");
        assert!(err.to_string().contains("tor_socks5h is required"));
    }

    #[test]
    fn default_mode_rejects_non_socks5h_scheme() {
        let mut cfg = base_cfg();
        cfg.production_hardening = false;
        cfg.tor_socks5h = Some("socks5://127.0.0.1:9050".to_string());
        let err = cfg
            .normalize()
            .expect_err("must reject tor_socks scheme without host resolution");
        assert!(
            err.to_string()
                .contains("tor_socks5h scheme must be socks5h")
        );
    }

    #[test]
    fn default_mode_rejects_non_loopback_socks_host() {
        let mut cfg = base_cfg();
        cfg.production_hardening = false;
        cfg.tor_socks5h = Some("socks5h://10.0.0.2:9050".to_string());
        let err = cfg
            .normalize()
            .expect_err("must reject non-loopback tor socks endpoint");
        assert!(
            err.to_string()
                .contains("tor_socks5h host must be loopback")
        );
    }

    #[test]
    fn reject_allow_remote_wallet_rpc_true_even_when_not_hardened() {
        let mut cfg = base_cfg();
        cfg.production_hardening = false;
        cfg.allow_remote_wallet_rpc = true;
        cfg.wallet_rpc.endpoint = "http://10.0.0.5:18088".to_string();
        let err = cfg
            .normalize()
            .expect_err("remote wallet-rpc override must be rejected");
        assert!(err.to_string().contains("no longer supported"));
    }

    #[test]
    fn production_hardening_rejects_allow_remote_wallet_rpc_true() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        let _vault = apply_production_vault_secrets(&mut cfg);
        cfg.allow_remote_wallet_rpc = true;
        cfg.wallet_rpc.endpoint = "http://10.0.0.5:18088".to_string();
        let err = cfg
            .normalize()
            .expect_err("hardening must reject remote wallet-rpc");
        assert!(err.to_string().contains("no longer supported"));
    }

    #[test]
    fn production_hardening_rejects_literal_secret_values() {
        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        let err = cfg
            .normalize()
            .expect_err("literal secrets must be rejected");
        assert!(
            err.to_string()
                .contains("wallet_rpc.wallet_password to use vault: secret reference")
        );
    }

    #[test]
    fn production_hardening_accepts_vault_secret_references() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        let _vault = apply_production_vault_secrets(&mut cfg);
        cfg.normalize()
            .expect("vault secret refs should pass in hardening");
        assert_eq!(cfg.host_vault_passphrase, "correct horse battery");
        assert_eq!(cfg.wallet_rpc.wallet_password, "wallet-pass");
        assert_eq!(cfg.wallet_rpc.password, "rpc-pass");
        assert_eq!(
            cfg.mailbox_push_token.as_deref().unwrap_or_default(),
            "1234567890abcdef-push"
        );
        assert_eq!(
            cfg.mailbox_pull_token.as_deref().unwrap_or_default(),
            "1234567890abcdef-pull"
        );
        assert_eq!(
            cfg.mailbox_ack_token.as_deref().unwrap_or_default(),
            "1234567890abcdef-ack"
        );
        assert_eq!(
            cfg.worker_service_token.as_deref().unwrap_or_default(),
            "1234567890abcdef-worker"
        );
    }

    #[test]
    fn production_hardening_rejects_env_secret_references() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        cfg.wallet_rpc.wallet_password = "env:NXMS_TEST_WALLET_PASSWORD".to_string();
        cfg.wallet_rpc.password = "env:NXMS_TEST_RPC_PASSWORD".to_string();
        cfg.mailbox_push_token = Some("env:NXMS_TEST_MAILBOX_PUSH_TOKEN".to_string());
        cfg.mailbox_pull_token = Some("env:NXMS_TEST_MAILBOX_PULL_TOKEN".to_string());
        cfg.mailbox_ack_token = Some("env:NXMS_TEST_MAILBOX_ACK_TOKEN".to_string());
        cfg.worker_service_token = Some("env:NXMS_TEST_WORKER_SERVICE_TOKEN".to_string());
        unsafe {
            std::env::set_var("NXMS_TEST_WALLET_PASSWORD", "wallet-pass");
            std::env::set_var("NXMS_TEST_RPC_PASSWORD", "rpc-pass");
            std::env::set_var("NXMS_TEST_MAILBOX_PUSH_TOKEN", "1234567890abcdef-push");
            std::env::set_var("NXMS_TEST_MAILBOX_PULL_TOKEN", "1234567890abcdef-pull");
            std::env::set_var("NXMS_TEST_MAILBOX_ACK_TOKEN", "1234567890abcdef-ack");
            std::env::set_var("NXMS_TEST_WORKER_SERVICE_TOKEN", "1234567890abcdef-worker");
        }
        let err = cfg
            .normalize()
            .expect_err("env secret refs must be rejected in hardening");
        assert!(
            err.to_string()
                .contains("wallet_rpc.wallet_password to use vault: secret reference")
        );
        unsafe {
            std::env::remove_var("NXMS_TEST_WALLET_PASSWORD");
            std::env::remove_var("NXMS_TEST_RPC_PASSWORD");
            std::env::remove_var("NXMS_TEST_MAILBOX_PUSH_TOKEN");
            std::env::remove_var("NXMS_TEST_MAILBOX_PULL_TOKEN");
            std::env::remove_var("NXMS_TEST_MAILBOX_ACK_TOKEN");
            std::env::remove_var("NXMS_TEST_WORKER_SERVICE_TOKEN");
        }
    }

    #[test]
    fn default_mode_requires_worker_service_token() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.worker_service_token = None;
        let err = cfg
            .normalize()
            .expect_err("default mode must reject missing worker service token");
        assert!(err.to_string().contains("worker_service_token"));
    }

    #[test]
    fn production_hardening_rejects_literal_worker_service_token() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.production_hardening = true;
        let _vault = apply_production_vault_secrets(&mut cfg);
        cfg.worker_service_token = Some("literal-worker-token".to_string());
        let err = cfg
            .normalize()
            .expect_err("literal worker service token must be rejected");
        assert!(
            err.to_string()
                .contains("worker_service_token to use vault: secret reference")
        );
    }

    #[test]
    fn default_mode_requires_action_token_section() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.production_hardening = false;
        cfg.action_token = None;
        let err = cfg
            .normalize()
            .expect_err("default mode must reject missing action token section");
        assert!(err.to_string().contains("requires [action_token] section"));
    }

    #[test]
    fn default_mode_requires_action_token_required_true() {
        let _guard = env_lock().lock().expect("env lock");
        let mut cfg = base_cfg();
        cfg.production_hardening = false;
        cfg.action_token.as_mut().expect("action token").required = false;
        let err = cfg
            .normalize()
            .expect_err("default mode must reject action token required=false");
        assert!(err.to_string().contains("required=true"));
    }

    #[test]
    fn normalize_clamps_ttl_and_txset_hex_len() {
        let mut cfg = base_cfg();
        cfg.default_ttl_secs = 1;
        cfg.max_txset_hex_len = 8;
        cfg.mailbox_retry_attempts = 0;
        cfg.mailbox_retry_backoff_ms = 1;
        cfg.action_token
            .as_mut()
            .expect("action token")
            .max_ttl_secs = 2;
        cfg.normalize().expect("normalize");
        assert_eq!(cfg.default_ttl_secs, 30);
        assert_eq!(cfg.max_txset_hex_len, 2048);
        assert_eq!(cfg.mailbox_retry_attempts, 1);
        assert_eq!(cfg.mailbox_retry_backoff_ms, 50);
        assert_eq!(
            cfg.action_token
                .as_ref()
                .expect("action token")
                .max_ttl_secs,
            10
        );
    }

    #[test]
    fn security_report_flags_missing_hardening() {
        let mut cfg = base_cfg();
        cfg.production_hardening = false;
        cfg.action_token = None;
        let report = cfg.security_report();
        assert!(!report.ok);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.contains("action_token_required"))
        );
    }
}
