use async_trait::async_trait;
use rand::RngCore;
use rand::rngs::OsRng;
use reqwest::Client;
use reqwest::StatusCode;
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::env;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::time::{sleep, timeout};
use tracing::warn;

use crate::limits::tx_hex_max_len;
use crate::types::{MoneroArbitraError, Result, WalletRpcError};

#[derive(Clone, Debug)]
pub struct WalletRpcConfig {
    pub endpoint: String,
    pub wallet_name: String,
    pub wallet_password: String,
    pub username: String,
    pub password: String,
    pub language: String,
    pub create_if_missing: bool,
}

impl WalletRpcConfig {
    pub fn json_rpc_url(&self) -> String {
        format!("{}/json_rpc", self.endpoint.trim_end_matches('/'))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedMultisigTx {
    pub tx_data_hex: String,
    pub tx_hash_list: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferDestination {
    pub address: String,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferByTxid {
    pub txid: String,
    pub transfer_type: String,
    pub confirmations: u64,
    pub double_spend_seen: bool,
    pub address: Option<String>,
    pub amount: Option<u64>,
    pub destinations: Vec<TransferDestination>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletMultisigStatus {
    pub multisig: bool,
    pub ready: bool,
    pub threshold: u64,
    pub total: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MultisigMode {
    Legacy,
    Auto,
    Strict,
}

#[derive(Clone, Copy, Debug)]
struct WalletOpenRetryConfig {
    attempts: u32,
    timeout_s: u64,
    backoff_base_ms: u64,
    backoff_max_ms: u64,
}

fn multisig_mode_from_env() -> MultisigMode {
    static MODE: OnceLock<MultisigMode> = OnceLock::new();
    *MODE.get_or_init(|| {
        let raw = env::var("XMR_MULTISIG_MODE")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .unwrap_or_else(|| "auto".to_string());
        match raw.as_str() {
            "legacy" => MultisigMode::Legacy,
            "" | "auto" => MultisigMode::Auto,
            "strict" => MultisigMode::Strict,
            _ => {
                warn!(
                    "invalid XMR_MULTISIG_MODE='{}'; defaulting to 'auto' (expected: legacy|auto|strict)",
                    raw
                );
                MultisigMode::Auto
            }
        }
    })
}

fn wallet_open_retry_config_from_env() -> WalletOpenRetryConfig {
    static CONFIG: OnceLock<WalletOpenRetryConfig> = OnceLock::new();
    *CONFIG.get_or_init(|| {
        let attempts = env::var("XMR_WALLET_RPC_OPEN_ATTEMPTS")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(3);
        let timeout_s = env::var("XMR_WALLET_RPC_OPEN_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(30);
        let backoff_base_ms = env::var("XMR_WALLET_RPC_OPEN_RETRY_BASE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(300);
        let backoff_max_ms = env::var("XMR_WALLET_RPC_OPEN_RETRY_MAX_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v >= backoff_base_ms)
            .unwrap_or(2_500);
        WalletOpenRetryConfig {
            attempts,
            timeout_s,
            backoff_base_ms,
            backoff_max_ms,
        }
    })
}

#[async_trait]
pub trait WalletRpcClient: Send + Sync {
    async fn prepare_multisig_flow(&self) -> Result<String>;
    async fn make_multisig_flow(
        &self,
        multisig_info: Vec<String>,
        threshold: u16,
    ) -> Result<String>;
    async fn exchange_multisig_keys_flow(&self, multisig_info: Vec<String>) -> Result<String>;
    async fn exchange_multisig_keys_optional_flow(
        &self,
        multisig_info: Vec<String>,
    ) -> Result<Option<String>>;
    async fn finalize_multisig_flow(&self, multisig_info: Vec<String>) -> Result<String>;
    async fn export_multisig_info_flow(&self) -> Result<String>;
    async fn import_multisig_info_flow(&self, info: Vec<String>) -> Result<u64>;
    async fn sign_multisig_flow(&self, tx_data_hex: String) -> Result<SignedMultisigTx>;
    async fn submit_multisig_flow(&self, tx_data_hex: String) -> Result<Vec<String>>;
    async fn get_balance_flow(&self) -> Result<(u64, u64)>;
    async fn get_address_flow(&self) -> Result<String>;
    async fn get_multisig_status_flow(&self) -> Result<WalletMultisigStatus>;
    async fn get_transfer_by_txid_flow(&self, txid: String) -> Result<TransferByTxid>;
}

fn wallet_rpc_transport(err: impl std::fmt::Display) -> MoneroArbitraError {
    MoneroArbitraError::WalletRpc(WalletRpcError::Transport(err.to_string()))
}

fn wallet_rpc_auth(msg: impl Into<String>) -> MoneroArbitraError {
    MoneroArbitraError::WalletRpc(WalletRpcError::Auth(msg.into()))
}

fn wallet_rpc_protocol(msg: impl Into<String>) -> MoneroArbitraError {
    MoneroArbitraError::WalletRpc(WalletRpcError::Protocol(msg.into()))
}

fn wallet_rpc_invalid_response(msg: impl Into<String>) -> MoneroArbitraError {
    MoneroArbitraError::WalletRpc(WalletRpcError::InvalidResponse(msg.into()))
}

fn wallet_rpc_http(status: StatusCode, detail: &str) -> MoneroArbitraError {
    let body = if detail.is_empty() {
        "<empty body>".to_string()
    } else {
        detail.to_string()
    };
    MoneroArbitraError::WalletRpc(WalletRpcError::HttpStatus {
        status: status.as_u16(),
        body,
    })
}

fn wallet_rpc_code(code: i64, message: impl Into<String>) -> MoneroArbitraError {
    MoneroArbitraError::WalletRpc(WalletRpcError::Rpc {
        code,
        message: message.into(),
    })
}

#[derive(Clone)]
pub struct HttpWalletRpcClient {
    http: Client,
    cfg: WalletRpcConfig,
    digest_nc: Arc<AtomicU32>,
    digest_nonce: Arc<Mutex<Option<String>>>,
    multisig_mode: MultisigMode,
}

impl HttpWalletRpcClient {
    pub fn new(mut cfg: WalletRpcConfig) -> Result<Self> {
        cfg.endpoint = cfg.endpoint.trim().trim_end_matches('/').to_string();
        let connect_timeout_s = env::var("XMR_WALLET_RPC_HTTP_CONNECT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(5);
        let request_timeout_s = env::var("XMR_WALLET_RPC_HTTP_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(180);
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(connect_timeout_s))
            .timeout(Duration::from_secs(request_timeout_s))
            .build()
            .map_err(|e| {
                wallet_rpc_transport(format!("failed to build wallet-rpc http client: {e}"))
            })?;
        Ok(Self {
            http,
            cfg,
            digest_nc: Arc::new(AtomicU32::new(0)),
            digest_nonce: Arc::new(Mutex::new(None)),
            multisig_mode: multisig_mode_from_env(),
        })
    }

    pub fn endpoint_key(&self) -> &str {
        self.cfg.endpoint.as_str()
    }

    async fn call<R: DeserializeOwned>(&self, method: &str, params: Value) -> Result<R> {
        let json_rpc_url = self.cfg.json_rpc_url();
        let payload = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params,
        });

        let mut resp = self.post_json_rpc(&json_rpc_url, &payload, None).await?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            let Some(challenge_1) = DigestChallenge::from_headers(resp.headers()) else {
                return Err(wallet_rpc_auth(
                    "wallet-rpc returned 401 without digest challenge",
                ));
            };

            let digest_uri = digest_uri_for_request(&json_rpc_url)?;
            resp = self
                .post_json_rpc_with_digest(&json_rpc_url, &payload, &digest_uri, &challenge_1)
                .await?;

            // Handle nonce rotation once (including stale=true challenge).
            if resp.status() == StatusCode::UNAUTHORIZED
                && let Some(challenge_2) = DigestChallenge::from_headers(resp.headers())
                && (challenge_2.stale || challenge_2.nonce != challenge_1.nonce)
            {
                resp = self
                    .post_json_rpc_with_digest(&json_rpc_url, &payload, &digest_uri, &challenge_2)
                    .await?;
            }
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let detail = body.trim();
            return Err(wallet_rpc_http(status, detail));
        }

        let wrapper = resp
            .json::<RpcResponse<R>>()
            .await
            .map_err(|e| wallet_rpc_invalid_response(e.to_string()))?;

        if let Some(err) = wrapper.error {
            return Err(wallet_rpc_code(err.code, err.message));
        }

        wrapper
            .result
            .ok_or_else(|| wallet_rpc_invalid_response("missing result in wallet-rpc response"))
    }

    async fn post_json_rpc(
        &self,
        json_rpc_url: &str,
        payload: &Value,
        auth_header: Option<String>,
    ) -> Result<reqwest::Response> {
        let mut req = self.http.post(json_rpc_url);
        if let Some(header) = auth_header {
            req = req.header(AUTHORIZATION, header);
        }
        req.json(payload).send().await.map_err(wallet_rpc_transport)
    }

    async fn post_json_rpc_with_digest(
        &self,
        json_rpc_url: &str,
        payload: &Value,
        digest_uri: &str,
        challenge: &DigestChallenge,
    ) -> Result<reqwest::Response> {
        let nc = self.next_digest_nc_for_nonce(&challenge.nonce);
        let auth_header = build_digest_authorization(
            challenge,
            "POST",
            digest_uri,
            &self.cfg.username,
            &self.cfg.password,
            None,
            Some(&nc),
        );
        self.post_json_rpc(json_rpc_url, payload, Some(auth_header))
            .await
    }

    fn next_digest_nc_for_nonce(&self, nonce: &str) -> String {
        {
            let mut lock = self
                .digest_nonce
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if lock.as_deref() != Some(nonce) {
                *lock = Some(nonce.to_string());
                self.digest_nc.store(0, Ordering::Relaxed);
            }
        }
        self.next_digest_nc()
    }

    fn next_digest_nc(&self) -> String {
        let next = self
            .digest_nc
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        if next == 0 {
            self.digest_nc.store(1, Ordering::Relaxed);
            return "00000001".to_string();
        }
        format!("{next:08x}")
    }

    async fn call_with_timeout<R: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
        timeout_s: u64,
    ) -> Result<R> {
        match timeout(Duration::from_secs(timeout_s), self.call(method, params)).await {
            Ok(v) => v,
            Err(_) => Err(wallet_rpc_protocol(format!(
                "wallet-rpc {method} timed out after {timeout_s}s"
            ))),
        }
    }

    async fn close_wallet_best_effort(&self, timeout_s: u64) {
        let _ = self
            .call_with_timeout::<Value>("close_wallet", json!({}), timeout_s)
            .await;
    }

    async fn open_wallet_once(&self, timeout_s: u64) -> Result<()> {
        self.call_with_timeout::<Value>(
            "open_wallet",
            json!({
                "filename": self.cfg.wallet_name,
                "password": self.cfg.wallet_password,
            }),
            timeout_s,
        )
        .await?;
        Ok(())
    }

    async fn create_wallet_once(&self, timeout_s: u64) -> Result<()> {
        self.call_with_timeout::<Value>(
            "create_wallet",
            json!({
                "filename": self.cfg.wallet_name,
                "password": self.cfg.wallet_password,
                "language": self.cfg.language,
            }),
            timeout_s,
        )
        .await?;
        Ok(())
    }

    async fn open_wallet_probe_once(&self, timeout_s: u64) -> Result<()> {
        let result: GetAddressResponse = self
            .call_with_timeout("get_address", json!({}), timeout_s)
            .await?;
        if result
            .address
            .as_deref()
            .is_some_and(|addr| !addr.trim().is_empty())
        {
            return Ok(());
        }
        if result.addresses.as_ref().is_some_and(|items| {
            items.iter().any(|item| {
                item.address
                    .as_deref()
                    .is_some_and(|addr| !addr.trim().is_empty())
            })
        }) {
            return Ok(());
        }
        Err(wallet_rpc_invalid_response(
            "wallet-rpc open probe (get_address) returned no usable address",
        ))
    }

    pub(crate) async fn ensure_wallet_open(&self) -> Result<()> {
        let cfg = wallet_open_retry_config_from_env();
        let mut backoff_ms = cfg.backoff_base_ms;
        let mut last_err: Option<MoneroArbitraError> = None;

        for attempt in 1..=cfg.attempts {
            let ensure_once = match self.open_wallet_once(cfg.timeout_s).await {
                Ok(_) => self.open_wallet_probe_once(cfg.timeout_s).await,
                Err(err) if is_wallet_not_found_error(&err) => {
                    if !self.cfg.create_if_missing {
                        return Err(err);
                    }
                    match self.create_wallet_once(cfg.timeout_s).await {
                        // create_wallet is expected to switch wallet-rpc context.
                        // Some builds report success before the wallet becomes active,
                        // so always verify with get_address probe.
                        Ok(_) => self.open_wallet_probe_once(cfg.timeout_s).await,
                        Err(create_err) if is_wallet_already_exists_error(&create_err) => {
                            match self.open_wallet_once(cfg.timeout_s).await {
                                Ok(_) => self.open_wallet_probe_once(cfg.timeout_s).await,
                                Err(open_err) => Err(open_err),
                            }
                        }
                        Err(create_err) => return Err(create_err),
                    }
                }
                Err(err) => Err(err),
            };

            match ensure_once {
                Ok(_) => return Ok(()),
                Err(err) => {
                    let retryable =
                        is_wallet_open_retryable_error(&err) || is_wallet_not_found_error(&err);
                    let final_attempt = attempt >= cfg.attempts;
                    if !retryable || final_attempt {
                        return Err(err);
                    }
                    last_err = Some(err);
                }
            }

            if attempt < cfg.attempts {
                // Some wallet-rpc builds can stall on re-open; best-effort close
                // is only used before retry so successful open paths stay untouched.
                self.close_wallet_best_effort(cfg.timeout_s).await;
                warn!(
                    "wallet-rpc open retry {}/{} in {}ms",
                    attempt, cfg.attempts, backoff_ms
                );
                sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2).min(cfg.backoff_max_ms);
            }
        }

        Err(last_err.unwrap_or_else(|| {
            wallet_rpc_protocol(format!(
                "wallet-rpc failed to open wallet after {} attempts",
                cfg.attempts
            ))
        }))
    }

    async fn persist_wallet_metadata(&self) -> Result<()> {
        // Reusing password change with identical old/new values forces wallet
        // metadata rewrite needed by some wallet-rpc multisig paths.
        self.call::<Value>(
            "change_wallet_password",
            json!({
                "old_password": self.cfg.wallet_password,
                "new_password": self.cfg.wallet_password,
            }),
        )
        .await?;
        Ok(())
    }

    async fn call_multisig<R: DeserializeOwned>(&self, method: &str, params: Value) -> Result<R> {
        match self.multisig_mode {
            MultisigMode::Strict => match self.call(method, params).await {
                Ok(v) => Ok(v),
                Err(err) if is_multisig_disabled_error(&err) => Err(wallet_rpc_protocol(format!(
                    "wallet-rpc multisig disabled for method {method} in strict mode; strict never retries with experimental bootstrap"
                ))),
                Err(err) => Err(err),
            },
            MultisigMode::Legacy => match self.call(method, params).await {
                Ok(v) => Ok(v),
                Err(err) if is_multisig_disabled_error(&err) => Err(wallet_rpc_protocol(format!(
                    "wallet-rpc multisig disabled for method {method} in legacy mode; run prepare_multisig with enable_multisig_experimental=true first"
                ))),
                Err(err) => Err(err),
            },
            MultisigMode::Auto => match self.call(method, params).await {
                Ok(v) => Ok(v),
                Err(err) if is_multisig_disabled_error(&err) => Err(wallet_rpc_protocol(format!(
                    "wallet-rpc multisig disabled for method {method} in auto mode; auto only retries experimental bootstrap during prepare_multisig"
                ))),
                Err(err) => Err(err),
            },
        }
    }

    async fn wallet_rpc_version(&self) -> Option<u32> {
        self.call::<GetVersionResponse>("get_version", json!({}))
            .await
            .ok()
            .and_then(|v| v.version)
    }

    fn auto_should_force_experimental(version: Option<u32>) -> bool {
        // Monero wallet-rpc v0.18.4.5 reports version=65565 and requires
        // experimental bootstrap during prepare_multisig for full multisig flow.
        matches!(version, Some(v) if v <= 65565)
    }

    async fn store_wallet(&self) -> Result<()> {
        self.call::<Value>("store", json!({})).await?;
        Ok(())
    }
}

fn is_wallet_not_found_error(err: &MoneroArbitraError) -> bool {
    let MoneroArbitraError::WalletRpc(rpc_err) = err else {
        return false;
    };
    let text = rpc_err.text().to_ascii_lowercase();
    let mentions_wallet = text.contains("wallet");
    let missing = text.contains("not found")
        || text.contains("no wallet")
        || text.contains("does not exist")
        || text.contains("doesn't exist")
        || text.contains("file not found")
        || text.contains("no such file");
    mentions_wallet && missing
}

fn is_wallet_already_exists_error(err: &MoneroArbitraError) -> bool {
    let MoneroArbitraError::WalletRpc(rpc_err) = err else {
        return false;
    };
    let text = rpc_err.text().to_ascii_lowercase();
    let mentions_wallet = text.contains("wallet");
    let already_exists = text.contains("already exists")
        || text.contains("exist already")
        || text.contains("file exists");
    mentions_wallet && already_exists
}

fn is_wallet_open_retryable_error(err: &MoneroArbitraError) -> bool {
    match err {
        MoneroArbitraError::Io(_) => true,
        MoneroArbitraError::WalletRpc(rpc_err) => {
            if rpc_err.is_transient() {
                return true;
            }
            let text = rpc_err.text().to_ascii_lowercase();
            text.contains("timed out")
                || text.contains("timeout")
                || text.contains("busy")
                || text.contains("temporar")
                || text.contains("connection reset")
                || text.contains("broken pipe")
        }
        _ => false,
    }
}

fn is_multisig_disabled_error(err: &MoneroArbitraError) -> bool {
    let MoneroArbitraError::WalletRpc(rpc_err) = err else {
        return false;
    };
    let text = rpc_err.text().to_ascii_lowercase();
    text.contains("multisig is disabled") || text.contains("enable-multisig-experimental")
}

#[derive(Debug, Clone)]
struct DigestChallenge {
    realm: String,
    nonce: String,
    qop: Option<String>,
    algorithm: String,
    opaque: Option<String>,
    stale: bool,
}

impl DigestChallenge {
    fn from_headers(headers: &reqwest::header::HeaderMap) -> Option<Self> {
        for val in headers.get_all(WWW_AUTHENTICATE) {
            let Ok(raw) = val.to_str() else { continue };
            if let Some(challenge) = Self::parse_header(raw) {
                return Some(challenge);
            }
        }
        None
    }

    fn parse_header(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if !trimmed.to_ascii_lowercase().starts_with("digest ") {
            return None;
        }
        let attrs = parse_digest_attributes(trimmed.split_at(7).1);
        let realm = attrs.get("realm")?.clone();
        let nonce = attrs.get("nonce")?.clone();
        let algorithm = attrs
            .get("algorithm")
            .cloned()
            .unwrap_or_else(|| "MD5".to_string());
        let algorithm_lc = algorithm.to_ascii_lowercase();
        if algorithm_lc != "md5" && algorithm_lc != "md5-sess" {
            return None;
        }

        let qop = attrs.get("qop").and_then(|v| choose_qop(v));
        let opaque = attrs.get("opaque").cloned();
        let stale = attrs
            .get("stale")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Some(Self {
            realm,
            nonce,
            qop,
            algorithm,
            opaque,
            stale,
        })
    }
}

fn parse_digest_attributes(input: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let mut part = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    let mut push_part = |raw_part: &str| {
        let p = raw_part.trim();
        if p.is_empty() {
            return;
        }
        let mut it = p.splitn(2, '=');
        let Some(k) = it.next() else { return };
        let Some(v) = it.next() else { return };
        let key = k.trim().to_ascii_lowercase();
        let mut value = v.trim().to_string();
        if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            value = value[1..value.len() - 1].replace("\\\"", "\"");
            value = value.replace("\\\\", "\\");
        }
        out.insert(key, value);
    };

    for ch in input.chars() {
        if escaped {
            part.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            part.push(ch);
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            part.push(ch);
            continue;
        }
        if ch == ',' && !in_quotes {
            push_part(&part);
            part.clear();
            continue;
        }
        part.push(ch);
    }
    if !part.trim().is_empty() {
        push_part(&part);
    }
    out
}

fn choose_qop(raw: &str) -> Option<String> {
    for token in raw.split(',') {
        if token.trim().eq_ignore_ascii_case("auth") {
            return Some("auth".to_string());
        }
    }
    raw.split(',')
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn digest_uri_for_request(url: &str) -> Result<String> {
    let parsed = Url::parse(url).map_err(|e| wallet_rpc_protocol(e.to_string()))?;
    let mut uri = parsed.path().to_string();
    if uri.is_empty() {
        uri = "/".to_string();
    }
    if let Some(query) = parsed.query() {
        uri.push('?');
        uri.push_str(query);
    }
    Ok(uri)
}

fn random_cnonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn md5_hex(data: &str) -> String {
    format!("{:x}", md5::compute(data.as_bytes()))
}

fn escape_digest_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn validate_hex_payload(value: &str, label: &str, max_len: usize) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(MoneroArbitraError::MissingData(format!(
            "{label} must not be empty"
        )));
    }
    if trimmed.len() > max_len {
        return Err(MoneroArbitraError::InvalidArgument(format!(
            "{label} too long (max {max_len} chars)"
        )));
    }
    if trimmed.len() % 2 != 0 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(MoneroArbitraError::InvalidArgument(format!(
            "{label} must be valid even-length hex"
        )));
    }
    Ok(trimmed.to_string())
}

fn validate_txid(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(MoneroArbitraError::InvalidTxid);
    }
    Ok(trimmed.to_string())
}

fn build_digest_authorization(
    challenge: &DigestChallenge,
    method: &str,
    uri: &str,
    username: &str,
    password: &str,
    cnonce_override: Option<&str>,
    nc_override: Option<&str>,
) -> String {
    let algorithm = challenge.algorithm.to_ascii_uppercase();
    let cnonce = cnonce_override
        .map(ToOwned::to_owned)
        .unwrap_or_else(random_cnonce);
    let nc = nc_override.unwrap_or("00000001").to_string();

    let ha1_base = md5_hex(&format!("{username}:{}:{password}", challenge.realm));
    let ha1 = if algorithm == "MD5-SESS" {
        md5_hex(&format!("{ha1_base}:{}:{cnonce}", challenge.nonce))
    } else {
        ha1_base
    };
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let response = if let Some(qop) = &challenge.qop {
        md5_hex(&format!(
            "{ha1}:{}:{nc}:{cnonce}:{qop}:{ha2}",
            challenge.nonce
        ))
    } else {
        md5_hex(&format!("{ha1}:{}:{ha2}", challenge.nonce))
    };

    let mut parts = vec![
        format!("username=\"{}\"", escape_digest_value(username)),
        format!("realm=\"{}\"", escape_digest_value(&challenge.realm)),
        format!("nonce=\"{}\"", escape_digest_value(&challenge.nonce)),
        format!("uri=\"{}\"", escape_digest_value(uri)),
        format!("response=\"{response}\""),
        format!("algorithm={algorithm}"),
    ];
    if let Some(opaque) = &challenge.opaque {
        parts.push(format!("opaque=\"{}\"", escape_digest_value(opaque)));
    }
    if let Some(qop) = &challenge.qop {
        parts.push(format!("qop={qop}"));
        parts.push(format!("nc={nc}"));
        parts.push(format!("cnonce=\"{}\"", escape_digest_value(&cnonce)));
    }
    format!("Digest {}", parts.join(", "))
}

#[async_trait]
impl WalletRpcClient for HttpWalletRpcClient {
    async fn prepare_multisig_flow(&self) -> Result<String> {
        self.ensure_wallet_open().await?;
        let mut used_experimental = false;
        let result: MultisigInfoResponse = match self.multisig_mode {
            MultisigMode::Strict => match self.call("prepare_multisig", json!({})).await {
                Ok(v) => v,
                Err(err) if is_multisig_disabled_error(&err) => {
                    return Err(wallet_rpc_protocol(
                        "wallet-rpc prepare_multisig reports multisig disabled in strict mode"
                            .to_string(),
                    ));
                }
                Err(err) => return Err(err),
            },
            MultisigMode::Legacy => {
                used_experimental = true;
                self.call(
                    "prepare_multisig",
                    json!({ "enable_multisig_experimental": true }),
                )
                .await?
            }
            MultisigMode::Auto => match self.call("prepare_multisig", json!({})).await {
                Ok(v) => {
                    let version = self.wallet_rpc_version().await;
                    if Self::auto_should_force_experimental(version) {
                        warn!(
                            "wallet-rpc auto mode forcing experimental prepare compatibility for endpoint {} version {:?}",
                            self.endpoint_key(),
                            version
                        );
                        used_experimental = true;
                        self.call(
                            "prepare_multisig",
                            json!({ "enable_multisig_experimental": true }),
                        )
                        .await?
                    } else {
                        v
                    }
                }
                Err(err) if is_multisig_disabled_error(&err) => {
                    warn!(
                        "wallet-rpc auto mode retrying prepare_multisig with experimental bootstrap for endpoint {}",
                        self.endpoint_key()
                    );
                    used_experimental = true;
                    self.call(
                        "prepare_multisig",
                        json!({ "enable_multisig_experimental": true }),
                    )
                    .await?
                }
                Err(err) => return Err(err),
            },
        };

        let out = result.multisig_info.ok_or_else(|| {
            wallet_rpc_invalid_response("prepare_multisig returned no multisig_info")
        })?;
        if used_experimental {
            self.persist_wallet_metadata().await?;
        }
        self.store_wallet().await?;
        Ok(out)
    }

    async fn make_multisig_flow(
        &self,
        multisig_info: Vec<String>,
        threshold: u16,
    ) -> Result<String> {
        self.ensure_wallet_open().await?;
        let result: MultisigInfoResponse = self
            .call_multisig(
                "make_multisig",
                json!({
                    "multisig_info": multisig_info,
                    "threshold": threshold,
                    "password": self.cfg.wallet_password,
                }),
            )
            .await?;
        let out = result.multisig_info.ok_or_else(|| {
            wallet_rpc_invalid_response("make_multisig returned no multisig_info")
        })?;
        self.store_wallet().await?;
        Ok(out)
    }

    async fn exchange_multisig_keys_flow(&self, multisig_info: Vec<String>) -> Result<String> {
        if multisig_info.is_empty() {
            return Err(MoneroArbitraError::MissingData(
                "multisig_info must not be empty".to_string(),
            ));
        }

        self.ensure_wallet_open().await?;

        let result: MultisigInfoResponse = self
            .call_multisig(
                "exchange_multisig_keys",
                json!({
                    "multisig_info": multisig_info,
                    "password": self.cfg.wallet_password,
                }),
            )
            .await?;

        self.store_wallet().await?;
        result
            .multisig_info
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                wallet_rpc_invalid_response("exchange_multisig_keys returned no multisig_info")
            })
    }

    async fn exchange_multisig_keys_optional_flow(
        &self,
        multisig_info: Vec<String>,
    ) -> Result<Option<String>> {
        if multisig_info.is_empty() {
            return Err(MoneroArbitraError::MissingData(
                "multisig_info must not be empty".to_string(),
            ));
        }

        self.ensure_wallet_open().await?;

        let result: MultisigInfoResponse = self
            .call_multisig(
                "exchange_multisig_keys",
                json!({
                    "multisig_info": multisig_info,
                    "password": self.cfg.wallet_password,
                }),
            )
            .await?;

        self.store_wallet().await?;
        Ok(result.multisig_info.filter(|v| !v.trim().is_empty()))
    }

    async fn finalize_multisig_flow(&self, multisig_info: Vec<String>) -> Result<String> {
        if multisig_info.is_empty() {
            return Err(MoneroArbitraError::MissingData(
                "multisig_info must not be empty".to_string(),
            ));
        }
        self.ensure_wallet_open().await?;
        let result: AddressResponse = self
            .call_multisig(
                "finalize_multisig",
                json!({
                    "multisig_info": multisig_info,
                    "password": self.cfg.wallet_password,
                }),
            )
            .await?;
        self.store_wallet().await?;
        result
            .address
            .ok_or_else(|| wallet_rpc_invalid_response("finalize_multisig returned no address"))
    }

    async fn export_multisig_info_flow(&self) -> Result<String> {
        self.ensure_wallet_open().await?;
        let result: ExportMultisigInfoResponse = self
            .call_multisig("export_multisig_info", json!({}))
            .await?;
        self.store_wallet().await?;
        result
            .info
            .ok_or_else(|| wallet_rpc_invalid_response("export_multisig_info returned no info"))
    }

    async fn import_multisig_info_flow(&self, info: Vec<String>) -> Result<u64> {
        if info.is_empty() {
            return Err(MoneroArbitraError::MissingData(
                "info must not be empty".to_string(),
            ));
        }
        self.ensure_wallet_open().await?;
        let result: ImportMultisigInfoResponse = self
            .call_multisig("import_multisig_info", json!({ "info": info }))
            .await?;
        self.store_wallet().await?;
        Ok(result.n_outputs.unwrap_or(0))
    }

    async fn sign_multisig_flow(&self, tx_data_hex: String) -> Result<SignedMultisigTx> {
        let tx_data_hex = validate_hex_payload(&tx_data_hex, "tx_data_hex", tx_hex_max_len())?;
        self.ensure_wallet_open().await?;
        let result: SignMultisigResponse = self
            .call_multisig("sign_multisig", json!({ "tx_data_hex": tx_data_hex }))
            .await?;
        self.store_wallet().await?;
        let tx_data_hex = result
            .tx_data_hex
            .ok_or_else(|| wallet_rpc_invalid_response("sign_multisig returned no tx_data_hex"))?;
        Ok(SignedMultisigTx {
            tx_data_hex,
            tx_hash_list: result.tx_hash_list.unwrap_or_default(),
        })
    }

    async fn submit_multisig_flow(&self, tx_data_hex: String) -> Result<Vec<String>> {
        let tx_data_hex = validate_hex_payload(&tx_data_hex, "tx_data_hex", tx_hex_max_len())?;
        self.ensure_wallet_open().await?;
        let result: SubmitMultisigResponse = self
            .call_multisig("submit_multisig", json!({ "tx_data_hex": tx_data_hex }))
            .await?;
        self.store_wallet().await?;
        Ok(result.tx_hash_list.unwrap_or_default())
    }

    async fn get_address_flow(&self) -> Result<String> {
        self.ensure_wallet_open().await?;
        let result: GetAddressResponse = self.call("get_address", json!({})).await?;

        if let Some(addr) = result.address {
            if !addr.trim().is_empty() {
                return Ok(addr);
            }
        }

        if let Some(addresses) = result.addresses {
            for item in addresses {
                if let Some(addr) = item.address {
                    if !addr.trim().is_empty() {
                        return Ok(addr);
                    }
                }
            }
        }

        Err(wallet_rpc_invalid_response(
            "get_address returned no usable address",
        ))
    }

    async fn get_balance_flow(&self) -> Result<(u64, u64)> {
        self.ensure_wallet_open().await?;
        let result: BalanceResponse = self.call("get_balance", json!({})).await?;
        Ok((
            result.balance.unwrap_or(0),
            result.unlocked_balance.unwrap_or(0),
        ))
    }

    async fn get_multisig_status_flow(&self) -> Result<WalletMultisigStatus> {
        self.ensure_wallet_open().await?;
        let result: IsMultisigResponse = self.call("is_multisig", json!({})).await?;
        Ok(WalletMultisigStatus {
            multisig: result.multisig.unwrap_or(false),
            ready: result.ready.unwrap_or(false),
            threshold: result.threshold.unwrap_or(0),
            total: result.total.unwrap_or(0),
        })
    }

    async fn get_transfer_by_txid_flow(&self, txid: String) -> Result<TransferByTxid> {
        let txid = validate_txid(&txid)?;
        self.ensure_wallet_open().await?;
        let txid_for_request = txid.clone();
        let result: GetTransferByTxidResponse = self
            .call("get_transfer_by_txid", json!({ "txid": txid_for_request }))
            .await?;

        let transfer = if let Some(primary) = result.transfer {
            primary
        } else {
            result
                .transfers
                .and_then(|mut v| {
                    if v.is_empty() {
                        None
                    } else {
                        Some(v.remove(0))
                    }
                })
                .ok_or_else(|| {
                    wallet_rpc_invalid_response("get_transfer_by_txid returned no transfer object")
                })?
        };

        let transfer_txid = transfer.txid.unwrap_or_default();
        if transfer_txid != txid {
            return Err(wallet_rpc_invalid_response(
                "get_transfer_by_txid returned mismatched txid",
            ));
        }

        let destinations = transfer
            .destinations
            .unwrap_or_default()
            .into_iter()
            .filter_map(|raw| {
                let address = raw.address?;
                let amount = raw.amount?;
                if address.trim().is_empty() {
                    return None;
                }
                Some(TransferDestination { address, amount })
            })
            .collect::<Vec<_>>();

        let address = transfer.address.and_then(|v| {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

        Ok(TransferByTxid {
            txid: transfer_txid,
            transfer_type: transfer.transfer_type.unwrap_or_default(),
            confirmations: transfer.confirmations.unwrap_or(0),
            double_spend_seen: transfer.double_spend_seen.unwrap_or(false),
            address,
            amount: transfer.amount,
            destinations,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcErrorObject>,
}

#[derive(Debug, Deserialize)]
struct RpcErrorObject {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct MultisigInfoResponse {
    multisig_info: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExportMultisigInfoResponse {
    info: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ImportMultisigInfoResponse {
    n_outputs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SignMultisigResponse {
    tx_data_hex: Option<String>,
    tx_hash_list: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct SubmitMultisigResponse {
    tx_hash_list: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct BalanceResponse {
    balance: Option<u64>,
    unlocked_balance: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AddressResponse {
    address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GetAddressResponse {
    address: Option<String>,
    addresses: Option<Vec<GetAddressItem>>,
}

#[derive(Debug, Deserialize)]
struct GetAddressItem {
    address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GetTransferByTxidResponse {
    transfer: Option<TransferByTxidEntry>,
    transfers: Option<Vec<TransferByTxidEntry>>,
}

#[derive(Debug, Deserialize)]
struct TransferByTxidEntry {
    txid: Option<String>,
    #[serde(rename = "type")]
    transfer_type: Option<String>,
    confirmations: Option<u64>,
    double_spend_seen: Option<bool>,
    address: Option<String>,
    amount: Option<u64>,
    destinations: Option<Vec<TransferDestinationEntry>>,
}

#[derive(Debug, Deserialize)]
struct TransferDestinationEntry {
    address: Option<String>,
    amount: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct GetVersionResponse {
    version: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct IsMultisigResponse {
    multisig: Option<bool>,
    ready: Option<bool>,
    threshold: Option<u64>,
    total: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_digest_header_basic() {
        let h =
            "Digest qop=\"auth\",algorithm=MD5,realm=\"monero-rpc\",nonce=\"abc123\",stale=false";
        let c = DigestChallenge::parse_header(h).expect("challenge");
        assert_eq!(c.realm, "monero-rpc");
        assert_eq!(c.nonce, "abc123");
        assert_eq!(c.algorithm, "MD5");
        assert_eq!(c.qop.as_deref(), Some("auth"));
        assert!(!c.stale);
    }

    #[test]
    fn digest_response_matches_rfc_2617_example() {
        let challenge = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            qop: Some("auth".to_string()),
            algorithm: "MD5".to_string(),
            opaque: None,
            stale: false,
        };
        let auth = build_digest_authorization(
            &challenge,
            "GET",
            "/dir/index.html",
            "Mufasa",
            "Circle Of Life",
            Some("0a4f113b"),
            Some("00000001"),
        );
        assert!(auth.contains("response=\"6629fae49393a05397450978507c4ef1\""));
    }

    #[test]
    fn parse_digest_header_stale_true() {
        let h = "Digest realm=\"monero-rpc\",nonce=\"abc123\",stale=true,qop=\"auth\"";
        let c = DigestChallenge::parse_header(h).expect("challenge");
        assert!(c.stale);
    }

    #[test]
    fn wallet_already_exists_error_detected() {
        let err = MoneroArbitraError::WalletRpc(WalletRpcError::Rpc {
            code: -1,
            message: "wallet file already exists".to_string(),
        });
        assert!(is_wallet_already_exists_error(&err));
    }

    #[test]
    fn wallet_not_found_detects_no_wallet_file_error() {
        let err = MoneroArbitraError::WalletRpc(WalletRpcError::Rpc {
            code: -13,
            message: "No wallet file".to_string(),
        });
        assert!(is_wallet_not_found_error(&err));
    }

    #[test]
    fn wallet_open_retryable_detects_transport_and_timeout() {
        let transport = MoneroArbitraError::WalletRpc(WalletRpcError::Transport(
            "connection reset by peer".to_string(),
        ));
        assert!(is_wallet_open_retryable_error(&transport));

        let timeout_proto = MoneroArbitraError::WalletRpc(WalletRpcError::Protocol(
            "wallet-rpc open_wallet timed out after 30s".to_string(),
        ));
        assert!(is_wallet_open_retryable_error(&timeout_proto));
    }

    #[test]
    fn wallet_open_retryable_rejects_auth_error() {
        let auth =
            MoneroArbitraError::WalletRpc(WalletRpcError::Auth("invalid digest".to_string()));
        assert!(!is_wallet_open_retryable_error(&auth));
    }
}
