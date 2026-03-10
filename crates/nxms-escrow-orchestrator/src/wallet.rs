use anyhow::{Result, anyhow};
use rand::RngCore;
use rand::rngs::OsRng;
use reqwest::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct WalletRpcConfig {
    pub endpoint: String,
    pub wallet_name: String,
    pub wallet_password: String,
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct WalletHealthSnapshot {
    pub is_multisig: bool,
    pub wallet_height: u64,
    pub daemon_height: Option<u64>,
    pub balance: u64,
    pub unlocked_balance: u64,
}

#[derive(Clone, Debug)]
pub struct TransferStatus {
    pub txid: String,
    pub confirmations: u64,
    pub double_spend_seen: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmationState {
    Pending,
    Confirmed,
    FailedDoubleSpend,
}

#[derive(Clone, Debug)]
struct DigestChallenge {
    realm: String,
    nonce: String,
    qop: Option<String>,
    algorithm: String,
    opaque: Option<String>,
    stale: bool,
}

#[derive(Clone, Debug)]
pub struct WalletRpcClient {
    http: Client,
    cfg: WalletRpcConfig,
    digest_nc: Arc<AtomicU32>,
    digest_nonce: Arc<Mutex<Option<String>>>,
}

impl WalletRpcClient {
    pub fn new(mut cfg: WalletRpcConfig) -> Self {
        cfg.endpoint = cfg.endpoint.trim().trim_end_matches('/').to_string();
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(180))
            .build()
            .unwrap_or_else(|e| panic!("failed to build wallet-rpc http client: {e}"));
        Self {
            http,
            cfg,
            digest_nc: Arc::new(AtomicU32::new(0)),
            digest_nonce: Arc::new(Mutex::new(None)),
        }
    }

    fn json_rpc_url(&self) -> String {
        format!("{}/json_rpc", self.cfg.endpoint)
    }

    pub async fn ensure_wallet_open(&self) -> Result<()> {
        let _ = self.call::<Value>("close_wallet", json!({})).await;
        self.call::<Value>(
            "open_wallet",
            json!({
                "filename": self.cfg.wallet_name,
                "password": self.cfg.wallet_password,
            }),
        )
        .await?;
        Ok(())
    }

    pub async fn health_snapshot(&self) -> Result<WalletHealthSnapshot> {
        self.ensure_wallet_open().await?;
        let m: IsMultisigResponse = self.call("is_multisig", json!({})).await?;
        let h: HeightResponse = self.call("get_height", json!({})).await?;
        let b: BalanceResponse = self.call("get_balance", json!({})).await?;
        let wallet_height = h.height.unwrap_or(0);
        let daemon_height = h.daemon_height.or(h.target_height);
        Ok(WalletHealthSnapshot {
            is_multisig: m.multisig.unwrap_or(false) || m.ready.unwrap_or(false),
            wallet_height,
            daemon_height,
            balance: b.balance.unwrap_or(0),
            unlocked_balance: b.unlocked_balance.unwrap_or(0),
        })
    }

    pub async fn refresh(&self) -> Result<()> {
        self.ensure_wallet_open().await?;
        let _: Value = self.call("refresh", json!({})).await?;
        Ok(())
    }

    pub async fn export_multisig_info(&self) -> Result<String> {
        self.refresh().await?;
        let result: ExportMultisigInfoResponse =
            self.call("export_multisig_info", json!({})).await?;
        let info = result.info.unwrap_or_default().trim().to_string();
        if info.is_empty() {
            return Err(anyhow!(
                "wallet-rpc export_multisig_info did not return non-empty info"
            ));
        }
        Ok(info)
    }

    pub async fn transfer_status(&self, txid: &str) -> Result<TransferStatus> {
        let txid = normalize_txid(txid)?;
        self.ensure_wallet_open().await?;
        let result: GetTransferByTxidResponse = self
            .call("get_transfer_by_txid", json!({ "txid": txid }))
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
                .ok_or_else(|| anyhow!("get_transfer_by_txid returned no transfer"))?
        };
        let transfer_txid = normalize_txid(&transfer.txid.unwrap_or_default())?;
        if !transfer_txid.eq_ignore_ascii_case(&txid) {
            return Err(anyhow!(
                "get_transfer_by_txid returned mismatched txid {}",
                transfer_txid
            ));
        }

        Ok(TransferStatus {
            txid: transfer_txid,
            confirmations: transfer.confirmations.unwrap_or(0),
            double_spend_seen: transfer.double_spend_seen.unwrap_or(false),
        })
    }

    pub async fn build_release_proposal(
        &self,
        seller_refund_address: &str,
        amount_atomic: u64,
    ) -> Result<String> {
        let address = seller_refund_address.trim();
        if address.is_empty() {
            return Err(anyhow!("seller_refund_address must be non-empty"));
        }
        if amount_atomic == 0 {
            return Err(anyhow!("amount_atomic must be > 0"));
        }
        self.ensure_wallet_open().await?;
        let result: TransferResponse = self
            .call(
                "transfer",
                json!({
                    "destinations": [
                        {
                            "address": address,
                            "amount": amount_atomic
                        }
                    ],
                    "do_not_relay": true,
                    "get_tx_hex": true,
                    "get_tx_metadata": true
                }),
            )
            .await?;
        let tx_data_hex = result.multisig_txset.unwrap_or_default().trim().to_string();
        if tx_data_hex.is_empty() {
            return Err(anyhow!("wallet-rpc transfer did not return multisig_txset"));
        }
        Ok(tx_data_hex)
    }

    async fn call<R: DeserializeOwned>(&self, method: &str, params: Value) -> Result<R> {
        let json_rpc_url = self.json_rpc_url();
        let payload = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params,
        });

        let mut resp = self.post_json_rpc_basic(&json_rpc_url, &payload).await?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            resp = self.post_json_rpc(&json_rpc_url, &payload, None).await?;
        }
        if resp.status() == StatusCode::UNAUTHORIZED {
            let challenge_1 = DigestChallenge::from_headers(resp.headers())
                .ok_or_else(|| anyhow!("wallet-rpc returned 401 without digest challenge"))?;
            let uri = digest_uri_for_request(&json_rpc_url)?;
            resp = self
                .post_json_rpc_with_digest(&json_rpc_url, &payload, &uri, &challenge_1)
                .await?;
            if resp.status() == StatusCode::UNAUTHORIZED
                && let Some(challenge_2) = DigestChallenge::from_headers(resp.headers())
                && (challenge_2.stale || challenge_2.nonce != challenge_1.nonce)
            {
                resp = self
                    .post_json_rpc_with_digest(&json_rpc_url, &payload, &uri, &challenge_2)
                    .await?;
            }
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("wallet-rpc http {}: {}", status.as_u16(), body));
        }

        let wrapper = resp.json::<RpcResponse<R>>().await?;
        if let Some(err) = wrapper.error {
            return Err(anyhow!(
                "wallet-rpc rpc code={} msg={}",
                err.code,
                err.message
            ));
        }
        wrapper
            .result
            .ok_or_else(|| anyhow!("wallet-rpc missing result for method {}", method))
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
        Ok(req.json(payload).send().await?)
    }

    async fn post_json_rpc_basic(
        &self,
        json_rpc_url: &str,
        payload: &Value,
    ) -> Result<reqwest::Response> {
        Ok(self
            .http
            .post(json_rpc_url)
            .basic_auth(&self.cfg.username, Some(&self.cfg.password))
            .json(payload)
            .send()
            .await?)
    }

    async fn post_json_rpc_with_digest(
        &self,
        json_rpc_url: &str,
        payload: &Value,
        uri: &str,
        challenge: &DigestChallenge,
    ) -> Result<reqwest::Response> {
        let nc = self.next_digest_nc_for_nonce(&challenge.nonce);
        let auth_header = build_digest_authorization(
            challenge,
            "POST",
            uri,
            &self.cfg.username,
            &self.cfg.password,
            &nc,
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
            .wrapping_add(1)
            .max(1);
        format!("{next:08x}")
    }
}

pub fn evaluate_preflight(
    health: &WalletHealthSnapshot,
    min_balance: u64,
    min_unlocked_balance: u64,
    max_height_lag: u64,
) -> Result<()> {
    if !health.is_multisig {
        return Err(anyhow!("wallet is not in multisig mode"));
    }
    if health.balance < min_balance {
        return Err(anyhow!(
            "wallet balance {} below required {}",
            health.balance,
            min_balance
        ));
    }
    if health.unlocked_balance < min_unlocked_balance {
        return Err(anyhow!(
            "wallet unlocked balance {} below required {}",
            health.unlocked_balance,
            min_unlocked_balance
        ));
    }
    if let Some(daemon_height) = health.daemon_height
        && daemon_height >= health.wallet_height
    {
        let lag = daemon_height.saturating_sub(health.wallet_height);
        if lag > max_height_lag {
            return Err(anyhow!(
                "wallet height lag {} above max {}",
                lag,
                max_height_lag
            ));
        }
    }
    Ok(())
}

pub fn evaluate_confirmation(
    status: &TransferStatus,
    required_confirmations: u64,
) -> ConfirmationState {
    if status.double_spend_seen {
        return ConfirmationState::FailedDoubleSpend;
    }
    if status.confirmations >= required_confirmations.max(1) {
        return ConfirmationState::Confirmed;
    }
    ConfirmationState::Pending
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
        let qop = attrs.get("qop").and_then(|raw| choose_qop(raw));
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

fn normalize_txid(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("txid must be 64 hex chars"));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn digest_uri_for_request(url: &str) -> Result<String> {
    let parsed = Url::parse(url)?;
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

fn build_digest_authorization(
    challenge: &DigestChallenge,
    method: &str,
    uri: &str,
    username: &str,
    password: &str,
    nc: &str,
) -> String {
    let algorithm = challenge.algorithm.to_ascii_uppercase();
    let cnonce = random_cnonce();
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
struct IsMultisigResponse {
    multisig: Option<bool>,
    ready: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct HeightResponse {
    height: Option<u64>,
    daemon_height: Option<u64>,
    target_height: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct BalanceResponse {
    balance: Option<u64>,
    unlocked_balance: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct TransferResponse {
    multisig_txset: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExportMultisigInfoResponse {
    info: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GetTransferByTxidResponse {
    transfer: Option<TransferByTxidEntry>,
    transfers: Option<Vec<TransferByTxidEntry>>,
}

#[derive(Debug, Deserialize)]
struct TransferByTxidEntry {
    txid: Option<String>,
    confirmations: Option<u64>,
    double_spend_seen: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_rejects_non_multisig() {
        let health = WalletHealthSnapshot {
            is_multisig: false,
            wallet_height: 10,
            daemon_height: Some(11),
            balance: 100,
            unlocked_balance: 100,
        };
        let err = evaluate_preflight(&health, 0, 0, 10).expect_err("must reject");
        assert!(err.to_string().contains("multisig"));
    }

    #[test]
    fn preflight_rejects_height_lag() {
        let health = WalletHealthSnapshot {
            is_multisig: true,
            wallet_height: 100,
            daemon_height: Some(120),
            balance: 100,
            unlocked_balance: 100,
        };
        let err = evaluate_preflight(&health, 0, 0, 10).expect_err("must reject");
        assert!(err.to_string().contains("height lag"));
    }

    #[test]
    fn confirmation_state_flags_double_spend() {
        let status = TransferStatus {
            txid: "aa".repeat(32),
            confirmations: 999,
            double_spend_seen: true,
        };
        assert_eq!(
            evaluate_confirmation(&status, 10),
            ConfirmationState::FailedDoubleSpend
        );
    }

    #[test]
    fn parse_digest_header_stale_true() {
        let h = "Digest realm=\"monero-rpc\",nonce=\"abc123\",stale=true,qop=\"auth\"";
        let c = DigestChallenge::parse_header(h).expect("challenge");
        assert!(c.stale);
    }

    #[tokio::test]
    async fn build_release_proposal_rejects_empty_address() {
        let client = WalletRpcClient::new(WalletRpcConfig {
            endpoint: "http://127.0.0.1:38083".to_string(),
            wallet_name: "arb_escrow_1".to_string(),
            wallet_password: "pass".to_string(),
            username: "u".to_string(),
            password: "p".to_string(),
        });
        let err = client
            .build_release_proposal("", 1)
            .await
            .expect_err("empty address must fail fast");
        assert!(err.to_string().contains("non-empty"));
    }

    #[tokio::test]
    async fn build_release_proposal_rejects_zero_amount() {
        let client = WalletRpcClient::new(WalletRpcConfig {
            endpoint: "http://127.0.0.1:38083".to_string(),
            wallet_name: "arb_escrow_1".to_string(),
            wallet_password: "pass".to_string(),
            username: "u".to_string(),
            password: "p".to_string(),
        });
        let err = client
            .build_release_proposal("fake", 0)
            .await
            .expect_err("zero amount must fail fast");
        assert!(err.to_string().contains("must be > 0"));
    }
}
