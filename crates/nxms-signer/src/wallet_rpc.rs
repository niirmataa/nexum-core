use crate::snapshot::{TransferCheck, TransferRecipient};
use anyhow::{Result, anyhow};
use rand::RngCore;
use rand::rngs::OsRng;
use reqwest::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::{Client, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct WalletRpcClient {
    http: Client,
    endpoint: String,
    wallet_name: String,
    wallet_password: String,
    username: String,
    password: String,
    digest_nc: Arc<AtomicU32>,
    digest_nonce: Arc<Mutex<Option<String>>>,
}

#[derive(Clone, Debug)]
pub struct SignedMultisigTx {
    pub tx_data_hex: String,
    pub tx_hash_list: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletMultisigStatus {
    pub multisig: bool,
    pub ready: bool,
    pub threshold: u32,
    pub total: u32,
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

impl WalletRpcClient {
    pub fn new(
        endpoint: String,
        wallet_name: String,
        wallet_password: String,
        username: String,
        password: String,
    ) -> Result<Self> {
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(180))
            .build()
            .map_err(|e| anyhow!("failed to build wallet-rpc http client: {}", e))?;
        Ok(Self {
            http,
            endpoint: endpoint.trim().trim_end_matches('/').to_string(),
            wallet_name,
            wallet_password,
            username,
            password,
            digest_nc: Arc::new(AtomicU32::new(0)),
            digest_nonce: Arc::new(Mutex::new(None)),
        })
    }

    pub fn json_rpc_url(&self) -> String {
        format!("{}/json_rpc", self.endpoint)
    }

    pub async fn ensure_wallet_open(&self) -> Result<()> {
        let _ = self.call::<Value>("close_wallet", json!({})).await;
        self.call::<Value>(
            "open_wallet",
            json!({
                "filename": self.wallet_name,
                "password": self.wallet_password,
            }),
        )
        .await?;
        Ok(())
    }

    pub async fn close_wallet_best_effort(&self) {
        let _ = self.call::<Value>("close_wallet", json!({})).await;
    }

    pub async fn sign_multisig(&self, tx_data_hex: &str) -> Result<SignedMultisigTx> {
        let result: SignMultisigResponse = self
            .call("sign_multisig", json!({ "tx_data_hex": tx_data_hex }))
            .await?;
        Ok(SignedMultisigTx {
            tx_data_hex: result
                .tx_data_hex
                .ok_or_else(|| anyhow!("sign_multisig returned no tx_data_hex"))?,
            tx_hash_list: result.tx_hash_list.unwrap_or_default(),
        })
    }

    pub async fn submit_multisig(&self, tx_data_hex: &str) -> Result<Vec<String>> {
        let result: SubmitMultisigResponse = self
            .call("submit_multisig", json!({ "tx_data_hex": tx_data_hex }))
            .await?;
        Ok(result.tx_hash_list.unwrap_or_default())
    }

    pub async fn transfer_multisig_do_not_relay(
        &self,
        recipients: &[TransferRecipient],
    ) -> Result<String> {
        if recipients.is_empty() {
            return Err(anyhow!("transfer recipients must not be empty"));
        }
        let destinations = recipients
            .iter()
            .map(|r| {
                json!({
                    "address": r.address,
                    "amount": r.amount,
                })
            })
            .collect::<Vec<_>>();

        let result: TransferResponse = self
            .call(
                "transfer",
                json!({
                    "destinations": destinations,
                    "do_not_relay": true
                }),
            )
            .await?;
        let multisig_txset = result
            .multisig_txset
            .ok_or_else(|| anyhow!("transfer returned no multisig_txset"))?;
        let trimmed = multisig_txset.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("transfer returned empty multisig_txset"));
        }
        Ok(trimmed.to_string())
    }

    pub async fn multisig_status(&self) -> Result<WalletMultisigStatus> {
        let result: IsMultisigResponse = self.call("is_multisig", json!({})).await?;
        Ok(multisig_status_from_rpc(result))
    }

    pub async fn describe_transfer(
        &self,
        multisig_txset_hex: &str,
    ) -> Result<(TransferCheck, Value)> {
        let result: DescribeTransferResponse = self
            .call(
                "describe_transfer",
                json!({
                    "multisig_txset": multisig_txset_hex
                }),
            )
            .await?;
        let raw = serde_json::to_value(&result)?;
        let desc = result
            .desc
            .ok_or_else(|| anyhow!("describe_transfer returned no desc"))?;
        if desc.is_empty() {
            return Err(anyhow!("describe_transfer returned empty desc"));
        }
        let check = transfer_check_from_desc(&desc)?;
        Ok((check, raw))
    }

    async fn call<R: DeserializeOwned>(&self, method: &str, params: Value) -> Result<R> {
        let json_rpc_url = self.json_rpc_url();
        let payload = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params,
        });

        let mut resp = self.post_json_rpc(&json_rpc_url, &payload, None).await?;
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

    async fn post_json_rpc_with_digest(
        &self,
        json_rpc_url: &str,
        payload: &Value,
        uri: &str,
        challenge: &DigestChallenge,
    ) -> Result<reqwest::Response> {
        let nc = self.next_digest_nc_for_nonce(&challenge.nonce);
        let auth_header =
            build_digest_authorization(challenge, "POST", uri, &self.username, &self.password, &nc);
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

fn multisig_status_from_rpc(result: IsMultisigResponse) -> WalletMultisigStatus {
    WalletMultisigStatus {
        multisig: result.multisig.unwrap_or(false),
        ready: result.ready.unwrap_or(false),
        threshold: result.threshold.unwrap_or(0),
        total: result.total.unwrap_or(0),
    }
}

fn transfer_check_from_desc(desc: &[DescribeTransferRow]) -> Result<TransferCheck> {
    if desc.is_empty() {
        return Err(anyhow!("describe_transfer returned empty desc"));
    }
    let tx_count = u64::try_from(desc.len()).unwrap_or(u64::MAX);
    let mut recipients = Vec::<TransferRecipient>::new();
    let mut fee_total: u64 = 0;
    let mut unlock_time: Option<u64> = None;
    let mut dummy_outputs_total: u64 = 0;

    for (i, item) in desc.iter().enumerate() {
        let fee = item
            .fee
            .ok_or_else(|| anyhow!("describe_transfer row {i} missing fee"))?;
        let item_unlock = item
            .unlock_time
            .ok_or_else(|| anyhow!("describe_transfer row {i} missing unlock_time"))?;
        let dummy_outputs = item
            .dummy_outputs
            .ok_or_else(|| anyhow!("describe_transfer row {i} missing dummy_outputs"))?;
        let row_recipients = item
            .recipients
            .as_ref()
            .ok_or_else(|| anyhow!("describe_transfer row {i} missing recipients"))?;
        if row_recipients.is_empty() {
            return Err(anyhow!("describe_transfer row {i} has empty recipients"));
        }

        fee_total = fee_total.saturating_add(fee);
        dummy_outputs_total = dummy_outputs_total.saturating_add(dummy_outputs);

        match unlock_time {
            None => unlock_time = Some(item_unlock),
            Some(v) if v == item_unlock => {}
            Some(v) => {
                return Err(anyhow!(
                    "describe_transfer unlock_time mismatch across txs: {} vs {}",
                    v,
                    item_unlock
                ));
            }
        }

        for (r_idx, r) in row_recipients.iter().enumerate() {
            let address = r.address.as_ref().ok_or_else(|| {
                anyhow!("describe_transfer row {i} recipient {r_idx} missing address")
            })?;
            if address.trim().is_empty() {
                return Err(anyhow!(
                    "describe_transfer row {i} recipient {r_idx} has empty address"
                ));
            }
            let amount = r.amount.ok_or_else(|| {
                anyhow!("describe_transfer row {i} recipient {r_idx} missing amount")
            })?;
            recipients.push(TransferRecipient {
                address: address.clone(),
                amount,
            });
        }
    }

    if recipients.is_empty() {
        return Err(anyhow!("describe_transfer has no recipients"));
    }

    Ok(TransferCheck {
        tx_count,
        recipients,
        fee: fee_total,
        unlock_time: unlock_time.unwrap_or(0),
        dummy_outputs: dummy_outputs_total,
    })
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
struct SignMultisigResponse {
    tx_data_hex: Option<String>,
    tx_hash_list: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct SubmitMultisigResponse {
    tx_hash_list: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct IsMultisigResponse {
    multisig: Option<bool>,
    ready: Option<bool>,
    threshold: Option<u32>,
    total: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct TransferResponse {
    multisig_txset: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DescribeTransferResponse {
    desc: Option<Vec<DescribeTransferRow>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DescribeTransferRow {
    recipients: Option<Vec<DescribeRecipient>>,
    fee: Option<u64>,
    unlock_time: Option<u64>,
    dummy_outputs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DescribeRecipient {
    address: Option<String>,
    amount: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row_ok() -> DescribeTransferRow {
        DescribeTransferRow {
            recipients: Some(vec![DescribeRecipient {
                address: Some("release_addr".to_string()),
                amount: Some(100),
            }]),
            fee: Some(5),
            unlock_time: Some(0),
            dummy_outputs: Some(0),
        }
    }

    #[test]
    fn transfer_check_from_desc_rejects_missing_required_fields() {
        let mut row = row_ok();
        row.fee = None;
        let err = transfer_check_from_desc(&[row]).expect_err("missing fee must fail");
        assert!(err.to_string().contains("missing fee"));
    }

    #[test]
    fn transfer_check_from_desc_rejects_empty_address() {
        let mut row = row_ok();
        row.recipients = Some(vec![DescribeRecipient {
            address: Some("".to_string()),
            amount: Some(100),
        }]);
        let err = transfer_check_from_desc(&[row]).expect_err("empty address must fail");
        assert!(err.to_string().contains("empty address"));
    }

    #[test]
    fn transfer_check_from_desc_accepts_valid_rows() {
        let check = transfer_check_from_desc(&[row_ok()]).expect("valid rows");
        assert_eq!(check.tx_count, 1);
        assert_eq!(check.fee, 5);
        assert_eq!(check.unlock_time, 0);
        assert_eq!(check.dummy_outputs, 0);
        assert_eq!(check.recipients.len(), 1);
        assert_eq!(check.recipients[0].address, "release_addr");
        assert_eq!(check.recipients[0].amount, 100);
    }

    #[test]
    fn multisig_status_from_rpc_defaults_missing_fields() {
        let status = multisig_status_from_rpc(IsMultisigResponse {
            multisig: None,
            ready: None,
            threshold: None,
            total: None,
        });
        assert_eq!(
            status,
            WalletMultisigStatus {
                multisig: false,
                ready: false,
                threshold: 0,
                total: 0,
            }
        );
    }

    #[test]
    fn multisig_status_from_rpc_maps_values() {
        let status = multisig_status_from_rpc(IsMultisigResponse {
            multisig: Some(true),
            ready: Some(true),
            threshold: Some(2),
            total: Some(3),
        });
        assert_eq!(
            status,
            WalletMultisigStatus {
                multisig: true,
                ready: true,
                threshold: 2,
                total: 3,
            }
        );
    }

    #[test]
    fn parse_digest_header_stale_true() {
        let h = "Digest realm=\"monero-rpc\",nonce=\"abc123\",stale=true,qop=\"auth\"";
        let c = DigestChallenge::parse_header(h).expect("challenge");
        assert!(c.stale);
    }
}
