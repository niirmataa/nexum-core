use crate::config::{SignerConfig, SignerRole};
use anyhow::{Result, anyhow};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ActionClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub scope: String,
    pub op: String,
    pub role: String,
    pub sign_round: String,
    pub escrow_id: String,
    pub wallet_id: String,
    pub sandbox_id: String,
    pub txset_hash: String,
    pub snapshot_hash: String,
    pub nettype: String,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub jti: String,
    #[serde(default)]
    pub proof_arbiter_jti: Option<String>,
    #[serde(default)]
    pub proof_seller_jti: Option<String>,
    #[serde(default)]
    pub proof_arbiter_req_id: Option<String>,
    #[serde(default)]
    pub proof_seller_req_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct VerifiedSignToken {
    pub claims: ActionClaims,
    pub req_id: String,
}

#[derive(Clone)]
struct VerifyRateLimiter {
    state: Arc<Mutex<HashMap<String, VerifyRateEntry>>>,
    max_attempts: u32,
    window_secs: u64,
    max_keys: usize,
}

#[derive(Clone, Copy, Debug)]
struct VerifyRateEntry {
    window_start: u64,
    count: u32,
    last_seen: u64,
}

impl VerifyRateLimiter {
    fn new(max_attempts: u32, window_secs: u64, max_keys: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            max_attempts: max_attempts.max(1),
            window_secs: window_secs.max(1),
            max_keys: max_keys.max(64),
        }
    }

    fn check(&self, action_token: &str, now_s: u64) -> Result<()> {
        // Keep only a digest in memory to avoid storing raw JWT material in limiter state.
        let key = hex::encode(Sha256::digest(action_token.as_bytes()));
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.retain(|_, entry| now_s.saturating_sub(entry.last_seen) < self.window_secs);
        if !guard.contains_key(&key) && guard.len() >= self.max_keys {
            evict_oldest_entry(&mut guard);
        }
        let entry = guard.entry(key).or_insert(VerifyRateEntry {
            window_start: now_s,
            count: 0,
            last_seen: now_s,
        });
        if now_s.saturating_sub(entry.window_start) >= self.window_secs {
            entry.window_start = now_s;
            entry.count = 0;
        }
        entry.last_seen = now_s;
        if entry.count >= self.max_attempts {
            return Err(anyhow!(
                "action token verification rate limit exceeded; retry later"
            ));
        }
        entry.count = entry.count.saturating_add(1);
        Ok(())
    }
}

fn evict_oldest_entry(entries: &mut HashMap<String, VerifyRateEntry>) {
    let oldest_key = entries
        .iter()
        .min_by_key(|(_, entry)| entry.last_seen)
        .map(|(key, _)| key.clone());
    if let Some(key) = oldest_key {
        let _ = entries.remove(&key);
    }
}

fn validate_public_key_pem_metadata(path: &std::path::Path, metadata: &std::fs::Metadata) -> Result<()> {
    if !metadata.is_file() {
        return Err(anyhow!(
            "action token public key path is not a regular file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(anyhow!(
                "action token public key has unsafe write permissions (mode {:03o}); require no group/other write",
                mode
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_public_key_pem_checked(path: &std::path::Path) -> Result<Vec<u8>> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| anyhow!("failed to open action token public key {}: {}", path.display(), e))?;
    let metadata = file.metadata().map_err(|e| {
        anyhow!(
            "failed to stat opened action token public key {}: {}",
            path.display(),
            e
        )
    })?;
    validate_public_key_pem_metadata(path, &metadata)?;
    let mut pem = Vec::new();
    file.read_to_end(&mut pem).map_err(|e| {
        anyhow!(
            "failed to read action token public key {}: {}",
            path.display(),
            e
        )
    })?;
    Ok(pem)
}

#[cfg(not(unix))]
fn read_public_key_pem_checked(path: &std::path::Path) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow!("failed to open action token public key {}: {}", path.display(), e))?;
    let metadata = file.metadata().map_err(|e| {
        anyhow!(
            "failed to stat opened action token public key {}: {}",
            path.display(),
            e
        )
    })?;
    validate_public_key_pem_metadata(path, &metadata)?;
    let mut pem = Vec::new();
    file.read_to_end(&mut pem).map_err(|e| {
        anyhow!(
            "failed to read action token public key {}: {}",
            path.display(),
            e
        )
    })?;
    Ok(pem)
}

#[derive(Clone)]
pub struct ActionTokenVerifier {
    required: bool,
    issuer: String,
    audience: String,
    algorithm: Algorithm,
    decoding_key: DecodingKey,
    clock_skew_secs: u64,
    max_ttl_secs: u64,
    signer_role: SignerRole,
    sandbox_id: String,
    wallet_id: String,
    nettype: String,
    verify_rate_limiter: VerifyRateLimiter,
}

impl ActionTokenVerifier {
    pub fn from_signer_config(cfg: &SignerConfig) -> Result<Option<Self>> {
        let Some(action_cfg) = &cfg.action_token else {
            return Ok(None);
        };

        let algorithm = parse_algorithm(&action_cfg.algorithm)?;
        let pem = read_public_key_pem_checked(&action_cfg.public_key_pem_path)?;
        let decoding_key = match algorithm {
            Algorithm::EdDSA => DecodingKey::from_ed_pem(&pem)?,
            Algorithm::ES256 => DecodingKey::from_ec_pem(&pem)?,
            _ => return Err(anyhow!("unsupported JWT algorithm for action token")),
        };
        let audience = action_cfg
            .audience
            .clone()
            .unwrap_or_else(|| format!("sandbox:{}", cfg.sandbox_id));

        Ok(Some(Self {
            required: action_cfg.required,
            issuer: action_cfg.issuer.clone(),
            audience,
            algorithm,
            decoding_key,
            clock_skew_secs: action_cfg.clock_skew_secs,
            max_ttl_secs: action_cfg.max_ttl_secs,
            signer_role: cfg.signer_role,
            sandbox_id: cfg.sandbox_id.clone(),
            wallet_id: cfg.wallet_id.clone(),
            nettype: cfg.nettype.clone(),
            verify_rate_limiter: VerifyRateLimiter::new(
                action_cfg.verify_rate_limit_max_attempts,
                action_cfg.verify_rate_limit_window_secs,
                action_cfg.verify_rate_limit_max_keys,
            ),
        }))
    }

    pub fn is_required(&self) -> bool {
        self.required
    }

    pub fn verify_sign_multisig(
        &self,
        action_token: &str,
        escrow_id_hex: &str,
        txset_hash_hex: &str,
        snapshot_hash_hex: &str,
    ) -> Result<VerifiedSignToken> {
        let sign_round_expected = expected_sign_round(self.signer_role);
        self.verify_common(
            action_token,
            "sign_multisig",
            sign_round_expected,
            escrow_id_hex,
            txset_hash_hex,
            snapshot_hash_hex,
        )
    }

    pub fn verify_submit_multisig(
        &self,
        action_token: &str,
        escrow_id_hex: &str,
        txset_hash_hex: &str,
        snapshot_hash_hex: &str,
    ) -> Result<VerifiedSignToken> {
        let submit_round_expected = expected_submit_round(self.signer_role);
        let verified = self.verify_common(
            action_token,
            "submit_multisig",
            submit_round_expected,
            escrow_id_hex,
            txset_hash_hex,
            snapshot_hash_hex,
        )?;
        let proof_arbiter = verified
            .claims
            .proof_arbiter_jti
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("submit token missing proof_arbiter_jti"))?;
        let proof_seller = verified
            .claims
            .proof_seller_jti
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("submit token missing proof_seller_jti"))?;
        let proof_arbiter_req = verified
            .claims
            .proof_arbiter_req_id
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("submit token missing proof_arbiter_req_id"))?;
        let proof_seller_req = verified
            .claims
            .proof_seller_req_id
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("submit token missing proof_seller_req_id"))?;
        if proof_arbiter == proof_seller {
            return Err(anyhow!("submit token quorum proof jti values must differ"));
        }
        if proof_arbiter.len() > 256 || proof_seller.len() > 256 {
            return Err(anyhow!(
                "submit token quorum proof jti too long (max 256 chars)"
            ));
        }
        if proof_arbiter_req == proof_seller_req {
            return Err(anyhow!(
                "submit token quorum proof req_id values must differ"
            ));
        }
        let proof_arbiter_req = normalize_hex_64(proof_arbiter_req, "claims.proof_arbiter_req_id")?;
        let proof_seller_req = normalize_hex_64(proof_seller_req, "claims.proof_seller_req_id")?;
        let txset_hash = normalize_hex_64(txset_hash_hex, "txset_hash_hex")?;
        let expected_arbiter_req =
            sign_req_id(escrow_id_hex, "sign_multisig", "arbiter_first", &txset_hash);
        let expected_seller_req =
            sign_req_id(escrow_id_hex, "sign_multisig", "seller_second", &txset_hash);
        if proof_arbiter_req != expected_arbiter_req {
            return Err(anyhow!(
                "submit token proof_arbiter_req_id does not match expected arbiter sign req_id"
            ));
        }
        if proof_seller_req != expected_seller_req {
            return Err(anyhow!(
                "submit token proof_seller_req_id does not match expected seller sign req_id"
            ));
        }
        Ok(verified)
    }

    fn verify_common(
        &self,
        action_token: &str,
        op_expected: &str,
        sign_round_expected: &str,
        escrow_id_hex: &str,
        txset_hash_hex: &str,
        snapshot_hash_hex: &str,
    ) -> Result<VerifiedSignToken> {
        self.verify_rate_limiter
            .check(action_token, unix_now_s()?)?;
        let mut validation = Validation::new(self.algorithm);
        validation.algorithms = vec![self.algorithm];
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = self.clock_skew_secs;
        validation.required_spec_claims = required_claims();
        validation.set_issuer(&[self.issuer.clone()]);
        validation.set_audience(&[self.audience.clone()]);
        let decoded = decode::<ActionClaims>(action_token, &self.decoding_key, &validation)
            .map_err(|e| anyhow!("invalid action token: {}", e))?;
        let claims = decoded.claims;

        if claims.scope != op_expected || claims.op != op_expected {
            return Err(anyhow!(
                "action token scope/op mismatch; expected {}/{}",
                op_expected,
                op_expected
            ));
        }
        let now_s = unix_now_s()?;
        if claims.iat > now_s.saturating_add(self.clock_skew_secs) {
            return Err(anyhow!("action token iat is in the future"));
        }
        if claims.exp < claims.iat {
            return Err(anyhow!("action token exp is before iat"));
        }
        if claims.exp < claims.nbf {
            return Err(anyhow!("action token exp is before nbf"));
        }
        let ttl_from_iat = claims.exp.saturating_sub(claims.iat);
        let ttl_from_nbf = claims.exp.saturating_sub(claims.nbf);
        if ttl_from_iat == 0
            || ttl_from_iat > self.max_ttl_secs
            || ttl_from_nbf == 0
            || ttl_from_nbf > self.max_ttl_secs
        {
            return Err(anyhow!(
                "action token ttl exceeds max_ttl_secs (max={}s)",
                self.max_ttl_secs
            ));
        }
        if claims.sub.trim().is_empty() || claims.sub.len() > 128 {
            return Err(anyhow!("action token sub invalid"));
        }
        let role_expected = role_key(self.signer_role);
        if claims.role != role_expected {
            return Err(anyhow!(
                "action token role mismatch: claim={} expected={}",
                claims.role,
                role_expected
            ));
        }
        if claims.sign_round != sign_round_expected {
            return Err(anyhow!(
                "action token sign_round mismatch: claim={} expected={}",
                claims.sign_round,
                sign_round_expected
            ));
        }
        if claims.escrow_id != escrow_id_hex {
            return Err(anyhow!("action token escrow_id mismatch"));
        }
        if claims.sandbox_id != self.sandbox_id {
            return Err(anyhow!("action token sandbox_id mismatch"));
        }
        if claims.wallet_id != self.wallet_id {
            return Err(anyhow!("action token wallet_id mismatch"));
        }
        if claims.nettype.trim().to_ascii_lowercase() != self.nettype {
            return Err(anyhow!("action token nettype mismatch"));
        }
        if claims.jti.trim().is_empty() || claims.jti.len() > 256 {
            return Err(anyhow!("action token jti invalid"));
        }

        let txset_hash_claim = normalize_hex_64(&claims.txset_hash, "claims.txset_hash")?;
        let txset_hash_expected = normalize_hex_64(txset_hash_hex, "txset_hash_hex")?;
        if txset_hash_claim != txset_hash_expected {
            return Err(anyhow!("action token txset_hash mismatch"));
        }
        let snapshot_hash_claim = normalize_hex_64(&claims.snapshot_hash, "claims.snapshot_hash")?;
        let snapshot_hash_expected = normalize_hex_64(snapshot_hash_hex, "snapshot_hash_hex")?;
        if snapshot_hash_claim != snapshot_hash_expected {
            return Err(anyhow!("action token snapshot_hash mismatch"));
        }

        let req_id = sign_req_id(
            escrow_id_hex,
            op_expected,
            &claims.sign_round,
            &txset_hash_expected,
        );

        Ok(VerifiedSignToken { claims, req_id })
    }
}

fn required_claims() -> HashSet<String> {
    [
        "iss",
        "aud",
        "sub",
        "scope",
        "op",
        "role",
        "sign_round",
        "escrow_id",
        "wallet_id",
        "sandbox_id",
        "txset_hash",
        "snapshot_hash",
        "nettype",
        "exp",
        "nbf",
        "iat",
        "jti",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn parse_algorithm(value: &str) -> Result<Algorithm> {
    match value.trim().to_ascii_uppercase().as_str() {
        "EDDSA" => Ok(Algorithm::EdDSA),
        "ES256" => Ok(Algorithm::ES256),
        _ => Err(anyhow!("unsupported JWT algorithm '{value}'")),
    }
}

fn unix_now_s() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system clock is before UNIX_EPOCH"))?
        .as_secs())
}

fn role_key(role: SignerRole) -> &'static str {
    match role {
        SignerRole::Arbiter => "arbiter",
        SignerRole::Seller => "seller",
        SignerRole::Buyer => "buyer",
    }
}

fn expected_sign_round(role: SignerRole) -> &'static str {
    match role {
        SignerRole::Arbiter => "arbiter_first",
        SignerRole::Seller => "seller_second",
        SignerRole::Buyer => "buyer_second",
    }
}

fn expected_submit_round(role: SignerRole) -> &'static str {
    match role {
        SignerRole::Arbiter => "arbiter_submit",
        SignerRole::Seller => "seller_submit",
        SignerRole::Buyer => "buyer_submit",
    }
}

fn normalize_hex_64(value: &str, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("{label} must be 64 hex chars"));
    }
    Ok(trimmed.to_ascii_lowercase())
}

pub fn sign_req_id(escrow_id: &str, op: &str, sign_round: &str, txset_hash_hex: &str) -> String {
    let material = format!("{escrow_id}|{op}|{sign_round}|{txset_hash_hex}");
    let mut hasher = Sha256::new();
    hasher.update(material.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ActionTokenConfig, WalletRpcConfig};
    use jsonwebtoken::{EncodingKey, Header, encode};
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    const ED25519_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJCBxRIEv7DU1o/rRG+beqeRLVa2kL9RAArTq6vRp7D0\n-----END PRIVATE KEY-----\n";
    const ED25519_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAD7TxzeCSPJhJljqWs/fABRUaUBlTkJP8O1v31Z64F/I=\n-----END PUBLIC KEY-----\n";

    fn now_s() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn unique_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nxms_signer_action_token_{label}_{}_{}.pem",
            std::process::id(),
            nanos
        ))
    }

    fn test_cfg(public_key_pem_path: PathBuf) -> SignerConfig {
        SignerConfig {
            local_id: "arbiter1".to_string(),
            signer_role: SignerRole::Arbiter,
            sandbox_id: "sbx-1".to_string(),
            wallet_id: "wallet-1".to_string(),
            nettype: "stagenet".to_string(),
            peers_path: PathBuf::from("peers.json"),
            keys_path: PathBuf::from("keys.json"),
            db_path: PathBuf::from("signer.db"),
            mailbox_url: "http://mailbox.onion".to_string(),
            mailbox_push_token: Some("push-token-123456".to_string()),
            mailbox_pull_token: Some("pull-token-123456".to_string()),
            mailbox_ack_token: Some("ack-token-123456".to_string()),
            mailbox_admin_token: None,
            worker_service_token: Some("service-token-123456".to_string()),
            tor_socks5h: Some("socks5h://127.0.0.1:9050".to_string()),
            mailbox_retry_attempts: 3,
            mailbox_retry_backoff_ms: 250,
            allow_remote_wallet_rpc: false,
            production_hardening: false,
            wallet_rpc: WalletRpcConfig {
                endpoint: "http://127.0.0.1:18088".to_string(),
                wallet_name: "wallet".to_string(),
                wallet_password: "pw".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            snapshot_quorum: 1,
            pull_max: 10,
            pull_wait_ms: 0,
            poll_interval_ms: 100,
            default_ttl_secs: 60,
            max_txset_hex_len: 1024,
            action_token: Some(ActionTokenConfig {
                required: true,
                issuer: "nxms-auth".to_string(),
                audience: Some("sandbox:sbx-1".to_string()),
                algorithm: "EDDSA".to_string(),
                public_key_pem_path,
                clock_skew_secs: 5,
                max_ttl_secs: 120,
                verify_rate_limit_max_attempts: 8,
                verify_rate_limit_window_secs: 60,
                verify_rate_limit_max_keys: 4096,
            }),
            wallet_provision: None,
        }
    }

    #[test]
    fn verify_sign_token_accepts_valid_claims() {
        let key_path = unique_path("accepts");
        std::fs::write(&key_path, ED25519_PUBLIC_PEM).expect("write pub key");
        let cfg = test_cfg(key_path.clone());
        let verifier = ActionTokenVerifier::from_signer_config(&cfg)
            .expect("verifier build")
            .expect("verifier enabled");

        let now = now_s();
        let claims = ActionClaims {
            iss: "nxms-auth".to_string(),
            aud: "sandbox:sbx-1".to_string(),
            sub: "arbiter_operator".to_string(),
            scope: "sign_multisig".to_string(),
            op: "sign_multisig".to_string(),
            role: "arbiter".to_string(),
            sign_round: "arbiter_first".to_string(),
            escrow_id: "00112233445566778899aabbccddeeff".to_string(),
            wallet_id: "wallet-1".to_string(),
            sandbox_id: "sbx-1".to_string(),
            txset_hash: "11".repeat(32),
            snapshot_hash: "22".repeat(32),
            nettype: "stagenet".to_string(),
            iat: now,
            nbf: now,
            exp: now + 60,
            jti: "abcd1234".to_string(),
            proof_arbiter_jti: None,
            proof_seller_jti: None,
            proof_arbiter_req_id: None,
            proof_seller_req_id: None,
        };

        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");

        let verified = verifier
            .verify_sign_multisig(
                &token,
                &claims.escrow_id,
                &claims.txset_hash,
                &claims.snapshot_hash,
            )
            .expect("verify ok");
        assert_eq!(verified.claims.role, "arbiter");
        assert_eq!(verified.claims.sub, "arbiter_operator");
        assert_eq!(verified.req_id.len(), 64);

        let _ = std::fs::remove_file(key_path);
    }

    #[cfg(unix)]
    #[test]
    fn from_signer_config_rejects_symlink_pubkey_path() {
        let real_path = unique_path("real_pubkey");
        let link_path = unique_path("symlink_pubkey");
        std::fs::write(&real_path, ED25519_PUBLIC_PEM).expect("write real pub key");
        symlink(&real_path, &link_path).expect("create symlink");

        let cfg = test_cfg(link_path.clone());
        let err = match ActionTokenVerifier::from_signer_config(&cfg) {
            Ok(_) => panic!("must reject symlink path"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("failed to open action token public key"),
            "unexpected error: {msg}"
        );

        let _ = std::fs::remove_file(&link_path);
        let _ = std::fs::remove_file(&real_path);
    }

    #[test]
    fn verify_sign_token_rejects_role_round_swap() {
        let key_path = unique_path("swap");
        std::fs::write(&key_path, ED25519_PUBLIC_PEM).expect("write pub key");
        let cfg = test_cfg(key_path.clone());
        let verifier = ActionTokenVerifier::from_signer_config(&cfg)
            .expect("verifier build")
            .expect("verifier enabled");

        let now = now_s();
        let claims = ActionClaims {
            iss: "nxms-auth".to_string(),
            aud: "sandbox:sbx-1".to_string(),
            sub: "arbiter_operator".to_string(),
            scope: "sign_multisig".to_string(),
            op: "sign_multisig".to_string(),
            role: "arbiter".to_string(),
            sign_round: "seller_second".to_string(),
            escrow_id: "00112233445566778899aabbccddeeff".to_string(),
            wallet_id: "wallet-1".to_string(),
            sandbox_id: "sbx-1".to_string(),
            txset_hash: "11".repeat(32),
            snapshot_hash: "22".repeat(32),
            nettype: "stagenet".to_string(),
            iat: now,
            nbf: now,
            exp: now + 60,
            jti: "swap-jti".to_string(),
            proof_arbiter_jti: None,
            proof_seller_jti: None,
            proof_arbiter_req_id: None,
            proof_seller_req_id: None,
        };
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        let err = verifier
            .verify_sign_multisig(
                &token,
                &claims.escrow_id,
                &claims.txset_hash,
                &claims.snapshot_hash,
            )
            .expect_err("must reject round swap");
        assert!(err.to_string().contains("sign_round mismatch"));

        let _ = std::fs::remove_file(key_path);
    }

    #[test]
    fn verify_submit_token_requires_quorum_proof_fields() {
        let key_path = unique_path("submit");
        std::fs::write(&key_path, ED25519_PUBLIC_PEM).expect("write pub key");
        let cfg = test_cfg(key_path.clone());
        let verifier = ActionTokenVerifier::from_signer_config(&cfg)
            .expect("verifier build")
            .expect("verifier enabled");

        let now = now_s();
        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        let txset_hash_hex = "11".repeat(32);
        let proof_arbiter_req_id = sign_req_id(
            escrow_id_hex,
            "sign_multisig",
            "arbiter_first",
            &txset_hash_hex,
        );
        let proof_seller_req_id = sign_req_id(
            escrow_id_hex,
            "sign_multisig",
            "seller_second",
            &txset_hash_hex,
        );
        let claims = ActionClaims {
            iss: "nxms-auth".to_string(),
            aud: "sandbox:sbx-1".to_string(),
            sub: "arbiter_operator".to_string(),
            scope: "submit_multisig".to_string(),
            op: "submit_multisig".to_string(),
            role: "arbiter".to_string(),
            sign_round: "arbiter_submit".to_string(),
            escrow_id: escrow_id_hex.to_string(),
            wallet_id: "wallet-1".to_string(),
            sandbox_id: "sbx-1".to_string(),
            txset_hash: txset_hash_hex.clone(),
            snapshot_hash: "22".repeat(32),
            nettype: "stagenet".to_string(),
            iat: now,
            nbf: now,
            exp: now + 60,
            jti: "submit-jti".to_string(),
            proof_arbiter_jti: Some("arbiter-proof".to_string()),
            proof_seller_jti: Some("seller-proof".to_string()),
            proof_arbiter_req_id: Some(proof_arbiter_req_id.clone()),
            proof_seller_req_id: Some(proof_seller_req_id.clone()),
        };
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        let verified = verifier
            .verify_submit_multisig(
                &token,
                &claims.escrow_id,
                &claims.txset_hash,
                &claims.snapshot_hash,
            )
            .expect("submit token must verify");
        assert_eq!(verified.claims.scope, "submit_multisig");

        let mut missing = claims.clone();
        missing.proof_seller_jti = None;
        let bad = encode(
            &Header::new(Algorithm::EdDSA),
            &missing,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        let err = verifier
            .verify_submit_multisig(
                &bad,
                &missing.escrow_id,
                &missing.txset_hash,
                &missing.snapshot_hash,
            )
            .expect_err("missing seller proof must fail");
        assert!(err.to_string().contains("proof_seller_jti"));

        let mut missing_req = claims.clone();
        missing_req.proof_seller_req_id = None;
        let bad_req = encode(
            &Header::new(Algorithm::EdDSA),
            &missing_req,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        let err = verifier
            .verify_submit_multisig(
                &bad_req,
                &missing_req.escrow_id,
                &missing_req.txset_hash,
                &missing_req.snapshot_hash,
            )
            .expect_err("missing seller req_id proof must fail");
        assert!(err.to_string().contains("proof_seller_req_id"));

        let mut wrong = claims.clone();
        wrong.proof_seller_req_id = Some("33".repeat(32));
        let wrong_token = encode(
            &Header::new(Algorithm::EdDSA),
            &wrong,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        let err = verifier
            .verify_submit_multisig(
                &wrong_token,
                &wrong.escrow_id,
                &wrong.txset_hash,
                &wrong.snapshot_hash,
            )
            .expect_err("wrong seller req_id proof must fail");
        assert!(err.to_string().contains("proof_seller_req_id"));

        let _ = std::fs::remove_file(key_path);
    }

    #[test]
    fn verify_sign_token_rejects_wallet_sandbox_or_nettype_mismatch() {
        let key_path = unique_path("mismatch");
        std::fs::write(&key_path, ED25519_PUBLIC_PEM).expect("write pub key");
        let cfg = test_cfg(key_path.clone());
        let verifier = ActionTokenVerifier::from_signer_config(&cfg)
            .expect("verifier build")
            .expect("verifier enabled");

        let now = now_s();
        let base = ActionClaims {
            iss: "nxms-auth".to_string(),
            aud: "sandbox:sbx-1".to_string(),
            sub: "arbiter_operator".to_string(),
            scope: "sign_multisig".to_string(),
            op: "sign_multisig".to_string(),
            role: "arbiter".to_string(),
            sign_round: "arbiter_first".to_string(),
            escrow_id: "00112233445566778899aabbccddeeff".to_string(),
            wallet_id: "wallet-1".to_string(),
            sandbox_id: "sbx-1".to_string(),
            txset_hash: "11".repeat(32),
            snapshot_hash: "22".repeat(32),
            nettype: "stagenet".to_string(),
            iat: now,
            nbf: now,
            exp: now + 60,
            jti: "jti-mm".to_string(),
            proof_arbiter_jti: None,
            proof_seller_jti: None,
            proof_arbiter_req_id: None,
            proof_seller_req_id: None,
        };

        let mut wallet_mismatch = base.clone();
        wallet_mismatch.wallet_id = "wallet-other".to_string();
        let wallet_token = encode(
            &Header::new(Algorithm::EdDSA),
            &wallet_mismatch,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        let wallet_err = verifier
            .verify_sign_multisig(
                &wallet_token,
                &wallet_mismatch.escrow_id,
                &wallet_mismatch.txset_hash,
                &wallet_mismatch.snapshot_hash,
            )
            .expect_err("wallet mismatch must fail");
        assert!(wallet_err.to_string().contains("wallet_id mismatch"));

        let mut sandbox_mismatch = base.clone();
        sandbox_mismatch.sandbox_id = "sbx-other".to_string();
        let sandbox_token = encode(
            &Header::new(Algorithm::EdDSA),
            &sandbox_mismatch,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        let sandbox_err = verifier
            .verify_sign_multisig(
                &sandbox_token,
                &sandbox_mismatch.escrow_id,
                &sandbox_mismatch.txset_hash,
                &sandbox_mismatch.snapshot_hash,
            )
            .expect_err("sandbox mismatch must fail");
        assert!(sandbox_err.to_string().contains("sandbox_id mismatch"));

        let mut nettype_mismatch = base.clone();
        nettype_mismatch.nettype = "mainnet".to_string();
        let net_token = encode(
            &Header::new(Algorithm::EdDSA),
            &nettype_mismatch,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        let net_err = verifier
            .verify_sign_multisig(
                &net_token,
                &nettype_mismatch.escrow_id,
                &nettype_mismatch.txset_hash,
                &nettype_mismatch.snapshot_hash,
            )
            .expect_err("nettype mismatch must fail");
        assert!(net_err.to_string().contains("nettype mismatch"));

        let _ = std::fs::remove_file(key_path);
    }

    #[test]
    fn verify_sign_token_rejects_expired_token() {
        let key_path = unique_path("expired");
        std::fs::write(&key_path, ED25519_PUBLIC_PEM).expect("write pub key");
        let cfg = test_cfg(key_path.clone());
        let verifier = ActionTokenVerifier::from_signer_config(&cfg)
            .expect("verifier build")
            .expect("verifier enabled");

        let now = now_s();
        let claims = ActionClaims {
            iss: "nxms-auth".to_string(),
            aud: "sandbox:sbx-1".to_string(),
            sub: "arbiter_operator".to_string(),
            scope: "sign_multisig".to_string(),
            op: "sign_multisig".to_string(),
            role: "arbiter".to_string(),
            sign_round: "arbiter_first".to_string(),
            escrow_id: "00112233445566778899aabbccddeeff".to_string(),
            wallet_id: "wallet-1".to_string(),
            sandbox_id: "sbx-1".to_string(),
            txset_hash: "11".repeat(32),
            snapshot_hash: "22".repeat(32),
            nettype: "stagenet".to_string(),
            iat: now.saturating_sub(120),
            nbf: now.saturating_sub(120),
            exp: now.saturating_sub(10),
            jti: "jti-expired".to_string(),
            proof_arbiter_jti: None,
            proof_seller_jti: None,
            proof_arbiter_req_id: None,
            proof_seller_req_id: None,
        };
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        let err = verifier
            .verify_sign_multisig(
                &token,
                &claims.escrow_id,
                &claims.txset_hash,
                &claims.snapshot_hash,
            )
            .expect_err("expired token must fail");
        assert!(err.to_string().contains("invalid action token"));

        let _ = std::fs::remove_file(key_path);
    }

    #[test]
    fn verify_sign_token_rejects_audience_mismatch() {
        let key_path = unique_path("aud_mismatch");
        std::fs::write(&key_path, ED25519_PUBLIC_PEM).expect("write pub key");
        let cfg = test_cfg(key_path.clone());
        let verifier = ActionTokenVerifier::from_signer_config(&cfg)
            .expect("verifier build")
            .expect("verifier enabled");

        let now = now_s();
        let claims = ActionClaims {
            iss: "nxms-auth".to_string(),
            aud: "sandbox:sbx-other".to_string(),
            sub: "arbiter_operator".to_string(),
            scope: "sign_multisig".to_string(),
            op: "sign_multisig".to_string(),
            role: "arbiter".to_string(),
            sign_round: "arbiter_first".to_string(),
            escrow_id: "00112233445566778899aabbccddeeff".to_string(),
            wallet_id: "wallet-1".to_string(),
            sandbox_id: "sbx-1".to_string(),
            txset_hash: "11".repeat(32),
            snapshot_hash: "22".repeat(32),
            nettype: "stagenet".to_string(),
            iat: now,
            nbf: now,
            exp: now + 60,
            jti: "jti-aud".to_string(),
            proof_arbiter_jti: None,
            proof_seller_jti: None,
            proof_arbiter_req_id: None,
            proof_seller_req_id: None,
        };
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        let err = verifier
            .verify_sign_multisig(
                &token,
                &claims.escrow_id,
                &claims.txset_hash,
                &claims.snapshot_hash,
            )
            .expect_err("audience mismatch must fail");
        assert!(err.to_string().contains("invalid action token"));

        let _ = std::fs::remove_file(key_path);
    }

    #[test]
    fn verify_sign_token_rejects_excessive_ttl() {
        let key_path = unique_path("ttl");
        std::fs::write(&key_path, ED25519_PUBLIC_PEM).expect("write pub key");
        let cfg = test_cfg(key_path.clone());
        let verifier = ActionTokenVerifier::from_signer_config(&cfg)
            .expect("verifier build")
            .expect("verifier enabled");

        let now = now_s();
        let claims = ActionClaims {
            iss: "nxms-auth".to_string(),
            aud: "sandbox:sbx-1".to_string(),
            sub: "arbiter_operator".to_string(),
            scope: "sign_multisig".to_string(),
            op: "sign_multisig".to_string(),
            role: "arbiter".to_string(),
            sign_round: "arbiter_first".to_string(),
            escrow_id: "00112233445566778899aabbccddeeff".to_string(),
            wallet_id: "wallet-1".to_string(),
            sandbox_id: "sbx-1".to_string(),
            txset_hash: "11".repeat(32),
            snapshot_hash: "22".repeat(32),
            nettype: "stagenet".to_string(),
            iat: now,
            nbf: now,
            exp: now + 600,
            jti: "jti-ttl".to_string(),
            proof_arbiter_jti: None,
            proof_seller_jti: None,
            proof_arbiter_req_id: None,
            proof_seller_req_id: None,
        };
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        let err = verifier
            .verify_sign_multisig(
                &token,
                &claims.escrow_id,
                &claims.txset_hash,
                &claims.snapshot_hash,
            )
            .expect_err("ttl must fail");
        assert!(err.to_string().contains("ttl exceeds max_ttl_secs"));

        let _ = std::fs::remove_file(key_path);
    }

    #[test]
    fn verify_sign_token_rejects_future_iat() {
        let key_path = unique_path("future_iat");
        std::fs::write(&key_path, ED25519_PUBLIC_PEM).expect("write pub key");
        let cfg = test_cfg(key_path.clone());
        let verifier = ActionTokenVerifier::from_signer_config(&cfg)
            .expect("verifier build")
            .expect("verifier enabled");

        let now = now_s();
        let claims = ActionClaims {
            iss: "nxms-auth".to_string(),
            aud: "sandbox:sbx-1".to_string(),
            sub: "arbiter_operator".to_string(),
            scope: "sign_multisig".to_string(),
            op: "sign_multisig".to_string(),
            role: "arbiter".to_string(),
            sign_round: "arbiter_first".to_string(),
            escrow_id: "00112233445566778899aabbccddeeff".to_string(),
            wallet_id: "wallet-1".to_string(),
            sandbox_id: "sbx-1".to_string(),
            txset_hash: "11".repeat(32),
            snapshot_hash: "22".repeat(32),
            nettype: "stagenet".to_string(),
            iat: now + 600,
            nbf: now,
            exp: now + 700,
            jti: "jti-future-iat".to_string(),
            proof_arbiter_jti: None,
            proof_seller_jti: None,
            proof_arbiter_req_id: None,
            proof_seller_req_id: None,
        };
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        let err = verifier
            .verify_sign_multisig(
                &token,
                &claims.escrow_id,
                &claims.txset_hash,
                &claims.snapshot_hash,
            )
            .expect_err("future iat must fail");
        assert!(err.to_string().contains("iat is in the future"));

        let _ = std::fs::remove_file(key_path);
    }

    #[test]
    fn verify_sign_token_rejects_future_nbf() {
        let key_path = unique_path("future_nbf");
        std::fs::write(&key_path, ED25519_PUBLIC_PEM).expect("write pub key");
        let cfg = test_cfg(key_path.clone());
        let verifier = ActionTokenVerifier::from_signer_config(&cfg)
            .expect("verifier build")
            .expect("verifier enabled");

        let now = now_s();
        let claims = ActionClaims {
            iss: "nxms-auth".to_string(),
            aud: "sandbox:sbx-1".to_string(),
            sub: "arbiter_operator".to_string(),
            scope: "sign_multisig".to_string(),
            op: "sign_multisig".to_string(),
            role: "arbiter".to_string(),
            sign_round: "arbiter_first".to_string(),
            escrow_id: "00112233445566778899aabbccddeeff".to_string(),
            wallet_id: "wallet-1".to_string(),
            sandbox_id: "sbx-1".to_string(),
            txset_hash: "11".repeat(32),
            snapshot_hash: "22".repeat(32),
            nettype: "stagenet".to_string(),
            iat: now,
            nbf: now + 60,
            exp: now + 120,
            jti: "jti-future-nbf".to_string(),
            proof_arbiter_jti: None,
            proof_seller_jti: None,
            proof_arbiter_req_id: None,
            proof_seller_req_id: None,
        };
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        let err = verifier
            .verify_sign_multisig(
                &token,
                &claims.escrow_id,
                &claims.txset_hash,
                &claims.snapshot_hash,
            )
            .expect_err("future nbf must fail");
        assert!(err.to_string().contains("invalid action token"));

        let _ = std::fs::remove_file(key_path);
    }

    #[test]
    fn verify_sign_token_rate_limit_blocks_repeated_token() {
        let key_path = unique_path("rate_limit");
        std::fs::write(&key_path, ED25519_PUBLIC_PEM).expect("write pub key");
        let mut cfg = test_cfg(key_path.clone());
        if let Some(action) = cfg.action_token.as_mut() {
            action.verify_rate_limit_max_attempts = 1;
            action.verify_rate_limit_window_secs = 300;
            action.verify_rate_limit_max_keys = 128;
        }
        let verifier = ActionTokenVerifier::from_signer_config(&cfg)
            .expect("verifier build")
            .expect("verifier enabled");

        let now = now_s();
        let claims = ActionClaims {
            iss: "nxms-auth".to_string(),
            aud: "sandbox:sbx-1".to_string(),
            sub: "arbiter_operator".to_string(),
            scope: "sign_multisig".to_string(),
            op: "sign_multisig".to_string(),
            role: "arbiter".to_string(),
            sign_round: "arbiter_first".to_string(),
            escrow_id: "00112233445566778899aabbccddeeff".to_string(),
            wallet_id: "wallet-1".to_string(),
            sandbox_id: "sbx-1".to_string(),
            txset_hash: "11".repeat(32),
            snapshot_hash: "22".repeat(32),
            nettype: "stagenet".to_string(),
            iat: now,
            nbf: now,
            exp: now + 60,
            jti: "rate-limit-jti".to_string(),
            proof_arbiter_jti: None,
            proof_seller_jti: None,
            proof_arbiter_req_id: None,
            proof_seller_req_id: None,
        };
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("encode");
        verifier
            .verify_sign_multisig(
                &token,
                &claims.escrow_id,
                &claims.txset_hash,
                &claims.snapshot_hash,
            )
            .expect("first verify");
        let err = verifier
            .verify_sign_multisig(
                &token,
                &claims.escrow_id,
                &claims.txset_hash,
                &claims.snapshot_hash,
            )
            .expect_err("second verify must hit limiter");
        assert!(err.to_string().contains("rate limit exceeded"));

        let _ = std::fs::remove_file(key_path);
    }

    #[cfg(unix)]
    #[test]
    fn from_signer_config_rejects_writable_public_key() {
        let key_path = unique_path("perm_reject");
        std::fs::write(&key_path, ED25519_PUBLIC_PEM).expect("write pub key");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o666))
            .expect("chmod pub key");
        let cfg = test_cfg(key_path.clone());
        let err = match ActionTokenVerifier::from_signer_config(&cfg) {
            Ok(_) => panic!("must reject perms"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("unsafe write permissions"));
        let _ = std::fs::remove_file(key_path);
    }
}
