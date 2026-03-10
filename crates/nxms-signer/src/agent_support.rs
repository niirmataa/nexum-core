use crate::config::{SignerConfig, SignerRole, WalletProvisionConfig};
use crate::snapshot::{AmountRule, ContractSnapshot, TransferRecipient};
use crate::wallet_rpc::WalletMultisigStatus;
use anyhow::{Result, anyhow};
use nxms_transport::wire::{EscrowAction, NxmsPayload, TxSignReqBody};
use sha3::{Digest, Sha3_256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

struct TemporarySecretFile {
    path: PathBuf,
}

impl TemporarySecretFile {
    fn new(label: &str, secret: &str) -> Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "nxms_signer_{}_{}_{}",
            label,
            std::process::id(),
            nonce
        ));
        std::fs::write(&path, format!("{}\n", secret)).map_err(|e| {
            anyhow!(
                "failed to write temporary secret file '{}': {}",
                path.display(),
                e
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| {
                    anyhow!(
                        "failed to set permissions on temporary secret file '{}': {}",
                        path.display(),
                        e
                    )
                },
            )?;
        }
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl Drop for TemporarySecretFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub(crate) async fn provision_wallet_multisig_enable(cfg: &SignerConfig) -> Result<()> {
    let provision = cfg
        .wallet_provision
        .as_ref()
        .ok_or_else(|| anyhow!("wallet provisioning config is missing"))?;
    if !provision.enabled {
        return Ok(());
    }
    let wallet_file = resolve_wallet_cli_wallet_file(cfg, provision.wallet_dir.as_ref());
    info!(
        wallet_file = %wallet_file.display(),
        "wallet provisioning: enabling multisig-experimental via server-side CLI"
    );
    run_wallet_cli_command(
        cfg,
        provision,
        &wallet_file,
        "set enable-multisig-experimental 1",
        Some(&cfg.wallet_rpc.wallet_password),
    )
    .await?;
    run_wallet_cli_command(cfg, provision, &wallet_file, "save", None).await?;
    info!(
        wallet_file = %wallet_file.display(),
        "wallet provisioning completed"
    );
    Ok(())
}

pub(crate) fn enforce_wallet_multisig_ready(
    cfg: &SignerConfig,
    status: WalletMultisigStatus,
) -> Result<()> {
    let require_ready = cfg.production_hardening
        || cfg
            .wallet_provision
            .as_ref()
            .map(|v| v.enabled)
            .unwrap_or(false);

    if !status.multisig || !status.ready {
        if require_ready {
            return Err(anyhow!(
                "wallet '{}' not ready for multisig signing (multisig={}, ready={}, threshold={}, total={}); \
complete multisig rounds/finalize before starting signer",
                cfg.wallet_rpc.wallet_name,
                status.multisig,
                status.ready,
                status.threshold,
                status.total
            ));
        }
        warn!(
            wallet_name = %cfg.wallet_rpc.wallet_name,
            multisig = status.multisig,
            ready = status.ready,
            threshold = status.threshold,
            total = status.total,
            "wallet is not multisig-ready; signer may reject signing/submitting in this state"
        );
        return Ok(());
    }

    if status.total == 0 || status.threshold == 0 || status.threshold > status.total {
        return Err(anyhow!(
            "wallet '{}' returned invalid multisig status from wallet-rpc: threshold={} total={}",
            cfg.wallet_rpc.wallet_name,
            status.threshold,
            status.total
        ));
    }
    Ok(())
}

pub(crate) fn resolve_wallet_cli_wallet_file(
    cfg: &SignerConfig,
    wallet_dir: Option<&PathBuf>,
) -> PathBuf {
    let wallet_name = cfg.wallet_rpc.wallet_name.trim();
    let wallet_path = PathBuf::from(wallet_name);
    if wallet_path.is_absolute() {
        return wallet_path;
    }
    if let Some(dir) = wallet_dir {
        return dir.join(wallet_path);
    }
    wallet_path
}

pub(crate) async fn run_wallet_cli_command(
    cfg: &SignerConfig,
    provision: &WalletProvisionConfig,
    wallet_file: &Path,
    command: &str,
    stdin_line: Option<&str>,
) -> Result<()> {
    let wallet_password_file =
        TemporarySecretFile::new("wallet_cli_password", &cfg.wallet_rpc.wallet_password)?;
    let mut cmd = tokio::process::Command::new(&provision.wallet_cli_path);
    cmd.arg("--wallet-file").arg(wallet_file);
    cmd.arg("--password-file").arg(wallet_password_file.path());
    if let Some(daemon_address) = provision.daemon_address.as_deref() {
        cmd.arg("--daemon-address").arg(daemon_address);
    }
    if provision.trusted_daemon {
        cmd.arg("--trusted-daemon");
    }
    match cfg.nettype.as_str() {
        "stagenet" => {
            cmd.arg("--stagenet");
        }
        "testnet" => {
            cmd.arg("--testnet");
        }
        _ => {}
    }
    for arg in &provision.extra_args {
        cmd.arg(arg);
    }
    cmd.arg("--command").arg(command);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.kill_on_drop(true);

    let mut child = cmd.spawn().map_err(|e| {
        anyhow!(
            "wallet provisioning failed to spawn '{}': {}",
            provision.wallet_cli_path.display(),
            e
        )
    })?;

    if let Some(line) = stdin_line
        && let Some(mut stdin) = child.stdin.take()
    {
        let payload = format!("{line}\n");
        if let Err(err) = stdin.write_all(payload.as_bytes()).await {
            warn!(
                "wallet provisioning stdin write failed for command '{}': {}",
                command, err
            );
        }
    }

    let output = tokio::time::timeout(
        Duration::from_secs(provision.timeout_secs),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "wallet provisioning command timed out after {}s: {}",
            provision.timeout_secs,
            command
        )
    })?
    .map_err(|e| anyhow!("wallet provisioning command '{}' failed: {}", command, e))?;

    if !output.status.success() {
        let stderr = trim_for_log(String::from_utf8_lossy(&output.stderr).as_ref(), 400);
        let stdout = trim_for_log(String::from_utf8_lossy(&output.stdout).as_ref(), 400);
        return Err(anyhow!(
            "wallet provisioning command '{}' exited with status {:?}; stderr='{}' stdout='{}'",
            command,
            output.status.code(),
            stderr,
            stdout
        ));
    }
    Ok(())
}

pub(crate) fn trim_for_log(input: &str, max_len: usize) -> String {
    let compact = input.replace('\n', " ").replace('\r', " ");
    let compact = compact.trim();
    if compact.len() <= max_len {
        return compact.to_string();
    }
    format!("{}...", &compact[..max_len])
}

pub(crate) fn validate_tx_sign_req(
    payload: &NxmsPayload,
    req: &TxSignReqBody,
    max_hex_len: usize,
) -> Result<()> {
    if req.escrow_id_hex != payload.escrow_id_hex {
        return Err(anyhow!("tx_sign_req escrow_id mismatch payload vs body"));
    }
    let hex_raw = req.multisig_txset_hex.trim();
    if hex_raw.is_empty() {
        return Err(anyhow!("multisig_txset_hex must not be empty"));
    }
    if hex_raw.len() > max_hex_len {
        return Err(anyhow!("multisig_txset_hex too large"));
    }
    if hex_raw.len() % 2 != 0 || !hex_raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("multisig_txset_hex must be valid even-length hex"));
    }
    let _ = normalize_hex_exact(&req.snapshot_hash_hex, 64, "snapshot_hash_hex")?;
    Ok(())
}

pub(crate) fn validate_tx_data_hex(value: &str, max_hex_len: usize) -> Result<String> {
    let hex_raw = value.trim();
    if hex_raw.is_empty() {
        return Err(anyhow!("tx_data_hex must not be empty"));
    }
    if hex_raw.len() > max_hex_len {
        return Err(anyhow!("tx_data_hex too large"));
    }
    if hex_raw.len() % 2 != 0 || !hex_raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("tx_data_hex must be valid even-length hex"));
    }
    Ok(hex_raw.to_ascii_lowercase())
}

pub(crate) fn parse_pending_action(action_json: &str) -> Result<EscrowAction> {
    serde_json::from_str(action_json)
        .map_err(|e| anyhow!("invalid stored action JSON '{}': {}", action_json, e))
}

pub(crate) fn proposal_recipients_from_snapshot(
    snapshot: &ContractSnapshot,
    action: EscrowAction,
    amount_override_atomic: Option<u64>,
) -> Result<Vec<TransferRecipient>> {
    let policy = match action {
        EscrowAction::Release => &snapshot.release_policy,
        EscrowAction::Refund => &snapshot.refund_policy,
    };

    let candidate_rules = if policy.allowed_recipients.iter().any(|r| r.required) {
        policy
            .allowed_recipients
            .iter()
            .filter(|r| r.required)
            .collect::<Vec<_>>()
    } else {
        policy.allowed_recipients.iter().collect::<Vec<_>>()
    };
    if candidate_rules.is_empty() {
        return Err(anyhow!("snapshot policy has no recipients"));
    }

    let mut out = Vec::with_capacity(candidate_rules.len());
    for rule in candidate_rules {
        let amount = match rule.amount {
            AmountRule::Exact { amount } => amount,
            AmountRule::Range { min, max } => {
                let override_amount = amount_override_atomic.ok_or_else(|| {
                    anyhow!(
                        "amount_override_atomic is required for range recipient '{}'",
                        rule.address
                    )
                })?;
                if override_amount < min || override_amount > max {
                    return Err(anyhow!(
                        "amount_override_atomic={} outside [{}..{}] for '{}'",
                        override_amount,
                        min,
                        max,
                        rule.address
                    ));
                }
                override_amount
            }
        };
        out.push(TransferRecipient {
            address: rule.address.clone(),
            amount,
        });
    }
    Ok(out)
}

pub(crate) fn signer_role_key(role: SignerRole) -> &'static str {
    match role {
        SignerRole::Arbiter => "arbiter",
        SignerRole::Seller => "seller",
        SignerRole::Buyer => "buyer",
    }
}

pub(crate) fn default_sign_round(role: SignerRole) -> &'static str {
    match role {
        SignerRole::Arbiter => "arbiter_first",
        SignerRole::Seller => "seller_second",
        SignerRole::Buyer => "buyer_second",
    }
}

pub(crate) fn default_submit_round(role: SignerRole) -> &'static str {
    match role {
        SignerRole::Arbiter => "arbiter_submit",
        SignerRole::Seller => "seller_submit",
        SignerRole::Buyer => "buyer_submit",
    }
}

pub(crate) fn audit_security_detail(
    op: &str,
    role: &str,
    sign_round: &str,
    req_id: Option<&str>,
    txset_hash_hex: &str,
    snapshot_hash_hex: &str,
    jti: Option<&str>,
    exp: Option<u64>,
    result: &str,
    reason: Option<&str>,
) -> String {
    let reason = reason
        .map(sanitize_runtime_detail)
        .unwrap_or_else(|| "-".to_string());
    format!(
        "op={op} role={role} sign_round={sign_round} req_id={} txset_hash={} snapshot_hash={} jti={} exp={} result={} reason={}",
        req_id.unwrap_or("-"),
        txset_hash_hex,
        snapshot_hash_hex,
        jti.unwrap_or("-"),
        exp.map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        result,
        reason,
    )
}

pub(crate) fn sanitize_runtime_detail(raw: &str) -> String {
    let compact = trim_for_log(raw, 1024);
    let lower = compact.to_ascii_lowercase();
    if lower.contains("authorization: bearer")
        || lower.contains("action_token=")
        || lower.contains("wallet_password")
        || lower.contains("password=")
        || lower.contains("\"password\"")
    {
        return "redacted_sensitive_detail".to_string();
    }
    if contains_probable_jwt(&compact) {
        return redact_probable_jwt_tokens(&compact);
    }
    compact
}

pub(crate) fn contains_probable_jwt(raw: &str) -> bool {
    raw.split_whitespace().any(looks_like_jwt_token)
}

fn redact_probable_jwt_tokens(raw: &str) -> String {
    raw.split_whitespace()
        .map(|token| {
            if looks_like_jwt_token(token) {
                "<redacted.jwt>"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn looks_like_jwt_token(token: &str) -> bool {
    let trimmed = token.trim_matches(|c: char| {
        !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '=')
    });
    let mut parts = trimmed.split('.');
    let Some(a) = parts.next() else { return false };
    let Some(b) = parts.next() else { return false };
    let Some(c) = parts.next() else { return false };
    if parts.next().is_some() {
        return false;
    }
    if a.len() < 8 || b.len() < 8 || c.len() < 8 {
        return false;
    }
    [a, b, c].iter().all(|part| {
        part.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '=')
    })
}

pub fn normalize_hex_exact(value: &str, expected_len: usize, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.len() != expected_len || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("{} must be {} hex chars", label, expected_len));
    }
    Ok(trimmed.to_ascii_lowercase())
}

pub(crate) fn decode_escrow_id_hex(hex_id: &str) -> Result<[u8; 16]> {
    let raw = hex::decode(hex_id)?;
    if raw.len() != 16 {
        return Err(anyhow!("escrow_id_hex must be 32 hex chars (16 bytes)"));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&raw);
    Ok(out)
}

pub(crate) fn txset_sha256_hex(multisig_txset_hex: &str) -> Result<String> {
    use sha2::{Digest, Sha256};

    let raw = multisig_txset_hex.trim();
    if raw.is_empty() {
        return Err(anyhow!("multisig_txset_hex must not be empty"));
    }
    let txset_bytes = hex::decode(raw).map_err(|_| anyhow!("multisig_txset_hex must be hex"))?;
    let mut hasher = Sha256::new();
    hasher.update(txset_bytes);
    Ok(hex::encode(hasher.finalize()))
}

pub(crate) fn sha3_hex(input: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

pub fn now_ms() -> u64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX_EPOCH");
    dur.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use nxms_transport::wire::{MsgType, NxmsPayload, TxSignReqBody};

    fn sample_payload() -> NxmsPayload {
        NxmsPayload {
            app_proto: "ESCROW/1".to_string(),
            msg_type: MsgType::TxSignReq,
            escrow_id_hex: "00112233445566778899aabbccddeeff".to_string(),
            from: "peer1".to_string(),
            to: "local".to_string(),
            seq: 1,
            data: "{\"kind\":\"tx_sign_req\"}".to_string(),
        }
    }

    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn rand_ascii(seed: &mut u64, max_len: usize) -> String {
        let len = (xorshift64(seed) as usize) % max_len;
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            let b = (32 + (xorshift64(seed) % 95) as u8) as char;
            out.push(b);
        }
        out
    }

    #[test]
    fn fuzz_target_signer_validation_smoke() {
        let payload = sample_payload();
        let mut seed: u64 = 0x7b4a_9c2e_5d61_8821;
        for _ in 0..1024 {
            let req = TxSignReqBody {
                escrow_id_hex: payload.escrow_id_hex.clone(),
                action: EscrowAction::Release,
                multisig_txset_hex: rand_ascii(&mut seed, 512),
                snapshot_hash_hex: rand_ascii(&mut seed, 96),
                human_hint: Some(rand_ascii(&mut seed, 48)),
            };
            let _ = validate_tx_sign_req(&payload, &req, 256);
            let _ = validate_tx_data_hex(&req.multisig_txset_hex, 256);
        }
    }

    #[test]
    fn validate_tx_data_hex_rejects_oversized_value() {
        let too_large = "aa".repeat(300);
        let err = validate_tx_data_hex(&too_large, 256).expect_err("must reject oversized txset");
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn sanitize_runtime_detail_redacts_password_markers_and_jwt() {
        assert_eq!(
            sanitize_runtime_detail("wallet-rpc failed password=supersecret"),
            "redacted_sensitive_detail"
        );
        let redacted = sanitize_runtime_detail(
            "invalid token eyJhbGciOiJFZERTQSJ9.eyJzY29wZSI6InNpZ25fbXVsdGlzaWcifQ.c2lnbmF0dXJlX2J5dGVz",
        );
        assert!(redacted.contains("<redacted.jwt>"));
        assert!(!redacted.contains("eyJhbGciOiJFZERTQSJ9"));
    }
}
