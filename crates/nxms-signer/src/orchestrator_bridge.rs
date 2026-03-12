use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::env;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::warn;

const ENV_STORE: &str = "NXMS_SIGNER_ORCH_QUORUM_PROOF_STORE";
const ENV_STORE_REQUIRED: &str = "NXMS_SIGNER_ORCH_QUORUM_PROOF_STORE_REQUIRED";
const ENV_VERIFY: &str = "NXMS_SIGNER_ORCH_QUORUM_PROOF_VERIFY";
const ENV_ORCH_CONFIG_PATH: &str = "NXMS_ORCH_CONFIG_PATH";
const ENV_BRIDGE_TOKEN: &str = "NXMS_SIGNER_ORCH_BRIDGE_TOKEN";
const ENV_BRIDGE_TOKEN_REF: &str = "NXMS_SIGNER_ORCH_BRIDGE_TOKEN_REF";
const ENV_BRIDGE_TOKEN_INPUT: &str = "NXMS_ORCH_BRIDGE_TOKEN_INPUT";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecretRefKind {
    Env,
    File,
    Vault,
    Literal,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct OrchestratorSubmitMultisigProofBundle {
    pub(crate) escrow_id_hex: String,
    pub(crate) txset_hash_hex: String,
    pub(crate) proof_arbiter_jti: String,
    pub(crate) proof_arbiter_req_id: String,
    pub(crate) proof_seller_jti: String,
    pub(crate) proof_seller_req_id: String,
    pub(crate) arbiter_proof_updated_at_ms: u64,
    pub(crate) seller_proof_updated_at_ms: u64,
    pub(crate) generated_at_ms: u64,
}

pub(crate) fn enforce_production_requirements(production_hardening: bool) -> Result<()> {
    let verify_enabled = resolve_submit_verify_mode(production_hardening, env_true(ENV_VERIFY))?;
    let bridge_enabled =
        env_true(ENV_STORE) || env_true(ENV_STORE_REQUIRED) || verify_enabled;
    if !bridge_enabled {
        return Ok(());
    }
    require_orchestrator_config_path()?;
    let (token, source) = bridge_token()?.ok_or_else(|| {
        anyhow!(
            "missing bridge token: set {}=vault:/path (preferred) or {} (legacy)",
            ENV_BRIDGE_TOKEN_REF,
            ENV_BRIDGE_TOKEN
        )
    })?;
    if token.len() < 32 {
        return Err(anyhow!(
            "bridge token must have min 32 chars (source: {})",
            match source {
                SecretRefKind::Env => "env reference",
                SecretRefKind::File => "file reference",
                SecretRefKind::Vault => "vault reference",
                SecretRefKind::Literal => "legacy env",
            }
        ));
    }
    if production_hardening {
        if source != SecretRefKind::Vault {
            return Err(anyhow!(
                "production_hardening=true requires {} to use vault:/path (legacy {} is not allowed)",
                ENV_BRIDGE_TOKEN_REF,
                ENV_BRIDGE_TOKEN
            ));
        }
        if env::var(ENV_BRIDGE_TOKEN_REF)
            .ok()
            .map(|v| v.trim().is_empty())
            .unwrap_or(false)
        {
            return Err(anyhow!(
                "production_hardening=true requires non-empty {}",
                ENV_BRIDGE_TOKEN_REF
            ));
        }
    }
    Ok(())
}

pub(crate) async fn maybe_store_quorum_sign_proof(
    escrow_id_hex: &str,
    role: &str,
    sign_round: &str,
    txset_hash_hex: &str,
    jti: &str,
    req_id: &str,
) -> Result<()> {
    if !env_true(ENV_STORE) {
        return Ok(());
    }
    let required = env_true(ENV_STORE_REQUIRED);
    match store_quorum_sign_proof(escrow_id_hex, role, sign_round, txset_hash_hex, jti, req_id)
        .await
    {
        Ok(()) => Ok(()),
        Err(err) if !required => {
            warn!(
                escrow_id_hex,
                role,
                sign_round,
                "orchestrator quorum-proof store failed (non-required mode): {}",
                err
            );
            Ok(())
        }
        Err(err) => Err(err),
    }
}

pub(crate) async fn verify_submit_seller_quorum_proof(
    escrow_id_hex: &str,
    txset_hash_hex: &str,
    token_seller_jti: &str,
    token_seller_req_id: &str,
    production_hardening: bool,
) -> Result<()> {
    let verify_enabled = resolve_submit_verify_mode(production_hardening, env_true(ENV_VERIFY))?;
    if !verify_enabled {
        return Ok(());
    }
    let bundle = fetch_submit_multisig_proof_bundle(escrow_id_hex, txset_hash_hex).await?;
    if bundle.proof_seller_jti != token_seller_jti
        || bundle.proof_seller_req_id != token_seller_req_id
    {
        return Err(anyhow!(
            "submit denied: orchestrator seller quorum proof mismatch (token vs orchestrator)"
        ));
    }
    Ok(())
}

pub(crate) async fn verify_submit_quorum_proof_bundle(
    escrow_id_hex: &str,
    txset_hash_hex: &str,
    token_arbiter_jti: &str,
    token_arbiter_req_id: &str,
    token_seller_jti: &str,
    token_seller_req_id: &str,
    production_hardening: bool,
) -> Result<()> {
    let verify_enabled = resolve_submit_verify_mode(production_hardening, env_true(ENV_VERIFY))?;
    if !verify_enabled {
        return Ok(());
    }
    let bundle = fetch_submit_multisig_proof_bundle(escrow_id_hex, txset_hash_hex).await?;
    if bundle.proof_arbiter_jti != token_arbiter_jti
        || bundle.proof_arbiter_req_id != token_arbiter_req_id
        || bundle.proof_seller_jti != token_seller_jti
        || bundle.proof_seller_req_id != token_seller_req_id
    {
        return Err(anyhow!(
            "submit token issuance denied: orchestrator quorum proof bundle mismatch"
        ));
    }
    Ok(())
}

async fn store_quorum_sign_proof(
    escrow_id_hex: &str,
    role: &str,
    sign_round: &str,
    txset_hash_hex: &str,
    jti: &str,
    req_id: &str,
) -> Result<()> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let role = normalize_non_empty(role, "role")?;
    let sign_round = normalize_non_empty(sign_round, "sign_round")?;
    let txset_hash_hex = normalize_hex_exact(txset_hash_hex, 64, "txset_hash_hex")?;
    let jti = normalize_non_empty(jti, "jti")?;
    if jti.len() > 256 {
        return Err(anyhow!("jti too long (max 256 chars)"));
    }
    let req_id = normalize_hex_exact(req_id, 64, "req_id")?;
    let args = vec![
        "quorum-proof".to_string(),
        "set".to_string(),
        "--escrow-id-hex".to_string(),
        escrow_id_hex,
        "--role".to_string(),
        role,
        "--sign-round".to_string(),
        sign_round,
        "--txset-hash-hex".to_string(),
        txset_hash_hex,
        "--jti".to_string(),
        jti,
        "--req-id".to_string(),
        req_id,
    ];
    let _ = run_orchestrator_command(args).await?;
    Ok(())
}

async fn fetch_submit_multisig_proof_bundle(
    escrow_id_hex: &str,
    txset_hash_hex: &str,
) -> Result<OrchestratorSubmitMultisigProofBundle> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let txset_hash_hex = normalize_hex_exact(txset_hash_hex, 64, "txset_hash_hex")?;
    let args = vec![
        "quorum-proof".to_string(),
        "submit-bundle".to_string(),
        "--escrow-id-hex".to_string(),
        escrow_id_hex.clone(),
        "--txset-hash-hex".to_string(),
        txset_hash_hex.clone(),
    ];
    let stdout = run_orchestrator_command(args).await?;
    let bundle =
        serde_json::from_str::<OrchestratorSubmitMultisigProofBundle>(&stdout).map_err(|e| {
            anyhow!(
                "orchestrator quorum-proof submit-bundle decode failed: {}",
                e
            )
        })?;
    if bundle.escrow_id_hex != escrow_id_hex || bundle.txset_hash_hex != txset_hash_hex {
        return Err(anyhow!(
            "orchestrator quorum-proof submit-bundle mismatch for escrow/hash"
        ));
    }
    Ok(bundle)
}

fn orchestrator_bin() -> String {
    env::var("NXMS_ORCH_BIN")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "nxms-escrow-orchestrator".to_string())
}

fn orchestrator_config_path() -> Option<String> {
    env::var(ENV_ORCH_CONFIG_PATH)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn require_orchestrator_config_path() -> Result<String> {
    orchestrator_config_path().ok_or_else(|| {
        anyhow!(
            "missing orchestrator config path: set {} to the canonical orchestrator TOML",
            ENV_ORCH_CONFIG_PATH
        )
    })
}

fn orchestrator_timeout_secs() -> u64 {
    env::var("NXMS_SIGNER_ORCH_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(15)
}

async fn run_orchestrator_command(args: Vec<String>) -> Result<String> {
    let bin = orchestrator_bin();
    let orchestrator_config_path = require_orchestrator_config_path()?;
    let timeout_secs = orchestrator_timeout_secs();
    let args_for_log = redact_args_for_log(&args);
    let bridge_token = bridge_token()?.map(|(value, _kind)| value);
    let mut cmd = Command::new(&bin);
    cmd.args(&args);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.env(ENV_ORCH_CONFIG_PATH, orchestrator_config_path);
    if let Some(token) = bridge_token.as_deref() {
        cmd.env(ENV_BRIDGE_TOKEN_INPUT, token);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("failed to spawn orchestrator binary '{}': {}", bin, e))?;

    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture orchestrator stdout"))?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture orchestrator stderr"))?;

    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        stdout_pipe.read_to_end(&mut buf).await.map(|_| buf)
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        stderr_pipe.read_to_end(&mut buf).await.map(|_| buf)
    });

    let status = match tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait()).await {
        Ok(wait_res) => wait_res.map_err(|e| anyhow!("orchestrator wait failed: {}", e))?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            return Err(anyhow!("orchestrator command timed out: {}", args_for_log));
        }
    };

    let stdout = stdout_task
        .await
        .map_err(|e| anyhow!("orchestrator stdout join error: {}", e))?
        .map_err(|e| anyhow!("orchestrator stdout read failed: {}", e))?;
    let stderr = stderr_task
        .await
        .map_err(|e| anyhow!("orchestrator stderr join error: {}", e))?
        .map_err(|e| anyhow!("orchestrator stderr read failed: {}", e))?;

    let stdout = String::from_utf8_lossy(&stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&stderr).trim().to_string();
    if !status.success() {
        return Err(anyhow!(
            "orchestrator command failed: status={:?} stderr='{}' stdout='{}'",
            status.code(),
            stderr,
            stdout
        ));
    }
    Ok(stdout)
}

fn bridge_token() -> Result<Option<(String, SecretRefKind)>> {
    if let Ok(raw_ref) = env::var(ENV_BRIDGE_TOKEN_REF) {
        let trimmed_ref = raw_ref.trim();
        if trimmed_ref.is_empty() {
            return Err(anyhow!("{} is set but empty", ENV_BRIDGE_TOKEN_REF));
        }
        let (token, kind) = resolve_secret_reference(
            trimmed_ref,
            ENV_BRIDGE_TOKEN_REF,
            true, /* vault strict */
        )?;
        return Ok(Some((token, kind)));
    }
    let legacy = env::var(ENV_BRIDGE_TOKEN)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    Ok(legacy.map(|v| (v, SecretRefKind::Literal)))
}

fn resolve_secret_reference(
    raw: &str,
    label: &str,
    vault_owner_only: bool,
) -> Result<(String, SecretRefKind)> {
    let trimmed = raw.trim();
    if let Some(var_name) = trimmed.strip_prefix("env:") {
        let key = var_name.trim();
        if key.is_empty() {
            return Err(anyhow!("{label} env: prefix without variable name"));
        }
        let value =
            env::var(key).map_err(|_| anyhow!("{label} env variable '{}' is missing", key))?;
        let out = value.trim().to_string();
        if out.is_empty() {
            return Err(anyhow!("{label} env variable '{}' is empty", key));
        }
        return Ok((out, SecretRefKind::Env));
    }
    if let Some(path_raw) = trimmed.strip_prefix("vault:") {
        let path = path_raw.trim();
        if path.is_empty() {
            return Err(anyhow!("{label} vault: prefix without path"));
        }
        let value = read_secret_file(path, label, vault_owner_only)?;
        return Ok((value, SecretRefKind::Vault));
    }
    if let Some(path_raw) = trimmed.strip_prefix("file:") {
        let path = path_raw.trim();
        if path.is_empty() {
            return Err(anyhow!("{label} file: prefix without path"));
        }
        let value = read_secret_file(path, label, false)?;
        return Ok((value, SecretRefKind::File));
    }
    Ok((trimmed.to_string(), SecretRefKind::Literal))
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

fn redact_args_for_log(args: &[String]) -> String {
    let mut out: Vec<String> = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            out.push("<redacted>".to_string());
            redact_next = false;
            continue;
        }
        if arg == "--bridge-token" {
            out.push(arg.clone());
            redact_next = true;
            continue;
        }
        out.push(arg.clone());
    }
    out.join(" ")
}

fn normalize_non_empty(value: &str, label: &str) -> Result<String> {
    let out = value.trim().to_string();
    if out.is_empty() {
        return Err(anyhow!("{label} must not be empty"));
    }
    Ok(out)
}

fn normalize_hex_exact(value: &str, expected_len: usize, label: &str) -> Result<String> {
    let out = value.trim().to_ascii_lowercase();
    if out.len() != expected_len || !out.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("{label} must be {expected_len} hex chars"));
    }
    Ok(out)
}

fn env_true(name: &str) -> bool {
    let value = env::var(name).unwrap_or_default();
    let trimmed = value.trim();
    trimmed.eq_ignore_ascii_case("true") || trimmed == "1"
}

fn resolve_submit_verify_mode(
    production_hardening: bool,
    verify_env_enabled: bool,
) -> Result<bool> {
    if verify_env_enabled {
        return Ok(true);
    }
    if production_hardening {
        return Err(anyhow!(
            "production_hardening=true requires {}=true",
            ENV_VERIFY
        ));
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn resolve_submit_verify_mode_allows_shadow_when_not_hardened() {
        let mode = resolve_submit_verify_mode(false, false).expect("shadow mode allowed");
        assert!(!mode);
    }

    #[test]
    fn resolve_submit_verify_mode_allows_explicit_enable() {
        let mode = resolve_submit_verify_mode(false, true).expect("enabled");
        assert!(mode);
        let mode = resolve_submit_verify_mode(true, true).expect("enabled in hardening");
        assert!(mode);
    }

    #[test]
    fn resolve_submit_verify_mode_rejects_hardening_without_verify_flag() {
        let err = resolve_submit_verify_mode(true, false).expect_err("must reject");
        assert!(err.to_string().contains(ENV_VERIFY));
    }

    #[test]
    fn redact_args_hides_bridge_token() {
        let args = vec![
            "quorum-proof".to_string(),
            "set".to_string(),
            "--bridge-token".to_string(),
            "secret-value".to_string(),
            "--escrow-id-hex".to_string(),
            "00112233445566778899aabbccddeeff".to_string(),
        ];
        let redacted = redact_args_for_log(&args);
        assert!(redacted.contains("--bridge-token <redacted>"));
        assert!(!redacted.contains("secret-value"));
    }

    #[test]
    fn require_orchestrator_config_path_rejects_missing_env() {
        let _guard = env_lock().lock().expect("env lock");
        // SAFETY: tests serialize environment mutation with env_lock.
        unsafe {
            std::env::remove_var(ENV_ORCH_CONFIG_PATH);
        }
        let err = require_orchestrator_config_path().expect_err("missing config path must fail");
        assert!(err.to_string().contains(ENV_ORCH_CONFIG_PATH));
    }

    #[test]
    fn require_orchestrator_config_path_accepts_non_empty_env() {
        let _guard = env_lock().lock().expect("env lock");
        // SAFETY: tests serialize environment mutation with env_lock.
        unsafe {
            std::env::set_var(ENV_ORCH_CONFIG_PATH, "/etc/nxms/orchestrator.toml");
        }
        let path = require_orchestrator_config_path().expect("config path");
        assert_eq!(path, "/etc/nxms/orchestrator.toml");
        // SAFETY: tests serialize environment mutation with env_lock.
        unsafe {
            std::env::remove_var(ENV_ORCH_CONFIG_PATH);
        }
    }

    #[test]
    fn enforce_production_requires_bridge_token() {
        let _guard = env_lock().lock().expect("env lock");
        // SAFETY: tests serialize environment mutation with env_lock.
        unsafe {
            std::env::set_var(ENV_VERIFY, "true");
            std::env::set_var(ENV_ORCH_CONFIG_PATH, "/etc/nxms/orchestrator.toml");
            std::env::remove_var(ENV_BRIDGE_TOKEN);
            std::env::remove_var(ENV_BRIDGE_TOKEN_REF);
        }
        let err = enforce_production_requirements(true).expect_err("must require bridge token");
        assert!(err.to_string().contains(ENV_BRIDGE_TOKEN_REF));
        // SAFETY: tests serialize environment mutation with env_lock.
        unsafe {
            std::env::remove_var(ENV_ORCH_CONFIG_PATH);
            std::env::remove_var(ENV_VERIFY);
        }
    }

    #[test]
    fn enforce_production_allows_no_bridge_when_disabled() {
        let _guard = env_lock().lock().expect("env lock");
        // SAFETY: tests serialize environment mutation with env_lock.
        unsafe {
            std::env::remove_var(ENV_ORCH_CONFIG_PATH);
            std::env::remove_var(ENV_VERIFY);
            std::env::remove_var(ENV_STORE);
            std::env::remove_var(ENV_STORE_REQUIRED);
            std::env::remove_var(ENV_BRIDGE_TOKEN);
            std::env::remove_var(ENV_BRIDGE_TOKEN_REF);
        }
        enforce_production_requirements(false).expect("bridge disabled");
    }

    #[test]
    #[cfg(unix)]
    fn enforce_production_accepts_vault_bridge_token_ref() {
        let _guard = env_lock().lock().expect("env lock");
        let path = std::env::temp_dir().join(format!(
            "nxms_bridge_token_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&path, "0123456789abcdef0123456789abcdef0123456789abcdef\n")
            .expect("write token");
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms).expect("chmod");
        // SAFETY: tests serialize environment mutation with env_lock.
        unsafe {
            std::env::set_var(ENV_VERIFY, "true");
            std::env::set_var(ENV_ORCH_CONFIG_PATH, "/etc/nxms/orchestrator.toml");
            std::env::set_var(ENV_BRIDGE_TOKEN_REF, format!("vault:{}", path.display()));
            std::env::remove_var(ENV_BRIDGE_TOKEN);
        }
        enforce_production_requirements(true).expect("bridge token accepted");
        // SAFETY: tests serialize environment mutation with env_lock.
        unsafe {
            std::env::remove_var(ENV_ORCH_CONFIG_PATH);
            std::env::remove_var(ENV_BRIDGE_TOKEN);
            std::env::remove_var(ENV_BRIDGE_TOKEN_REF);
            std::env::remove_var(ENV_VERIFY);
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn enforce_production_rejects_legacy_bridge_token_env() {
        let _guard = env_lock().lock().expect("env lock");
        // SAFETY: tests serialize environment mutation with env_lock.
        unsafe {
            std::env::set_var(ENV_VERIFY, "true");
            std::env::set_var(ENV_ORCH_CONFIG_PATH, "/etc/nxms/orchestrator.toml");
            std::env::set_var(
                ENV_BRIDGE_TOKEN,
                "0123456789abcdef0123456789abcdef0123456789abcdef",
            );
            std::env::remove_var(ENV_BRIDGE_TOKEN_REF);
        }
        let err =
            enforce_production_requirements(true).expect_err("legacy env token must be rejected");
        assert!(err.to_string().contains(ENV_BRIDGE_TOKEN_REF));
        // SAFETY: tests serialize environment mutation with env_lock.
        unsafe {
            std::env::remove_var(ENV_ORCH_CONFIG_PATH);
            std::env::remove_var(ENV_BRIDGE_TOKEN);
            std::env::remove_var(ENV_BRIDGE_TOKEN_REF);
            std::env::remove_var(ENV_VERIFY);
        }
    }
}
