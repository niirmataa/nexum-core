use std::fs::OpenOptions;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use clap::{Subcommand, ValueEnum};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use nxms_transport::trust::RuntimeTrustBundle;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::db::{OrchestratorDb, SubmitMultisigProofBundle};
use crate::flow::WorkflowState;

const ENV_ACTION_TOKEN_ISSUER: &str = "NXMS_ORCH_ACTION_TOKEN_ISSUER";
const ENV_ACTION_TOKEN_ALGORITHM: &str = "NXMS_ORCH_ACTION_TOKEN_ALGORITHM";
const ENV_ACTION_TOKEN_PRIVATE_KEY_PEM_PATH: &str = "NXMS_ORCH_ACTION_TOKEN_PRIVATE_KEY_PEM_PATH";
const ENV_ACTION_TOKEN_TTL_SECS: &str = "NXMS_ORCH_ACTION_TOKEN_TTL_SECS";

#[derive(Subcommand, Debug)]
pub enum ActionTokenCommand {
    Issue {
        #[arg(
            long,
            env = "NXMS_ORCH_DB_PATH",
            default_value = "nxms_orchestrator.db"
        )]
        db_path: PathBuf,
        #[arg(long)]
        escrow_id_hex: String,
        #[arg(long)]
        txset_hash_hex: String,
        #[arg(long)]
        role: ActionTokenRole,
        #[arg(long)]
        op: ActionTokenOp,
        #[arg(long)]
        bridge_token: Option<String>,
        #[arg(long)]
        runtime_trust_bundle_path: Option<PathBuf>,
        #[arg(long, env = ENV_ACTION_TOKEN_ISSUER)]
        issuer: Option<String>,
        #[arg(long, env = ENV_ACTION_TOKEN_ALGORITHM, default_value = "EDDSA")]
        algorithm: String,
        #[arg(long, env = ENV_ACTION_TOKEN_PRIVATE_KEY_PEM_PATH)]
        private_key_pem_path: Option<PathBuf>,
        #[arg(long, env = ENV_ACTION_TOKEN_TTL_SECS, default_value_t = 60)]
        ttl_secs: u64,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        wallet_id: Option<String>,
        #[arg(long)]
        sandbox_id: Option<String>,
        #[arg(long)]
        audience: Option<String>,
        #[arg(long)]
        nettype: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum ActionTokenRole {
    Arbiter,
    Seller,
    Buyer,
}

impl ActionTokenRole {
    fn claim_value(self) -> &'static str {
        match self {
            Self::Arbiter => "arbiter",
            Self::Seller => "seller",
            Self::Buyer => "buyer",
        }
    }

    fn env_prefix(self) -> &'static str {
        match self {
            Self::Arbiter => "ARBITER",
            Self::Seller => "SELLER",
            Self::Buyer => "BUYER",
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum ActionTokenOp {
    SignMultisig,
    SubmitMultisig,
}

impl ActionTokenOp {
    fn claim_value(self) -> &'static str {
        match self {
            Self::SignMultisig => "sign_multisig",
            Self::SubmitMultisig => "submit_multisig",
        }
    }

    fn expected_sign_round(self, role: ActionTokenRole) -> &'static str {
        match (self, role) {
            (Self::SignMultisig, ActionTokenRole::Arbiter) => "arbiter_first",
            (Self::SignMultisig, ActionTokenRole::Seller) => "seller_second",
            (Self::SignMultisig, ActionTokenRole::Buyer) => "buyer_second",
            (Self::SubmitMultisig, ActionTokenRole::Arbiter) => "arbiter_submit",
            (Self::SubmitMultisig, ActionTokenRole::Seller) => "seller_submit",
            (Self::SubmitMultisig, ActionTokenRole::Buyer) => "buyer_submit",
        }
    }
}

#[derive(Clone)]
pub struct IssueActionTokenParams {
    escrow_id_hex: String,
    txset_hash_hex: String,
    role: ActionTokenRole,
    op: ActionTokenOp,
    issuer: String,
    algorithm: Algorithm,
    encoding_key: EncodingKey,
    ttl_secs: u64,
    subject: String,
    wallet_id: String,
    sandbox_id: String,
    audience: String,
    nettype: String,
    runtime_trust_epoch: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionTokenClaims {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_trust_epoch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escrow_admission_hash: Option<String>,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_arbiter_jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_seller_jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_arbiter_req_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_seller_req_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IssuedActionTokenOutput {
    pub token: String,
    pub claims: ActionTokenClaims,
}

pub async fn handle_action_token(cmd: ActionTokenCommand) -> Result<()> {
    match cmd {
        ActionTokenCommand::Issue {
            db_path,
            escrow_id_hex,
            txset_hash_hex,
            role,
            op,
            bridge_token,
            runtime_trust_bundle_path,
            issuer,
            algorithm,
            private_key_pem_path,
            ttl_secs,
            subject,
            wallet_id,
            sandbox_id,
            audience,
            nettype,
        } => {
            crate::require_bridge_token(bridge_token.as_deref())?;
            let params = build_issue_params(ActionTokenCliInput {
                escrow_id_hex,
                txset_hash_hex,
                role,
                op,
                runtime_trust_bundle_path,
                issuer,
                algorithm,
                private_key_pem_path,
                ttl_secs,
                subject,
                wallet_id,
                sandbox_id,
                audience,
                nettype,
            })?;
            let db = OrchestratorDb::new(db_path);
            db.init().await?;
            let out = issue_action_token(&db, &params).await?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ActionTokenCliInput {
    pub escrow_id_hex: String,
    pub txset_hash_hex: String,
    pub role: ActionTokenRole,
    pub op: ActionTokenOp,
    pub runtime_trust_bundle_path: Option<PathBuf>,
    pub issuer: Option<String>,
    pub algorithm: String,
    pub private_key_pem_path: Option<PathBuf>,
    pub ttl_secs: u64,
    pub subject: Option<String>,
    pub wallet_id: Option<String>,
    pub sandbox_id: Option<String>,
    pub audience: Option<String>,
    pub nettype: Option<String>,
}

pub fn build_issue_params(input: ActionTokenCliInput) -> Result<IssueActionTokenParams> {
    let runtime_trust_bundle = input
        .runtime_trust_bundle_path
        .as_ref()
        .map(RuntimeTrustBundle::load)
        .transpose()?;
    let escrow_id_hex = normalize_hex_exact(&input.escrow_id_hex, 32, "escrow_id_hex")?;
    let txset_hash_hex = normalize_hex_exact(&input.txset_hash_hex, 64, "txset_hash_hex")?;
    let issuer = normalize_non_empty(
        resolve_required_with_env(input.issuer, ENV_ACTION_TOKEN_ISSUER, "issuer")?,
        "issuer",
        256,
    )?;
    let algorithm = parse_algorithm(&input.algorithm)?;
    if let Some(bundle) = &runtime_trust_bundle {
        if issuer != bundle.action_token.issuer {
            bail!(
                "issuer '{}' does not match runtime trust bundle issuer '{}'",
                issuer,
                bundle.action_token.issuer
            );
        }
        if algorithm_name(algorithm) != bundle.action_token.algorithm.trim().to_ascii_uppercase() {
            bail!(
                "algorithm '{}' does not match runtime trust bundle algorithm '{}'",
                algorithm_name(algorithm),
                bundle.action_token.algorithm
            );
        }
    }
    let private_key_pem_path = input.private_key_pem_path.or_else(|| {
        std::env::var(ENV_ACTION_TOKEN_PRIVATE_KEY_PEM_PATH)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    });
    let private_key_pem_path = private_key_pem_path.ok_or_else(|| {
        anyhow!(
            "missing private_key_pem_path (or {})",
            ENV_ACTION_TOKEN_PRIVATE_KEY_PEM_PATH
        )
    })?;
    let pem = read_private_key_pem_checked(&private_key_pem_path)?;
    let encoding_key = match algorithm {
        Algorithm::EdDSA => EncodingKey::from_ed_pem(&pem)?,
        Algorithm::ES256 => EncodingKey::from_ec_pem(&pem)?,
        _ => bail!("unsupported JWT algorithm for action token issuer"),
    };
    if input.ttl_secs == 0 {
        bail!("ttl_secs must be > 0");
    }
    if input.ttl_secs > 120 {
        bail!("ttl_secs exceeds hard limit (120s)");
    }
    let ttl_secs = input.ttl_secs;

    let role = input.role;
    let subject = normalize_non_empty(
        resolve_role_required(input.subject, role, "SUBJECT", "subject")?,
        "subject",
        256,
    )?;
    let wallet_id = normalize_non_empty(
        resolve_role_required(input.wallet_id, role, "WALLET_ID", "wallet_id")?,
        "wallet_id",
        256,
    )?;
    let sandbox_id = normalize_non_empty(
        resolve_role_required(input.sandbox_id, role, "SANDBOX_ID", "sandbox_id")?,
        "sandbox_id",
        256,
    )?;
    let audience = normalize_non_empty(
        resolve_role_optional(input.audience, role, "AUDIENCE")
            .unwrap_or_else(|| format!("sandbox:{}", sandbox_id)),
        "audience",
        256,
    )?;
    let nettype = normalize_non_empty(
        resolve_role_required(input.nettype, role, "NETTYPE", "nettype")?,
        "nettype",
        32,
    )?;

    Ok(IssueActionTokenParams {
        escrow_id_hex,
        txset_hash_hex,
        role,
        op: input.op,
        issuer,
        algorithm,
        encoding_key,
        ttl_secs,
        subject,
        wallet_id,
        sandbox_id,
        audience,
        nettype,
        runtime_trust_epoch: runtime_trust_bundle.map(|bundle| bundle.trust_epoch),
    })
}

pub async fn issue_action_token(
    db: &OrchestratorDb,
    params: &IssueActionTokenParams,
) -> Result<IssuedActionTokenOutput> {
    let workflow = db
        .get_workflow(&params.escrow_id_hex)
        .await?
        .ok_or_else(|| {
            anyhow!(
                "workflow not found for escrow_id_hex={}",
                params.escrow_id_hex
            )
        })?;
    if !workflow_state_allows_action_token(workflow.state) {
        bail!(
            "workflow state {:?} does not allow action token issuance",
            workflow.state
        );
    }

    let proposal = db
        .get_proposal_blob_by_txset_hash(&params.escrow_id_hex, &params.txset_hash_hex)
        .await?
        .ok_or_else(|| {
            anyhow!(
                "proposal blob not found for escrow_id_hex={} txset_hash_hex={}",
                params.escrow_id_hex,
                params.txset_hash_hex
            )
        })?;
    if proposal.txset_hash_hex != params.txset_hash_hex {
        bail!("proposal txset_hash mismatch");
    }

    let claims = build_claims(db, params, &workflow, &proposal).await?;
    let token = encode(
        &Header::new(params.algorithm),
        &claims,
        &params.encoding_key,
    )?;
    Ok(IssuedActionTokenOutput { token, claims })
}

async fn build_claims(
    db: &OrchestratorDb,
    params: &IssueActionTokenParams,
    workflow: &crate::db::WorkflowInstance,
    _proposal: &crate::db::ProposalBlob,
) -> Result<ActionTokenClaims> {
    let now = now_s()?;
    let ttl_secs = params.ttl_secs;
    let mut claims = ActionTokenClaims {
        iss: params.issuer.clone(),
        aud: params.audience.clone(),
        sub: params.subject.clone(),
        scope: params.op.claim_value().to_string(),
        op: params.op.claim_value().to_string(),
        role: params.role.claim_value().to_string(),
        sign_round: params.op.expected_sign_round(params.role).to_string(),
        escrow_id: params.escrow_id_hex.clone(),
        wallet_id: params.wallet_id.clone(),
        sandbox_id: params.sandbox_id.clone(),
        txset_hash: params.txset_hash_hex.clone(),
        snapshot_hash: normalize_hex_exact(&workflow.snapshot_hash_hex, 64, "snapshot_hash_hex")?,
        nettype: params.nettype.clone(),
        runtime_trust_epoch: params.runtime_trust_epoch.clone(),
        escrow_admission_hash: None,
        iat: now,
        nbf: now,
        exp: now.saturating_add(ttl_secs),
        jti: new_jti(params.role, params.op),
        proof_arbiter_jti: None,
        proof_seller_jti: None,
        proof_arbiter_req_id: None,
        proof_seller_req_id: None,
    };

    let admission = db.get_escrow_admission_artifact(&params.escrow_id_hex).await?;
    if let Some(admission) = admission {
        if admission.snapshot_hash_hex != claims.snapshot_hash {
            bail!("escrow admission snapshot_hash mismatch against workflow");
        }
        if let Some(expected_epoch) = &params.runtime_trust_epoch
            && admission.runtime_trust_epoch != *expected_epoch
        {
            bail!("escrow admission runtime_trust_epoch mismatch");
        }
        if admission.action != workflow_action_key(&_proposal.action)? {
            bail!("escrow admission action mismatch against proposal");
        }
        claims.escrow_admission_hash = Some(normalize_hex_exact(
            &admission.artifact_hash_hex,
            64,
            "escrow_admission_hash",
        )?);
    } else if params.runtime_trust_epoch.is_some() {
        bail!("missing escrow admission artifact for runtime-trusted action token issuance");
    }

    if matches!(params.op, ActionTokenOp::SubmitMultisig) {
        let bundle = db
            .get_submit_multisig_proof_bundle(&params.escrow_id_hex, &params.txset_hash_hex)
            .await?;
        apply_submit_proof_bundle(&mut claims, &bundle)?;
    }

    Ok(claims)
}

fn workflow_action_key(action: &str) -> Result<String> {
    normalize_non_empty(action.to_string(), "proposal.action", 32)
        .map(|value| value.to_ascii_lowercase())
}

fn apply_submit_proof_bundle(
    claims: &mut ActionTokenClaims,
    bundle: &SubmitMultisigProofBundle,
) -> Result<()> {
    if claims.escrow_id != bundle.escrow_id_hex {
        bail!("submit proof bundle escrow_id mismatch");
    }
    if claims.txset_hash != bundle.txset_hash_hex {
        bail!("submit proof bundle txset_hash mismatch");
    }
    claims.proof_arbiter_jti = Some(normalize_non_empty(
        bundle.proof_arbiter_jti.clone(),
        "proof_arbiter_jti",
        256,
    )?);
    claims.proof_seller_jti = Some(normalize_non_empty(
        bundle.proof_seller_jti.clone(),
        "proof_seller_jti",
        256,
    )?);
    claims.proof_arbiter_req_id = Some(normalize_hex_exact(
        &bundle.proof_arbiter_req_id,
        64,
        "proof_arbiter_req_id",
    )?);
    claims.proof_seller_req_id = Some(normalize_hex_exact(
        &bundle.proof_seller_req_id,
        64,
        "proof_seller_req_id",
    )?);
    Ok(())
}

fn workflow_state_allows_action_token(state: WorkflowState) -> bool {
    matches!(
        state,
        WorkflowState::Funded
            | WorkflowState::TxSignPending
            | WorkflowState::TxSignedQuorum
            | WorkflowState::Submitted
    )
}

fn parse_algorithm(raw: &str) -> Result<Algorithm> {
    let value = raw.trim().to_ascii_uppercase();
    match value.as_str() {
        "EDDSA" => Ok(Algorithm::EdDSA),
        "ES256" => Ok(Algorithm::ES256),
        _ => bail!("unsupported action token algorithm '{}'", raw.trim()),
    }
}

fn algorithm_name(algorithm: Algorithm) -> String {
    match algorithm {
        Algorithm::EdDSA => "EDDSA".to_string(),
        Algorithm::ES256 => "ES256".to_string(),
        _ => "UNSUPPORTED".to_string(),
    }
}

fn resolve_required_with_env(
    cli_value: Option<String>,
    env_name: &str,
    label: &str,
) -> Result<String> {
    if let Some(v) = cli_value {
        return Ok(v);
    }
    std::env::var(env_name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("missing {} (or {})", label, env_name))
}

fn resolve_role_required(
    cli_value: Option<String>,
    role: ActionTokenRole,
    suffix: &str,
    label: &str,
) -> Result<String> {
    if let Some(v) = cli_value {
        return Ok(v);
    }
    let env_name = format!("NXMS_ORCH_ACTION_TOKEN_{}_{}", role.env_prefix(), suffix);
    std::env::var(&env_name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "missing {} for role {} (or {})",
                label,
                role.claim_value(),
                env_name
            )
        })
}

fn resolve_role_optional(
    cli_value: Option<String>,
    role: ActionTokenRole,
    suffix: &str,
) -> Option<String> {
    cli_value.or_else(|| {
        let env_name = format!("NXMS_ORCH_ACTION_TOKEN_{}_{}", role.env_prefix(), suffix);
        std::env::var(env_name)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

fn normalize_non_empty(value: String, label: &str, max_len: usize) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{label} must not be empty");
    }
    if trimmed.len() > max_len {
        bail!("{label} too long (max {} chars)", max_len);
    }
    Ok(trimmed.to_string())
}

fn normalize_hex_exact(value: &str, expected_len: usize, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.len() != expected_len || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{label} must be {} hex chars", expected_len);
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn new_jti(role: ActionTokenRole, op: ActionTokenOp) -> String {
    let mut random = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut random);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!(
        "orch-{}-{}-{}-{}",
        now,
        role.claim_value(),
        op.claim_value(),
        hex::encode(random)
    )
}

fn now_s() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system clock is before UNIX_EPOCH"))?
        .as_secs())
}

fn validate_private_key_pem_metadata(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if !metadata.is_file() {
        bail!(
            "action token private key path is not a regular file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "action token private key has unsafe permissions (mode {:03o}); require owner-only permissions (e.g. 600)",
                mode
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_private_key_pem_checked(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            anyhow!(
                "failed to open action token private key {}: {}",
                path.display(),
                e
            )
        })?;
    let metadata = file.metadata().map_err(|e| {
        anyhow!(
            "failed to stat opened action token private key {}: {}",
            path.display(),
            e
        )
    })?;
    validate_private_key_pem_metadata(path, &metadata)?;
    let mut pem = Vec::new();
    file.read_to_end(&mut pem).map_err(|e| {
        anyhow!(
            "failed to read action token private key {}: {}",
            path.display(),
            e
        )
    })?;
    Ok(pem)
}

#[cfg(not(unix))]
fn read_private_key_pem_checked(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new().read(true).open(path).map_err(|e| {
        anyhow!(
            "failed to open action token private key {}: {}",
            path.display(),
            e
        )
    })?;
    let metadata = file.metadata().map_err(|e| {
        anyhow!(
            "failed to stat opened action token private key {}: {}",
            path.display(),
            e
        )
    })?;
    validate_private_key_pem_metadata(path, &metadata)?;
    let mut pem = Vec::new();
    file.read_to_end(&mut pem).map_err(|e| {
        anyhow!(
            "failed to read action token private key {}: {}",
            path.display(),
            e
        )
    })?;
    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::OrchestratorDb;
    use crate::flow::WorkflowState;
    use jsonwebtoken::{DecodingKey, Validation, decode};
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{SystemTime, UNIX_EPOCH};

    const ED25519_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJCBxRIEv7DU1o/rRG+beqeRLVa2kL9RAArTq6vRp7D0\n-----END PRIVATE KEY-----\n";
    const ED25519_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAD7TxzeCSPJhJljqWs/fABRUaUBlTkJP8O1v31Z64F/I=\n-----END PUBLIC KEY-----\n";

    fn unique_path(prefix: &str, suffix: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nxms_orch_action_token_{}_{}_{}.{}",
            prefix,
            std::process::id(),
            ts,
            suffix
        ))
    }

    fn test_issue_params(
        private_key_pem_path: PathBuf,
        role: ActionTokenRole,
        op: ActionTokenOp,
        escrow_id_hex: &str,
        txset_hash_hex: &str,
    ) -> Result<IssueActionTokenParams> {
        let pem = read_private_key_pem_checked(&private_key_pem_path)?;
        Ok(IssueActionTokenParams {
            escrow_id_hex: escrow_id_hex.to_string(),
            txset_hash_hex: txset_hash_hex.to_string(),
            role,
            op,
            issuer: "nxms-auth".to_string(),
            algorithm: Algorithm::EdDSA,
            encoding_key: EncodingKey::from_ed_pem(&pem)?,
            ttl_secs: 60,
            subject: format!("{}-operator", role.claim_value()),
            wallet_id: match role {
                ActionTokenRole::Arbiter => "wallet-arbiter",
                ActionTokenRole::Seller => "wallet-seller",
                ActionTokenRole::Buyer => "wallet-buyer",
            }
            .to_string(),
            sandbox_id: "sbx-1".to_string(),
            audience: "sandbox:sbx-1".to_string(),
            nettype: "stagenet".to_string(),
            runtime_trust_epoch: None,
        })
    }

    async fn setup_db_with_workflow_and_proposal(
        escrow_id_hex: &str,
        txset_hash_hex: &str,
    ) -> (OrchestratorDb, PathBuf) {
        let db_path = unique_path("db", "sqlite");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init db");
        db.create_workflow(
            escrow_id_hex,
            &"11".repeat(32),
            &[
                "buyer".to_string(),
                "seller".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await
        .expect("create workflow");
        for state in [
            WorkflowState::PrepareCollected,
            WorkflowState::MakeCollected,
            WorkflowState::ExchangeR1Collected,
            WorkflowState::ExchangeR2Collected,
            WorkflowState::FinalizedReady,
            WorkflowState::Funded,
        ] {
            db.transition_workflow(escrow_id_hex, state, Some("test"))
                .await
                .expect("transition workflow state");
        }
        db.upsert_proposal_blob(escrow_id_hex, "release", "aa11", txset_hash_hex)
            .await
            .expect("proposal store");
        (db, db_path)
    }

    fn decode_claims(token: &str) -> ActionTokenClaims {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&["nxms-auth"]);
        validation.set_audience(&["sandbox:sbx-1"]);
        let decoded = decode::<ActionTokenClaims>(
            token,
            &DecodingKey::from_ed_pem(ED25519_PUBLIC_PEM.as_bytes()).expect("decoding key"),
            &validation,
        )
        .expect("decode token");
        decoded.claims
    }

    #[tokio::test]
    async fn issue_sign_multisig_token_from_db_state() {
        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        let txset_hash_hex = &"aa".repeat(32);
        let (db, db_path) =
            setup_db_with_workflow_and_proposal(escrow_id_hex, txset_hash_hex).await;

        let key_path = unique_path("issuer", "pem");
        std::fs::write(&key_path, ED25519_PRIVATE_PEM).expect("write private key");
        #[cfg(unix)]
        {
            let mut perms = std::fs::metadata(&key_path).expect("meta").permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&key_path, perms).expect("chmod 600");
        }

        let params = test_issue_params(
            key_path.clone(),
            ActionTokenRole::Seller,
            ActionTokenOp::SignMultisig,
            escrow_id_hex,
            txset_hash_hex,
        )
        .expect("params");
        let out = issue_action_token(&db, &params).await.expect("issue token");
        let claims = decode_claims(&out.token);

        assert_eq!(claims.op, "sign_multisig");
        assert_eq!(claims.scope, "sign_multisig");
        assert_eq!(claims.role, "seller");
        assert_eq!(claims.sign_round, "seller_second");
        assert_eq!(claims.escrow_id, escrow_id_hex);
        assert_eq!(claims.txset_hash, *txset_hash_hex);
        assert_eq!(claims.snapshot_hash, "11".repeat(32));
        assert!(claims.proof_arbiter_jti.is_none());
        assert!(claims.proof_seller_jti.is_none());
        assert_ne!(claims.jti.trim(), "");

        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn issue_submit_multisig_token_includes_quorum_proofs() {
        let escrow_id_hex = "00112233445566778899aabbccddeeff";
        let txset_hash_hex = &"bb".repeat(32);
        let (db, db_path) =
            setup_db_with_workflow_and_proposal(escrow_id_hex, txset_hash_hex).await;

        db.upsert_quorum_sign_proof(
            escrow_id_hex,
            "arbiter",
            "arbiter_first",
            txset_hash_hex,
            "arbiter-jti-1",
            &"11".repeat(32),
        )
        .await
        .expect("arbiter proof");
        db.upsert_quorum_sign_proof(
            escrow_id_hex,
            "seller",
            "seller_second",
            txset_hash_hex,
            "seller-jti-1",
            &"22".repeat(32),
        )
        .await
        .expect("seller proof");

        let key_path = unique_path("issuer_submit", "pem");
        std::fs::write(&key_path, ED25519_PRIVATE_PEM).expect("write private key");
        #[cfg(unix)]
        {
            let mut perms = std::fs::metadata(&key_path).expect("meta").permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&key_path, perms).expect("chmod 600");
        }

        let params = test_issue_params(
            key_path.clone(),
            ActionTokenRole::Arbiter,
            ActionTokenOp::SubmitMultisig,
            escrow_id_hex,
            txset_hash_hex,
        )
        .expect("params");
        let out = issue_action_token(&db, &params).await.expect("issue token");
        let claims = decode_claims(&out.token);

        assert_eq!(claims.op, "submit_multisig");
        assert_eq!(claims.role, "arbiter");
        assert_eq!(claims.sign_round, "arbiter_submit");
        assert_eq!(claims.proof_arbiter_jti.as_deref(), Some("arbiter-jti-1"));
        assert_eq!(claims.proof_seller_jti.as_deref(), Some("seller-jti-1"));
        let expected_arbiter_req = "11".repeat(32);
        let expected_seller_req = "22".repeat(32);
        assert_eq!(
            claims.proof_arbiter_req_id.as_deref(),
            Some(expected_arbiter_req.as_str())
        );
        assert_eq!(
            claims.proof_seller_req_id.as_deref(),
            Some(expected_seller_req.as_str())
        );

        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(db_path);
    }

    #[cfg(unix)]
    #[test]
    fn read_private_key_rejects_symlink_path() {
        let real_path = unique_path("real_key", "pem");
        let link_path = unique_path("link_key", "pem");
        std::fs::write(&real_path, ED25519_PRIVATE_PEM).expect("write key");
        let mut perms = std::fs::metadata(&real_path).expect("meta").permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&real_path, perms).expect("chmod");
        symlink(&real_path, &link_path).expect("symlink");

        let err = read_private_key_pem_checked(&link_path).expect_err("symlink must fail");
        assert!(err.to_string().contains("failed to open") || err.to_string().contains("unsafe"));

        let _ = std::fs::remove_file(link_path);
        let _ = std::fs::remove_file(real_path);
    }

    #[test]
    fn build_issue_params_rejects_ttl_over_hard_limit() {
        let key_path = unique_path("ttl_limit", "pem");
        std::fs::write(&key_path, ED25519_PRIVATE_PEM).expect("write private key");
        #[cfg(unix)]
        {
            let mut perms = std::fs::metadata(&key_path).expect("meta").permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&key_path, perms).expect("chmod 600");
        }
        let err = match build_issue_params(ActionTokenCliInput {
            escrow_id_hex: "00112233445566778899aabbccddeeff".to_string(),
            txset_hash_hex: "aa".repeat(32),
            role: ActionTokenRole::Seller,
            op: ActionTokenOp::SignMultisig,
            runtime_trust_bundle_path: None,
            issuer: Some("nxms-auth".to_string()),
            algorithm: "EDDSA".to_string(),
            private_key_pem_path: Some(key_path.clone()),
            ttl_secs: 121,
            subject: Some("seller-op".to_string()),
            wallet_id: Some("wallet-seller".to_string()),
            sandbox_id: Some("sbx-1".to_string()),
            audience: Some("sandbox:sbx-1".to_string()),
            nettype: Some("stagenet".to_string()),
        }) {
            Ok(_) => panic!("ttl > 120 must fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("ttl_secs exceeds hard limit"));
        let _ = std::fs::remove_file(key_path);
    }
}
