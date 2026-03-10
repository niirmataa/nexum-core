use crate::action_token::{ActionTokenVerifier, sign_req_id};
use crate::agent_support::*;
use crate::audit_event::{
    CHALLENGE_ISSUED, CHALLENGE_VERIFIED, TOKEN_ISSUED, normalize_auth_event_kind,
};
use crate::config::SignerConfig;
use crate::db::{
    AuditLogInsert, PendingTxSign, SecurityAlertReport, SecurityAlertThresholds, SecurityDashboard,
    SignerDb,
};
use crate::orchestrator_bridge::{
    enforce_production_requirements, verify_submit_quorum_proof_bundle,
};
use crate::snapshot::{
    ContractSnapshot, canonical_policy_hash_sha256_hex, validate_transfer_against_snapshot,
};
use crate::wallet_rpc::{SignedMultisigTx, WalletRpcClient};
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use nxms_mailbox_client::MailboxClient;
use nxms_transport::crypto::{Keys, SealedPacket, decrypt, encrypt, suite_kem_id, suite_sig_id};
use nxms_transport::peers::PeerBook;
use nxms_transport::wire::{
    ESCROW_APP_PROTO_V1, EscrowAction, EscrowBody, EscrowErrBody, MsgType, NxmsEnvelope,
    NxmsPayload, TxSignRespBody, msg_type_key,
};
use std::time::Duration;
use tracing::{debug, info, warn};

pub struct SignerAgent {
    cfg: SignerConfig,
    db: SignerDb,
    peers: PeerBook,
    keys: Keys,
    mailbox: MailboxClient,
    wallet: WalletRpcClient,
    action_token_verifier: Option<ActionTokenVerifier>,
}

#[derive(Clone, Debug, Default)]
pub struct AuthEventContext {
    pub op: Option<String>,
    pub txset_hash_hex: Option<String>,
    pub proof_arbiter_jti: Option<String>,
    pub proof_arbiter_req_id: Option<String>,
    pub proof_seller_jti: Option<String>,
    pub proof_seller_req_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ProposedMultisigTx {
    pub tx_data_hex: String,
    pub txset_hash_hex: String,
}

mod flow_ops;
mod pending;
mod transport;

#[cfg(test)]
mod tests;

impl SignerAgent {
    pub async fn from_config(cfg: SignerConfig) -> Result<Self> {
        enforce_production_requirements(cfg.production_hardening)?;
        let peers = PeerBook::load(cfg.peers_path.clone())?;
        let keys = Keys::read_json(&cfg.keys_path)?;
        let db = SignerDb::new(cfg.db_path.clone());
        db.init().await?;

        let mut builder = MailboxClient::builder(&cfg.mailbox_url)?;
        if let Some(token) = &cfg.mailbox_token {
            builder = builder.token(token.clone());
        }
        if let Some(admin_token) = &cfg.mailbox_admin_token {
            builder = builder.admin_token(admin_token.clone());
        }
        if let Some(socks5h) = &cfg.tor_socks5h {
            builder = builder.tor_socks(socks5h.clone());
        }
        let mailbox = builder.timeout(Duration::from_secs(90)).build()?;

        let wallet = WalletRpcClient::new(
            cfg.wallet_rpc.endpoint.clone(),
            cfg.wallet_rpc.wallet_name.clone(),
            cfg.wallet_rpc.wallet_password.clone(),
            cfg.wallet_rpc.username.clone(),
            cfg.wallet_rpc.password.clone(),
        )?;
        if cfg
            .wallet_provision
            .as_ref()
            .map(|v| v.enabled)
            .unwrap_or(false)
        {
            wallet.close_wallet_best_effort().await;
            provision_wallet_multisig_enable(&cfg).await?;
        }
        wallet.ensure_wallet_open().await?;
        let multisig_status = wallet.multisig_status().await?;
        enforce_wallet_multisig_ready(&cfg, multisig_status)?;
        info!(
            wallet_name = %cfg.wallet_rpc.wallet_name,
            multisig = multisig_status.multisig,
            ready = multisig_status.ready,
            threshold = multisig_status.threshold,
            total = multisig_status.total,
            "wallet multisig readiness check passed"
        );
        let action_token_verifier = ActionTokenVerifier::from_signer_config(&cfg)?;

        Ok(Self {
            cfg,
            db,
            peers,
            keys,
            mailbox,
            wallet,
            action_token_verifier,
        })
    }

    async fn mailbox_pull_with_retry(&self) -> Result<nxms_mailbox_client::PullResponse> {
        let attempts = self.cfg.mailbox_retry_attempts.max(1);
        let base_backoff_ms = self.cfg.mailbox_retry_backoff_ms.max(50);
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 1..=attempts {
            match self
                .mailbox
                .pull(
                    &self.cfg.local_id,
                    Some(self.cfg.pull_max),
                    Some(self.cfg.pull_wait_ms),
                )
                .await
            {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    if attempt == attempts {
                        return Err(err);
                    }
                    warn!(
                        "mailbox pull attempt {}/{} failed: {}; retrying",
                        attempt, attempts, err
                    );
                    last_err = Some(err);
                    tokio::time::sleep(Duration::from_millis(mailbox_retry_backoff_ms(
                        base_backoff_ms,
                        attempt,
                    )))
                    .await;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("mailbox pull failed without error details")))
    }

    async fn mailbox_ack_with_retry(&self, receipt: &str) -> Result<()> {
        let attempts = self.cfg.mailbox_retry_attempts.max(1);
        let base_backoff_ms = self.cfg.mailbox_retry_backoff_ms.max(50);
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 1..=attempts {
            match self.mailbox.ack(receipt).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    if attempt == attempts {
                        return Err(err);
                    }
                    warn!(
                        "mailbox ack attempt {}/{} failed for receipt {}: {}; retrying",
                        attempt, attempts, receipt, err
                    );
                    last_err = Some(err);
                    tokio::time::sleep(Duration::from_millis(mailbox_retry_backoff_ms(
                        base_backoff_ms,
                        attempt,
                    )))
                    .await;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("mailbox ack failed without error details")))
    }

    async fn mailbox_push_with_retry(
        &self,
        env: &NxmsEnvelope,
        ttl_secs: Option<u64>,
    ) -> Result<nxms_mailbox_client::PushResponse> {
        let attempts = self.cfg.mailbox_retry_attempts.max(1);
        let base_backoff_ms = self.cfg.mailbox_retry_backoff_ms.max(50);
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 1..=attempts {
            match self.mailbox.push(env, ttl_secs).await {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    if attempt == attempts {
                        return Err(err);
                    }
                    warn!(
                        "mailbox push attempt {}/{} failed for to={} escrow={} seq={}: {}; retrying",
                        attempt, attempts, env.to, env.escrow_id_hex, env.seq, err
                    );
                    last_err = Some(err);
                    tokio::time::sleep(Duration::from_millis(mailbox_retry_backoff_ms(
                        base_backoff_ms,
                        attempt,
                    )))
                    .await;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("mailbox push failed without error details")))
    }

    pub async fn run(&self) -> Result<()> {
        info!("nxms-signer started for local_id={}", self.cfg.local_id);
        loop {
            let pulled = self.mailbox_pull_with_retry().await;
            match pulled {
                Ok(resp) => {
                    for msg in resp.messages {
                        let receipt = msg.receipt.clone();
                        match self.process_envelope(msg.envelope).await {
                            Ok(()) => {
                                if let Err(err) = self.mailbox_ack_with_retry(&receipt).await {
                                    warn!("ack failed for receipt {}: {}", receipt, err);
                                }
                            }
                            Err(err) => {
                                warn!("failed to process message (receipt={}): {}", receipt, err);
                                if should_ack_non_retryable_process_error(&err) {
                                    if let Err(ack_err) =
                                        self.mailbox_ack_with_retry(&receipt).await
                                    {
                                        warn!(
                                            "ack failed for non-retryable error (receipt={}): {}",
                                            receipt, ack_err
                                        );
                                    } else {
                                        warn!(
                                            "acked non-retryable message after validation error (receipt={})",
                                            receipt
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!("mailbox pull failed: {}", err);
                    tokio::time::sleep(Duration::from_millis(self.cfg.poll_interval_ms)).await;
                }
            }

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("received ctrl-c; signer loop stopping");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        Ok(())
    }

    pub async fn record_auth_event(
        &self,
        escrow_id_hex: &str,
        event_kind: &str,
        actor_id: Option<&str>,
        detail: Option<&str>,
        context: Option<AuthEventContext>,
    ) -> Result<()> {
        append_auth_event(
            &self.cfg,
            &self.db,
            &self.cfg.local_id,
            escrow_id_hex,
            event_kind,
            actor_id,
            detail,
            context,
        )
        .await
    }

    pub async fn security_dashboard(&self) -> Result<SecurityDashboard> {
        self.db.audit_security_dashboard().await
    }

    pub async fn security_alert_report(
        &self,
        window_ms: u64,
        thresholds: SecurityAlertThresholds,
    ) -> Result<SecurityAlertReport> {
        self.db
            .audit_security_alert_report(window_ms, thresholds)
            .await
    }
}

fn normalize_auth_event_context(
    context: Option<AuthEventContext>,
) -> Result<Option<AuthEventContext>> {
    let Some(mut context) = context else {
        return Ok(None);
    };
    context.op = context
        .op
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_ascii_lowercase());
    if let Some(op) = context.op.as_deref()
        && op != "sign_multisig"
        && op != "submit_multisig"
    {
        return Err(anyhow!(
            "auth event context op must be one of: sign_multisig|submit_multisig"
        ));
    }
    context.txset_hash_hex = context
        .txset_hash_hex
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| normalize_hex_exact(v, 64, "context.txset_hash_hex"))
        .transpose()?;
    context.proof_arbiter_jti = normalize_context_jti(
        context.proof_arbiter_jti.as_deref(),
        "context.proof_arbiter_jti",
    )?;
    context.proof_seller_jti = normalize_context_jti(
        context.proof_seller_jti.as_deref(),
        "context.proof_seller_jti",
    )?;
    context.proof_arbiter_req_id = context
        .proof_arbiter_req_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| normalize_hex_exact(v, 64, "context.proof_arbiter_req_id"))
        .transpose()?;
    context.proof_seller_req_id = context
        .proof_seller_req_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| normalize_hex_exact(v, 64, "context.proof_seller_req_id"))
        .transpose()?;
    Ok(Some(context))
}

fn normalize_context_jti(value: Option<&str>, label: &str) -> Result<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if value.len() > 256 {
        return Err(anyhow!("{label} too long (max 256 chars)"));
    }
    Ok(Some(value.to_string()))
}

fn enforce_token_issued_context_requirements(
    escrow_id_hex: &str,
    context: Option<&AuthEventContext>,
    production_hardening: bool,
) -> Result<()> {
    if !production_hardening {
        return Ok(());
    }
    let context = context
        .ok_or_else(|| anyhow!("production_hardening requires token_issued auth event context"))?;
    let op = context
        .op
        .as_deref()
        .ok_or_else(|| anyhow!("production_hardening requires token_issued context op"))?;
    if op == "submit_multisig" {
        if context.txset_hash_hex.is_none()
            || context.proof_arbiter_jti.is_none()
            || context.proof_arbiter_req_id.is_none()
            || context.proof_seller_jti.is_none()
            || context.proof_seller_req_id.is_none()
        {
            return Err(anyhow!(
                "token_issued submit_multisig requires txset_hash_hex and all proof_* fields"
            ));
        }
        let expected_arbiter_req = sign_req_id(
            escrow_id_hex,
            "sign_multisig",
            "arbiter_first",
            context
                .txset_hash_hex
                .as_deref()
                .ok_or_else(|| anyhow!("token_issued missing txset_hash_hex"))?,
        );
        let expected_seller_req = sign_req_id(
            escrow_id_hex,
            "sign_multisig",
            "seller_second",
            context
                .txset_hash_hex
                .as_deref()
                .ok_or_else(|| anyhow!("token_issued missing txset_hash_hex"))?,
        );
        if context.proof_arbiter_req_id.as_deref() != Some(expected_arbiter_req.as_str())
            || context.proof_seller_req_id.as_deref() != Some(expected_seller_req.as_str())
        {
            return Err(anyhow!(
                "token_issued submit_multisig proof req_id mismatch expected sign req_id contract"
            ));
        }
    }
    Ok(())
}

fn merged_auth_event_detail(
    detail: Option<&str>,
    context: Option<&AuthEventContext>,
) -> Result<Option<String>> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(detail) = detail {
        let detail = detail.trim();
        if !detail.is_empty() {
            parts.push(detail.to_string());
        }
    }
    if let Some(context) = context {
        if let Some(op) = context.op.as_deref() {
            parts.push(format!("op={}", op));
        }
        if let Some(txset_hash_hex) = context.txset_hash_hex.as_deref() {
            parts.push(format!("txset_hash_hex={}", txset_hash_hex));
        }
        if let Some(proof_arbiter_jti) = context.proof_arbiter_jti.as_deref() {
            parts.push(format!("proof_arbiter_jti={}", proof_arbiter_jti));
        }
        if let Some(proof_arbiter_req_id) = context.proof_arbiter_req_id.as_deref() {
            parts.push(format!("proof_arbiter_req_id={}", proof_arbiter_req_id));
        }
        if let Some(proof_seller_jti) = context.proof_seller_jti.as_deref() {
            parts.push(format!("proof_seller_jti={}", proof_seller_jti));
        }
        if let Some(proof_seller_req_id) = context.proof_seller_req_id.as_deref() {
            parts.push(format!("proof_seller_req_id={}", proof_seller_req_id));
        }
    }
    if parts.is_empty() {
        return Ok(None);
    }
    let merged = parts.join(" ");
    if merged.len() > 1024 {
        return Err(anyhow!("auth event detail too long after context merge"));
    }
    Ok(Some(merged))
}

pub(crate) async fn append_auth_event(
    cfg: &SignerConfig,
    db: &SignerDb,
    local_id: &str,
    escrow_id_hex: &str,
    event_kind: &str,
    actor_id: Option<&str>,
    detail: Option<&str>,
    context: Option<AuthEventContext>,
) -> Result<()> {
    let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
    let event_kind = normalize_auth_event_kind(event_kind)?;
    let context = normalize_auth_event_context(context)?;

    let actor_id = actor_id
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned);
    if actor_id.as_ref().map(|v| v.len()).unwrap_or(0) > 128 {
        return Err(anyhow!("actor_id too long (max 128 chars)"));
    }
    let detail = detail
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(sanitize_runtime_detail);
    if detail.as_ref().map(|v| v.len()).unwrap_or(0) > 1024 {
        return Err(anyhow!("detail too long (max 1024 chars)"));
    }
    if detail
        .as_deref()
        .map(contains_probable_jwt)
        .unwrap_or(false)
    {
        return Err(anyhow!("detail must not include raw JWT material"));
    }
    if detail
        .as_deref()
        .map(|v| v == "redacted_sensitive_detail")
        .unwrap_or(false)
    {
        return Err(anyhow!(
            "detail must not include secrets/token/password markers"
        ));
    }

    if event_kind == TOKEN_ISSUED {
        enforce_token_issued_context_requirements(
            &escrow_id_hex,
            context.as_ref(),
            cfg.production_hardening,
        )?;
        if let Some(ctx) = context.as_ref()
            && ctx.op.as_deref() == Some("submit_multisig")
        {
            verify_submit_quorum_proof_bundle(
                &escrow_id_hex,
                ctx.txset_hash_hex
                    .as_deref()
                    .ok_or_else(|| anyhow!("token_issued missing txset_hash_hex"))?,
                ctx.proof_arbiter_jti
                    .as_deref()
                    .ok_or_else(|| anyhow!("token_issued missing proof_arbiter_jti"))?,
                ctx.proof_arbiter_req_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("token_issued missing proof_arbiter_req_id"))?,
                ctx.proof_seller_jti
                    .as_deref()
                    .ok_or_else(|| anyhow!("token_issued missing proof_seller_jti"))?,
                ctx.proof_seller_req_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("token_issued missing proof_seller_req_id"))?,
                cfg.production_hardening,
            )
            .await?;
        }
    }

    let decision = match event_kind {
        CHALLENGE_ISSUED => "issued",
        CHALLENGE_VERIFIED => "verified",
        TOKEN_ISSUED => "issued",
        _ => "recorded",
    };
    let detail = merged_auth_event_detail(detail.as_deref(), context.as_ref())?;
    db.append_audit_log(AuditLogInsert {
        event_kind,
        escrow_id_hex: &escrow_id_hex,
        from_id: actor_id.as_deref(),
        to_id: Some(local_id),
        seq: None,
        envelope_hash_hex: None,
        payload_hash_hex: None,
        decision: Some(decision),
        detail: detail.as_deref(),
    })
    .await?;
    Ok(())
}

fn should_ack_non_retryable_process_error(err: &anyhow::Error) -> bool {
    let lower = err.to_string().to_ascii_lowercase();
    [
        "sender '",
        "not in allowlist",
        "envelope addressed to",
        "unexpected cipher suite ids",
        "unsupported msg_type",
        "invalid action token",
        "action token scope/op mismatch",
        "action token ttl exceeds",
        "action token jti invalid",
        "action token wallet_id mismatch",
        "action token sandbox_id mismatch",
        "action token nettype mismatch",
        "replayed jti",
        "replay/out-of-order seq detected",
        "replay seq detected",
        "tx_sign_req payload kind mismatch",
        "payload too large",
        "seq must be > 0",
        "must be 64 hex chars",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn mailbox_retry_backoff_ms(base_backoff_ms: u64, attempt: u32) -> u64 {
    let exp = attempt.saturating_sub(1).min(6);
    base_backoff_ms
        .saturating_mul(1_u64 << exp)
        .clamp(50, 10_000)
}
