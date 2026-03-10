use crate::agent::{AuthEventContext, SignerAgent};
use crate::agent_support::sanitize_runtime_detail;
use crate::db::{SecurityAlertThresholds, SecurityDashboard};
use anyhow::{Result, anyhow};
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use nxms_transport::wire::EscrowAction;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

const WORKER_HTTP_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const SERVICE_AUTH_HEADER: &str = "x-nxms-service-authorization";

#[derive(Clone)]
struct WorkerState {
    agent: Arc<SignerAgent>,
    service_token: Arc<String>,
    // Wallet RPC is stateful and shared per wallet; serialize critical operations.
    op_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Deserialize)]
struct SignMultisigRequest {
    escrow_id_hex: String,
    action: String,
    tx_data_hex: String,
    action_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct SignMultisigResponse {
    tx_data_hex: String,
    tx_hash_list: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SubmitMultisigRequest {
    escrow_id_hex: String,
    action: String,
    tx_data_hex: String,
    action_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct SubmitMultisigResponse {
    tx_hash_list: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ProposeMultisigRequest {
    escrow_id_hex: String,
    action: String,
    amount_override_atomic: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ProposeMultisigResponse {
    tx_data_hex: String,
    txset_hash_hex: String,
}

#[derive(Debug, Deserialize)]
struct AuthAuditEventRequest {
    escrow_id_hex: String,
    event_kind: String,
    actor_id: Option<String>,
    detail: Option<String>,
    op: Option<String>,
    txset_hash_hex: Option<String>,
    proof_arbiter_jti: Option<String>,
    proof_arbiter_req_id: Option<String>,
    proof_seller_jti: Option<String>,
    proof_seller_req_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize)]
struct AuditAlertsQuery {
    window_secs: Option<u64>,
    token_reject_total: Option<u64>,
    replay_reject_total: Option<u64>,
    policy_reject_total: Option<u64>,
    rpc_fail_total: Option<u64>,
    shadow_allow_total: Option<u64>,
}

pub async fn serve(agent: SignerAgent, bind: &str) -> Result<()> {
    enforce_bind_policy(bind)?;
    let service_token = agent
        .worker_service_token()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("worker_service_token must be configured"))?;

    let state = WorkerState {
        agent: Arc::new(agent),
        service_token: Arc::new(service_token),
        op_lock: Arc::new(Mutex::new(())),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/audit/metrics", get(audit_metrics))
        .route("/v1/audit/alerts", get(audit_alerts))
        .route("/v1/propose_multisig", post(propose_multisig))
        .route("/v1/sign_multisig", post(sign_multisig))
        .route("/v1/submit_multisig", post(submit_multisig))
        .route("/v1/audit/auth_event", post(auth_event))
        .layer(DefaultBodyLimit::max(WORKER_HTTP_MAX_BODY_BYTES))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| anyhow!("failed to bind worker API on {}: {}", bind, e))?;
    info!("nxms-signer worker API listening on {}", bind);
    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow!("worker API server error: {}", e))
}

fn bind_is_loopback(bind: &str) -> Result<bool> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| anyhow!("worker bind '{}' must be explicit socket address host:port: {}", bind, e))?;
    Ok(match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    })
}

fn enforce_bind_policy(bind: &str) -> Result<()> {
    if bind_is_loopback(bind)? {
        return Ok(());
    }
    Err(anyhow!(
        "worker bind '{}' rejected: loopback-only bind is required",
        bind
    ))
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(HealthResponse { ok: true }))
}

async fn audit_metrics(State(state): State<WorkerState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(resp) = require_service_auth(&headers, state.service_token.as_str()) {
        return resp;
    }
    match state.agent.security_dashboard().await {
        Ok(v) => {
            let dashboard: SecurityDashboard = v;
            (StatusCode::OK, Json(dashboard)).into_response()
        }
        Err(err) => map_error(err),
    }
}

async fn audit_alerts(
    State(state): State<WorkerState>,
    headers: HeaderMap,
    Query(q): Query<AuditAlertsQuery>,
) -> impl IntoResponse {
    if let Err(resp) = require_service_auth(&headers, state.service_token.as_str()) {
        return resp;
    }
    let window_ms = q.window_secs.unwrap_or(300).max(1).saturating_mul(1000);
    let thresholds = SecurityAlertThresholds {
        token_reject_total: q.token_reject_total.unwrap_or(5).max(1),
        replay_reject_total: q.replay_reject_total.unwrap_or(3).max(1),
        policy_reject_total: q.policy_reject_total.unwrap_or(1).max(1),
        rpc_fail_total: q.rpc_fail_total.unwrap_or(2).max(1),
        shadow_allow_total: q.shadow_allow_total.unwrap_or(1).max(1),
    };
    match state
        .agent
        .security_alert_report(window_ms, thresholds)
        .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(err) => map_error(err),
    }
}

async fn sign_multisig(
    State(state): State<WorkerState>,
    headers: HeaderMap,
    Json(req): Json<SignMultisigRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_service_auth(&headers, state.service_token.as_str()) {
        return resp;
    }
    let action = match parse_action(&req.action) {
        Ok(v) => v,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: err.to_string(),
                }),
            )
                .into_response();
        }
    };

    let action_token = match resolve_action_token(&headers, req.action_token.as_deref()) {
        Ok(v) => v,
        Err((status, msg)) => {
            return (status, Json(ErrorResponse { error: msg })).into_response();
        }
    };

    let _guard = state.op_lock.lock().await;
    match state
        .agent
        .sign_multisig_flow(
            &req.escrow_id_hex,
            action,
            &req.tx_data_hex,
            action_token.as_deref(),
        )
        .await
    {
        Ok(signed) => (
            StatusCode::OK,
            Json(SignMultisigResponse {
                tx_data_hex: signed.tx_data_hex,
                tx_hash_list: signed.tx_hash_list,
            }),
        )
            .into_response(),
        Err(err) => map_error(err),
    }
}

async fn propose_multisig(
    State(state): State<WorkerState>,
    headers: HeaderMap,
    Json(req): Json<ProposeMultisigRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_service_auth(&headers, state.service_token.as_str()) {
        return resp;
    }
    let action = match parse_action(&req.action) {
        Ok(v) => v,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: err.to_string(),
                }),
            )
                .into_response();
        }
    };

    let _guard = state.op_lock.lock().await;
    match state
        .agent
        .propose_multisig_flow(&req.escrow_id_hex, action, req.amount_override_atomic)
        .await
    {
        Ok(v) => (
            StatusCode::OK,
            Json(ProposeMultisigResponse {
                tx_data_hex: v.tx_data_hex,
                txset_hash_hex: v.txset_hash_hex,
            }),
        )
            .into_response(),
        Err(err) => map_error(err),
    }
}

async fn submit_multisig(
    State(state): State<WorkerState>,
    headers: HeaderMap,
    Json(req): Json<SubmitMultisigRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_service_auth(&headers, state.service_token.as_str()) {
        return resp;
    }
    let action = match parse_action(&req.action) {
        Ok(v) => v,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: err.to_string(),
                }),
            )
                .into_response();
        }
    };

    let action_token = match resolve_action_token(&headers, req.action_token.as_deref()) {
        Ok(v) => v,
        Err((status, msg)) => {
            return (status, Json(ErrorResponse { error: msg })).into_response();
        }
    };

    let _guard = state.op_lock.lock().await;
    match state
        .agent
        .submit_multisig_flow(
            &req.escrow_id_hex,
            action,
            &req.tx_data_hex,
            action_token.as_deref(),
        )
        .await
    {
        Ok(tx_hash_list) => (
            StatusCode::OK,
            Json(SubmitMultisigResponse { tx_hash_list }),
        )
            .into_response(),
        Err(err) => map_error(err),
    }
}

async fn auth_event(
    State(state): State<WorkerState>,
    headers: HeaderMap,
    Json(req): Json<AuthAuditEventRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_service_auth(&headers, state.service_token.as_str()) {
        return resp;
    }
    let context = AuthEventContext {
        op: req.op.clone(),
        txset_hash_hex: req.txset_hash_hex.clone(),
        proof_arbiter_jti: req.proof_arbiter_jti.clone(),
        proof_arbiter_req_id: req.proof_arbiter_req_id.clone(),
        proof_seller_jti: req.proof_seller_jti.clone(),
        proof_seller_req_id: req.proof_seller_req_id.clone(),
    };
    let has_context = context.op.is_some()
        || context.txset_hash_hex.is_some()
        || context.proof_arbiter_jti.is_some()
        || context.proof_arbiter_req_id.is_some()
        || context.proof_seller_jti.is_some()
        || context.proof_seller_req_id.is_some();
    match state
        .agent
        .record_auth_event(
            &req.escrow_id_hex,
            &req.event_kind,
            req.actor_id.as_deref(),
            req.detail.as_deref(),
            if has_context { Some(context) } else { None },
        )
        .await
    {
        Ok(()) => (StatusCode::OK, Json(HealthResponse { ok: true })).into_response(),
        Err(err) => map_error(err),
    }
}

fn parse_action(raw: &str) -> Result<EscrowAction> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "release" => Ok(EscrowAction::Release),
        "refund" => Ok(EscrowAction::Refund),
        _ => Err(anyhow!("action must be one of: release|refund")),
    }
}

fn bearer_token_from_service_headers(
    headers: &HeaderMap,
) -> std::result::Result<Option<String>, (StatusCode, String)> {
    let header_name = HeaderName::from_static(SERVICE_AUTH_HEADER);
    let Some(raw) = headers.get(header_name) else {
        return Ok(None);
    };
    let raw = raw.to_str().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "invalid service auth header".to_string(),
        )
    })?;
    let (scheme, token) = raw.split_once(' ').ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "bad service auth header format".to_string(),
        )
    })?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err((
            StatusCode::UNAUTHORIZED,
            "service auth scheme must be Bearer".to_string(),
        ));
    }
    let token = token.trim();
    if token.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "empty service bearer token".to_string(),
        ));
    }
    Ok(Some(token.to_string()))
}

fn require_service_auth(
    headers: &HeaderMap,
    expected_token: &str,
) -> std::result::Result<(), axum::response::Response> {
    let token = match bearer_token_from_service_headers(headers) {
        Ok(Some(token)) => token,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "missing service auth header".to_string(),
                }),
            )
                .into_response());
        }
        Err((status, msg)) => {
            return Err((status, Json(ErrorResponse { error: msg })).into_response());
        }
    };

    if token != expected_token {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized service caller".to_string(),
            }),
        )
            .into_response());
    }
    Ok(())
}

fn resolve_action_token(
    headers: &HeaderMap,
    body_token: Option<&str>,
) -> std::result::Result<Option<String>, (StatusCode, String)> {
    let header_token = bearer_token_from_headers(headers)?;
    match (
        header_token,
        body_token.map(str::trim).filter(|v| !v.is_empty()),
    ) {
        (Some(h), Some(b)) if h != b => Err((
            StatusCode::BAD_REQUEST,
            "action token mismatch between Authorization header and body".to_string(),
        )),
        (Some(h), _) => Ok(Some(h)),
        (None, Some(b)) => Ok(Some(b.to_string())),
        (None, None) => Ok(None),
    }
}

fn bearer_token_from_headers(
    headers: &HeaderMap,
) -> std::result::Result<Option<String>, (StatusCode, String)> {
    let Some(raw) = headers.get(AUTHORIZATION) else {
        return Ok(None);
    };
    let raw = raw.to_str().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "invalid Authorization header".to_string(),
        )
    })?;
    let (scheme, token) = raw.split_once(' ').ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "bad Authorization header format".to_string(),
        )
    })?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Authorization scheme must be Bearer".to_string(),
        ));
    }
    let token = token.trim();
    if token.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "empty bearer token".to_string()));
    }
    Ok(Some(token.to_string()))
}

fn map_error(err: anyhow::Error) -> axum::response::Response {
    let raw_text = err.to_string();
    let low = raw_text.to_ascii_lowercase();
    let status = if low.contains("action token")
        || low.contains("invalid action token")
        || low.contains("issuer")
        || low.contains("audience")
        || low.contains("scope/op")
        || low.contains("replayed jti")
        || low.contains("submit denied")
    {
        StatusCode::UNAUTHORIZED
    } else if low.contains("already in progress") || low.contains("duplicate req_id") {
        StatusCode::CONFLICT
    } else if low.contains("wallet-rpc") {
        StatusCode::BAD_GATEWAY
    } else if low.contains("must be")
        || low.contains("mismatch")
        || low.contains("no active snapshot")
        || low.contains("invalid")
        || low.contains("describe_transfer")
        || low.contains("policy")
    {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    let text = sanitize_runtime_detail(&raw_text);
    (status, Json(ErrorResponse { error: text })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn resolve_action_token_prefers_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token"),
        );
        let token =
            resolve_action_token(&headers, Some("header-token")).expect("token resolution failed");
        assert_eq!(token.as_deref(), Some("header-token"));
    }

    #[test]
    fn resolve_action_token_rejects_mismatch() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token"),
        );
        let err = resolve_action_token(&headers, Some("body-token"))
            .expect_err("mismatched tokens must fail");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn bind_policy_accepts_loopback() {
        assert!(bind_is_loopback("127.0.0.1:28090").expect("parse"));
        assert!(bind_is_loopback("[::1]:28090").expect("parse"));
    }

    #[test]
    fn bind_policy_rejects_non_loopback_without_override() {
        let err = enforce_bind_policy("0.0.0.0:28090").expect_err("must reject remote bind");
        assert!(err.to_string().contains("loopback-only"));
    }

    #[test]
    fn service_auth_rejects_missing_bearer() {
        let err = require_service_auth(&HeaderMap::new(), "service-token-123456")
            .expect_err("missing auth");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn service_auth_rejects_wrong_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(SERVICE_AUTH_HEADER),
            HeaderValue::from_static("Bearer wrong-token"),
        );
        let err = require_service_auth(&headers, "service-token-123456").expect_err("wrong auth");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn service_auth_accepts_matching_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(SERVICE_AUTH_HEADER),
            HeaderValue::from_static("Bearer service-token-123456"),
        );
        require_service_auth(&headers, "service-token-123456").expect("service auth");
    }
}
