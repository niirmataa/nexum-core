use std::time::{Duration, Instant};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header::CONTENT_LENGTH, header::RETRY_AFTER};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use nxms_transport::security::timing_safe_eq_fixed;
use nxms_transport::wire::{NxmsEnvelope, validate_peer_id};

use crate::AppState;
use crate::db::{MailboxLimits, PushRejection};

const AUTH_HEADER_COMPARE_MAX_LEN: usize = 1024;

#[derive(Clone, Debug)]
pub(crate) struct ApiConfig {
    pub token: Option<String>,
    pub admin_token: Option<String>,
    pub max_body_bytes: usize,
    pub default_ttl_secs: u64,
    pub max_ttl_secs: u64,
    pub lease_secs: u64,
    pub max_wait_ms: u64,
    pub limits: MailboxLimits,
    pub rate_limit_ip_per_min: u32,
    pub rate_limit_to_per_min: u32,
}

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    detail: String,
    retry_after_secs: Option<u64>,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
            retry_after_secs: None,
        }
    }

    pub(crate) fn with_retry_after(
        status: StatusCode,
        detail: impl Into<String>,
        retry_after_secs: u64,
    ) -> Self {
        Self {
            status,
            detail: detail.into(),
            retry_after_secs: Some(retry_after_secs.max(1)),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    ok: bool,
    detail: String,
    retry_after_secs: Option<u64>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            ok: false,
            detail: self.detail.clone(),
            retry_after_secs: self.retry_after_secs,
        };
        if let Some(retry_after_secs) = self.retry_after_secs {
            let mut response = (self.status, Json(body)).into_response();
            if let Ok(hv) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                response.headers_mut().insert(RETRY_AFTER, hv);
            }
            return response;
        }
        (self.status, Json(body)).into_response()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct PushRequest {
    pub envelope: NxmsEnvelope,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PushResponse {
    pub ok: bool,
    pub dedup: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PullRequest {
    pub to: String,
    pub max: Option<u32>,
    pub wait_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PullResponse {
    pub ok: bool,
    pub messages: Vec<PulledMessage>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PulledMessage {
    pub receipt: String,
    pub envelope: NxmsEnvelope,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AckRequest {
    pub receipt: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct AckResponse {
    pub ok: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminStatsResponse {
    pub ok: bool,
    pub total_rows: u64,
    pub db_bytes: u64,
    pub wal_bytes: u64,
    pub inboxes: Vec<AdminInboxStats>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminInboxStats {
    pub to: String,
    pub backlog_count: u64,
    pub oldest_age_secs: u64,
    pub bytes: u64,
}

pub(crate) async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true }))
}

pub(crate) async fn push(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PushResponse>, ApiError> {
    require_auth(&state.cfg, &headers)?;
    let max_body_bytes = state.cfg.max_body_bytes.max(1);
    if let Some(raw_len) = headers.get(CONTENT_LENGTH)
        && let Ok(raw_len) = raw_len.to_str()
        && let Ok(content_len) = raw_len.parse::<usize>()
        && content_len > max_body_bytes
    {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request body exceeds {} bytes", max_body_bytes),
        ));
    }
    if body.len() > max_body_bytes {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request body exceeds {} bytes", max_body_bytes),
        ));
    }
    let req: PushRequest = serde_json::from_slice(body.as_ref())
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("invalid push json: {e}")))?;

    enforce_push_rate_limits(&state, connect_info, &headers, &req.envelope.to)?;
    req.envelope
        .validate_basic()
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;

    // Server-side TTL policy (mailbox is not allowed to mutate the envelope).
    let ttl_secs = req.ttl_secs.unwrap_or(state.cfg.default_ttl_secs);
    if ttl_secs == 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "ttl_secs must be > 0",
        ));
    }
    let ttl_secs = ttl_secs.min(state.cfg.max_ttl_secs.max(1));

    let to = req.envelope.to.clone();
    let result = state
        .db
        .push(&req.envelope, ttl_secs, state.cfg.limits)
        .await
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if let Some(rejection) = result.rejection {
        return Err(map_push_rejection(rejection));
    }

    if !result.dedup {
        state.notify.notify_inbox(&to);
    }

    Ok(Json(PushResponse {
        ok: true,
        dedup: result.dedup,
    }))
}

pub(crate) async fn pull(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PullRequest>,
) -> Result<Json<PullResponse>, ApiError> {
    require_auth(&state.cfg, &headers)?;

    validate_peer_id(&req.to)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("invalid to: {e}")))?;

    let max = req.max.unwrap_or(10).clamp(1, 50);
    let mut wait_ms = req.wait_ms.unwrap_or(0);
    wait_ms = wait_ms.min(state.cfg.max_wait_ms);

    let deadline = Instant::now() + Duration::from_millis(wait_ms);

    loop {
        let leased = state
            .db
            .pull(&req.to, max, state.cfg.lease_secs)
            .await
            .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if !leased.is_empty() {
            return Ok(Json(PullResponse {
                ok: true,
                messages: leased
                    .into_iter()
                    .map(|m| PulledMessage {
                        receipt: m.receipt,
                        envelope: m.envelope,
                    })
                    .collect(),
            }));
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(Json(PullResponse {
                ok: true,
                messages: Vec::new(),
            }));
        }

        let notify = state.notify.inbox(&req.to);
        tokio::select! {
            _ = notify.notified() => {},
            _ = tokio::time::sleep(remaining) => {
                return Ok(Json(PullResponse{ ok: true, messages: Vec::new() }));
            }
        }
    }
}

pub(crate) async fn ack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AckRequest>,
) -> Result<Json<AckResponse>, ApiError> {
    require_auth(&state.cfg, &headers)?;

    let receipt = req.receipt.trim();
    if receipt.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "receipt must not be empty",
        ));
    }

    let ok = state
        .db
        .ack(receipt)
        .await
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if !ok {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "unknown receipt"));
    }
    Ok(Json(AckResponse { ok: true }))
}

pub(crate) async fn admin_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminStatsResponse>, ApiError> {
    require_admin_auth(&state.cfg, &headers)?;
    let stats = state
        .db
        .stats()
        .await
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(AdminStatsResponse {
        ok: true,
        total_rows: stats.total_rows,
        db_bytes: stats.db_bytes,
        wal_bytes: stats.wal_bytes,
        inboxes: stats
            .inboxes
            .into_iter()
            .map(|inbox| AdminInboxStats {
                to: inbox.to,
                backlog_count: inbox.backlog_count,
                oldest_age_secs: inbox.oldest_age_secs,
                bytes: inbox.bytes,
            })
            .collect(),
    }))
}

fn require_auth(cfg: &ApiConfig, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(token) = cfg.token.as_deref() else {
        return Ok(());
    };

    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let want = format!("Bearer {}", token);
    if !timing_safe_eq_fixed::<AUTH_HEADER_COMPARE_MAX_LEN>(auth, &want) {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(())
}

fn require_admin_auth(cfg: &ApiConfig, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(token) = cfg.admin_token.as_deref() else {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "admin endpoint disabled",
        ));
    };

    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let want = format!("Bearer {}", token);
    if !timing_safe_eq_fixed::<AUTH_HEADER_COMPARE_MAX_LEN>(auth, &want) {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(())
}

fn enforce_push_rate_limits(
    state: &AppState,
    connect_info: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: &HeaderMap,
    to: &str,
) -> Result<(), ApiError> {
    if let Some(retry_after_secs) = state
        .rate_limits
        .check_to(to, state.cfg.rate_limit_to_per_min)
    {
        return Err(ApiError::with_retry_after(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded for target inbox",
            retry_after_secs,
        ));
    }

    let source_ip = extract_source_ip(connect_info, headers);
    if let Some(retry_after_secs) = state
        .rate_limits
        .check_ip(&source_ip, state.cfg.rate_limit_ip_per_min)
    {
        return Err(ApiError::with_retry_after(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded for source ip",
            retry_after_secs,
        ));
    }
    Ok(())
}

fn map_push_rejection(rejection: PushRejection) -> ApiError {
    match rejection {
        PushRejection::InboxMessageLimit => ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "inbox message quota exceeded",
        ),
        PushRejection::InboxBytesLimit => ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "inbox bytes quota exceeded",
        ),
        PushRejection::GlobalRowsLimit => ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "global mailbox row quota exceeded",
        ),
    }
}

fn extract_source_ip(
    connect_info: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: &HeaderMap,
) -> String {
    if let Some(v) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
    {
        let ip = v.trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }

    if let Some(v) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = v.trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }

    connect_info
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::SqliteMailboxDb;
    use crate::{NotifyMap, RateLimits};
    use nxms_transport::wire::{MsgType, NXMS_PROTO_V1};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_db_path(label: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "nxms_mailbox_api_test_{label}_{}_{}.db",
            std::process::id(),
            ts
        ))
    }

    fn sample_envelope(to: &str, seq: u64) -> NxmsEnvelope {
        NxmsEnvelope {
            proto: NXMS_PROTO_V1.to_string(),
            kem_id: "FrodoKEM-640-SHAKE".to_string(),
            sig_id: "Falcon-1024-CT".to_string(),
            msg_type: MsgType::PrepareInfo,
            escrow_id_hex: "1".repeat(32),
            from: "alice".to_string(),
            to: to.to_string(),
            seq,
            kem_ct_b64: "x".to_string(),
            nonce_b64: "x".to_string(),
            ciphertext_b64: "x".to_string(),
            tag_b64: "x".to_string(),
            sig_b64: "x".to_string(),
        }
    }

    async fn make_state(
        db_path: PathBuf,
        limits: MailboxLimits,
        rate_limit_ip_per_min: u32,
        rate_limit_to_per_min: u32,
    ) -> AppState {
        let db = SqliteMailboxDb::new(db_path);
        db.init().await.expect("db init");
        AppState {
            db,
            cfg: ApiConfig {
                token: None,
                admin_token: Some("admin".to_string()),
                max_body_bytes: 1024 * 1024,
                default_ttl_secs: 60,
                max_ttl_secs: 600,
                lease_secs: 30,
                max_wait_ms: 1000,
                limits,
                rate_limit_ip_per_min,
                rate_limit_to_per_min,
            },
            notify: Arc::new(NotifyMap::default()),
            rate_limits: Arc::new(RateLimits::default()),
        }
    }

    #[tokio::test]
    async fn push_rate_limit_returns_429_with_retry_after() {
        let db_path = unique_db_path("rate_limit");
        let state = make_state(
            db_path.clone(),
            MailboxLimits {
                max_messages_per_inbox: 100,
                max_bytes_per_inbox: 1024 * 1024,
                max_rows_global: 1000,
            },
            1000,
            1,
        )
        .await;

        let req1 = PushRequest {
            envelope: sample_envelope("bob", 1),
            ttl_secs: Some(60),
        };
        let req2 = PushRequest {
            envelope: sample_envelope("bob", 2),
            ttl_secs: Some(60),
        };
        let headers = HeaderMap::new();
        let connect_info = Some(ConnectInfo(
            "127.0.0.1:40123"
                .parse::<std::net::SocketAddr>()
                .expect("addr"),
        ));

        let req1_body = Bytes::from(serde_json::to_vec(&req1).expect("req1 json"));
        let _ = push(
            State(state.clone()),
            connect_info.clone(),
            headers.clone(),
            req1_body,
        )
        .await
        .expect("first push ok");

        let req2_body = Bytes::from(serde_json::to_vec(&req2).expect("req2 json"));
        let err = push(State(state), connect_info, headers, req2_body)
            .await
            .expect_err("second push must be rate limited");
        assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(err.retry_after_secs.is_some());
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn push_quota_returns_507() {
        let db_path = unique_db_path("quota");
        let state = make_state(
            db_path.clone(),
            MailboxLimits {
                max_messages_per_inbox: 1,
                max_bytes_per_inbox: 1024 * 1024,
                max_rows_global: 1000,
            },
            1000,
            1000,
        )
        .await;

        let headers = HeaderMap::new();
        let connect_info = Some(ConnectInfo(
            "127.0.0.1:40124"
                .parse::<std::net::SocketAddr>()
                .expect("addr"),
        ));

        let req1 = PushRequest {
            envelope: sample_envelope("bob", 1),
            ttl_secs: Some(60),
        };
        let _ = push(
            State(state.clone()),
            connect_info.clone(),
            headers.clone(),
            Bytes::from(serde_json::to_vec(&req1).expect("req1 json")),
        )
        .await
        .expect("first push ok");

        let req2 = PushRequest {
            envelope: sample_envelope("bob", 2),
            ttl_secs: Some(60),
        };
        let err = push(
            State(state),
            connect_info,
            headers,
            Bytes::from(serde_json::to_vec(&req2).expect("req2 json")),
        )
        .await
        .expect_err("second push must exceed quota");
        assert_eq!(err.status, StatusCode::INSUFFICIENT_STORAGE);
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn push_rejects_malformed_envelope() {
        let db_path = unique_db_path("malformed");
        let state = make_state(
            db_path.clone(),
            MailboxLimits {
                max_messages_per_inbox: 100,
                max_bytes_per_inbox: 1024 * 1024,
                max_rows_global: 1000,
            },
            1000,
            1000,
        )
        .await;

        let mut env = sample_envelope("bob", 1);
        env.seq = 0; // invalid per envelope rules
        let req = PushRequest {
            envelope: env,
            ttl_secs: Some(60),
        };
        let err = push(
            State(state),
            Some(ConnectInfo(
                "127.0.0.1:40125"
                    .parse::<std::net::SocketAddr>()
                    .expect("addr"),
            )),
            HeaderMap::new(),
            Bytes::from(serde_json::to_vec(&req).expect("req json")),
        )
        .await
        .expect_err("malformed envelope must be rejected");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_file(db_path);
    }
}
