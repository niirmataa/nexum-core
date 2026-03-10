pub mod api;
pub mod db;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use tokio::sync::Notify;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct AppState {
    pub db: db::SqliteMailboxDb,
    pub cfg: api::ApiConfig,
    pub(crate) notify: Arc<NotifyMap>,
    pub(crate) rate_limits: Arc<RateLimits>,
}

impl AppState {
    pub fn new(db: db::SqliteMailboxDb, cfg: api::ApiConfig) -> Self {
        Self {
            db,
            cfg,
            notify: Arc::new(NotifyMap::default()),
            rate_limits: Arc::new(RateLimits::default()),
        }
    }
}

pub fn build_app(state: AppState, max_body_bytes: usize) -> Router {
    Router::new()
        .route("/health", get(api::health))
        .route("/v1/push", post(api::push))
        .route("/v1/pull", post(api::pull))
        .route("/v1/ack", post(api::ack))
        .route("/v1/admin/stats", get(api::admin_stats))
        .layer(TraceLayer::new_for_http())
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

#[derive(Default)]
pub(crate) struct NotifyMap {
    inner: Mutex<HashMap<String, Arc<Notify>>>,
}

impl NotifyMap {
    pub(crate) fn inbox(&self, to: &str) -> Arc<Notify> {
        let mut lock = self.inner.lock().expect("notify map lock");
        lock.entry(to.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    pub(crate) fn notify_inbox(&self, to: &str) {
        let n = self.inbox(to);
        n.notify_waiters();
    }
}

#[derive(Default)]
pub(crate) struct FixedWindowLimiter {
    inner: Mutex<HashMap<String, WindowCounter>>,
}

#[derive(Clone, Copy)]
struct WindowCounter {
    started_at: u64,
    count: u32,
}

impl FixedWindowLimiter {
    fn check(&self, key: &str, limit_per_min: u32, now: u64) -> Option<u64> {
        if limit_per_min == 0 || key.trim().is_empty() {
            return None;
        }
        let mut lock = self.inner.lock().expect("rate limiter lock");
        let counter = lock.entry(key.to_string()).or_insert(WindowCounter {
            started_at: now,
            count: 0,
        });
        if now.saturating_sub(counter.started_at) >= 60 {
            counter.started_at = now;
            counter.count = 0;
        }
        if counter.count >= limit_per_min {
            let elapsed = now.saturating_sub(counter.started_at).min(60);
            return Some(60 - elapsed);
        }
        counter.count = counter.count.saturating_add(1);

        if lock.len() > 50_000 {
            lock.retain(|_, v| now.saturating_sub(v.started_at) < 120);
        }
        None
    }
}

#[derive(Default)]
pub(crate) struct RateLimits {
    by_ip: FixedWindowLimiter,
    by_to: FixedWindowLimiter,
}

impl RateLimits {
    pub(crate) fn check_ip(&self, ip: &str, limit_per_min: u32) -> Option<u64> {
        self.by_ip.check(ip, limit_per_min, now_secs())
    }

    pub(crate) fn check_to(&self, to: &str, limit_per_min: u32) -> Option<u64> {
        self.by_to.check(to, limit_per_min, now_secs())
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
