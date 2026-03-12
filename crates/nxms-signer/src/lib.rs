pub mod action_token;
pub mod agent;
pub mod config;
pub mod db;
pub mod snapshot;
pub mod trust;
pub mod worker_http;

pub(crate) mod agent_support;
pub(crate) mod audit_event;
pub(crate) mod orchestrator_bridge;
pub(crate) mod wallet_rpc;

pub use agent::{AuthEventContext, SignerAgent, append_auth_event};
pub use agent_support::{normalize_hex_exact, now_ms};
pub use config::SignerConfig;
pub use db::{
    AuditLogRow, PendingTxSign, SecurityAlertThresholds, SignEventAuditRow, SignerDb, SnapshotRow,
    SnapshotSigRow,
};
