#![forbid(unsafe_code)]

pub mod action_token;
pub mod config;
pub mod db;
pub mod flow;
pub mod tx_profile;

pub use action_token::{
    ActionTokenClaims, ActionTokenCliInput, ActionTokenCommand, ActionTokenOp, ActionTokenRole,
    IssuedActionTokenOutput, build_issue_params, handle_action_token, issue_action_token,
};
pub use config::{
    ENV_ORCHESTRATOR_CONFIG_PATH, OrchestratorConfig, load_optional_orchestrator_config,
};
pub use db::{OrchestratorDb, SloAlertThresholds};

const ENV_BRIDGE_TOKEN_INPUT: &str = "NXMS_ORCH_BRIDGE_TOKEN_INPUT";

pub fn require_bridge_token(bridge_token: Option<&str>) -> anyhow::Result<()> {
    let cli_token_ok = bridge_token
        .map(str::trim)
        .map(|v| !v.is_empty())
        .unwrap_or(false);

    if cli_token_ok {
        return Ok(());
    }

    let env_token_ok = std::env::var(ENV_BRIDGE_TOKEN_INPUT)
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    if env_token_ok {
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "missing bridge token: pass --bridge-token or set {}",
        ENV_BRIDGE_TOKEN_INPUT
    ))
}
