use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::types::{MoneroArbitraError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub wallet_id: String,
    pub network: crate::types::Network,
    pub rpc_bind: String,
    pub data_dir: String,
    pub daemon_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            wallet_id: "arbiter-main".to_string(),
            network: crate::types::Network::Stagenet,
            rpc_bind: "127.0.0.1:18100".to_string(),
            data_dir: "./data/monero-arbitra".to_string(),
            daemon_url: "http://127.0.0.1:18081/json_rpc".to_string(),
        }
    }
}

pub fn load_config(path: impl AsRef<Path>) -> Result<Config> {
    let p = path.as_ref();
    if !p.exists() {
        return Ok(Config::default());
    }
    let raw = fs::read_to_string(p).map_err(MoneroArbitraError::Io)?;
    toml::from_str::<Config>(&raw).map_err(MoneroArbitraError::ConfigToml)
}
