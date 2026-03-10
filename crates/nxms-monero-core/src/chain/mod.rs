use crate::types::{MoneroOutput, MoneroTransaction, Result};

pub trait DaemonClient: Send + Sync {
    fn network_height(&self) -> Result<u64>;
    fn submit_transaction(&self, tx: &MoneroTransaction) -> Result<String>;
    fn scan_outputs(&self, from_height: u64, to_height: u64) -> Result<Vec<MoneroOutput>>;
}
