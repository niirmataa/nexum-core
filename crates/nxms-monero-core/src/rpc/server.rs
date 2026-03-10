use tokio::sync::mpsc;
use tracing::info;

use crate::multisig::wallet::WalletCommand;
use crate::types::Result;

/// Phase-1 RPC facade.
///
/// This server is intentionally transport-agnostic and only owns the command
/// channel toward wallet logic. HTTP/JSON-RPC binding will be added in phase 2.
#[derive(Clone)]
pub struct MoneroRpcServer {
    wallet_tx: mpsc::Sender<WalletCommand>,
}

impl MoneroRpcServer {
    pub fn new(wallet_tx: mpsc::Sender<WalletCommand>) -> Self {
        Self { wallet_tx }
    }

    pub fn wallet_tx(&self) -> mpsc::Sender<WalletCommand> {
        self.wallet_tx.clone()
    }

    pub async fn run(self, bind_addr: &str) -> Result<()> {
        info!(target: "monero_arbitra", "rpc stub listening on {bind_addr}");
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| crate::types::MoneroArbitraError::InvalidArgument(e.to_string()))?;
        Ok(())
    }
}
