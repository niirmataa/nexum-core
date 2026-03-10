use crate::multisig::state::EscrowContract;
use crate::types::{MoneroTransaction, Result, WalletId};

pub trait MoneroStorage: Send + Sync {
    fn load_contract(&self, id: u64) -> Result<Option<EscrowContract>>;
    fn save_contract(&self, contract: &EscrowContract) -> Result<()>;

    fn load_transactions(&self, wallet_id: &WalletId) -> Result<Vec<MoneroTransaction>>;
    fn save_transaction(&self, tx: &MoneroTransaction) -> Result<()>;
}
