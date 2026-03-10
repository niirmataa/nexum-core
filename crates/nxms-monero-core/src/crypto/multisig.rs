use sha3::{Digest, Keccak256};

use crate::limits::tx_hex_max_len;
use crate::rpc::wallet_rpc::{SignedMultisigTx, TransferByTxid, WalletRpcClient};
use crate::types::{
    Hash, KeyImage, MoneroArbitraError, MoneroOutput, MultisigKeySet, PublicKey, Result,
    Round1Data, Round2Data, Round3Data, SecretKey,
};

const LOCAL_CRYPTO_DISABLED_REASON: &str =
    "local multisig crypto path disabled; use wallet-rpc backed flow";
const MAX_RPC_BLOB_ITEMS: usize = 16;
const MAX_RPC_BLOB_LEN: usize = 20_000;

fn local_crypto_disabled(op: &str) -> MoneroArbitraError {
    MoneroArbitraError::InvalidArgument(format!("{op} is disabled: {LOCAL_CRYPTO_DISABLED_REASON}"))
}

fn validate_blob_list(name: &str, values: &[String], expected_items: Option<usize>) -> Result<()> {
    if values.is_empty() {
        return Err(MoneroArbitraError::MissingData(format!(
            "{name} must not be empty"
        )));
    }
    if values.len() > MAX_RPC_BLOB_ITEMS {
        return Err(MoneroArbitraError::InvalidArgument(format!(
            "{name} has too many items (max {MAX_RPC_BLOB_ITEMS})"
        )));
    }
    if let Some(expected) = expected_items
        && values.len() != expected
    {
        return Err(MoneroArbitraError::InvalidArgument(format!(
            "{name} must contain exactly {expected} item(s)"
        )));
    }

    for (idx, item) in values.iter().enumerate() {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            return Err(MoneroArbitraError::InvalidArgument(format!(
                "{name}[{idx}] cannot be empty"
            )));
        }
        if trimmed.len() > MAX_RPC_BLOB_LEN {
            return Err(MoneroArbitraError::InvalidArgument(format!(
                "{name}[{idx}] too long (max {MAX_RPC_BLOB_LEN})"
            )));
        }
    }
    Ok(())
}

fn validate_hex_payload(value: &str, label: &str) -> Result<String> {
    let max_len = tx_hex_max_len();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(MoneroArbitraError::MissingData(format!(
            "{label} must not be empty"
        )));
    }
    if trimmed.len() > max_len {
        return Err(MoneroArbitraError::InvalidArgument(format!(
            "{label} too long (max {max_len} chars)"
        )));
    }
    if trimmed.len() % 2 != 0 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(MoneroArbitraError::InvalidArgument(format!(
            "{label} must be valid even-length hex"
        )));
    }
    Ok(trimmed.to_string())
}

/// Multisig engine wired for production safety:
/// all cryptographic operations must run via Monero wallet-rpc.
///
/// Local round helpers are intentionally blocked to prevent accidental use
/// of non-production placeholder cryptography.
#[derive(Debug, Clone)]
pub struct MoneroMultisigEngine {
    threshold: u16,
    total: u16,
    my_index: u16,
}

impl MoneroMultisigEngine {
    pub fn new(threshold: u16, total: u16, my_index: u16) -> Result<Self> {
        if threshold == 0 || threshold > total {
            return Err(MoneroArbitraError::InvalidArgument(
                "threshold must be in range 1..=total".to_string(),
            ));
        }
        if my_index >= total {
            return Err(MoneroArbitraError::InvalidArgument(
                "my_index must be < total".to_string(),
            ));
        }

        Ok(Self {
            threshold,
            total,
            my_index,
        })
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn total(&self) -> u16 {
        self.total
    }

    pub fn my_index(&self) -> u16 {
        self.my_index
    }

    pub fn generate_round1(&self) -> Result<Round1Data> {
        Err(local_crypto_disabled("generate_round1"))
    }

    pub fn process_round1(
        &self,
        my_round1: &Round1Data,
        others: &[Round1Data],
    ) -> Result<(Vec<SecretKey>, PublicKey)> {
        let _ = (my_round1, others);
        Err(local_crypto_disabled("process_round1"))
    }

    pub fn generate_round2(
        &self,
        partial_privkeys: &[SecretKey],
        others_round1: &[Round1Data],
    ) -> Result<Round2Data> {
        let _ = (partial_privkeys, others_round1);
        Err(local_crypto_disabled("generate_round2"))
    }

    pub fn process_round2(
        &self,
        my_round2: &Round2Data,
        others: &[Round2Data],
    ) -> Result<MultisigKeySet> {
        let _ = (my_round2, others);
        Err(local_crypto_disabled("process_round2"))
    }

    pub fn generate_round3(
        &self,
        key_set: &MultisigKeySet,
        outputs: &[MoneroOutput],
    ) -> Result<Round3Data> {
        let _ = (key_set, outputs);
        Err(local_crypto_disabled("generate_round3"))
    }

    pub fn aggregate_key_images(&self, partials: &[Round3Data]) -> Result<Vec<KeyImage>> {
        let _ = partials;
        Err(local_crypto_disabled("aggregate_key_images"))
    }

    pub fn hash_unsigned_tx(&self, payload: &[u8]) -> Hash {
        let mut hasher = Keccak256::new();
        hasher.update(b"unsigned_tx");
        hasher.update(payload);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..32]);
        out
    }

    pub async fn prepare_round1_via_wallet_rpc<C: WalletRpcClient>(
        &self,
        client: &C,
    ) -> Result<String> {
        client.prepare_multisig_flow().await
    }

    pub async fn make_round2_via_wallet_rpc<C: WalletRpcClient>(
        &self,
        client: &C,
        other_r1: &[String],
    ) -> Result<String> {
        validate_blob_list(
            "other_r1",
            other_r1,
            Some(self.total.saturating_sub(1) as usize),
        )?;
        client
            .make_multisig_flow(other_r1.to_vec(), self.threshold)
            .await
    }

    pub async fn exchange_round3_via_wallet_rpc<C: WalletRpcClient>(
        &self,
        client: &C,
        other_r2: &[String],
    ) -> Result<String> {
        validate_blob_list(
            "other_r2",
            other_r2,
            Some(self.total.saturating_sub(1) as usize),
        )?;
        client.exchange_multisig_keys_flow(other_r2.to_vec()).await
    }

    pub async fn deposit_address_via_wallet_rpc<C: WalletRpcClient>(
        &self,
        client: &C,
    ) -> Result<String> {
        client.get_address_flow().await
    }

    pub async fn balance_via_wallet_rpc<C: WalletRpcClient>(
        &self,
        client: &C,
    ) -> Result<(u64, u64)> {
        client.get_balance_flow().await
    }

    pub async fn transfer_by_txid_via_wallet_rpc<C: WalletRpcClient>(
        &self,
        client: &C,
        txid: &str,
    ) -> Result<TransferByTxid> {
        client.get_transfer_by_txid_flow(txid.to_string()).await
    }

    pub async fn finalize_multisig_via_wallet_rpc<C: WalletRpcClient>(
        &self,
        client: &C,
        multisig_info: &[String],
    ) -> Result<String> {
        validate_blob_list(
            "multisig_info",
            multisig_info,
            Some(self.total.saturating_sub(1) as usize),
        )?;
        client.finalize_multisig_flow(multisig_info.to_vec()).await
    }

    pub async fn export_multisig_info_via_wallet_rpc<C: WalletRpcClient>(
        &self,
        client: &C,
    ) -> Result<String> {
        client.export_multisig_info_flow().await
    }

    pub async fn import_multisig_info_via_wallet_rpc<C: WalletRpcClient>(
        &self,
        client: &C,
        info: &[String],
    ) -> Result<u64> {
        validate_blob_list("info", info, None)?;
        client.import_multisig_info_flow(info.to_vec()).await
    }

    pub async fn sign_multisig_via_wallet_rpc<C: WalletRpcClient>(
        &self,
        client: &C,
        tx_data_hex: &str,
    ) -> Result<SignedMultisigTx> {
        let tx_data_hex = validate_hex_payload(tx_data_hex, "tx_data_hex")?;
        client.sign_multisig_flow(tx_data_hex).await
    }

    pub async fn submit_multisig_via_wallet_rpc<C: WalletRpcClient>(
        &self,
        client: &C,
        tx_data_hex: &str,
    ) -> Result<Vec<String>> {
        let tx_data_hex = validate_hex_payload(tx_data_hex, "tx_data_hex")?;
        client.submit_multisig_flow(tx_data_hex).await
    }
}
