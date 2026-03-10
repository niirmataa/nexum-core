use crate::crypto::multisig::MoneroMultisigEngine;
use crate::rpc::wallet_rpc::{SignedMultisigTx, WalletRpcClient};
use crate::types::{
    KeyImage, MoneroArbitraError, MoneroOutput, MultisigKeySet, MultisigPolicy, PeerId, Result,
    Round1Data, Round2Data, Round3Data,
};

const LOCAL_WALLET_FLOW_DISABLED_REASON: &str =
    "local multisig wallet flow is disabled; use rpc_* methods backed by wallet-rpc";

fn local_wallet_flow_disabled(op: &str) -> MoneroArbitraError {
    MoneroArbitraError::InvalidArgument(format!(
        "{op} is disabled: {LOCAL_WALLET_FLOW_DISABLED_REASON}"
    ))
}

#[derive(Debug, Clone)]
pub enum WalletCommand {
    InitMultisig { threshold: u16, peers: Vec<PeerId> },
    ExchangeRound1 { data: Round1Data },
    ExchangeRound2 { data: Round2Data },
    ExchangeRound3 { data: Round3Data },
}

#[derive(Debug, Clone)]
pub struct WalletBootstrapResult {
    pub round1_to_broadcast: Round1Data,
}

#[derive(Debug, Clone)]
pub struct MoneroMultisigWallet {
    pub wallet_id: String,
    pub policy: MultisigPolicy,
    pub key_set: Option<MultisigKeySet>,

    engine: MoneroMultisigEngine,
}

impl MoneroMultisigWallet {
    pub fn new(
        wallet_id: impl Into<String>,
        threshold: u16,
        total_signers: u16,
        my_index: u16,
    ) -> Result<Self> {
        let policy = MultisigPolicy {
            threshold,
            total_signers,
            signers: Vec::new(),
            creation_height: 0,
        };
        let engine = MoneroMultisigEngine::new(threshold, total_signers, my_index)?;

        Ok(Self {
            wallet_id: wallet_id.into(),
            policy,
            key_set: None,
            engine,
        })
    }

    pub fn init_multisig(&mut self) -> Result<WalletBootstrapResult> {
        Err(local_wallet_flow_disabled("init_multisig"))
    }

    pub fn accept_round1(&mut self, from_peer: Round1Data) -> Result<Option<Round2Data>> {
        let _ = from_peer;
        Err(local_wallet_flow_disabled("accept_round1"))
    }

    pub fn accept_round2(
        &mut self,
        from_peer: Round2Data,
        known_outputs: &[MoneroOutput],
    ) -> Result<Option<Round3Data>> {
        let _ = (from_peer, known_outputs);
        Err(local_wallet_flow_disabled("accept_round2"))
    }

    pub fn accept_round3(&mut self, from_peer: Round3Data) -> Result<Option<Vec<KeyImage>>> {
        let _ = from_peer;
        Err(local_wallet_flow_disabled("accept_round3"))
    }

    pub async fn rpc_prepare_round1<C: WalletRpcClient>(&self, client: &C) -> Result<String> {
        self.engine.prepare_round1_via_wallet_rpc(client).await
    }

    pub async fn rpc_make_round2<C: WalletRpcClient>(
        &self,
        client: &C,
        other_r1: &[String],
    ) -> Result<String> {
        self.engine
            .make_round2_via_wallet_rpc(client, other_r1)
            .await
    }

    pub async fn rpc_exchange_round3<C: WalletRpcClient>(
        &self,
        client: &C,
        other_r2: &[String],
    ) -> Result<String> {
        self.engine
            .exchange_round3_via_wallet_rpc(client, other_r2)
            .await
    }

    pub async fn rpc_deposit_address<C: WalletRpcClient>(&self, client: &C) -> Result<String> {
        self.engine.deposit_address_via_wallet_rpc(client).await
    }

    pub async fn rpc_finalize_multisig<C: WalletRpcClient>(
        &self,
        client: &C,
        multisig_info: &[String],
    ) -> Result<String> {
        self.engine
            .finalize_multisig_via_wallet_rpc(client, multisig_info)
            .await
    }

    pub async fn rpc_export_multisig_info<C: WalletRpcClient>(&self, client: &C) -> Result<String> {
        self.engine
            .export_multisig_info_via_wallet_rpc(client)
            .await
    }

    pub async fn rpc_import_multisig_info<C: WalletRpcClient>(
        &self,
        client: &C,
        info: &[String],
    ) -> Result<u64> {
        self.engine
            .import_multisig_info_via_wallet_rpc(client, info)
            .await
    }

    pub async fn rpc_sign_multisig_tx<C: WalletRpcClient>(
        &self,
        client: &C,
        tx_data_hex: &str,
    ) -> Result<SignedMultisigTx> {
        self.engine
            .sign_multisig_via_wallet_rpc(client, tx_data_hex)
            .await
    }

    pub async fn rpc_submit_multisig_tx<C: WalletRpcClient>(
        &self,
        client: &C,
        tx_data_hex: &str,
    ) -> Result<Vec<String>> {
        self.engine
            .submit_multisig_via_wallet_rpc(client, tx_data_hex)
            .await
    }
}
