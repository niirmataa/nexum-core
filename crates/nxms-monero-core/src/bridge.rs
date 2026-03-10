use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::fee_policy::escrow_fee_policy_from_env;
use crate::multisig::state::EscrowContract;
use crate::rpc::wallet_runtime::wallet_rpc_call;
use crate::types::{EscrowParticipant, EscrowState, MoneroArbitraError, Result};
use crate::xmr_address::is_valid_xmr_address;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgePrepareR1Request {
    pub escrow_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgePrepareR1Response {
    pub multisig_info: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeFinalizeMultisigRequest {
    pub escrow_id: u64,
    pub multisig_info: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeFinalizeMultisigResponse {
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeExportMultisigInfoRequest {
    pub escrow_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeExportMultisigInfoResponse {
    pub info: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeImportMultisigInfoRequest {
    pub escrow_id: u64,
    pub info: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeImportMultisigInfoResponse {
    pub n_outputs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSignMultisigRequest {
    pub escrow_id: u64,
    pub tx_data_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSignMultisigResponse {
    pub tx_data_hex: String,
    pub tx_hash_list: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSubmitMultisigRequest {
    pub escrow_id: u64,
    pub tx_data_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSubmitMultisigResponse {
    pub tx_hash_list: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSubmitR1Request {
    pub escrow_id: u64,
    pub state: String,
    pub actor_role: String,
    pub multisig_info: String,
    pub refund_address: Option<String>,

    pub xmr_r1_buyer: Option<String>,
    pub xmr_r1_seller: Option<String>,
    pub xmr_r1_arbiter: Option<String>,
    pub xmr_r2_arbiter: Option<String>,

    pub refund_address_buyer: Option<String>,
    pub refund_address_seller: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSubmitR1Response {
    pub state: String,
    pub xmr_r1_buyer: Option<String>,
    pub xmr_r1_seller: Option<String>,
    pub xmr_r1_arbiter: Option<String>,
    pub xmr_r2_arbiter: Option<String>,
    pub refund_address_buyer: Option<String>,
    pub refund_address_seller: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSubmitR2Request {
    pub escrow_id: u64,
    pub state: String,
    pub actor_role: String,
    pub multisig_info: String,

    pub xmr_r2_buyer: Option<String>,
    pub xmr_r2_seller: Option<String>,
    pub xmr_r2_arbiter: Option<String>,
    pub xmr_r3_arbiter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSubmitR2Response {
    pub state: String,
    pub xmr_r2_buyer: Option<String>,
    pub xmr_r2_seller: Option<String>,
    pub xmr_r2_arbiter: Option<String>,
    pub xmr_r3_arbiter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSubmitR3Request {
    pub escrow_id: u64,
    pub state: String,
    pub actor_role: String,
    pub multisig_info: String,

    pub xmr_r3_buyer: Option<String>,
    pub xmr_r3_seller: Option<String>,
    pub xmr_r3_arbiter: Option<String>,
    pub deposit_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSubmitR3Response {
    pub state: String,
    pub xmr_r3_buyer: Option<String>,
    pub xmr_r3_seller: Option<String>,
    pub xmr_r3_arbiter: Option<String>,
    pub deposit_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDisputeRequest {
    pub state: String,
    pub actor_role: String,
    pub reason: Option<String>,
    pub dispute_opened_by: Option<String>,
    pub dispute_reason: Option<String>,
    pub dispute_opened_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDisputeResponse {
    pub state: String,
    pub dispute_opened_by: Option<String>,
    pub dispute_reason: Option<String>,
    pub dispute_opened_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfirmReleaseRequest {
    pub state: String,
    pub actor_role: String,
    pub txid: Option<String>,

    pub release_txid: Option<String>,
    pub release_confirm_buyer: bool,
    pub release_confirm_seller: bool,
    pub release_confirm_arbiter: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfirmReleaseResponse {
    pub state: String,
    pub release_txid: Option<String>,
    pub release_confirm_buyer: bool,
    pub release_confirm_seller: bool,
    pub release_confirm_arbiter: bool,
    pub confirmations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfirmRefundRequest {
    pub state: String,
    pub actor_role: String,
    pub txid: Option<String>,

    pub refund_txid: Option<String>,
    pub refund_confirm_buyer: bool,
    pub refund_confirm_seller: bool,
    pub refund_confirm_arbiter: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfirmRefundResponse {
    pub state: String,
    pub refund_txid: Option<String>,
    pub refund_confirm_buyer: bool,
    pub refund_confirm_seller: bool,
    pub refund_confirm_arbiter: bool,
    pub confirmations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeFundedRequest {
    pub state: String,
    pub amount_atomic: u64,
    pub unlocked_balance: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeFundedResponse {
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeValidateAddressRequest {
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeValidateAddressResponse {
    pub valid: bool,
}

pub async fn prepare_r1(req: BridgePrepareR1Request) -> Result<BridgePrepareR1Response> {
    let multisig_info = wallet_rpc_call(
        req.escrow_id,
        "prepare_multisig",
        |engine, client| async move { engine.prepare_round1_via_wallet_rpc(client.as_ref()).await },
    )
    .await?;
    Ok(BridgePrepareR1Response { multisig_info })
}

pub async fn finalize_multisig(
    req: BridgeFinalizeMultisigRequest,
) -> Result<BridgeFinalizeMultisigResponse> {
    let multisig_info = req.multisig_info;
    let address = wallet_rpc_call(
        req.escrow_id,
        "finalize_multisig",
        |engine, client| async move {
            engine
                .finalize_multisig_via_wallet_rpc(client.as_ref(), &multisig_info)
                .await
        },
    )
    .await?;
    Ok(BridgeFinalizeMultisigResponse { address })
}

pub async fn export_multisig_info(
    req: BridgeExportMultisigInfoRequest,
) -> Result<BridgeExportMultisigInfoResponse> {
    let info = wallet_rpc_call(
        req.escrow_id,
        "export_multisig_info",
        |engine, client| async move {
            engine
                .export_multisig_info_via_wallet_rpc(client.as_ref())
                .await
        },
    )
    .await?;
    Ok(BridgeExportMultisigInfoResponse { info })
}

pub async fn import_multisig_info(
    req: BridgeImportMultisigInfoRequest,
) -> Result<BridgeImportMultisigInfoResponse> {
    let info = req.info;
    let n_outputs = wallet_rpc_call(
        req.escrow_id,
        "import_multisig_info",
        |engine, client| async move {
            engine
                .import_multisig_info_via_wallet_rpc(client.as_ref(), &info)
                .await
        },
    )
    .await?;
    Ok(BridgeImportMultisigInfoResponse { n_outputs })
}

pub async fn sign_multisig(req: BridgeSignMultisigRequest) -> Result<BridgeSignMultisigResponse> {
    let tx_data_hex = req.tx_data_hex;
    let signed = wallet_rpc_call(
        req.escrow_id,
        "sign_multisig",
        |engine, client| async move {
            engine
                .sign_multisig_via_wallet_rpc(client.as_ref(), &tx_data_hex)
                .await
        },
    )
    .await?;
    Ok(BridgeSignMultisigResponse {
        tx_data_hex: signed.tx_data_hex,
        tx_hash_list: signed.tx_hash_list,
    })
}

pub async fn submit_multisig(
    req: BridgeSubmitMultisigRequest,
) -> Result<BridgeSubmitMultisigResponse> {
    let tx_data_hex = req.tx_data_hex;
    let tx_hash_list = wallet_rpc_call(
        req.escrow_id,
        "submit_multisig",
        |engine, client| async move {
            engine
                .submit_multisig_via_wallet_rpc(client.as_ref(), &tx_data_hex)
                .await
        },
    )
    .await?;
    Ok(BridgeSubmitMultisigResponse { tx_hash_list })
}

pub async fn submit_r1(req: BridgeSubmitR1Request) -> Result<BridgeSubmitR1Response> {
    let escrow_id = req.escrow_id;
    let mut c = EscrowContract::new_xmr(req.escrow_id, "buyer", "seller", "server", 0);
    c.state = parse_state(&req.state)?;
    c.xmr_r1_buyer = req.xmr_r1_buyer;
    c.xmr_r1_seller = req.xmr_r1_seller;
    c.xmr_r1_arbiter = req.xmr_r1_arbiter;
    c.xmr_r2_arbiter = req.xmr_r2_arbiter;
    c.refund_address_buyer = req.refund_address_buyer;
    c.refund_address_seller = req.refund_address_seller;

    let actor = parse_participant(&req.actor_role)?;
    match actor {
        EscrowParticipant::Buyer | EscrowParticipant::Seller => {
            c.submit_round1(actor, req.multisig_info, req.refund_address)?;
        }
        EscrowParticipant::Arbiter => {
            c.set_arbiter_round1(req.multisig_info)?;
        }
    }

    if c.xmr_r1_buyer.is_some()
        && c.xmr_r1_seller.is_some()
        && c.xmr_r1_arbiter.is_some()
        && c.xmr_r2_arbiter.is_none()
    {
        let r2_inputs = vec![
            c.xmr_r1_buyer.clone().ok_or_else(|| {
                MoneroArbitraError::MissingData("xmr_r1_buyer missing".to_string())
            })?,
            c.xmr_r1_seller.clone().ok_or_else(|| {
                MoneroArbitraError::MissingData("xmr_r1_seller missing".to_string())
            })?,
        ];
        let r2 = wallet_rpc_call(escrow_id, "make_multisig", |engine, client| async move {
            engine
                .make_round2_via_wallet_rpc(client.as_ref(), &r2_inputs)
                .await
        })
        .await?;
        c.set_arbiter_round2(r2)?;
    }

    Ok(BridgeSubmitR1Response {
        state: format_state(&c.state).to_string(),
        xmr_r1_buyer: c.xmr_r1_buyer,
        xmr_r1_seller: c.xmr_r1_seller,
        xmr_r1_arbiter: c.xmr_r1_arbiter,
        xmr_r2_arbiter: c.xmr_r2_arbiter,
        refund_address_buyer: c.refund_address_buyer,
        refund_address_seller: c.refund_address_seller,
    })
}

pub async fn submit_r2(req: BridgeSubmitR2Request) -> Result<BridgeSubmitR2Response> {
    let escrow_id = req.escrow_id;
    let mut c = EscrowContract::new_xmr(req.escrow_id, "buyer", "seller", "server", 0);
    c.state = parse_state(&req.state)?;
    c.xmr_r2_buyer = req.xmr_r2_buyer;
    c.xmr_r2_seller = req.xmr_r2_seller;
    c.xmr_r2_arbiter = req.xmr_r2_arbiter;
    c.xmr_r3_arbiter = req.xmr_r3_arbiter;

    let actor = parse_participant(&req.actor_role)?;
    match actor {
        EscrowParticipant::Buyer | EscrowParticipant::Seller => {
            c.submit_round2(actor, req.multisig_info)?;
        }
        EscrowParticipant::Arbiter => {
            c.set_arbiter_round2(req.multisig_info)?;
        }
    }

    if c.xmr_r2_buyer.is_some()
        && c.xmr_r2_seller.is_some()
        && c.xmr_r2_arbiter.is_some()
        && c.xmr_r3_arbiter.is_none()
    {
        let r3_inputs = vec![
            c.xmr_r2_buyer.clone().ok_or_else(|| {
                MoneroArbitraError::MissingData("xmr_r2_buyer missing".to_string())
            })?,
            c.xmr_r2_seller.clone().ok_or_else(|| {
                MoneroArbitraError::MissingData("xmr_r2_seller missing".to_string())
            })?,
        ];
        let r3 = wallet_rpc_call(
            escrow_id,
            "exchange_multisig_keys",
            |engine, client| async move {
                engine
                    .exchange_round3_via_wallet_rpc(client.as_ref(), &r3_inputs)
                    .await
            },
        )
        .await?;
        c.set_arbiter_round3(r3)?;
    }

    Ok(BridgeSubmitR2Response {
        state: format_state(&c.state).to_string(),
        xmr_r2_buyer: c.xmr_r2_buyer,
        xmr_r2_seller: c.xmr_r2_seller,
        xmr_r2_arbiter: c.xmr_r2_arbiter,
        xmr_r3_arbiter: c.xmr_r3_arbiter,
    })
}

pub async fn submit_r3(req: BridgeSubmitR3Request) -> Result<BridgeSubmitR3Response> {
    let escrow_id = req.escrow_id;
    let mut c = EscrowContract::new_xmr(req.escrow_id, "buyer", "seller", "server", 0);
    c.state = parse_state(&req.state)?;
    c.xmr_r3_buyer = req.xmr_r3_buyer;
    c.xmr_r3_seller = req.xmr_r3_seller;
    c.xmr_r3_arbiter = req.xmr_r3_arbiter;
    c.deposit_address = req.deposit_address;

    let actor = parse_participant(&req.actor_role)?;
    match actor {
        EscrowParticipant::Buyer | EscrowParticipant::Seller => {
            c.submit_round3(actor, req.multisig_info)?;
        }
        EscrowParticipant::Arbiter => {
            c.set_arbiter_round3(req.multisig_info)?;
        }
    }

    if c.xmr_r3_buyer.is_some()
        && c.xmr_r3_seller.is_some()
        && c.xmr_r3_arbiter.is_some()
        && c.deposit_address.is_none()
    {
        let finalize_inputs = vec![
            c.xmr_r3_buyer.clone().ok_or_else(|| {
                MoneroArbitraError::MissingData("xmr_r3_buyer missing".to_string())
            })?,
            c.xmr_r3_seller.clone().ok_or_else(|| {
                MoneroArbitraError::MissingData("xmr_r3_seller missing".to_string())
            })?,
        ];

        let deposit = wallet_rpc_call(
            escrow_id,
            "finalize_or_address_multisig",
            |engine, client| async move {
                match engine
                    .finalize_multisig_via_wallet_rpc(client.as_ref(), &finalize_inputs)
                    .await
                {
                    Ok(address) => Ok(address),
                    Err(err) if is_finalize_fallback_error(&err) => {
                        warn!(
                            "finalize_multisig fallback to get_address for escrow {}: {}",
                            escrow_id, err
                        );
                        engine.deposit_address_via_wallet_rpc(client.as_ref()).await
                    }
                    Err(err) => Err(err),
                }
            },
        )
        .await?;
        c.set_deposit_address(deposit)?;
    }

    Ok(BridgeSubmitR3Response {
        state: format_state(&c.state).to_string(),
        xmr_r3_buyer: c.xmr_r3_buyer,
        xmr_r3_seller: c.xmr_r3_seller,
        xmr_r3_arbiter: c.xmr_r3_arbiter,
        deposit_address: c.deposit_address,
    })
}

pub fn dispute(req: BridgeDisputeRequest) -> Result<BridgeDisputeResponse> {
    let mut c = EscrowContract::new_xmr(0, "buyer", "seller", "server", 0);
    c.state = parse_state(&req.state)?;
    c.import_dispute_snapshot(
        parse_participant_opt(req.dispute_opened_by.as_deref())?,
        req.dispute_reason,
        req.dispute_opened_at,
    )?;
    c.open_dispute(parse_participant(&req.actor_role)?, req.reason)?;
    let (opened_by, reason, opened_at) = c.dispute_snapshot();
    Ok(BridgeDisputeResponse {
        state: format_state(&c.state).to_string(),
        dispute_opened_by: opened_by.map(format_participant).map(str::to_string),
        dispute_reason: reason,
        dispute_opened_at: opened_at,
    })
}

pub fn confirm_release(req: BridgeConfirmReleaseRequest) -> Result<BridgeConfirmReleaseResponse> {
    let mut c = EscrowContract::new_xmr(0, "buyer", "seller", "server", 0);
    c.state = parse_state(&req.state)?;
    c.import_release_snapshot(
        req.release_confirm_buyer,
        req.release_confirm_seller,
        req.release_confirm_arbiter,
        req.release_txid,
    )?;
    let (_, confirmations) = c.confirm_release(parse_participant(&req.actor_role)?, req.txid)?;
    let (buyer, seller, arbiter, txid) = c.release_snapshot();

    Ok(BridgeConfirmReleaseResponse {
        state: format_state(&c.state).to_string(),
        release_txid: txid,
        release_confirm_buyer: buyer,
        release_confirm_seller: seller,
        release_confirm_arbiter: arbiter,
        confirmations,
    })
}

pub fn confirm_refund(req: BridgeConfirmRefundRequest) -> Result<BridgeConfirmRefundResponse> {
    let mut c = EscrowContract::new_xmr(0, "buyer", "seller", "server", 0);
    c.state = parse_state(&req.state)?;
    c.import_refund_snapshot(
        req.refund_confirm_buyer,
        req.refund_confirm_seller,
        req.refund_confirm_arbiter,
        req.refund_txid,
    )?;
    let (_, confirmations) = c.confirm_refund(parse_participant(&req.actor_role)?, req.txid)?;
    let (buyer, seller, arbiter, txid) = c.refund_snapshot();

    Ok(BridgeConfirmRefundResponse {
        state: format_state(&c.state).to_string(),
        refund_txid: txid,
        refund_confirm_buyer: buyer,
        refund_confirm_seller: seller,
        refund_confirm_arbiter: arbiter,
        confirmations,
    })
}

pub fn funded_check(req: BridgeFundedRequest) -> Result<BridgeFundedResponse> {
    let mut c = EscrowContract::new_xmr(0, "buyer", "seller", "server", req.amount_atomic);
    c.state = parse_state(&req.state)?;
    let fee_policy = escrow_fee_policy_from_env()?;
    let required_funding_atomic = fee_policy.quote(req.amount_atomic)?.required_funding_atomic;

    if matches!(c.state, EscrowState::Ready) && req.unlocked_balance >= required_funding_atomic {
        let _ = c.mark_funded(req.unlocked_balance)?;
    }

    Ok(BridgeFundedResponse {
        state: format_state(&c.state).to_string(),
    })
}

pub fn validate_address(
    req: BridgeValidateAddressRequest,
) -> Result<BridgeValidateAddressResponse> {
    Ok(BridgeValidateAddressResponse {
        valid: is_valid_xmr_address(req.address.trim()),
    })
}

fn is_finalize_fallback_error(err: &MoneroArbitraError) -> bool {
    if let MoneroArbitraError::WalletRpc(rpc_err) = err {
        if rpc_err.contains_case_insensitive("already multisig")
            || rpc_err.contains_case_insensitive("already finalized")
        {
            return true;
        }
        if let crate::types::WalletRpcError::Rpc { code, message } = rpc_err
            && *code == 0
            && message.trim().is_empty()
        {
            return true;
        }
    }
    false
}

fn parse_participant(role: &str) -> Result<EscrowParticipant> {
    match role {
        "buyer" => Ok(EscrowParticipant::Buyer),
        "seller" => Ok(EscrowParticipant::Seller),
        "arbiter" => Ok(EscrowParticipant::Arbiter),
        _ => Err(MoneroArbitraError::InvalidArgument(format!(
            "unknown actor role: {role}"
        ))),
    }
}

fn parse_participant_opt(role: Option<&str>) -> Result<Option<EscrowParticipant>> {
    let Some(role) = role else {
        return Ok(None);
    };
    Ok(Some(parse_participant(role)?))
}

fn format_participant(role: EscrowParticipant) -> &'static str {
    match role {
        EscrowParticipant::Buyer => "buyer",
        EscrowParticipant::Seller => "seller",
        EscrowParticipant::Arbiter => "arbiter",
    }
}

fn parse_state(v: &str) -> Result<EscrowState> {
    match v {
        "NEW" => Ok(EscrowState::New),
        "XMR_MSIG_R1" => Ok(EscrowState::XmrMsigR1),
        "XMR_MSIG_R2" => Ok(EscrowState::XmrMsigR2),
        "XMR_MSIG_R3" => Ok(EscrowState::XmrMsigR3),
        "READY" => Ok(EscrowState::Ready),
        "FUNDED" => Ok(EscrowState::Funded),
        "RELEASED" => Ok(EscrowState::Released),
        "REFUNDED" => Ok(EscrowState::Refunded),
        "DISPUTE" => Ok(EscrowState::Dispute),
        "CLOSED" => Ok(EscrowState::Closed),
        _ => Err(MoneroArbitraError::InvalidArgument(format!(
            "unknown escrow state: {v}"
        ))),
    }
}

fn format_state(v: &EscrowState) -> &'static str {
    match v {
        EscrowState::New => "NEW",
        EscrowState::XmrMsigR1 => "XMR_MSIG_R1",
        EscrowState::XmrMsigR2 => "XMR_MSIG_R2",
        EscrowState::XmrMsigR3 => "XMR_MSIG_R3",
        EscrowState::Ready => "READY",
        EscrowState::Funded => "FUNDED",
        EscrowState::Released => "RELEASED",
        EscrowState::Refunded => "REFUNDED",
        EscrowState::Dispute => "DISPUTE",
        EscrowState::Closed => "CLOSED",
    }
}
