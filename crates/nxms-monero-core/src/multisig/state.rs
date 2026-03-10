use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::types::{Asset, EscrowParticipant, EscrowState, MoneroArbitraError, Result};
use crate::xmr_address::is_valid_xmr_address;

const MAX_DISPUTE_REASON_LEN: usize = 2_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscrowTransition {
    pub from: EscrowState,
    pub to: EscrowState,
    pub action: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowReport {
    pub id: u64,
    pub state: EscrowState,
    pub release_confirmations: usize,
    pub refund_confirmations: usize,
    pub deposit_address: Option<String>,
    pub release_txid: Option<String>,
    pub refund_txid: Option<String>,
    pub dispute_opened_by: Option<EscrowParticipant>,
    pub dispute_reason: Option<String>,
    pub dispute_opened_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowContract {
    pub id: u64,
    pub asset: Asset,
    pub state: EscrowState,

    pub buyer_nick: String,
    pub seller_nick: String,
    pub arbiter_nick: String,

    pub amount_atomic: u64,
    pub memo: Option<String>,

    pub refund_address_buyer: Option<String>,
    pub refund_address_seller: Option<String>,

    pub xmr_r1_buyer: Option<String>,
    pub xmr_r1_seller: Option<String>,
    pub xmr_r1_arbiter: Option<String>,

    pub xmr_r2_buyer: Option<String>,
    pub xmr_r2_seller: Option<String>,
    pub xmr_r2_arbiter: Option<String>,

    pub xmr_r3_buyer: Option<String>,
    pub xmr_r3_seller: Option<String>,
    pub xmr_r3_arbiter: Option<String>,

    pub deposit_address: Option<String>,

    pub release_txid: Option<String>,
    pub refund_txid: Option<String>,
    pub dispute_opened_by: Option<EscrowParticipant>,
    pub dispute_reason: Option<String>,
    pub dispute_opened_at: Option<i64>,

    release_confirmations: HashSet<EscrowParticipant>,
    refund_confirmations: HashSet<EscrowParticipant>,
}

impl EscrowContract {
    pub fn new_xmr(
        id: u64,
        buyer_nick: impl Into<String>,
        seller_nick: impl Into<String>,
        arbiter_nick: impl Into<String>,
        amount_atomic: u64,
    ) -> Self {
        Self {
            id,
            asset: Asset::Xmr,
            state: EscrowState::New,
            buyer_nick: buyer_nick.into(),
            seller_nick: seller_nick.into(),
            arbiter_nick: arbiter_nick.into(),
            amount_atomic,
            memo: None,
            refund_address_buyer: None,
            refund_address_seller: None,
            xmr_r1_buyer: None,
            xmr_r1_seller: None,
            xmr_r1_arbiter: None,
            xmr_r2_buyer: None,
            xmr_r2_seller: None,
            xmr_r2_arbiter: None,
            xmr_r3_buyer: None,
            xmr_r3_seller: None,
            xmr_r3_arbiter: None,
            deposit_address: None,
            release_txid: None,
            refund_txid: None,
            dispute_opened_by: None,
            dispute_reason: None,
            dispute_opened_at: None,
            release_confirmations: HashSet::new(),
            refund_confirmations: HashSet::new(),
        }
    }

    pub fn set_arbiter_round1(&mut self, multisig_info: String) -> Result<EscrowTransition> {
        if self.asset != Asset::Xmr {
            return Err(MoneroArbitraError::InvalidArgument(
                "round1 only valid for XMR".to_string(),
            ));
        }

        let prev = self.state.clone();
        ensure_state_in(
            &self.state,
            &[EscrowState::New, EscrowState::XmrMsigR1],
            "set_arbiter_round1",
        )?;
        set_once(
            &mut self.xmr_r1_arbiter,
            multisig_info,
            true,
            "xmr_r1_arbiter",
        )?;
        self.state = EscrowState::XmrMsigR1;

        Ok(EscrowTransition {
            from: prev,
            to: self.state.clone(),
            action: "xmr_r1_arbiter".to_string(),
        })
    }

    pub fn submit_round1(
        &mut self,
        who: EscrowParticipant,
        multisig_info: String,
        refund_address: Option<String>,
    ) -> Result<EscrowTransition> {
        if self.asset != Asset::Xmr {
            return Err(MoneroArbitraError::InvalidArgument(
                "round1 only valid for XMR".to_string(),
            ));
        }

        let prev = self.state.clone();
        ensure_state_in(
            &self.state,
            &[EscrowState::New, EscrowState::XmrMsigR1],
            "submit_round1",
        )?;

        match who {
            EscrowParticipant::Buyer => {
                set_once(&mut self.xmr_r1_buyer, multisig_info, true, "xmr_r1_buyer")?;
                set_refund_once(
                    &mut self.refund_address_buyer,
                    refund_address,
                    "refund_address_buyer",
                )?;
            }
            EscrowParticipant::Seller => {
                set_once(
                    &mut self.xmr_r1_seller,
                    multisig_info,
                    true,
                    "xmr_r1_seller",
                )?;
                set_refund_once(
                    &mut self.refund_address_seller,
                    refund_address,
                    "refund_address_seller",
                )?;
            }
            EscrowParticipant::Arbiter => {
                return Err(MoneroArbitraError::InvalidArgument(
                    "arbiter should use set_arbiter_round1".to_string(),
                ));
            }
        }

        self.state = EscrowState::XmrMsigR1;

        Ok(EscrowTransition {
            from: prev,
            to: self.state.clone(),
            action: "xmr_r1".to_string(),
        })
    }

    pub fn set_arbiter_round2(&mut self, multisig_info: String) -> Result<EscrowTransition> {
        if self.asset != Asset::Xmr {
            return Err(MoneroArbitraError::InvalidArgument(
                "round2 only valid for XMR".to_string(),
            ));
        }
        ensure_state_in(
            &self.state,
            &[EscrowState::XmrMsigR1, EscrowState::XmrMsigR2],
            "set_arbiter_round2",
        )?;

        if self.xmr_r1_buyer.is_none()
            || self.xmr_r1_seller.is_none()
            || self.xmr_r1_arbiter.is_none()
        {
            return Err(MoneroArbitraError::MissingData(
                "round1 data incomplete".to_string(),
            ));
        }

        let prev = self.state.clone();
        set_once(
            &mut self.xmr_r2_arbiter,
            multisig_info,
            true,
            "xmr_r2_arbiter",
        )?;
        self.state = EscrowState::XmrMsigR2;

        Ok(EscrowTransition {
            from: prev,
            to: self.state.clone(),
            action: "xmr_r2_arbiter".to_string(),
        })
    }

    pub fn submit_round2(
        &mut self,
        who: EscrowParticipant,
        multisig_info: String,
    ) -> Result<EscrowTransition> {
        if self.asset != Asset::Xmr {
            return Err(MoneroArbitraError::InvalidArgument(
                "round2 only valid for XMR".to_string(),
            ));
        }

        let prev = self.state.clone();
        ensure_state_in(&self.state, &[EscrowState::XmrMsigR2], "submit_round2")?;

        match who {
            EscrowParticipant::Buyer => {
                set_once(&mut self.xmr_r2_buyer, multisig_info, true, "xmr_r2_buyer")?;
            }
            EscrowParticipant::Seller => {
                set_once(
                    &mut self.xmr_r2_seller,
                    multisig_info,
                    true,
                    "xmr_r2_seller",
                )?;
            }
            EscrowParticipant::Arbiter => {
                return Err(MoneroArbitraError::InvalidArgument(
                    "arbiter should use set_arbiter_round2".to_string(),
                ));
            }
        }

        Ok(EscrowTransition {
            from: prev,
            to: self.state.clone(),
            action: "xmr_r2".to_string(),
        })
    }

    pub fn set_arbiter_round3(&mut self, multisig_info: String) -> Result<EscrowTransition> {
        if self.asset != Asset::Xmr {
            return Err(MoneroArbitraError::InvalidArgument(
                "round3 only valid for XMR".to_string(),
            ));
        }
        ensure_state_in(
            &self.state,
            &[EscrowState::XmrMsigR2, EscrowState::XmrMsigR3],
            "set_arbiter_round3",
        )?;

        if self.xmr_r2_buyer.is_none()
            || self.xmr_r2_seller.is_none()
            || self.xmr_r2_arbiter.is_none()
        {
            return Err(MoneroArbitraError::MissingData(
                "round2 data incomplete".to_string(),
            ));
        }

        let prev = self.state.clone();
        set_once(
            &mut self.xmr_r3_arbiter,
            multisig_info,
            true,
            "xmr_r3_arbiter",
        )?;
        self.state = EscrowState::XmrMsigR3;

        Ok(EscrowTransition {
            from: prev,
            to: self.state.clone(),
            action: "xmr_r3_arbiter".to_string(),
        })
    }

    pub fn submit_round3(
        &mut self,
        who: EscrowParticipant,
        multisig_info: String,
    ) -> Result<EscrowTransition> {
        if self.asset != Asset::Xmr {
            return Err(MoneroArbitraError::InvalidArgument(
                "round3 only valid for XMR".to_string(),
            ));
        }

        let prev = self.state.clone();
        ensure_state_in(&self.state, &[EscrowState::XmrMsigR3], "submit_round3")?;

        match who {
            EscrowParticipant::Buyer => {
                set_once(&mut self.xmr_r3_buyer, multisig_info, true, "xmr_r3_buyer")?;
            }
            EscrowParticipant::Seller => {
                set_once(
                    &mut self.xmr_r3_seller,
                    multisig_info,
                    true,
                    "xmr_r3_seller",
                )?;
            }
            EscrowParticipant::Arbiter => {
                return Err(MoneroArbitraError::InvalidArgument(
                    "arbiter should use set_arbiter_round3".to_string(),
                ));
            }
        }

        Ok(EscrowTransition {
            from: prev,
            to: self.state.clone(),
            action: "xmr_r3".to_string(),
        })
    }

    pub fn set_deposit_address(&mut self, address: String) -> Result<EscrowTransition> {
        if self.asset != Asset::Xmr {
            return Err(MoneroArbitraError::InvalidArgument(
                "deposit address only valid for XMR".to_string(),
            ));
        }
        ensure_state_in(
            &self.state,
            &[EscrowState::XmrMsigR3, EscrowState::Ready],
            "set_deposit_address",
        )?;

        if self.xmr_r3_buyer.is_none()
            || self.xmr_r3_seller.is_none()
            || self.xmr_r3_arbiter.is_none()
        {
            return Err(MoneroArbitraError::MissingData(
                "round3 data incomplete".to_string(),
            ));
        }
        let normalized = address.trim();
        if !is_xmr_address(normalized) {
            return Err(MoneroArbitraError::InvalidArgument(
                "invalid deposit address".to_string(),
            ));
        }

        let prev = self.state.clone();
        set_once(
            &mut self.deposit_address,
            normalized.to_string(),
            true,
            "deposit_address",
        )?;
        self.state = EscrowState::Ready;

        Ok(EscrowTransition {
            from: prev,
            to: self.state.clone(),
            action: "deposit_address".to_string(),
        })
    }

    pub fn mark_funded(&mut self, unlocked_balance: u64) -> Result<EscrowTransition> {
        let prev = self.state.clone();
        ensure_state_in(&self.state, &[EscrowState::Ready], "mark_funded")?;

        if unlocked_balance < self.amount_atomic {
            return Err(MoneroArbitraError::InsufficientBalance {
                available: unlocked_balance,
                needed: self.amount_atomic,
            });
        }

        self.state = EscrowState::Funded;
        Ok(EscrowTransition {
            from: prev,
            to: self.state.clone(),
            action: "funded".to_string(),
        })
    }

    pub fn open_dispute(
        &mut self,
        who: EscrowParticipant,
        reason: Option<String>,
    ) -> Result<EscrowTransition> {
        let prev = self.state.clone();
        ensure_state_in(
            &self.state,
            &[
                EscrowState::Ready,
                EscrowState::Funded,
                EscrowState::Dispute,
            ],
            "open_dispute",
        )?;
        let normalized_reason = normalize_dispute_reason(reason)?;
        if let Some(existing) = self.dispute_opened_by {
            if existing != who {
                return Err(MoneroArbitraError::Conflict(
                    "dispute already opened by a different participant".to_string(),
                ));
            }
        } else {
            self.dispute_opened_by = Some(who);
        }

        if let Some(incoming_reason) = normalized_reason {
            match self.dispute_reason.as_deref() {
                Some(current) if current != incoming_reason => {
                    return Err(MoneroArbitraError::Conflict(
                        "dispute reason already set to a different value".to_string(),
                    ));
                }
                Some(_) => {}
                None => self.dispute_reason = Some(incoming_reason),
            }
        }

        if self.dispute_opened_at.is_none() {
            self.dispute_opened_at = Some(now_ts());
        }
        self.state = EscrowState::Dispute;

        Ok(EscrowTransition {
            from: prev,
            to: self.state.clone(),
            action: "dispute".to_string(),
        })
    }

    pub fn confirm_release(
        &mut self,
        who: EscrowParticipant,
        txid: Option<String>,
    ) -> Result<(EscrowTransition, usize)> {
        let prev = self.state.clone();

        if self.state == EscrowState::Refunded {
            return Err(MoneroArbitraError::InvalidArgument(
                "escrow already refunded".to_string(),
            ));
        }

        ensure_state_in(
            &self.state,
            &[
                EscrowState::Funded,
                EscrowState::Dispute,
                EscrowState::Released,
            ],
            "confirm_release",
        )?;

        if let Some(v) = txid {
            validate_txid(&v)?;
            set_once(&mut self.release_txid, v, true, "release_txid")?;
        }

        self.release_confirmations.insert(who);
        if self.release_confirmations.len() >= 2 {
            self.state = EscrowState::Released;
        }

        Ok((
            EscrowTransition {
                from: prev,
                to: self.state.clone(),
                action: "release_confirm".to_string(),
            },
            self.release_confirmations.len(),
        ))
    }

    pub fn import_dispute_snapshot(
        &mut self,
        opened_by: Option<EscrowParticipant>,
        reason: Option<String>,
        opened_at: Option<i64>,
    ) -> Result<()> {
        if let Some(ts) = opened_at
            && ts <= 0
        {
            return Err(MoneroArbitraError::InvalidArgument(
                "dispute_opened_at must be > 0".to_string(),
            ));
        }
        self.dispute_opened_by = opened_by;
        self.dispute_reason = normalize_dispute_reason(reason)?;
        self.dispute_opened_at = opened_at;
        Ok(())
    }

    pub fn dispute_snapshot(&self) -> (Option<EscrowParticipant>, Option<String>, Option<i64>) {
        (
            self.dispute_opened_by,
            self.dispute_reason.clone(),
            self.dispute_opened_at,
        )
    }

    pub fn import_release_snapshot(
        &mut self,
        buyer: bool,
        seller: bool,
        arbiter: bool,
        txid: Option<String>,
    ) -> Result<()> {
        self.release_confirmations.clear();
        if buyer {
            self.release_confirmations.insert(EscrowParticipant::Buyer);
        }
        if seller {
            self.release_confirmations.insert(EscrowParticipant::Seller);
        }
        if arbiter {
            self.release_confirmations
                .insert(EscrowParticipant::Arbiter);
        }
        if let Some(v) = txid {
            validate_txid(&v)?;
            self.release_txid = Some(v);
        } else {
            self.release_txid = None;
        }
        Ok(())
    }

    pub fn release_snapshot(&self) -> (bool, bool, bool, Option<String>) {
        (
            self.release_confirmations
                .contains(&EscrowParticipant::Buyer),
            self.release_confirmations
                .contains(&EscrowParticipant::Seller),
            self.release_confirmations
                .contains(&EscrowParticipant::Arbiter),
            self.release_txid.clone(),
        )
    }

    pub fn confirm_refund(
        &mut self,
        who: EscrowParticipant,
        txid: Option<String>,
    ) -> Result<(EscrowTransition, usize)> {
        let prev = self.state.clone();

        if self.state == EscrowState::Released {
            return Err(MoneroArbitraError::InvalidArgument(
                "escrow already released".to_string(),
            ));
        }

        ensure_state_in(
            &self.state,
            &[
                EscrowState::Funded,
                EscrowState::Dispute,
                EscrowState::Refunded,
            ],
            "confirm_refund",
        )?;

        if let Some(v) = txid {
            validate_txid(&v)?;
            set_once(&mut self.refund_txid, v, true, "refund_txid")?;
        }

        self.refund_confirmations.insert(who);
        if self.refund_confirmations.len() >= 2 {
            self.state = EscrowState::Refunded;
        }

        Ok((
            EscrowTransition {
                from: prev,
                to: self.state.clone(),
                action: "refund_confirm".to_string(),
            },
            self.refund_confirmations.len(),
        ))
    }

    pub fn import_refund_snapshot(
        &mut self,
        buyer: bool,
        seller: bool,
        arbiter: bool,
        txid: Option<String>,
    ) -> Result<()> {
        self.refund_confirmations.clear();
        if buyer {
            self.refund_confirmations.insert(EscrowParticipant::Buyer);
        }
        if seller {
            self.refund_confirmations.insert(EscrowParticipant::Seller);
        }
        if arbiter {
            self.refund_confirmations.insert(EscrowParticipant::Arbiter);
        }
        if let Some(v) = txid {
            validate_txid(&v)?;
            self.refund_txid = Some(v);
        } else {
            self.refund_txid = None;
        }
        Ok(())
    }

    pub fn refund_snapshot(&self) -> (bool, bool, bool, Option<String>) {
        (
            self.refund_confirmations
                .contains(&EscrowParticipant::Buyer),
            self.refund_confirmations
                .contains(&EscrowParticipant::Seller),
            self.refund_confirmations
                .contains(&EscrowParticipant::Arbiter),
            self.refund_txid.clone(),
        )
    }

    pub fn report(&self) -> EscrowReport {
        EscrowReport {
            id: self.id,
            state: self.state.clone(),
            release_confirmations: self.release_confirmations.len(),
            refund_confirmations: self.refund_confirmations.len(),
            deposit_address: self.deposit_address.clone(),
            release_txid: self.release_txid.clone(),
            refund_txid: self.refund_txid.clone(),
            dispute_opened_by: self.dispute_opened_by,
            dispute_reason: self.dispute_reason.clone(),
            dispute_opened_at: self.dispute_opened_at,
        }
    }
}

fn ensure_state_in(state: &EscrowState, allowed: &[EscrowState], op: &str) -> Result<()> {
    if allowed.contains(state) {
        return Ok(());
    }

    Err(MoneroArbitraError::InvalidArgument(format!(
        "bad state for {op}: {state:?}"
    )))
}

fn set_once(
    slot: &mut Option<String>,
    incoming: String,
    require_non_empty: bool,
    label: &str,
) -> Result<()> {
    if require_non_empty && incoming.trim().is_empty() {
        return Err(MoneroArbitraError::InvalidArgument(format!(
            "{label} cannot be empty"
        )));
    }

    match slot {
        Some(current) if current != &incoming => Err(MoneroArbitraError::Conflict(format!(
            "different value already stored for {label}"
        ))),
        Some(_) => Ok(()),
        None => {
            *slot = Some(incoming);
            Ok(())
        }
    }
}

fn set_refund_once(slot: &mut Option<String>, incoming: Option<String>, label: &str) -> Result<()> {
    let Some(refund) = incoming else {
        return Ok(());
    };

    let normalized = refund.trim();
    if normalized.is_empty() {
        return Ok(());
    }
    if !is_xmr_address(normalized) {
        return Err(MoneroArbitraError::InvalidArgument(format!(
            "invalid refund address for {label}"
        )));
    }

    match slot {
        Some(current) if current != normalized => Err(MoneroArbitraError::Conflict(format!(
            "different value already stored for {label}"
        ))),
        Some(_) => Ok(()),
        None => {
            *slot = Some(normalized.to_string());
            Ok(())
        }
    }
}

fn validate_txid(txid: &str) -> Result<()> {
    if txid.len() == 64 && txid.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(MoneroArbitraError::InvalidTxid)
    }
}

fn normalize_dispute_reason(reason: Option<String>) -> Result<Option<String>> {
    let Some(raw_reason) = reason else {
        return Ok(None);
    };
    let trimmed = raw_reason.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > MAX_DISPUTE_REASON_LEN {
        return Err(MoneroArbitraError::InvalidArgument(format!(
            "reason too long (max {MAX_DISPUTE_REASON_LEN})"
        )));
    }
    Ok(Some(trimmed.to_string()))
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn is_xmr_address(addr: &str) -> bool {
    is_valid_xmr_address(addr)
}
