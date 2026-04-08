use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowState {
    New,
    PrepareCollected,
    MakeCollected,
    ExchangeR1Collected,
    ExchangeR2Collected,
    FinalizedReady,
    Funded,
    TxSignPending,
    TxSignedQuorum,
    Submitted,
    Confirmed,
    FailedDeadLetter,
}

impl WorkflowState {
    pub fn as_str(self) -> &'static str {
        match self {
            WorkflowState::New => "new",
            WorkflowState::PrepareCollected => "prepare_collected",
            WorkflowState::MakeCollected => "make_collected",
            WorkflowState::ExchangeR1Collected => "exchange_r1_collected",
            WorkflowState::ExchangeR2Collected => "exchange_r2_collected",
            WorkflowState::FinalizedReady => "finalized_ready",
            WorkflowState::Funded => "funded",
            WorkflowState::TxSignPending => "tx_sign_pending",
            WorkflowState::TxSignedQuorum => "tx_signed_quorum",
            WorkflowState::Submitted => "submitted",
            WorkflowState::Confirmed => "confirmed",
            WorkflowState::FailedDeadLetter => "failed_dead_letter",
        }
    }

    pub fn can_transition_to(self, to: WorkflowState) -> bool {
        use WorkflowState::*;
        match (self, to) {
            (New, PrepareCollected)
            | (PrepareCollected, MakeCollected)
            | (MakeCollected, ExchangeR1Collected)
            | (ExchangeR1Collected, ExchangeR2Collected)
            | (ExchangeR2Collected, FinalizedReady)
            | (FinalizedReady, Funded)
            | (Funded, TxSignPending)
            | (TxSignPending, TxSignedQuorum)
            | (TxSignedQuorum, Submitted)
            | (Submitted, Confirmed) => true,
            (Confirmed, FailedDeadLetter) => false,
            (FailedDeadLetter, _) => false,
            (_, FailedDeadLetter) => true,
            _ => false,
        }
    }
}

impl FromStr for WorkflowState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_ascii_lowercase();
        match s.as_str() {
            "new" => Ok(WorkflowState::New),
            "prepare_collected" => Ok(WorkflowState::PrepareCollected),
            "make_collected" => Ok(WorkflowState::MakeCollected),
            "exchange_r1_collected" => Ok(WorkflowState::ExchangeR1Collected),
            "exchange_r2_collected" => Ok(WorkflowState::ExchangeR2Collected),
            "finalized_ready" => Ok(WorkflowState::FinalizedReady),
            "funded" => Ok(WorkflowState::Funded),
            "tx_sign_pending" => Ok(WorkflowState::TxSignPending),
            "tx_signed_quorum" => Ok(WorkflowState::TxSignedQuorum),
            "submitted" => Ok(WorkflowState::Submitted),
            "confirmed" => Ok(WorkflowState::Confirmed),
            "failed_dead_letter" => Ok(WorkflowState::FailedDeadLetter),
            _ => Err(format!("unknown workflow state '{s}'")),
        }
    }
}

pub fn expected_msg_type_for_state(state: WorkflowState) -> Option<&'static str> {
    use WorkflowState::*;
    match state {
        PrepareCollected => Some("prepare_info"),
        MakeCollected => Some("make_info"),
        ExchangeR1Collected => Some("exchange_round1"),
        ExchangeR2Collected => Some("exchange_round2"),
        Funded => Some("escrow_funded"),
        TxSignPending => Some("tx_sign_req"),
        TxSignedQuorum => Some("tx_sign_resp"),
        _ => None,
    }
}

pub fn step_idem_key(escrow_id_hex: &str, state: WorkflowState, from_id: &str, seq: u64) -> String {
    let raw = format!("{}:{}:{}:{}", escrow_id_hex, state.as_str(), from_id, seq);
    let mut hasher = Sha3_256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn outbox_idem_key(
    escrow_id_hex: &str,
    state: WorkflowState,
    to_id: &str,
    msg_type: &str,
    payload_hash_hex: &str,
) -> String {
    let raw = format!(
        "{}:{}:{}:{}:{}",
        escrow_id_hex,
        state.as_str(),
        to_id,
        msg_type,
        payload_hash_hex
    );
    let mut hasher = Sha3_256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machine_allows_only_frozen_path() {
        assert!(WorkflowState::New.can_transition_to(WorkflowState::PrepareCollected));
        assert!(!WorkflowState::New.can_transition_to(WorkflowState::Funded));
        assert!(WorkflowState::Funded.can_transition_to(WorkflowState::TxSignPending));
        assert!(!WorkflowState::Confirmed.can_transition_to(WorkflowState::FailedDeadLetter));
    }

    #[test]
    fn idem_key_is_stable() {
        let k1 = step_idem_key("001122", WorkflowState::PrepareCollected, "alice", 7);
        let k2 = step_idem_key("001122", WorkflowState::PrepareCollected, "alice", 7);
        assert_eq!(k1, k2);
    }
}
