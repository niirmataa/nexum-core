use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxDestination {
    pub address: String,
    pub amount: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxConstructionCandidate {
    pub destinations: Vec<TxDestination>,
    pub fee_atomic: u64,
    pub unlock_time: u64,
    pub tx_size_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxConstructionProfile {
    pub require_single_destination: bool,
    pub fee_cap_atomic: u64,
    pub require_unlock_time_zero: bool,
    pub max_tx_size_bytes: usize,
}

impl TxConstructionProfile {
    pub fn strict_defaults(fee_cap_atomic: u64, max_tx_size_bytes: usize) -> Self {
        Self {
            require_single_destination: true,
            fee_cap_atomic,
            require_unlock_time_zero: true,
            max_tx_size_bytes: max_tx_size_bytes.max(1),
        }
    }
}

pub fn validate_tx_candidate(
    profile: &TxConstructionProfile,
    candidate: &TxConstructionCandidate,
) -> Result<()> {
    if candidate.destinations.is_empty() {
        return Err(anyhow!("tx candidate has no destinations"));
    }
    if profile.require_single_destination && candidate.destinations.len() != 1 {
        return Err(anyhow!(
            "single destination policy violation: got {} destinations",
            candidate.destinations.len()
        ));
    }
    for (idx, d) in candidate.destinations.iter().enumerate() {
        if d.address.trim().is_empty() {
            return Err(anyhow!("destination[{idx}] address must not be empty"));
        }
        if d.amount == 0 {
            return Err(anyhow!("destination[{idx}] amount must be > 0"));
        }
    }
    if candidate.fee_atomic > profile.fee_cap_atomic {
        return Err(anyhow!(
            "fee cap violation: {} > {}",
            candidate.fee_atomic,
            profile.fee_cap_atomic
        ));
    }
    if profile.require_unlock_time_zero && candidate.unlock_time != 0 {
        return Err(anyhow!(
            "unlock_time policy violation: expected 0, got {}",
            candidate.unlock_time
        ));
    }
    if candidate.tx_size_bytes > profile.max_tx_size_bytes {
        return Err(anyhow!(
            "tx size policy violation: {} > {}",
            candidate.tx_size_bytes,
            profile.max_tx_size_bytes
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> TxConstructionProfile {
        TxConstructionProfile::strict_defaults(10, 2048)
    }

    fn candidate_ok() -> TxConstructionCandidate {
        TxConstructionCandidate {
            destinations: vec![TxDestination {
                address: "44Affq5kSiGBoZ...".to_string(),
                amount: 100,
            }],
            fee_atomic: 10,
            unlock_time: 0,
            tx_size_bytes: 1200,
        }
    }

    #[test]
    fn accepts_strict_valid_candidate() {
        let c = candidate_ok();
        validate_tx_candidate(&profile(), &c).expect("valid");
    }

    #[test]
    fn rejects_multiple_destinations_when_single_required() {
        let mut c = candidate_ok();
        c.destinations.push(TxDestination {
            address: "48".repeat(10),
            amount: 1,
        });
        let err = validate_tx_candidate(&profile(), &c).expect_err("must reject");
        assert!(err.to_string().contains("single destination"));
    }

    #[test]
    fn rejects_fee_cap_violation() {
        let mut c = candidate_ok();
        c.fee_atomic = 11;
        let err = validate_tx_candidate(&profile(), &c).expect_err("must reject");
        assert!(err.to_string().contains("fee cap"));
    }

    #[test]
    fn rejects_unlock_time_violation() {
        let mut c = candidate_ok();
        c.unlock_time = 5;
        let err = validate_tx_candidate(&profile(), &c).expect_err("must reject");
        assert!(err.to_string().contains("unlock_time"));
    }

    #[test]
    fn rejects_tx_size_violation() {
        let mut c = candidate_ok();
        c.tx_size_bytes = 4096;
        let err = validate_tx_candidate(&profile(), &c).expect_err("must reject");
        assert!(err.to_string().contains("tx size"));
    }
}
