use std::env;

use crate::types::{MoneroArbitraError, Result};

const BPS_DENOMINATOR: u128 = 10_000;

#[derive(Debug, Clone, Copy)]
pub struct EscrowFeePolicy {
    pub min_escrow_amount_atomic: u64,
    pub fee_floor_atomic: u64,
    pub fee_bps: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct EscrowFundingQuote {
    pub fee_atomic: u64,
    pub required_funding_atomic: u64,
}

impl EscrowFeePolicy {
    pub fn quote(self, amount_atomic: u64) -> Result<EscrowFundingQuote> {
        let percent_fee_u128 = if self.fee_bps == 0 {
            0
        } else {
            // Round up so fee reserve is never underestimated.
            (u128::from(amount_atomic) * u128::from(self.fee_bps))
                .saturating_add(BPS_DENOMINATOR - 1)
                / BPS_DENOMINATOR
        };
        let percent_fee = u64::try_from(percent_fee_u128).map_err(|_| {
            MoneroArbitraError::InvalidArgument(format!(
                "computed percent fee does not fit u64 for amount_atomic={amount_atomic}, fee_bps={}",
                self.fee_bps
            ))
        })?;

        let fee_atomic = self.fee_floor_atomic.max(percent_fee);
        let required_funding_atomic = amount_atomic.checked_add(fee_atomic).ok_or_else(|| {
            MoneroArbitraError::InvalidArgument(format!(
                "required funding overflow: amount_atomic={amount_atomic}, fee_atomic={fee_atomic}"
            ))
        })?;

        Ok(EscrowFundingQuote {
            fee_atomic,
            required_funding_atomic,
        })
    }
}

pub fn escrow_fee_policy_from_env() -> Result<EscrowFeePolicy> {
    let min_escrow_amount_atomic = env_u64_or_default("ESCROW_MIN_AMOUNT_ATOMIC", 1)?;
    let fee_floor_atomic = env_u64_or_default("ESCROW_FEE_FLOOR_ATOMIC", 0)?;
    let fee_bps_u64 = env_u64_or_default("ESCROW_FEE_BPS", 0)?;
    let fee_bps = u32::try_from(fee_bps_u64).map_err(|_| {
        MoneroArbitraError::InvalidArgument(format!(
            "ESCROW_FEE_BPS out of range for u32: {fee_bps_u64}"
        ))
    })?;
    if fee_bps > 10_000 {
        return Err(MoneroArbitraError::InvalidArgument(format!(
            "ESCROW_FEE_BPS must be <= 10000, got {fee_bps}"
        )));
    }

    Ok(EscrowFeePolicy {
        min_escrow_amount_atomic,
        fee_floor_atomic,
        fee_bps,
    })
}

fn env_u64_or_default(key: &str, default_value: u64) -> Result<u64> {
    let Some(raw) = env::var(key).ok() else {
        return Ok(default_value);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(default_value);
    }
    trimmed.parse::<u64>().map_err(|e| {
        MoneroArbitraError::InvalidArgument(format!("{key} must be u64, got '{trimmed}': {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_uses_floor_when_percent_is_lower() {
        let policy = EscrowFeePolicy {
            min_escrow_amount_atomic: 1,
            fee_floor_atomic: 50,
            fee_bps: 100, // 1%
        };
        let q = policy.quote(1_000).expect("quote");
        assert_eq!(q.fee_atomic, 50);
        assert_eq!(q.required_funding_atomic, 1_050);
    }

    #[test]
    fn quote_uses_percent_when_higher_than_floor() {
        let policy = EscrowFeePolicy {
            min_escrow_amount_atomic: 1,
            fee_floor_atomic: 10,
            fee_bps: 250, // 2.5%
        };
        let q = policy.quote(10_000).expect("quote");
        assert_eq!(q.fee_atomic, 250);
        assert_eq!(q.required_funding_atomic, 10_250);
    }

    #[test]
    fn quote_percent_rounds_up() {
        let policy = EscrowFeePolicy {
            min_escrow_amount_atomic: 1,
            fee_floor_atomic: 0,
            fee_bps: 1,
        };
        let q = policy.quote(1).expect("quote");
        assert_eq!(q.fee_atomic, 1);
        assert_eq!(q.required_funding_atomic, 2);
    }
}
