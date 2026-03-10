use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use nxms_transport::crypto::{falcon_sign_ct, falcon_verify};
use nxms_transport::wire::EscrowAction;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Asset {
    Xmr,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AmountRule {
    Exact { amount: u64 },
    Range { min: u64, max: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientRule {
    pub address: String,
    pub amount: AmountRule,
    pub required: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayoutPolicy {
    pub allowed_recipients: Vec<RecipientRule>,
    pub allow_split_tx: bool,
    pub allow_dummy_outputs: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractSnapshot {
    pub app_proto: String,
    pub escrow_id_hex: String,
    pub asset: Asset,
    pub buyer_id: String,
    pub seller_id: String,
    pub arbiter_id: String,
    pub release_policy: PayoutPolicy,
    pub refund_policy: PayoutPolicy,
    pub fee_cap_atomic: u64,
    pub require_unlock_time_zero: bool,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotSignature {
    pub signer_id: String,
    pub sig_pk_b64: String,
    pub sig_b64: String,
    pub hash_hex: String,
    pub alg: String,
    pub created_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferRecipient {
    pub address: String,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferCheck {
    pub tx_count: u64,
    pub recipients: Vec<TransferRecipient>,
    pub fee: u64,
    pub unlock_time: u64,
    pub dummy_outputs: u64,
}

pub fn canonical_hash_hex(snapshot: &ContractSnapshot) -> Result<String> {
    let raw = serde_json::to_vec(snapshot)?;
    let mut hasher = Sha3_256::new();
    hasher.update(raw);
    Ok(hex::encode(hasher.finalize()))
}

pub fn canonical_policy_hash_sha256_hex(snapshot: &ContractSnapshot) -> Result<String> {
    let v = serde_json::to_value(snapshot)?;
    canonical_json_sha256_hex(&v)
}

pub fn canonical_json_sha256_hex(v: &serde_json::Value) -> Result<String> {
    let canonical = canonicalize_json(v);
    let raw = serde_json::to_vec(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(raw);
    Ok(hex::encode(hasher.finalize()))
}

fn canonicalize_json(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                let child = map.get(&k).expect("key from map.keys() must exist");
                out.insert(k, canonicalize_json(child));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => {
            let out = items.iter().map(canonicalize_json).collect::<Vec<_>>();
            serde_json::Value::Array(out)
        }
        _ => v.clone(),
    }
}

pub fn sign_snapshot(
    snapshot: &ContractSnapshot,
    signer_id: &str,
    sig_sk: &[u8],
    sig_pk: &[u8],
    now_unix_ms: u64,
) -> Result<SnapshotSignature> {
    let hash_hex = canonical_hash_hex(snapshot)?;
    let hash_raw = hex::decode(&hash_hex)?;
    let sig = falcon_sign_ct(sig_sk, &hash_raw)?;
    Ok(SnapshotSignature {
        signer_id: signer_id.to_string(),
        sig_pk_b64: B64.encode(sig_pk),
        sig_b64: B64.encode(sig),
        hash_hex,
        alg: "Falcon-1024-CT".to_string(),
        created_at_unix_ms: now_unix_ms,
    })
}

pub fn verify_snapshot_signature(
    snapshot: &ContractSnapshot,
    sig: &SnapshotSignature,
) -> Result<()> {
    if sig.alg != "Falcon-1024-CT" {
        return Err(anyhow!("unsupported signature algorithm '{}'", sig.alg));
    }
    let hash_hex = canonical_hash_hex(snapshot)?;
    if hash_hex != sig.hash_hex {
        return Err(anyhow!("snapshot hash mismatch"));
    }
    let hash_raw = hex::decode(&sig.hash_hex)?;
    let sig_pk = B64.decode(sig.sig_pk_b64.as_bytes())?;
    let sig_raw = B64.decode(sig.sig_b64.as_bytes())?;
    falcon_verify(&sig_pk, &hash_raw, &sig_raw)?;
    Ok(())
}

pub fn validate_transfer_against_snapshot(
    snapshot: &ContractSnapshot,
    action: EscrowAction,
    transfer: &TransferCheck,
) -> Result<()> {
    let policy = match action {
        EscrowAction::Release => &snapshot.release_policy,
        EscrowAction::Refund => &snapshot.refund_policy,
    };

    if !policy.allow_split_tx && transfer.tx_count != 1 {
        return Err(anyhow!(
            "split policy violation: expected exactly one tx, got {}",
            transfer.tx_count
        ));
    }

    if transfer.fee > snapshot.fee_cap_atomic {
        return Err(anyhow!(
            "fee cap violation: fee {} > cap {}",
            transfer.fee,
            snapshot.fee_cap_atomic
        ));
    }

    if snapshot.require_unlock_time_zero && transfer.unlock_time != 0 {
        return Err(anyhow!(
            "unlock_time policy violation: expected 0, got {}",
            transfer.unlock_time
        ));
    }

    if !policy.allow_dummy_outputs && transfer.dummy_outputs > 0 {
        return Err(anyhow!(
            "dummy_outputs policy violation: got {}",
            transfer.dummy_outputs
        ));
    }

    for recipient in &transfer.recipients {
        let Some(rule) = policy
            .allowed_recipients
            .iter()
            .find(|r| r.address == recipient.address)
        else {
            return Err(anyhow!(
                "recipient '{}' is not in allowed policy",
                recipient.address
            ));
        };
        match rule.amount {
            AmountRule::Exact { amount } => {
                if recipient.amount != amount {
                    return Err(anyhow!(
                        "amount mismatch for '{}': expected {}, got {}",
                        recipient.address,
                        amount,
                        recipient.amount
                    ));
                }
            }
            AmountRule::Range { min, max } => {
                if recipient.amount < min || recipient.amount > max {
                    return Err(anyhow!(
                        "amount out of range for '{}': [{}..{}], got {}",
                        recipient.address,
                        min,
                        max,
                        recipient.amount
                    ));
                }
            }
        }
    }

    for required in policy.allowed_recipients.iter().filter(|r| r.required) {
        let found = transfer
            .recipients
            .iter()
            .any(|r| r.address == required.address);
        if !found {
            return Err(anyhow!(
                "required recipient '{}' missing from tx",
                required.address
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nxms_transport::wire::EscrowAction;

    fn sample_snapshot() -> ContractSnapshot {
        ContractSnapshot {
            app_proto: "ESCROW/1".to_string(),
            escrow_id_hex: "a".repeat(32),
            asset: Asset::Xmr,
            buyer_id: "buyer".to_string(),
            seller_id: "seller".to_string(),
            arbiter_id: "arbiter".to_string(),
            release_policy: PayoutPolicy {
                allowed_recipients: vec![RecipientRule {
                    address: "release_addr".to_string(),
                    amount: AmountRule::Exact { amount: 100 },
                    required: true,
                }],
                allow_split_tx: false,
                allow_dummy_outputs: false,
            },
            refund_policy: PayoutPolicy {
                allowed_recipients: vec![RecipientRule {
                    address: "refund_addr".to_string(),
                    amount: AmountRule::Range { min: 100, max: 120 },
                    required: true,
                }],
                allow_split_tx: false,
                allow_dummy_outputs: false,
            },
            fee_cap_atomic: 10,
            require_unlock_time_zero: true,
            created_at_unix_ms: 1,
            updated_at_unix_ms: 1,
        }
    }

    #[test]
    fn snapshot_hash_is_stable() {
        let s = sample_snapshot();
        let h1 = canonical_hash_hex(&s).expect("h1");
        let h2 = canonical_hash_hex(&s).expect("h2");
        assert_eq!(h1, h2);
    }

    #[test]
    fn canonical_policy_hash_sha256_is_stable_and_order_independent() {
        let s = sample_snapshot();
        let h1 = canonical_policy_hash_sha256_hex(&s).expect("h1");
        let h2 = canonical_policy_hash_sha256_hex(&s).expect("h2");
        assert_eq!(h1, h2);

        let v1 = serde_json::json!({
            "b": 2,
            "a": {"z": 1, "x": [3,2,1]}
        });
        let v2 = serde_json::json!({
            "a": {"x": [3,2,1], "z": 1},
            "b": 2
        });
        let j1 = canonical_json_sha256_hex(&v1).expect("j1");
        let j2 = canonical_json_sha256_hex(&v2).expect("j2");
        assert_eq!(j1, j2);
    }

    #[test]
    fn transfer_validation_accepts_matching_policy() {
        let s = sample_snapshot();
        let t = TransferCheck {
            tx_count: 1,
            recipients: vec![TransferRecipient {
                address: "release_addr".to_string(),
                amount: 100,
            }],
            fee: 10,
            unlock_time: 0,
            dummy_outputs: 0,
        };
        validate_transfer_against_snapshot(&s, EscrowAction::Release, &t).expect("valid");
    }

    #[test]
    fn transfer_validation_rejects_split_when_policy_bans_it() {
        let s = sample_snapshot();
        let t = TransferCheck {
            tx_count: 2,
            recipients: vec![TransferRecipient {
                address: "release_addr".to_string(),
                amount: 100,
            }],
            fee: 5,
            unlock_time: 0,
            dummy_outputs: 0,
        };
        let err = validate_transfer_against_snapshot(&s, EscrowAction::Release, &t)
            .expect_err("split must be rejected");
        assert!(err.to_string().contains("split policy"));
    }

    #[test]
    fn transfer_validation_rejects_extra_recipient() {
        let s = sample_snapshot();
        let t = TransferCheck {
            tx_count: 1,
            recipients: vec![
                TransferRecipient {
                    address: "release_addr".to_string(),
                    amount: 100,
                },
                TransferRecipient {
                    address: "hacker_addr".to_string(),
                    amount: 1,
                },
            ],
            fee: 5,
            unlock_time: 0,
            dummy_outputs: 0,
        };
        let err = validate_transfer_against_snapshot(&s, EscrowAction::Release, &t)
            .expect_err("extra recipient must be rejected");
        assert!(err.to_string().contains("not in allowed policy"));
    }

    #[test]
    fn transfer_validation_rejects_fee_overflow() {
        let s = sample_snapshot();
        let t = TransferCheck {
            tx_count: 1,
            recipients: vec![TransferRecipient {
                address: "release_addr".to_string(),
                amount: 100,
            }],
            fee: 11,
            unlock_time: 0,
            dummy_outputs: 0,
        };
        let err = validate_transfer_against_snapshot(&s, EscrowAction::Release, &t)
            .expect_err("fee overflow must be rejected");
        assert!(err.to_string().contains("fee cap violation"));
    }

    #[test]
    fn transfer_validation_rejects_unlock_time_mismatch() {
        let s = sample_snapshot();
        let t = TransferCheck {
            tx_count: 1,
            recipients: vec![TransferRecipient {
                address: "release_addr".to_string(),
                amount: 100,
            }],
            fee: 5,
            unlock_time: 9,
            dummy_outputs: 0,
        };
        let err = validate_transfer_against_snapshot(&s, EscrowAction::Release, &t)
            .expect_err("unlock_time mismatch must be rejected");
        assert!(err.to_string().contains("unlock_time"));
    }
}
