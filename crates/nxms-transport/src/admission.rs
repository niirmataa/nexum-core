use crate::wire::EscrowAction;
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "crypto")]
use crate::crypto::{Keys, falcon_sign_ct, falcon_verify};
#[cfg(feature = "crypto")]
use crate::trust::RuntimeTrustBundle;
#[cfg(feature = "crypto")]
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
#[cfg(feature = "crypto")]
use std::collections::HashSet;

const ESCROW_ADMISSION_SCHEMA_V1: &str = "nxms-escrow-admission/v1";
const ESCROW_ADMISSION_SIG_ALG: &str = "Falcon-1024-CT";
const REQUIRED_GUARD_ROLES: [&str; 2] = ["ag-01", "ag-02"];

fn default_schema() -> String {
    ESCROW_ADMISSION_SCHEMA_V1.to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscrowAdmissionSignature {
    pub signer_id: String,
    pub signer_role: String,
    pub sig_pk_b64: String,
    pub sig_b64: String,
    pub hash_hex: String,
    pub alg: String,
    pub created_at_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscrowAdmissionArtifact {
    #[serde(default = "default_schema")]
    pub schema: String,
    pub escrow_id_hex: String,
    pub snapshot_hash_hex: String,
    pub action: EscrowAction,
    pub runtime_trust_epoch: String,
    pub admitted_at_unix_ms: u64,
    #[serde(default)]
    pub signatures: Vec<EscrowAdmissionSignature>,
}

impl EscrowAdmissionArtifact {
    pub fn new(
        escrow_id_hex: impl Into<String>,
        snapshot_hash_hex: impl Into<String>,
        action: EscrowAction,
        runtime_trust_epoch: impl Into<String>,
        admitted_at_unix_ms: u64,
    ) -> Self {
        Self {
            schema: default_schema(),
            escrow_id_hex: escrow_id_hex.into(),
            snapshot_hash_hex: snapshot_hash_hex.into(),
            action,
            runtime_trust_epoch: runtime_trust_epoch.into(),
            admitted_at_unix_ms,
            signatures: Vec::new(),
        }
    }

    pub fn hash_hex(&self) -> Result<String> {
        let canonical = canonical_unsigned_json(self)?;
        let raw = serde_json::to_vec(&canonical)?;
        Ok(hex::encode(Sha256::digest(raw)))
    }

    #[cfg(feature = "crypto")]
    pub fn sign_with_local_keys(
        &mut self,
        signer_id: &str,
        signer_role: &str,
        keys: &Keys,
        created_at_unix_ms: u64,
    ) -> Result<()> {
        let sig_pk = keys.sig_pk()?;
        let sig_sk = keys.sig_sk_zeroizing()?;
        self.sign(
            signer_id,
            signer_role,
            sig_sk.as_slice(),
            &sig_pk,
            created_at_unix_ms,
        )
    }

    #[cfg(feature = "crypto")]
    pub fn sign(
        &mut self,
        signer_id: &str,
        signer_role: &str,
        sig_sk: &[u8],
        sig_pk: &[u8],
        created_at_unix_ms: u64,
    ) -> Result<()> {
        self.validate_unsigned()?;
        let signer_id = normalize_non_empty(signer_id, "signer_id", 128)?;
        let signer_role = normalize_non_empty(signer_role, "signer_role", 128)?;
        let hash_hex = self.hash_hex()?;
        let hash_raw = hex::decode(&hash_hex)?;
        let sig = falcon_sign_ct(sig_sk, &hash_raw)?;
        let signature = EscrowAdmissionSignature {
            signer_id: signer_id.clone(),
            signer_role,
            sig_pk_b64: B64.encode(sig_pk),
            sig_b64: B64.encode(sig),
            hash_hex,
            alg: ESCROW_ADMISSION_SIG_ALG.to_string(),
            created_at_unix_ms,
        };
        if let Some(existing) = self
            .signatures
            .iter_mut()
            .find(|existing| existing.signer_id == signer_id)
        {
            *existing = signature;
        } else {
            self.signatures.push(signature);
        }
        Ok(())
    }

    pub fn validate_unsigned(&self) -> Result<()> {
        if self.schema.trim() != ESCROW_ADMISSION_SCHEMA_V1 {
            bail!(
                "escrow admission schema mismatch: expected '{}' got '{}'",
                ESCROW_ADMISSION_SCHEMA_V1,
                self.schema
            );
        }
        validate_hex_exact(&self.escrow_id_hex, 32, "escrow_id_hex")?;
        validate_hex_exact(&self.snapshot_hash_hex, 64, "snapshot_hash_hex")?;
        let epoch = self.runtime_trust_epoch.trim();
        if epoch.is_empty() || epoch.len() > 128 {
            bail!("runtime_trust_epoch must be 1..=128 chars");
        }
        Ok(())
    }

    #[cfg(feature = "crypto")]
    pub fn verify_against_bundle(&self, bundle: &RuntimeTrustBundle) -> Result<()> {
        self.validate_unsigned()?;
        if self.runtime_trust_epoch.trim() != bundle.trust_epoch.trim() {
            bail!("escrow admission runtime_trust_epoch mismatch");
        }
        let hash_hex = self.hash_hex()?;
        let hash_raw = hex::decode(&hash_hex)?;
        if self.signatures.len() != REQUIRED_GUARD_ROLES.len() {
            bail!(
                "escrow admission requires exactly {} guard signatures",
                REQUIRED_GUARD_ROLES.len()
            );
        }

        let mut seen_ids = HashSet::new();
        let mut seen_roles = HashSet::new();
        for signature in &self.signatures {
            let signer_id = normalize_non_empty(&signature.signer_id, "signature.signer_id", 128)?;
            let signer_role =
                normalize_non_empty(&signature.signer_role, "signature.signer_role", 128)?;
            if !REQUIRED_GUARD_ROLES.contains(&signer_role.as_str()) {
                bail!(
                    "escrow admission signature role '{}' is not part of AG quorum",
                    signer_role
                );
            }
            if !seen_ids.insert(signer_id.clone()) {
                bail!("duplicate escrow admission signer_id '{}'", signer_id);
            }
            if !seen_roles.insert(signer_role.clone()) {
                bail!("duplicate escrow admission signer_role '{}'", signer_role);
            }
            if signature.alg.trim() != ESCROW_ADMISSION_SIG_ALG {
                bail!(
                    "unsupported escrow admission signature algorithm '{}'",
                    signature.alg
                );
            }
            if signature.hash_hex.trim().to_ascii_lowercase() != hash_hex {
                bail!("escrow admission signature hash mismatch");
            }

            let peer = bundle
                .peers
                .iter()
                .find(|peer| peer.id == signer_id)
                .ok_or_else(|| anyhow!("escrow admission signer '{}' not in runtime trust bundle", signer_id))?;
            if peer.role != signer_role {
                bail!(
                    "escrow admission signer '{}' role mismatch: artifact='{}' bundle='{}'",
                    signer_id,
                    signer_role,
                    peer.role
                );
            }
            if peer.sig_pk_b64 != signature.sig_pk_b64 {
                bail!(
                    "escrow admission signer '{}' sig_pk mismatch against runtime trust bundle",
                    signer_id
                );
            }
            let sig_pk = B64.decode(signature.sig_pk_b64.as_bytes())?;
            let sig = B64.decode(signature.sig_b64.as_bytes())?;
            falcon_verify(&sig_pk, &hash_raw, &sig)?;
        }

        for role in REQUIRED_GUARD_ROLES {
            if !seen_roles.contains(role) {
                bail!("missing escrow admission signature for guard role '{}'", role);
            }
        }

        Ok(())
    }
}

fn canonical_unsigned_json(
    artifact: &EscrowAdmissionArtifact,
) -> Result<serde_json::Value> {
    let value = serde_json::json!({
        "schema": artifact.schema,
        "escrow_id_hex": artifact.escrow_id_hex,
        "snapshot_hash_hex": artifact.snapshot_hash_hex,
        "action": artifact.action,
        "runtime_trust_epoch": artifact.runtime_trust_epoch,
        "admitted_at_unix_ms": artifact.admitted_at_unix_ms,
    });
    Ok(canonicalize_json(&value))
}

fn canonicalize_json(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                let child = map.get(&key).expect("key from map.keys() must exist");
                out.insert(key, canonicalize_json(child));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonicalize_json).collect())
        }
        _ => v.clone(),
    }
}

fn normalize_non_empty(value: &str, field: &str, max_len: usize) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_len {
        bail!("{field} must be 1..={max_len} chars");
    }
    Ok(trimmed.to_string())
}

fn validate_hex_exact(value: &str, len: usize, field: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.len() != len || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{field} must be exactly {len} hex chars");
    }
    Ok(())
}
