use crate::crypto::Keys;
use crate::host_identity::HostIdentityBundle;
use crate::peers::{Peer, PeerBook};
use anyhow::{Context, Result, anyhow, bail};
#[cfg(feature = "crypto")]
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[cfg(feature = "crypto")]
use crate::crypto::{falcon_sign_ct, falcon_verify};

const RUNTIME_TRUST_BUNDLE_SCHEMA_V1: &str = "nxms-runtime-trust-bundle/v1";
const RUNTIME_TRUST_SIG_ALG: &str = "Falcon-1024-CT";
const REQUIRED_GUARD_ROLES: [&str; 2] = ["ag-01", "ag-02"];

fn default_schema() -> String {
    RUNTIME_TRUST_BUNDLE_SCHEMA_V1.to_string()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTrustPeer {
    pub id: String,
    pub role: String,
    pub host: String,
    pub port: u16,
    pub kem_pk_b64: String,
    pub sig_pk_b64: String,
}

impl RuntimeTrustPeer {
    pub fn from_host_identity(bundle: &HostIdentityBundle) -> Result<Self> {
        bundle.validate()?;
        Ok(Self {
            id: bundle.host_id.clone(),
            role: bundle.role.clone(),
            host: bundle.host.clone(),
            port: bundle.port,
            kem_pk_b64: bundle.kem_pk_b64.clone(),
            sig_pk_b64: bundle.sig_pk_b64.clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeActionTokenIssuer {
    pub issuer: String,
    pub algorithm: String,
    pub public_key_pem: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTrustSignature {
    pub signer_id: String,
    pub signer_role: String,
    pub sig_pk_b64: String,
    pub sig_b64: String,
    pub hash_hex: String,
    pub alg: String,
    pub created_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTrustBundle {
    #[serde(default = "default_schema")]
    pub schema: String,
    pub trust_epoch: String,
    pub peers: Vec<RuntimeTrustPeer>,
    pub action_token: RuntimeActionTokenIssuer,
    #[serde(default)]
    pub signatures: Vec<RuntimeTrustSignature>,
}

impl RuntimeTrustBundle {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let raw = std::fs::read(&path)
            .with_context(|| format!("failed to read runtime trust bundle {}", path.display()))?;
        let bundle: Self = serde_json::from_slice(&raw)
            .with_context(|| format!("invalid runtime trust bundle {}", path.display()))?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn write_json(&self, path: impl AsRef<Path>) -> Result<()> {
        self.validate()?;
        let path = path.as_ref();
        let parent = path.parent().ok_or_else(|| {
            anyhow!(
                "cannot materialize runtime trust bundle without parent directory: {}",
                path.display()
            )
        })?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, serde_json::to_vec_pretty(self)?).with_context(|| {
            format!("failed to write temporary runtime trust bundle {}", tmp_path.display())
        })?;
        #[cfg(unix)]
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o644))
            .with_context(|| format!("failed to chmod {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, path).with_context(|| {
            format!(
                "failed to replace runtime trust bundle {} -> {}",
                tmp_path.display(),
                path.display()
            )
        })?;
        Ok(())
    }

    pub fn from_host_identities(
        trust_epoch: impl Into<String>,
        peers: &[HostIdentityBundle],
        action_token: RuntimeActionTokenIssuer,
    ) -> Result<Self> {
        if peers.is_empty() {
            bail!("runtime trust bundle requires at least one host identity");
        }
        let peers = peers
            .iter()
            .map(RuntimeTrustPeer::from_host_identity)
            .collect::<Result<Vec<_>>>()?;
        let bundle = Self {
            schema: default_schema(),
            trust_epoch: trust_epoch.into(),
            peers,
            action_token,
            signatures: Vec::new(),
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema.trim() != RUNTIME_TRUST_BUNDLE_SCHEMA_V1 {
            bail!(
                "runtime trust bundle schema mismatch: expected '{}' got '{}'",
                RUNTIME_TRUST_BUNDLE_SCHEMA_V1,
                self.schema
            );
        }

        let trust_epoch = self.trust_epoch.trim();
        if trust_epoch.is_empty() || trust_epoch.len() > 128 {
            bail!("runtime trust bundle trust_epoch must be 1..=128 chars");
        }

        if self.peers.is_empty() {
            bail!("runtime trust bundle peers list must not be empty");
        }

        let mut seen_ids = HashSet::new();
        for peer in &self.peers {
            let peer_id = peer.id.trim();
            if peer_id.is_empty() || peer_id.len() > 128 {
                bail!("runtime trust peer id must be 1..=128 chars");
            }
            if !seen_ids.insert(peer_id.to_string()) {
                bail!("runtime trust bundle duplicate peer id '{}'", peer_id);
            }
            let role = peer.role.trim();
            if role.is_empty() || role.len() > 128 {
                bail!("runtime trust peer '{}' role must be 1..=128 chars", peer_id);
            }
            let host = peer.host.trim();
            if host.is_empty() || host.len() > 255 {
                bail!("runtime trust peer '{}' host must be 1..=255 chars", peer_id);
            }
            if host.contains("://") {
                bail!(
                    "runtime trust peer '{}' host must be onion host only, not URL",
                    peer_id
                );
            }
            if !host.ends_with(".onion") {
                bail!(
                    "runtime trust peer '{}' host must be Tor hidden service (.onion)",
                    peer_id
                );
            }
            if peer.port == 0 {
                bail!("runtime trust peer '{}' port must be > 0", peer_id);
            }
            if peer.kem_pk_b64.trim().is_empty() {
                bail!("runtime trust peer '{}' kem_pk_b64 must not be empty", peer_id);
            }
            if peer.sig_pk_b64.trim().is_empty() {
                bail!("runtime trust peer '{}' sig_pk_b64 must not be empty", peer_id);
            }
        }

        let issuer = self.action_token.issuer.trim();
        if issuer.is_empty() || issuer.len() > 256 {
            bail!("runtime trust bundle action_token.issuer must be 1..=256 chars");
        }
        let algorithm = self.action_token.algorithm.trim().to_ascii_uppercase();
        match algorithm.as_str() {
            "EDDSA" | "ES256" => {}
            _ => bail!(
                "runtime trust bundle action_token.algorithm must be EDDSA or ES256"
            ),
        }
        let public_key_pem = self.action_token.public_key_pem.trim();
        if public_key_pem.is_empty() {
            bail!("runtime trust bundle action_token.public_key_pem must not be empty");
        }
        if !public_key_pem.contains("BEGIN PUBLIC KEY") {
            bail!("runtime trust bundle action_token.public_key_pem must contain a PEM public key");
        }

        for signature in &self.signatures {
            validate_signature_metadata(signature)?;
        }

        Ok(())
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
        self.validate()?;
        let signer_id = normalize_non_empty(signer_id, "signer_id", 128)?;
        let signer_role = normalize_non_empty(signer_role, "signer_role", 128)?;
        let hash_hex = self.hash_hex()?;
        let hash_raw = hex::decode(&hash_hex)?;
        let sig = falcon_sign_ct(sig_sk, &hash_raw)?;
        let signature = RuntimeTrustSignature {
            signer_id: signer_id.clone(),
            signer_role,
            sig_pk_b64: B64.encode(sig_pk),
            sig_b64: B64.encode(sig),
            hash_hex,
            alg: RUNTIME_TRUST_SIG_ALG.to_string(),
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

    #[cfg(feature = "crypto")]
    pub fn verify_guard_quorum(&self) -> Result<()> {
        self.validate()?;
        if self.signatures.len() != REQUIRED_GUARD_ROLES.len() {
            bail!(
                "runtime trust bundle requires exactly {} guard signatures",
                REQUIRED_GUARD_ROLES.len()
            );
        }
        let hash_hex = self.hash_hex()?;
        let hash_raw = hex::decode(&hash_hex)?;
        let mut seen_ids = HashSet::new();
        let mut seen_roles = HashSet::new();
        for signature in &self.signatures {
            validate_signature_metadata(signature)?;
            let signer_id = signature.signer_id.trim().to_string();
            let signer_role = signature.signer_role.trim().to_string();
            if !REQUIRED_GUARD_ROLES.contains(&signer_role.as_str()) {
                bail!(
                    "runtime trust signature role '{}' is not part of AG quorum",
                    signer_role
                );
            }
            if !seen_ids.insert(signer_id.clone()) {
                bail!("duplicate runtime trust signer_id '{}'", signer_id);
            }
            if !seen_roles.insert(signer_role.clone()) {
                bail!("duplicate runtime trust signer_role '{}'", signer_role);
            }
            if signature.hash_hex.trim().to_ascii_lowercase() != hash_hex {
                bail!("runtime trust signature hash mismatch");
            }

            let peer =
                self.peers.iter().find(|peer| peer.id == signer_id).ok_or_else(|| {
                    anyhow!("runtime trust signer '{}' not in peers list", signer_id)
                })?;
            if peer.role != signer_role {
                bail!(
                    "runtime trust signer '{}' role mismatch: signature='{}' bundle='{}'",
                    signer_id,
                    signer_role,
                    peer.role
                );
            }
            if peer.sig_pk_b64 != signature.sig_pk_b64 {
                bail!(
                    "runtime trust signer '{}' sig_pk mismatch against peers list",
                    signer_id
                );
            }
            let sig_pk = B64.decode(signature.sig_pk_b64.as_bytes())?;
            let sig = B64.decode(signature.sig_b64.as_bytes())?;
            falcon_verify(&sig_pk, &hash_raw, &sig)?;
        }
        for role in REQUIRED_GUARD_ROLES {
            if !seen_roles.contains(role) {
                bail!("missing runtime trust signature for guard role '{}'", role);
            }
        }
        Ok(())
    }

    pub fn local_peer(&self, local_id: &str) -> Result<&RuntimeTrustPeer> {
        let local_id = local_id.trim();
        self.peers
            .iter()
            .find(|peer| peer.id == local_id)
            .ok_or_else(|| anyhow!("local_id '{}' not present in runtime trust bundle", local_id))
    }

    pub fn validate_local_keys(&self, local_id: &str, keys: &Keys) -> Result<()> {
        let peer = self.local_peer(local_id)?;
        if keys.kem_pk_b64 != peer.kem_pk_b64 {
            bail!(
                "runtime trust bundle kem_pk mismatch for local_id '{}'",
                local_id
            );
        }
        if keys.sig_pk_b64 != peer.sig_pk_b64 {
            bail!(
                "runtime trust bundle sig_pk mismatch for local_id '{}'",
                local_id
            );
        }
        Ok(())
    }

    pub fn peer_book_for(&self, local_id: &str) -> Result<PeerBook> {
        let local_id = local_id.trim();
        self.local_peer(local_id)?;
        let peers = self
            .peers
            .iter()
            .filter(|peer| peer.id != local_id)
            .map(|peer| Peer {
                id: peer.id.clone(),
                host: peer.host.clone(),
                port: peer.port,
                kem_pk_b64: peer.kem_pk_b64.clone(),
                sig_pk_b64: peer.sig_pk_b64.clone(),
            })
            .collect::<Vec<_>>();
        if peers.is_empty() {
            bail!(
                "runtime trust bundle has no remote peers after excluding local_id '{}'",
                local_id
            );
        }
        Ok(PeerBook { peers })
    }

    pub fn action_token_public_key_pem(&self) -> &str {
        self.action_token.public_key_pem.as_str()
    }

    pub fn materialize_for_local(
        &self,
        local_id: &str,
        peers_path: &Path,
        action_token_public_key_path: &Path,
    ) -> Result<()> {
        let peer_book = self.peer_book_for(local_id)?;
        write_json_atomic(peers_path, &peer_book)?;
        write_public_text_atomic(
            action_token_public_key_path,
            self.action_token_public_key_pem(),
            0o644,
        )?;
        Ok(())
    }
}

fn validate_signature_metadata(signature: &RuntimeTrustSignature) -> Result<()> {
    let _ = normalize_non_empty(&signature.signer_id, "signature.signer_id", 128)?;
    let _ = normalize_non_empty(&signature.signer_role, "signature.signer_role", 128)?;
    if signature.alg.trim() != RUNTIME_TRUST_SIG_ALG {
        bail!(
            "unsupported runtime trust signature algorithm '{}'",
            signature.alg
        );
    }
    validate_hex_exact(&signature.hash_hex, 64, "signature.hash_hex")?;
    if signature.sig_pk_b64.trim().is_empty() {
        bail!("runtime trust signature sig_pk_b64 must not be empty");
    }
    if signature.sig_b64.trim().is_empty() {
        bail!("runtime trust signature sig_b64 must not be empty");
    }
    Ok(())
}

fn canonical_unsigned_json(bundle: &RuntimeTrustBundle) -> Result<serde_json::Value> {
    let value = serde_json::json!({
        "schema": bundle.schema,
        "trust_epoch": bundle.trust_epoch,
        "peers": bundle.peers,
        "action_token": bundle.action_token,
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

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_bytes_atomic(path, &bytes, 0o644)
}

fn write_public_text_atomic(path: &Path, value: &str, mode: u32) -> Result<()> {
    write_bytes_atomic(path, value.as_bytes(), mode)
}

fn write_bytes_atomic(path: &Path, value: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow!(
            "cannot materialize runtime trust artifact without parent directory: {}",
            path.display()
        )
    })?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, value)
        .with_context(|| format!("failed to write temporary artifact {}", tmp_path.display()))?;
    #[cfg(unix)]
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to chmod temporary artifact {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to replace runtime trust artifact {} -> {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keys;

    fn sample_action_token() -> RuntimeActionTokenIssuer {
        RuntimeActionTokenIssuer {
            issuer: "nxms-auth".to_string(),
            algorithm: "EDDSA".to_string(),
            public_key_pem:
                "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n".to_string(),
        }
    }

    #[test]
    fn runtime_trust_bundle_roundtrip_from_host_identities() {
        let signer_keys = Keys::generate().expect("signer keys");
        let ag01_keys = Keys::generate().expect("ag01 keys");
        let ag02_keys = Keys::generate().expect("ag02 keys");
        let peers = vec![
            HostIdentityBundle::from_local_keys(
                "signer-a",
                "signer",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
                443,
                &signer_keys,
            )
            .expect("signer"),
            HostIdentityBundle::from_local_keys(
                "ag01",
                "ag-01",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion",
                443,
                &ag01_keys,
            )
            .expect("ag01"),
            HostIdentityBundle::from_local_keys(
                "ag02",
                "ag-02",
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccc.onion",
                443,
                &ag02_keys,
            )
            .expect("ag02"),
        ];
        let bundle =
            RuntimeTrustBundle::from_host_identities("epoch-1", &peers, sample_action_token())
                .expect("bundle");
        assert_eq!(bundle.peers.len(), 3);
        assert!(bundle.signatures.is_empty());
    }

    #[test]
    fn runtime_trust_bundle_requires_guard_quorum() {
        let ag01_keys = Keys::generate().expect("ag01 keys");
        let ag02_keys = Keys::generate().expect("ag02 keys");
        let peers = vec![
            HostIdentityBundle::from_local_keys(
                "ag01",
                "ag-01",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion",
                443,
                &ag01_keys,
            )
            .expect("ag01"),
            HostIdentityBundle::from_local_keys(
                "ag02",
                "ag-02",
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccc.onion",
                443,
                &ag02_keys,
            )
            .expect("ag02"),
        ];
        let mut bundle =
            RuntimeTrustBundle::from_host_identities("epoch-1", &peers, sample_action_token())
                .expect("bundle");
        bundle
            .sign_with_local_keys("ag01", "ag-01", &ag01_keys, 1)
            .expect("sign ag01");
        let err = bundle
            .verify_guard_quorum()
            .expect_err("missing second signature must fail");
        assert!(err.to_string().contains("requires exactly 2 guard signatures"));
        bundle
            .sign_with_local_keys("ag02", "ag-02", &ag02_keys, 2)
            .expect("sign ag02");
        bundle.verify_guard_quorum().expect("guard quorum");
    }
}
