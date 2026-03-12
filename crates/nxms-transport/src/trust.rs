use crate::crypto::Keys;
use crate::peers::{Peer, PeerBook};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const RUNTIME_TRUST_BUNDLE_SCHEMA_V1: &str = "nxms-runtime-trust-bundle/v1";

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeActionTokenIssuer {
    pub issuer: String,
    pub algorithm: String,
    pub public_key_pem: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTrustBundle {
    #[serde(default = "default_schema")]
    pub schema: String,
    pub trust_epoch: String,
    pub peers: Vec<RuntimeTrustPeer>,
    pub action_token: RuntimeActionTokenIssuer,
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
