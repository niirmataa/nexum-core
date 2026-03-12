use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    /// Onion host (e.g. abcd.onion) or DNS host
    pub host: String,
    pub port: u16,
    /// Base64 of peer FrodoKEM public key
    pub kem_pk_b64: String,
    /// Base64 of peer Falcon public key
    pub sig_pk_b64: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerBook {
    pub peers: Vec<Peer>,
}

impl PeerBook {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let p = path.into();
        let data = std::fs::read(&p)?;
        let pb: PeerBook = serde_json::from_slice(&data)?;
        if pb.peers.is_empty() {
            return Err(anyhow!("peers.json has empty peers list"));
        }
        Ok(pb)
    }

    pub fn get(&self, id: &str) -> Option<&Peer> {
        self.peers.iter().find(|p| p.id == id)
    }

    pub fn others(&self, me: &str) -> Vec<&Peer> {
        self.peers.iter().filter(|p| p.id != me).collect()
    }
}
