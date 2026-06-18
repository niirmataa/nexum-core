use anyhow::{Result, anyhow};
use nxms_transport::crypto::Keys;
use nxms_transport::p2p::{SecureChannel, dial, listen};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Debug, Serialize, Deserialize)]
pub struct PingPayload {
    pub msg: String,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PongPayload {
    pub msg: String,
    pub nonce: String,
}

/// Node loads its PQ identity, listens on a TCP port, and can dial peers.
pub struct Node {
    pub keys: Keys,
    pub listen_addr: String,
}

impl Node {
    pub fn generate(listen_addr: &str) -> Result<Self> {
        let keys = Keys::generate()?;
        Ok(Self {
            keys,
            listen_addr: listen_addr.to_string(),
        })
    }

    pub fn from_keys(keys: Keys, listen_addr: &str) -> Self {
        Self {
            keys,
            listen_addr: listen_addr.to_string(),
        }
    }

    /// Start listening and handle one PING → respond with PONG.
    /// Requires the dialer's public keys for decryption + signature verification.
    pub async fn run_responder(
        &self,
        dialer_kem_pk: Vec<u8>,
        dialer_sig_pk: Vec<u8>,
    ) -> Result<()> {
        let listener = listen(&self.listen_addr).await?;
        let (stream, peer_addr) = listener.accept().await?;
        tracing::info!(%peer_addr, "responder accepted connection");

        let mut channel = SecureChannel::new(
            stream,
            self.keys.clone(),
            dialer_kem_pk,
            dialer_sig_pk,
        );

        let data = channel.recv("PING").await?;
        let ping: PingPayload = serde_json::from_slice(&data)?;

        if ping.msg != "PING" {
            return Err(anyhow!("expected PING, got '{}'", ping.msg));
        }
        tracing::info!(nonce=%ping.nonce, "responder received PING");

        let pong = PongPayload {
            msg: "PONG".into(),
            nonce: ping.nonce,
        };
        let pong_bytes = serde_json::to_vec(&pong)?;
        channel.send("PONG", &pong_bytes).await?;

        tracing::info!(%peer_addr, "responder sent PONG");
        Ok(())
    }

    /// Accept a stream and wrap it in a SecureChannel with known peer keys.
    pub async fn accept_secure(
        &self,
        listener: &TcpListener,
        peer_kem_pk: Vec<u8>,
        peer_sig_pk: Vec<u8>,
    ) -> Result<SecureChannel> {
        let (stream, addr) = listener.accept().await?;
        tracing::info!(%addr, "secure channel accepted");
        Ok(SecureChannel::new(stream, self.keys.clone(), peer_kem_pk, peer_sig_pk))
    }

    /// Dial a peer and wrap in SecureChannel.
    pub async fn dial_secure(
        &self,
        addr: &str,
        peer_kem_pk: Vec<u8>,
        peer_sig_pk: Vec<u8>,
    ) -> Result<SecureChannel> {
        let stream = dial(addr).await?;
        tracing::info!(%addr, "secure channel dialed");
        Ok(SecureChannel::new(stream, self.keys.clone(), peer_kem_pk, peer_sig_pk))
    }

    pub fn kem_pk(&self) -> Result<Vec<u8>> {
        self.keys.kem_pk()
    }

    pub fn sig_pk(&self) -> Result<Vec<u8>> {
        self.keys.sig_pk()
    }
}

/// Full PING→PONG exchange between two nodes over encrypted channels.
pub async fn run_ping_pong(
    node_a: &Node,
    node_b: &Node,
) -> Result<()> {
    let listener = listen(&node_b.listen_addr).await?;

    let a_kem_pk = node_a.kem_pk()?;
    let a_sig_pk = node_a.sig_pk()?;
    let b_kem_pk = node_b.kem_pk()?;
    let b_sig_pk = node_b.sig_pk()?;

    let mut chan_a = node_a.dial_secure(&node_b.listen_addr, b_kem_pk.clone(), b_sig_pk.clone()).await?;
    let mut chan_b = node_b.accept_secure(&listener, a_kem_pk, a_sig_pk).await?;

    let nonce = "42".to_string();
    let ping = PingPayload {
        msg: "PING".into(),
        nonce: nonce.clone(),
    };
    let ping_bytes = serde_json::to_vec(&ping)?;

    tracing::info!("[Node A] sending encrypted PING");
    chan_a.send("PING", &ping_bytes).await?;

    tracing::info!("[Node B] waiting for message");
    let recv_bytes = chan_b.recv("PING").await?;
    let recv_ping: PingPayload = serde_json::from_slice(&recv_bytes)?;

    if recv_ping.msg != "PING" {
        return Err(anyhow!("expected PING, got '{}'", recv_ping.msg));
    }
    tracing::info!("[Node B] decrypted PING, Falcon signature valid");

    let pong_nonce = (nonce.parse::<u64>().unwrap_or(0) + 1).to_string();
    let pong = PongPayload {
        msg: "PONG".into(),
        nonce: pong_nonce,
    };
    let pong_bytes = serde_json::to_vec(&pong)?;

    tracing::info!("[Node B] sending encrypted PONG");
    chan_b.send("PONG", &pong_bytes).await?;

    let pong_recv = chan_a.recv("PONG").await?;
    let pong_data: PongPayload = serde_json::from_slice(&pong_recv)?;

    if pong_data.msg != "PONG" {
        return Err(anyhow!("expected PONG, got '{}'", pong_data.msg));
    }
    tracing::info!("[Node A] decrypted PONG, Falcon signature valid");

    Ok(())
}

/// Secure PING — dial a peer, send encrypted PING, return decrypted PONG payload.
/// This is the public API for clients that have a peer's public keys and want
/// a one-shot authenticated session.
pub async fn secure_ping(
    local_keys: &Keys,
    peer_addr: &str,
    peer_kem_pk: Vec<u8>,
    peer_sig_pk: Vec<u8>,
) -> Result<PongPayload> {
    let stream = dial(peer_addr).await?;
    let mut channel = SecureChannel::new(stream, local_keys.clone(), peer_kem_pk, peer_sig_pk);

    let ping = PingPayload {
        msg: "PING".into(),
        nonce: "1".to_string(),
    };
    let ping_bytes = serde_json::to_vec(&ping)?;
    channel.send("PING", &ping_bytes).await?;

    let pong_data = channel.recv("PONG").await?;
    serde_json::from_slice(&pong_data).map_err(Into::into)
}
