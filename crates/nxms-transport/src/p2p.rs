use crate::crypto::{self, Keys, SealedPacket};
use crate::tor_net;
use anyhow::Result;
use tokio::net::TcpStream;

/// Wraps a TcpStream with FrodoKEM + Falcon secure messaging.
pub struct SecureChannel {
    stream: TcpStream,
    keys: Keys,
    peer_kem_pk: Vec<u8>,
    peer_sig_pk: Vec<u8>,
    send_seq: u64,
    recv_seq: u64,
}

impl SecureChannel {
    /// Create a channel from an already-connected TcpStream.
    /// `keys` — local identity (kem + sig keypair).
    /// `peer_kem_pk` — recipient's KEM public key (raw bytes).
    /// `peer_sig_pk` — recipient's Falcon public key (raw bytes).
    pub fn new(stream: TcpStream, keys: Keys, peer_kem_pk: Vec<u8>, peer_sig_pk: Vec<u8>) -> Self {
        Self {
            stream,
            keys,
            peer_kem_pk,
            peer_sig_pk,
            send_seq: 1,
            recv_seq: 1,
        }
    }

    /// Send an encrypted, signed, framed message.
    /// On the wire: u32be(len) || json(SealedPacket).
    pub async fn send(&mut self, msg_type: &str, payload: &[u8]) -> Result<()> {
        let sig_sk = self.keys.sig_sk_zeroizing()?;
        let sealed = crypto::encrypt(
            &self.our_id(),
            &self.peer_id(),
            msg_type,
            &self.escrow_id(),
            self.send_seq,
            &self.peer_kem_pk,
            sig_sk.as_slice(),
            payload,
        )?;
        self.send_seq += 1;

        let wire = serde_json::to_vec(&sealed)?;
        tor_net::write_frame(&mut self.stream, &wire).await
    }

    /// Receive one framed message, decrypt it, and verify the Falcon signature.
    /// Returns the plaintext payload bytes on success.
    pub async fn recv(&mut self, msg_type: &str) -> Result<Vec<u8>> {
        let wire = tor_net::read_frame_default(&mut self.stream).await?;
        let sealed: SealedPacket = serde_json::from_slice(&wire)?;

        let kem_sk = self.keys.kem_sk_zeroizing()?;
        let plaintext = crypto::decrypt(
            &self.our_id(),
            &self.peer_id(),
            msg_type,
            &self.escrow_id(),
            self.recv_seq,
            &sealed,
            kem_sk.as_slice(),
            &self.peer_sig_pk,
        )?;
        self.recv_seq += 1;
        Ok(plaintext)
    }

    fn our_id(&self) -> String {
        "local".into()
    }

    fn peer_id(&self) -> String {
        "peer".into()
    }

    fn escrow_id(&self) -> [u8; 16] {
        [0u8; 16]
    }
}

/// Spawn a TCP listener. For each incoming connection, accept and
/// return the raw TcpStream. Caller wraps it with `SecureChannel::new`.
pub async fn listen(addr: &str) -> Result<tokio::net::TcpListener> {
    tor_net::serve(addr).await
}

/// Connect to a peer over plain TCP (no Tor for local dev).
pub async fn dial(addr: &str) -> Result<TcpStream> {
    let stream = TcpStream::connect(addr).await?;
    Ok(stream)
}
