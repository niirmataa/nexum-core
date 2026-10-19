//! Peer-side NXMS component (`nxms-peer`).
//!
//! Initiates the escrow `tx_sign_req` flow towards signers over the mailbox:
//! builds NXMS envelopes (FrodoKEM-640-SHAKE + Falcon-1024-CT) with the peer
//! host-vault keys, pushes them to the mailbox, polls its own inbox for the
//! matching `tx_sign_resp` (or error) envelope, and acks the receipt.
//!
//! The peer is the `from` side of the flow, so it must be present in the
//! signer's `peers.json` allowlist. Conversely the peer's own peer book must
//! contain the signer entry (`to`) to obtain the signer's FrodoKEM public key
//! (envelope encryption) and Falcon public key (response authentication).

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use nxms_mailbox_client::MailboxClient;
use nxms_transport::admission::EscrowAdmissionArtifact;
use nxms_transport::crypto::{Keys, decrypt, encrypt, suite_kem_id, suite_sig_id, SealedPacket};
use nxms_transport::host_vault::HostVault;
use nxms_transport::peers::{Peer, PeerBook};
use nxms_transport::wire::{
    ESCROW_APP_PROTO_V1, EscrowAction, EscrowBody, MsgType, NXMS_ESCROW_ID_HEX_LEN, NXMS_PROTO_V1,
    NxmsEnvelope, NxmsPayload, TxSignReqBody, msg_type_key, validate_hex, validate_peer_id,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, info};

/// Per-escrow outgoing sequence counter state, stored next to the host vault.
pub const PEER_STATE_FILE_NAME: &str = "peer_state.json";

const SNAPSHOT_HASH_HEX_LEN: usize = 64;
const PULL_MAX: u32 = 10;

/// Vault + mailbox + request parameters for one `tx_sign_req` round trip.
///
/// Deliberately not `Debug`: it carries the vault passphrase and mailbox
/// bearer tokens.
#[derive(Clone)]
pub struct SignReqConfig {
    pub vault_dir: PathBuf,
    pub passphrase: String,
    /// Peer-side peer book; must contain the signer entry selected by `to`.
    pub peers_path: PathBuf,
    pub mailbox_url: String,
    pub push_token: String,
    pub pull_token: String,
    pub ack_token: String,
    /// Signer local id (recipient of the request, must exist in `peers_path`).
    pub to: String,
    pub escrow_id_hex: String,
    pub action: EscrowAction,
    pub multisig_txset_hex: String,
    pub snapshot_hash_hex: String,
    pub human_hint: Option<String>,
    /// Escrow admission artifact — required by signers with runtime trust
    /// enforcement (runtime_trust_bundle_path set).
    pub escrow_admission_artifact: Option<EscrowAdmissionArtifact>,
    pub ttl_secs: u64,
    pub wait_ms: u64,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignReqStatus {
    Approved,
    Rejected,
    Error,
}

/// Result of one `tx_sign_req` round trip, serialized to stdout by the CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignReqOutcome {
    pub status: SignReqStatus,
    pub escrow_id_hex: String,
    pub signer_id: String,
    pub request_seq: u64,
    pub approved: bool,
    pub signed_tx_data_hex: Option<String>,
    pub tx_hash_list: Vec<String>,
    pub reason: Option<String>,
}

/// Generate a fresh peer host vault (FrodoKEM + Falcon keys).
/// Fails if a vault already exists in `vault_dir`.
pub fn init_vault(vault_dir: &Path, passphrase: &str, local_id: &str) -> Result<Keys> {
    validate_wire_peer_id(local_id, "local_id")?;
    nxms_transport::bootstrap::generate_local_host_vault_with_passphrase(
        local_id,
        vault_dir,
        passphrase,
    )
}

/// Export the peer identity as a `peers.json`-ready `Peer` entry so signer
/// operators can add this peer to their allowlists.
pub fn export_identity(
    vault_dir: &Path,
    passphrase: &str,
    host: &str,
    port: u16,
    out: &Path,
) -> Result<Peer> {
    let vault = HostVault::load(vault_dir, passphrase)
        .with_context(|| format!("load host vault {}", vault_dir.display()))?;
    validate_wire_peer_id(&vault.local_id, "vault local_id")?;
    let peer = Peer {
        id: vault.local_id.clone(),
        host: host.trim().to_string(),
        port,
        kem_pk_b64: vault.keys.kem_pk_b64.clone(),
        sig_pk_b64: vault.keys.sig_pk_b64.clone(),
    };
    std::fs::write(out, serde_json::to_vec_pretty(&peer)?)
        .with_context(|| format!("write peer identity {}", out.display()))?;
    Ok(peer)
}

/// Push a `tx_sign_req` to the signer and wait for its `tx_sign_resp`.
pub async fn sign_req(cfg: &SignReqConfig) -> Result<SignReqOutcome> {
    let vault = HostVault::load(&cfg.vault_dir, &cfg.passphrase)
        .with_context(|| format!("load host vault {}", cfg.vault_dir.display()))?;
    let local_id = vault.local_id.clone();
    validate_wire_peer_id(&local_id, "vault local_id")?;
    validate_wire_peer_id(&cfg.to, "to")?;

    let escrow_id_hex = cfg.escrow_id_hex.trim().to_ascii_lowercase();
    validate_hex(&escrow_id_hex, NXMS_ESCROW_ID_HEX_LEN)
        .map_err(|e| anyhow!("invalid escrow_id_hex: {e}"))?;
    let snapshot_hash_hex = cfg.snapshot_hash_hex.trim().to_ascii_lowercase();
    validate_hex(&snapshot_hash_hex, SNAPSHOT_HASH_HEX_LEN)
        .map_err(|e| anyhow!("invalid snapshot_hash_hex: {e}"))?;
    let multisig_txset_hex = cfg.multisig_txset_hex.trim().to_ascii_lowercase();
    if multisig_txset_hex.is_empty()
        || multisig_txset_hex.len() % 2 != 0
        || !multisig_txset_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        bail!("multisig_txset_hex must be valid even-length hex");
    }
    if local_id == cfg.to {
        bail!("peer local_id and signer id must differ");
    }
    if let Some(artifact) = &cfg.escrow_admission_artifact
        && artifact.escrow_id_hex.trim().to_ascii_lowercase() != escrow_id_hex
    {
        bail!(
            "escrow admission artifact escrow_id mismatch: artifact {} != request {}",
            artifact.escrow_id_hex,
            escrow_id_hex
        );
    }

    // The signer entry gives us its FrodoKEM public key (envelope encryption)
    // and Falcon public key (response authentication).
    let peers = PeerBook::load(&cfg.peers_path)
        .with_context(|| format!("load peer book {}", cfg.peers_path.display()))?;
    let signer = peers.get(&cfg.to).ok_or_else(|| {
        anyhow!(
            "signer '{}' not in peer book {}",
            cfg.to,
            cfg.peers_path.display()
        )
    })?;

    let escrow_id_raw = decode_escrow_id_hex(&escrow_id_hex)?;
    let seq = next_out_seq(&seq_state_path(&cfg.vault_dir), &escrow_id_hex)?;

    let body = EscrowBody::TxSignReq(TxSignReqBody {
        escrow_id_hex: escrow_id_hex.clone(),
        action: cfg.action.clone(),
        multisig_txset_hex: multisig_txset_hex.clone(),
        snapshot_hash_hex: snapshot_hash_hex.clone(),
        escrow_admission_artifact: cfg.escrow_admission_artifact.clone(),
        human_hint: cfg.human_hint.clone(),
    });
    let payload = NxmsPayload {
        app_proto: ESCROW_APP_PROTO_V1.to_string(),
        msg_type: MsgType::TxSignReq,
        escrow_id_hex: escrow_id_hex.clone(),
        from: local_id.clone(),
        to: cfg.to.clone(),
        seq,
        data: serde_json::to_string(&body)?,
    };
    let plain = serde_json::to_vec(&payload)?;
    let signer_kem_pk = B64.decode(signer.kem_pk_b64.as_bytes())?;
    let self_sig_sk = vault.keys.sig_sk_zeroizing()?;
    let sealed = encrypt(
        &local_id,
        &cfg.to,
        msg_type_key(&MsgType::TxSignReq),
        &escrow_id_raw,
        seq,
        &signer_kem_pk,
        self_sig_sk.as_slice(),
        &plain,
    )?;

    let env = NxmsEnvelope {
        proto: NXMS_PROTO_V1.to_string(),
        kem_id: suite_kem_id().to_string(),
        sig_id: suite_sig_id().to_string(),
        msg_type: MsgType::TxSignReq,
        escrow_id_hex: escrow_id_hex.clone(),
        from: local_id.clone(),
        to: cfg.to.clone(),
        seq,
        kem_ct_b64: sealed.kem_ct_b64,
        nonce_b64: sealed.nonce_b64,
        ciphertext_b64: sealed.ciphertext_b64,
        tag_b64: sealed.tag_b64,
        sig_b64: sealed.sig_b64,
    };
    env.validate_basic().map_err(|e| anyhow!(e))?;

    let client = MailboxClient::builder(&cfg.mailbox_url)?
        .push_token(cfg.push_token.clone())
        .pull_token(cfg.pull_token.clone())
        .ack_token(cfg.ack_token.clone())
        .build()?;
    let pushed = client.push(&env, Some(cfg.ttl_secs)).await?;
    info!(
        "pushed tx_sign_req to={} escrow={} seq={} dedup={}",
        cfg.to, escrow_id_hex, seq, pushed.dedup
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(cfg.timeout_secs);
    loop {
        let pulled = client
            .pull(&local_id, Some(PULL_MAX), Some(cfg.wait_ms))
            .await?;
        for msg in pulled.messages {
            let env = &msg.envelope;
            if env.to != local_id
                || env.from != cfg.to
                || env.escrow_id_hex != escrow_id_hex
                || !matches!(env.msg_type, MsgType::TxSignResp | MsgType::Error)
            {
                // Not for this round trip; leave it leased for its consumer.
                debug!(
                    "skipping foreign mailbox message from={} escrow={} type={}",
                    env.from,
                    env.escrow_id_hex,
                    msg_type_key(&env.msg_type)
                );
                continue;
            }

            let body = open_signer_body(&vault.keys, signer, env)?;
            match body {
                EscrowBody::TxSignResp(resp) => {
                    if resp.escrow_id_hex != escrow_id_hex {
                        bail!(
                            "tx_sign_resp escrow_id mismatch: resp={} requested={}",
                            resp.escrow_id_hex,
                            escrow_id_hex
                        );
                    }
                    client.ack(&msg.receipt).await?;
                    let status = if resp.approved {
                        SignReqStatus::Approved
                    } else {
                        SignReqStatus::Rejected
                    };
                    info!(
                        "received tx_sign_resp status={:?} escrow={} seq={}",
                        status, escrow_id_hex, env.seq
                    );
                    return Ok(SignReqOutcome {
                        status,
                        escrow_id_hex,
                        signer_id: cfg.to.clone(),
                        request_seq: seq,
                        approved: resp.approved,
                        signed_tx_data_hex: resp.signed_tx_data_hex,
                        tx_hash_list: resp.tx_hash_list,
                        reason: resp.reason,
                    });
                }
                EscrowBody::Err(err) => {
                    client.ack(&msg.receipt).await?;
                    info!(
                        "received escrow error code={} escrow={} seq={}",
                        err.code, escrow_id_hex, env.seq
                    );
                    return Ok(SignReqOutcome {
                        status: SignReqStatus::Error,
                        escrow_id_hex,
                        signer_id: cfg.to.clone(),
                        request_seq: seq,
                        approved: false,
                        signed_tx_data_hex: None,
                        tx_hash_list: Vec::new(),
                        reason: Some(format!("{}: {}", err.code, err.reason)),
                    });
                }
                other => {
                    bail!(
                        "unexpected response body kind '{}' from signer '{}'",
                        body_kind(&other),
                        cfg.to
                    );
                }
            }
        }

        if tokio::time::Instant::now() >= deadline {
            bail!(
                "timed out after {}s waiting for tx_sign_resp escrow={} from={}",
                cfg.timeout_secs,
                escrow_id_hex,
                cfg.to
            );
        }
    }
}

/// Path of the peer's per-escrow outgoing sequence state file.
pub fn seq_state_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(PEER_STATE_FILE_NAME)
}

/// Read an owner-only secret file (passphrase / bearer token) as trimmed text.
pub fn read_secret_text(path: &Path, label: &str) -> Result<String> {
    #[cfg(unix)]
    let mut raw = {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| anyhow!("{label} failed to open '{}': {}", path.display(), e))?;
        let metadata = file
            .metadata()
            .map_err(|e| anyhow!("{label} failed to stat '{}': {}", path.display(), e))?;
        validate_owner_only_file(path, &metadata, label)?;
        let mut raw = String::new();
        std::io::Read::read_to_string(&mut file, &mut raw)
            .map_err(|e| anyhow!("{label} failed to read '{}': {}", path.display(), e))?;
        raw
    };
    #[cfg(not(unix))]
    let mut raw = {
        let metadata = std::fs::metadata(path)
            .map_err(|e| anyhow!("{label} failed to stat '{}': {}", path.display(), e))?;
        validate_owner_only_file(path, &metadata, label)?;
        std::fs::read_to_string(path)
            .map_err(|e| anyhow!("{label} failed to read '{}': {}", path.display(), e))?
    };
    let out = raw.trim().to_string();
    raw.clear();
    if out.is_empty() {
        return Err(anyhow!("{label} '{}' is empty", path.display()));
    }
    Ok(out)
}

fn validate_owner_only_file(path: &Path, metadata: &std::fs::Metadata, label: &str) -> Result<()> {
    if !metadata.is_file() {
        bail!("{label} '{}' is not a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            bail!(
                "{label} '{}' must not be group/other accessible (mode {:03o})",
                path.display(),
                metadata.mode() & 0o777
            );
        }
    }
    Ok(())
}

fn validate_wire_peer_id(value: &str, label: &str) -> Result<()> {
    validate_peer_id(value).map_err(|e| anyhow!("invalid {label} '{value}': {e}"))
}

fn decode_escrow_id_hex(escrow_id_hex: &str) -> Result<[u8; 16]> {
    let raw = hex::decode(escrow_id_hex).context("decode escrow id hex")?;
    raw.try_into()
        .map_err(|_| anyhow!("escrow id must decode to exactly 16 bytes"))
}

/// Verify + decrypt a signer envelope and parse its escrow body.
fn open_signer_body(keys: &Keys, signer: &Peer, env: &NxmsEnvelope) -> Result<EscrowBody> {
    env.validate_basic().map_err(|e| anyhow!(e))?;
    let escrow_id_raw = decode_escrow_id_hex(&env.escrow_id_hex)?;
    let sealed = SealedPacket {
        kem_ct_b64: env.kem_ct_b64.clone(),
        nonce_b64: env.nonce_b64.clone(),
        ciphertext_b64: env.ciphertext_b64.clone(),
        tag_b64: env.tag_b64.clone(),
        sig_b64: env.sig_b64.clone(),
    };
    let self_kem_sk = keys.kem_sk_zeroizing()?;
    let signer_sig_pk = B64.decode(signer.sig_pk_b64.as_bytes())?;
    let plain = decrypt(
        &env.from,
        &env.to,
        msg_type_key(&env.msg_type),
        &escrow_id_raw,
        env.seq,
        &sealed,
        self_kem_sk.as_slice(),
        &signer_sig_pk,
    )?;
    let payload: NxmsPayload = serde_json::from_slice(&plain)?;
    payload.validate_matches_envelope(env).map_err(|e| anyhow!(e))?;
    Ok(serde_json::from_str(&payload.data)?)
}

fn body_kind(body: &EscrowBody) -> &'static str {
    match body {
        EscrowBody::ContractPropose(_) => "contract_propose",
        EscrowBody::ContractSig(_) => "contract_sig",
        EscrowBody::TxSignReq(_) => "tx_sign_req",
        EscrowBody::TxSignResp(_) => "tx_sign_resp",
        EscrowBody::Err(_) => "err",
    }
}

/// Allocate the next monotonic outgoing seq for `(escrow_id, from)` and
/// persist it before the envelope leaves the peer (gaps are allowed, replays
/// and out-of-order sends are not).
fn next_out_seq(state_path: &Path, escrow_id_hex: &str) -> Result<u64> {
    let mut state = read_seq_state(state_path)?;
    let next = state
        .out_seq
        .get(escrow_id_hex)
        .copied()
        .unwrap_or(0)
        .saturating_add(1)
        .max(1);
    state.out_seq.insert(escrow_id_hex.to_string(), next);
    write_seq_state(state_path, &state)?;
    Ok(next)
}

#[derive(Default, Serialize, Deserialize)]
struct SeqState {
    #[serde(default)]
    out_seq: BTreeMap<String, u64>,
}

fn read_seq_state(state_path: &Path) -> Result<SeqState> {
    if !state_path.exists() {
        return Ok(SeqState::default());
    }
    let raw = std::fs::read(state_path)
        .with_context(|| format!("read peer seq state {}", state_path.display()))?;
    serde_json::from_slice(&raw)
        .with_context(|| format!("parse peer seq state {}", state_path.display()))
}

fn write_seq_state(state_path: &Path, state: &SeqState) -> Result<()> {
    let data = serde_json::to_vec_pretty(state)?;
    write_private_file(state_path, &data)
        .with_context(|| format!("write peer seq state {}", state_path.display()))
}

#[cfg(unix)]
fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension(format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp_path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp_path)
        .map_err(|e| anyhow!("failed to create {}: {}", tmp_path.display(), e))?;
    file.write_all(data)
        .map_err(|e| anyhow!("failed to write {}: {}", tmp_path.display(), e))?;
    file.sync_all()
        .map_err(|e| anyhow!("failed to sync {}: {}", tmp_path.display(), e))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| anyhow!("failed to replace {}: {}", path.display(), e))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| anyhow!("failed to chmod {}: {}", path.display(), e))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, data)
        .map_err(|e| anyhow!("failed to write {}: {}", path.display(), e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_out_seq_is_monotonic_per_escrow() {
        let dir = std::env::temp_dir().join(format!(
            "nxms_peer_seq_state_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let state_path = seq_state_path(&dir);
        let escrow = "00112233445566778899aabbccddeeff";
        assert_eq!(next_out_seq(&state_path, escrow).expect("seq 1"), 1);
        assert_eq!(next_out_seq(&state_path, escrow).expect("seq 2"), 2);
        assert_eq!(
            next_out_seq(&state_path, "ffeeddccbbaa99887766554433221100").expect("other"),
            1
        );
        assert_eq!(next_out_seq(&state_path, escrow).expect("seq 3"), 3);
        let _ = std::fs::remove_file(&state_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_sets_owner_only_mode() {
        let path = std::env::temp_dir().join(format!(
            "nxms_peer_private_file_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        write_private_file(&path, b"secret").expect("write");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn read_secret_text_rejects_group_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "nxms_peer_secret_text_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::write(&path, "correct horse battery").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let err = read_secret_text(&path, "passphrase_file").expect_err("must reject 0644");
        assert!(err.to_string().contains("group/other accessible"));
        let _ = std::fs::remove_file(&path);
    }
}
