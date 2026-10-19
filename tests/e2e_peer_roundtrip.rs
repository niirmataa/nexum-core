mod support;

use anyhow::{Context, Result, anyhow};
use nxms_peer::{SignReqConfig, SignReqStatus, export_identity, init_vault, sign_req};
use nxms_transport::crypto::{Keys, decrypt, encrypt};
use nxms_transport::host_vault::HostVault;
use nxms_transport::peers::{Peer, PeerBook};
use nxms_transport::wire::{EscrowAction, MsgType, msg_type_key};

use support::{policy_hash_hex, stop_agent_task, txset_sha256_hex, WorkspaceSignerHarness};

const PEER_PASSPHRASE: &str = "peer vault passphrase";

/// Seed a peer host vault with the given keys so the signer's peers.json
/// allowlist entry for this peer matches the peer identity under test.
fn seed_peer_vault(vault_dir: &std::path::Path, keys: &Keys) -> Result<()> {
    HostVault::store(vault_dir, PEER_PASSPHRASE, "peer1", keys)
        .with_context(|| format!("seed peer vault {}", vault_dir.display()))
}

/// Peer-side peer book entry for the signer ("local" in the harness).
fn signer_peer_entry(harness: &WorkspaceSignerHarness) -> Peer {
    Peer {
        id: "local".to_string(),
        host: "signer.test".to_string(),
        port: 443,
        kem_pk_b64: harness.local_keys.kem_pk_b64.clone(),
        sig_pk_b64: harness.local_keys.sig_pk_b64.clone(),
    }
}

#[tokio::test]
async fn peer_sign_req_roundtrip_via_mailbox() -> Result<()> {
    let harness = WorkspaceSignerHarness::setup().await?;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let peer_home = tempfile::TempDir::new().context("peer home tempdir")?;
    let vault_dir = peer_home.path().join("host-vault");
    seed_peer_vault(&vault_dir, &harness.peer_keys)?;

    let peers_path = peer_home.path().join("peers.json");
    let peer_book = PeerBook {
        peers: vec![signer_peer_entry(&harness)],
    };
    std::fs::write(&peers_path, serde_json::to_vec_pretty(&peer_book)?)?;

    let snapshot = harness.seed_active_snapshot(escrow_id_hex).await?;
    let snapshot_hash = nxms_signer::snapshot::canonical_hash_hex(&snapshot)?;
    let snapshot_hash_for_token = policy_hash_hex(&snapshot)?;

    let agent_task = harness.spawn_agent();

    // The wallet mock signs exactly this txset; the sign action token below
    // binds the same txset hash.
    let txset_hex = "aa11".to_string();
    let cfg = SignReqConfig {
        vault_dir: vault_dir.clone(),
        passphrase: PEER_PASSPHRASE.to_string(),
        peers_path: peers_path.clone(),
        mailbox_url: harness.mailbox_url.clone(),
        push_token: "push-token-123456".to_string(),
        pull_token: "peer1-pull-token-123456".to_string(),
        ack_token: "peer1-ack-token-123456".to_string(),
        to: "local".to_string(),
        escrow_id_hex: escrow_id_hex.to_string(),
        action: EscrowAction::Release,
        multisig_txset_hex: txset_hex.clone(),
        snapshot_hash_hex: snapshot_hash.clone(),
        human_hint: Some("approve release".to_string()),
        escrow_admission_artifact: None,
        ttl_secs: 60,
        wait_ms: 50,
        timeout_secs: 15,
    };
    let sign_req_task = tokio::spawn(async move { sign_req(&cfg).await });

    let pending_id = harness.wait_for_pending_id().await?;
    let txset_hash_hex = txset_sha256_hex(&txset_hex)?;
    let sign_token = harness.build_sign_action_token(
        escrow_id_hex,
        &snapshot_hash_for_token,
        &txset_hash_hex,
        "jti-root-e2e-peer-roundtrip-sign",
    )?;
    harness
        .agent
        .approve_pending(pending_id, Some(&sign_token))
        .await?;

    let outcome = sign_req_task
        .await
        .map_err(|e| anyhow!("sign_req task join: {e}"))??;
    assert_eq!(outcome.status, SignReqStatus::Approved);
    assert!(outcome.approved);
    assert_eq!(outcome.escrow_id_hex, escrow_id_hex);
    assert_eq!(outcome.signer_id, "local");
    assert_eq!(outcome.request_seq, 1);
    assert_eq!(outcome.signed_tx_data_hex.as_deref(), Some("aa11"));

    // The peer acked the response; the mailbox is drained.
    let stats = harness.peer_client()?.admin_stats().await?;
    assert_eq!(stats.total_rows, 0);

    stop_agent_task(agent_task).await;
    Ok(())
}

#[test]
fn peer_init_and_identity_export_roundtrip() -> Result<()> {
    let home = tempfile::TempDir::new().context("peer home tempdir")?;
    let vault_dir = home.path().join("host-vault");

    let keys = init_vault(&vault_dir, PEER_PASSPHRASE, "peer1")?;
    // A second init must not overwrite an existing vault.
    assert!(init_vault(&vault_dir, PEER_PASSPHRASE, "peer1").is_err());

    let out = home.path().join("peer1.identity.json");
    let peer = export_identity(&vault_dir, PEER_PASSPHRASE, "peer1.test", 80, &out)?;
    assert_eq!(peer.id, "peer1");
    assert_eq!(peer.host, "peer1.test");
    assert_eq!(peer.port, 80);

    let vault = HostVault::load(&vault_dir, PEER_PASSPHRASE)?;
    assert_eq!(vault.local_id, "peer1");
    assert_eq!(peer.kem_pk_b64, vault.keys.kem_pk_b64);
    assert_eq!(peer.sig_pk_b64, vault.keys.sig_pk_b64);
    assert_eq!(peer.kem_pk_b64, keys.kem_pk_b64);

    // The exported entry is peers.json-ready and usable for the NXMS
    // envelope: encrypt to the peer with it and open with the vault keys.
    let entry: Peer = serde_json::from_slice(&std::fs::read(&out)?)?;
    let peer_book = PeerBook {
        peers: vec![entry.clone()],
    };
    assert_eq!(peer_book.get("peer1"), Some(&entry));

    let sender_keys = Keys::generate().context("generate sender keys")?;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let escrow_id_raw: [u8; 16] = hex::decode(escrow_id_hex)
        .context("decode escrow id")?
        .try_into()
        .map_err(|_| anyhow!("escrow id must be 16 bytes"))?;
    let plain = b"{\"app_proto\":\"ESCROW/1\"}";
    let recipient_kem_pk = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        entry.kem_pk_b64.as_bytes(),
    )?;
    let sender_sig_sk = sender_keys.sig_sk_zeroizing()?;
    let sealed = encrypt(
        "local",
        "peer1",
        msg_type_key(&MsgType::TxSignResp),
        &escrow_id_raw,
        1,
        &recipient_kem_pk,
        sender_sig_sk.as_slice(),
        plain,
    )?;
    let peer_kem_sk = vault.keys.kem_sk_zeroizing()?;
    let sender_sig_pk = sender_keys.sig_pk()?;
    let opened = decrypt(
        "local",
        "peer1",
        msg_type_key(&MsgType::TxSignResp),
        &escrow_id_raw,
        1,
        &sealed,
        peer_kem_sk.as_slice(),
        &sender_sig_pk,
    )?;
    assert_eq!(opened, plain);
    Ok(())
}
