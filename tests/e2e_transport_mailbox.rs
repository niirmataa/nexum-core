mod support;

use anyhow::{anyhow, Result};
use nxms_transport::wire::{EscrowBody, TxSignRespBody};

use support::{policy_hash_hex, stop_agent_task, txset_sha256_hex, WorkspaceSignerHarness};

#[tokio::test]
async fn workspace_e2e_transport_mailbox_smoke_roundtrip() -> Result<()> {
    let harness = WorkspaceSignerHarness::setup().await?;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";

    let snapshot = harness.seed_active_snapshot(escrow_id_hex).await?;
    let snapshot_hash = nxms_signer::snapshot::canonical_hash_hex(&snapshot)?;
    let snapshot_hash_for_token = policy_hash_hex(&snapshot)?;

    let agent_task = harness.spawn_agent();
    harness
        .push_sign_request(escrow_id_hex, &snapshot_hash, 1)
        .await?;

    let pending_id = harness.wait_for_pending_id().await?;
    let sign_token = harness.build_sign_action_token(
        escrow_id_hex,
        &snapshot_hash_for_token,
        &txset_sha256_hex("aa11")?,
        "jti-root-e2e-transport-mailbox",
    )?;
    harness
        .agent
        .approve_pending(pending_id, Some(&sign_token))
        .await?;

    let peer_client = harness.peer_client()?;
    let pulled = peer_client.pull("peer1", Some(1), Some(1000)).await?;
    assert_eq!(pulled.messages.len(), 1);

    let body = harness.decode_envelope_body(&pulled.messages[0].envelope)?;
    let EscrowBody::TxSignResp(TxSignRespBody {
        approved,
        signed_tx_data_hex,
        ..
    }) = body
    else {
        return Err(anyhow!("expected TxSignResp body"));
    };
    assert!(approved);
    assert_eq!(signed_tx_data_hex.as_deref(), Some("aa11"));

    peer_client.ack(&pulled.messages[0].receipt).await?;
    let stats = peer_client.admin_stats().await?;
    assert_eq!(stats.total_rows, 0);

    let audit = harness.db.list_audit_logs(200).await?;
    assert!(audit.iter().any(|row| row.event_kind == "pending_enqueued"));
    assert!(audit
        .iter()
        .any(|row| row.event_kind == "decision_approved"));

    stop_agent_task(agent_task).await;
    Ok(())
}
