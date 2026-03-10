mod support;

use anyhow::{Result, anyhow};
use nxms_mailbox_client::MailboxClient;
use nxms_transport::wire::{EscrowBody, TxSignRespBody};

use support::{WorkspaceSignerHarness, policy_hash_hex, stop_agent_task, txset_sha256_hex};

#[tokio::test]
async fn workspace_smoke_boots_real_stack_and_clears_mailbox() -> Result<()> {
    let harness = WorkspaceSignerHarness::setup().await?;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";

    let health_client = MailboxClient::builder(&harness.mailbox_url)?.build()?;
    health_client.health().await?;

    let admin_client = harness.peer_client()?;
    let initial_stats = admin_client.admin_stats().await?;
    assert_eq!(initial_stats.total_rows, 0);

    let snapshot = harness.seed_active_snapshot(escrow_id_hex).await?;
    let snapshot_hash = nxms_signer::snapshot::canonical_hash_hex(&snapshot)?;
    let snapshot_hash_for_token = policy_hash_hex(&snapshot)?;

    let agent_task = harness.spawn_agent();
    harness
        .push_sign_request(escrow_id_hex, &snapshot_hash, 1)
        .await?;

    let pending_id = harness.wait_for_pending_id().await?;
    let pending = harness
        .db
        .get_pending(pending_id)
        .await?
        .ok_or_else(|| anyhow!("missing pending row after ingress"))?;
    assert_eq!(pending.escrow_id_hex, escrow_id_hex);
    assert_eq!(pending.from_id, "peer1");
    assert_eq!(pending.to_id, "local");
    assert_eq!(pending.status, "pending");

    let sign_token = harness.build_sign_action_token(
        escrow_id_hex,
        &snapshot_hash_for_token,
        &txset_sha256_hex("aa11")?,
        "jti-root-workspace-smoke-sign",
    )?;
    harness
        .agent
        .approve_pending(pending_id, Some(&sign_token))
        .await?;

    let pulled = admin_client.pull("peer1", Some(1), Some(1000)).await?;
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

    admin_client.ack(&pulled.messages[0].receipt).await?;
    let final_stats = admin_client.admin_stats().await?;
    assert_eq!(final_stats.total_rows, 0);

    stop_agent_task(agent_task).await;
    Ok(())
}
