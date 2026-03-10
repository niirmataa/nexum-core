mod support;

use anyhow::{anyhow, Result};
use nxms_transport::wire::{EscrowAction, EscrowBody, TxSignRespBody};

use support::{policy_hash_hex, stop_agent_task, txset_sha256_hex, WorkspaceSignerHarness};

#[tokio::test]
async fn workspace_e2e_sign_submit_roundtrip() -> Result<()> {
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
    let txset_hash_hex = txset_sha256_hex("aa11")?;
    let sign_jti = "jti-root-e2e-sign-submit-sign";
    let sign_token = harness.build_sign_action_token(
        escrow_id_hex,
        &snapshot_hash_for_token,
        &txset_hash_hex,
        sign_jti,
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
    let signed_tx_data_hex =
        signed_tx_data_hex.ok_or_else(|| anyhow!("missing signed_tx_data_hex"))?;

    peer_client.ack(&pulled.messages[0].receipt).await?;

    let submit_token = harness.build_submit_action_token(
        escrow_id_hex,
        &snapshot_hash_for_token,
        &txset_hash_hex,
        "jti-root-e2e-sign-submit-submit",
        sign_jti,
        "seller-proof-jti-root-e2e-sign-submit",
    )?;
    let submitted = harness
        .agent
        .submit_multisig_flow(
            escrow_id_hex,
            EscrowAction::Release,
            &signed_tx_data_hex,
            Some(&submit_token),
        )
        .await?;
    assert_eq!(submitted, vec!["submithash".to_string()]);
    assert!(harness
        .wallet_calls()
        .iter()
        .any(|call| call == "submit_multisig"));

    let audit = harness.db.list_audit_logs(200).await?;
    assert!(audit.iter().any(|row| row.event_kind == "submit_success"));

    let stats = peer_client.admin_stats().await?;
    assert_eq!(stats.total_rows, 0);

    stop_agent_task(agent_task).await;
    Ok(())
}
