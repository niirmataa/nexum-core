mod support;

use std::sync::Arc;

use anyhow::Result;
use nxms_signer::trust::materialize_runtime_trust_from_config;
use nxms_signer::{SignerAgent, SignerConfig};
use nxms_transport::wire::{EscrowAction, EscrowBody, TxSignRespBody};

use support::{
    WorkspaceSignerHarness, policy_hash_hex, stop_agent_task, txset_sha256_hex,
    write_runtime_trust_bundle,
};

async fn setup_runtime_trust_agent() -> Result<(WorkspaceSignerHarness, SignerConfig, String)> {
    let harness = WorkspaceSignerHarness::setup().await?;
    let trust_epoch = "epoch-2026-03-12-a".to_string();
    let bundle_path = harness
        .cfg
        .db_path
        .parent()
        .expect("db path parent")
        .join("runtime-trust-bundle.json");
    let action_pub_path = harness
        .cfg
        .action_token
        .as_ref()
        .expect("action token config")
        .public_key_pem_path
        .clone();
    write_runtime_trust_bundle(
        &bundle_path,
        &harness.cfg.local_id,
        &harness.local_keys,
        "peer1",
        &harness.peer_keys,
        &harness.ag01_keys,
        &harness.ag02_keys,
        &action_pub_path,
        &trust_epoch,
    )?;

    let mut cfg = harness.cfg.clone();
    cfg.runtime_trust_bundle_path = Some(bundle_path);
    let _ = std::fs::remove_file(&cfg.peers_path);
    let _ = std::fs::remove_file(
        &cfg.action_token
            .as_ref()
            .expect("action token config")
            .public_key_pem_path,
    );
    materialize_runtime_trust_from_config(&cfg)?;

    Ok((harness, cfg, trust_epoch))
}

#[tokio::test]
async fn workspace_e2e_runtime_trust_materialize_sign_and_submit() -> Result<()> {
    let (harness, cfg, trust_epoch) = setup_runtime_trust_agent().await?;
    let agent = Arc::new(SignerAgent::from_config(cfg).await?);
    let run_agent = Arc::clone(&agent);
    let agent_task = tokio::spawn(async move { run_agent.run().await });

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = harness.seed_active_snapshot(escrow_id_hex).await?;
    let snapshot_hash = nxms_signer::snapshot::canonical_hash_hex(&snapshot)?;
    let snapshot_hash_for_token = policy_hash_hex(&snapshot)?;
    let admission = harness.build_escrow_admission_artifact(
        escrow_id_hex,
        &snapshot_hash_for_token,
        EscrowAction::Release,
        &trust_epoch,
    )?;
    let admission_hash = admission.hash_hex()?;

    harness
        .push_sign_request_with_admission(escrow_id_hex, &snapshot_hash, 1, admission)
        .await?;
    let pending_id = harness.wait_for_pending_id().await?;

    let txset_hash_hex = txset_sha256_hex("aa11")?;
    let sign_jti = "jti-runtime-trust-sign";
    let sign_token = harness.build_sign_action_token_with_runtime(
        escrow_id_hex,
        &snapshot_hash_for_token,
        &txset_hash_hex,
        sign_jti,
        Some(&trust_epoch),
        Some(&admission_hash),
    )?;
    agent.approve_pending(pending_id, Some(&sign_token)).await?;

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
        panic!("expected TxSignResp body");
    };
    assert!(approved);
    let signed_tx_data_hex = signed_tx_data_hex.expect("missing signed tx data");
    peer_client.ack(&pulled.messages[0].receipt).await?;

    let submit_token = harness.build_submit_action_token_with_runtime(
        escrow_id_hex,
        &snapshot_hash_for_token,
        &txset_hash_hex,
        "jti-runtime-trust-submit",
        sign_jti,
        "seller-proof-jti-runtime-trust",
        Some(&trust_epoch),
        Some(&admission_hash),
    )?;
    let submitted = agent
        .submit_multisig_flow(
            escrow_id_hex,
            EscrowAction::Release,
            &signed_tx_data_hex,
            Some(&submit_token),
        )
        .await?;
    assert_eq!(submitted, vec!["submithash".to_string()]);

    stop_agent_task(agent_task).await;
    Ok(())
}

#[tokio::test]
async fn workspace_e2e_runtime_trust_rejects_epoch_mismatch() -> Result<()> {
    let (harness, cfg, _trust_epoch) = setup_runtime_trust_agent().await?;
    let agent = Arc::new(SignerAgent::from_config(cfg).await?);
    let run_agent = Arc::clone(&agent);
    let agent_task = tokio::spawn(async move { run_agent.run().await });

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = harness.seed_active_snapshot(escrow_id_hex).await?;
    let snapshot_hash = nxms_signer::snapshot::canonical_hash_hex(&snapshot)?;
    let snapshot_hash_for_token = policy_hash_hex(&snapshot)?;
    let admission = harness.build_escrow_admission_artifact(
        escrow_id_hex,
        &snapshot_hash_for_token,
        EscrowAction::Release,
        "epoch-2026-03-12-a",
    )?;
    let admission_hash = admission.hash_hex()?;

    harness
        .push_sign_request_with_admission(escrow_id_hex, &snapshot_hash, 1, admission)
        .await?;
    let pending_id = harness.wait_for_pending_id().await?;

    let txset_hash_hex = txset_sha256_hex("aa11")?;
    let bad_token = harness.build_sign_action_token_with_runtime(
        escrow_id_hex,
        &snapshot_hash_for_token,
        &txset_hash_hex,
        "jti-runtime-trust-bad-epoch",
        Some("epoch-wrong"),
        Some(&admission_hash),
    )?;
    let err = agent
        .approve_pending(pending_id, Some(&bad_token))
        .await
        .expect_err("epoch mismatch must reject token");
    assert!(err.to_string().contains("runtime_trust_epoch mismatch"));

    let row = harness
        .db
        .get_pending(pending_id)
        .await?
        .expect("pending row must exist");
    assert_eq!(row.status, "pending");

    stop_agent_task(agent_task).await;
    Ok(())
}

#[tokio::test]
async fn workspace_e2e_runtime_trust_rejects_projection_drift_on_start() -> Result<()> {
    let (_harness, cfg, _trust_epoch) = setup_runtime_trust_agent().await?;
    std::fs::write(
        &cfg.peers_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "peers": [{
                "id": "peer1",
                "host": "driftedhiddenservice.onion",
                "port": 443,
                "kem_pk_b64": "ZmFrZS1rZW0=",
                "sig_pk_b64": "ZmFrZS1zaWc="
            }]
        }))?,
    )?;

    let err = match SignerAgent::from_config(cfg).await {
        Ok(_) => panic!("drifted peers projection must fail startup"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("peers.json does not match runtime trust bundle projection"));
    Ok(())
}
