mod support;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use nxms_escrow_orchestrator::{
    ActionTokenCliInput, ActionTokenOp, ActionTokenRole, OrchestratorDb, build_issue_params,
    db::EscrowAdmissionArtifactRow, flow::WorkflowState, issue_action_token,
};
use nxms_signer::trust::materialize_runtime_trust_from_config;
use nxms_signer::{SignerAgent, SignerConfig};
use nxms_transport::admission::EscrowAdmissionArtifact;
use nxms_transport::wire::{EscrowAction, EscrowBody, TxSignRespBody};
use tempfile::TempDir;

use support::{
    WorkspaceSignerHarness, policy_hash_hex, stop_agent_task, txset_sha256_hex,
    write_action_token_private_key_pem, write_runtime_trust_bundle,
};

async fn setup_runtime_trust_agent() -> Result<(WorkspaceSignerHarness, SignerConfig, String)> {
    let harness = WorkspaceSignerHarness::setup().await?;
    let trust_epoch = "epoch-2026-03-12-admission".to_string();
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

async fn transition_workflow_to_funded(db: &OrchestratorDb, escrow_id_hex: &str) -> Result<()> {
    for state in [
        WorkflowState::PrepareCollected,
        WorkflowState::MakeCollected,
        WorkflowState::ExchangeR1Collected,
        WorkflowState::ExchangeR2Collected,
        WorkflowState::FinalizedReady,
        WorkflowState::Funded,
    ] {
        db.transition_workflow(escrow_id_hex, state, Some("e2e escrow admission"))
            .await?;
    }
    Ok(())
}

fn admission_row(artifact: &EscrowAdmissionArtifact) -> Result<EscrowAdmissionArtifactRow> {
    let now_ms = artifact.admitted_at_unix_ms;
    Ok(EscrowAdmissionArtifactRow {
        escrow_id_hex: artifact.escrow_id_hex.clone(),
        snapshot_hash_hex: artifact.snapshot_hash_hex.clone(),
        action: match artifact.action {
            EscrowAction::Release => "release".to_string(),
            EscrowAction::Refund => "refund".to_string(),
        },
        runtime_trust_epoch: artifact.runtime_trust_epoch.clone(),
        artifact_hash_hex: artifact.hash_hex()?,
        artifact_json: serde_json::to_string(artifact)?,
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
    })
}

#[tokio::test]
async fn workspace_e2e_escrow_admission_orchestrated_sign_and_submit() -> Result<()> {
    let (harness, cfg, trust_epoch) = setup_runtime_trust_agent().await?;
    let bundle_path = cfg
        .runtime_trust_bundle_path
        .clone()
        .ok_or_else(|| anyhow!("runtime trust bundle path missing"))?;
    let agent = Arc::new(SignerAgent::from_config(cfg.clone()).await?);
    let run_agent = Arc::clone(&agent);
    let agent_task = tokio::spawn(async move { run_agent.run().await });

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let txset_hash_hex = txset_sha256_hex("aa11")?;
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

    let orchestrator_tempdir = TempDir::new()?;
    let orchestrator_db_path = orchestrator_tempdir.path().join("orchestrator.db");
    let orchestrator_key_path = orchestrator_tempdir
        .path()
        .join("orch_action_token_ed25519.pem");
    write_action_token_private_key_pem(&orchestrator_key_path)?;

    let orchestrator_db = OrchestratorDb::new(orchestrator_db_path);
    orchestrator_db.init().await?;
    orchestrator_db
        .create_workflow(
            escrow_id_hex,
            &snapshot_hash_for_token,
            &[
                "buyer".to_string(),
                "seller".to_string(),
                "arbiter".to_string(),
            ],
        )
        .await?;
    transition_workflow_to_funded(&orchestrator_db, escrow_id_hex).await?;
    orchestrator_db
        .upsert_proposal_blob(escrow_id_hex, "release", "aa11", &txset_hash_hex)
        .await?;
    orchestrator_db
        .upsert_escrow_admission_artifact(&admission_row(&admission)?)
        .await?;

    harness
        .push_sign_request_with_admission(escrow_id_hex, &snapshot_hash, 1, admission)
        .await?;
    let pending_id = harness.wait_for_pending_id().await?;

    let issue_sign = build_issue_params(ActionTokenCliInput {
        escrow_id_hex: escrow_id_hex.to_string(),
        txset_hash_hex: txset_hash_hex.clone(),
        role: ActionTokenRole::Arbiter,
        op: ActionTokenOp::SignMultisig,
        runtime_trust_bundle_path: Some(bundle_path.clone()),
        issuer: Some("nxms-auth".to_string()),
        algorithm: "EDDSA".to_string(),
        private_key_pem_path: Some(orchestrator_key_path.clone()),
        ttl_secs: 60,
        subject: Some("arbiter_operator".to_string()),
        wallet_id: Some(harness.cfg.wallet_id.clone()),
        sandbox_id: Some(harness.cfg.sandbox_id.clone()),
        audience: Some(format!("sandbox:{}", harness.cfg.sandbox_id)),
        nettype: Some(harness.cfg.nettype.clone()),
    })?;
    let issued_sign = issue_action_token(&orchestrator_db, &issue_sign).await?;
    assert_eq!(issued_sign.claims.runtime_trust_epoch.as_deref(), Some(trust_epoch.as_str()));
    assert_eq!(
        issued_sign.claims.escrow_admission_hash.as_deref(),
        Some(admission_hash.as_str())
    );
    agent
        .approve_pending(pending_id, Some(&issued_sign.token))
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

    let arbiter_req_id = nxms_signer::action_token::sign_req_id(
        escrow_id_hex,
        "sign_multisig",
        "arbiter_first",
        &txset_hash_hex,
    );
    let seller_jti = "seller-proof-jti-e2e-admission";
    let seller_req_id = nxms_signer::action_token::sign_req_id(
        escrow_id_hex,
        "sign_multisig",
        "seller_second",
        &txset_hash_hex,
    );
    orchestrator_db
        .transition_workflow(
            escrow_id_hex,
            WorkflowState::TxSignPending,
            Some("sign request delivered"),
        )
        .await?;
    orchestrator_db
        .upsert_quorum_sign_proof(
            escrow_id_hex,
            "arbiter",
            "arbiter_first",
            &txset_hash_hex,
            issued_sign.claims.jti.as_str(),
            &arbiter_req_id,
        )
        .await?;
    orchestrator_db
        .upsert_quorum_sign_proof(
            escrow_id_hex,
            "seller",
            "seller_second",
            &txset_hash_hex,
            seller_jti,
            &seller_req_id,
        )
        .await?;
    orchestrator_db
        .transition_workflow(
            escrow_id_hex,
            WorkflowState::TxSignedQuorum,
            Some("quorum proofs stored"),
        )
        .await?;

    let issue_submit = build_issue_params(ActionTokenCliInput {
        escrow_id_hex: escrow_id_hex.to_string(),
        txset_hash_hex: txset_hash_hex.clone(),
        role: ActionTokenRole::Arbiter,
        op: ActionTokenOp::SubmitMultisig,
        runtime_trust_bundle_path: Some(bundle_path),
        issuer: Some("nxms-auth".to_string()),
        algorithm: "EDDSA".to_string(),
        private_key_pem_path: Some(orchestrator_key_path),
        ttl_secs: 60,
        subject: Some("arbiter_operator".to_string()),
        wallet_id: Some(harness.cfg.wallet_id.clone()),
        sandbox_id: Some(harness.cfg.sandbox_id.clone()),
        audience: Some(format!("sandbox:{}", harness.cfg.sandbox_id)),
        nettype: Some(harness.cfg.nettype.clone()),
    })?;
    let issued_submit = issue_action_token(&orchestrator_db, &issue_submit).await?;
    assert_eq!(
        issued_submit.claims.escrow_admission_hash.as_deref(),
        Some(admission_hash.as_str())
    );

    let submitted = agent
        .submit_multisig_flow(
            escrow_id_hex,
            EscrowAction::Release,
            &signed_tx_data_hex,
            Some(&issued_submit.token),
        )
        .await?;
    assert_eq!(submitted, vec!["submithash".to_string()]);

    stop_agent_task(agent_task).await;
    Ok(())
}

#[tokio::test]
async fn workspace_e2e_escrow_admission_missing_from_ingress_rejects_pending() -> Result<()> {
    let (harness, cfg, _trust_epoch) = setup_runtime_trust_agent().await?;
    let agent = Arc::new(SignerAgent::from_config(cfg).await?);
    let run_agent = Arc::clone(&agent);
    let agent_task = tokio::spawn(async move { run_agent.run().await });

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = harness.seed_active_snapshot(escrow_id_hex).await?;
    let snapshot_hash = nxms_signer::snapshot::canonical_hash_hex(&snapshot)?;
    harness
        .push_sign_request(escrow_id_hex, &snapshot_hash, 1)
        .await?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut rejected = false;
    while tokio::time::Instant::now() < deadline {
        let audit = harness.db.list_audit_logs(50).await?;
        if audit.iter().any(|row| row.event_kind == "tx_sign_req_rejected") {
            rejected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(rejected, "tx_sign_req without admission artifact must be rejected");
    assert!(harness.db.list_pending().await?.is_empty());

    stop_agent_task(agent_task).await;
    Ok(())
}

#[tokio::test]
async fn workspace_e2e_escrow_admission_hash_mismatch_rejects_action_token() -> Result<()> {
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
    harness
        .push_sign_request_with_admission(escrow_id_hex, &snapshot_hash, 1, admission)
        .await?;
    let pending_id = harness.wait_for_pending_id().await?;

    let bad_token = harness.build_sign_action_token_with_runtime(
        escrow_id_hex,
        &snapshot_hash_for_token,
        &txset_sha256_hex("aa11")?,
        "jti-admission-hash-mismatch",
        Some(&trust_epoch),
        Some(&"ff".repeat(32)),
    )?;
    let err = agent
        .approve_pending(pending_id, Some(&bad_token))
        .await
        .expect_err("mismatched admission hash must reject");
    assert!(err.to_string().contains("escrow_admission_hash mismatch"));
    assert_eq!(
        harness
            .db
            .get_pending(pending_id)
            .await?
            .ok_or_else(|| anyhow!("missing pending row"))?
            .status,
        "pending"
    );

    stop_agent_task(agent_task).await;
    Ok(())
}
