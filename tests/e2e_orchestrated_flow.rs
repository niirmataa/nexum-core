mod support;

use std::sync::Arc;

use anyhow::{anyhow, Result};
use nxms_escrow_orchestrator::{
    build_issue_params, flow::WorkflowState, issue_action_token, ActionTokenCliInput,
    ActionTokenOp, ActionTokenRole, OrchestratorDb,
};
use nxms_signer::action_token::sign_req_id;
use nxms_signer::SignerAgent;
use nxms_transport::wire::{EscrowAction, EscrowBody, TxSignRespBody};
use nxms_transport::ActionTokenIssuerVault;
use tempfile::TempDir;

use support::{
    generate_action_token_issuer_vault, policy_hash_hex, stop_agent_task, txset_sha256_hex,
    WorkspaceSignerHarness,
};

async fn transition_workflow_to_funded(db: &OrchestratorDb, escrow_id_hex: &str) -> Result<()> {
    for state in [
        WorkflowState::PrepareCollected,
        WorkflowState::MakeCollected,
        WorkflowState::ExchangeR1Collected,
        WorkflowState::ExchangeR2Collected,
        WorkflowState::FinalizedReady,
        WorkflowState::Funded,
    ] {
        db.transition_workflow(escrow_id_hex, state, Some("e2e orchestrated flow"))
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn workspace_e2e_orchestrated_flow_issues_submit_token_from_control_plane() -> Result<()> {
    let harness = WorkspaceSignerHarness::setup().await?;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let txset_hash_hex = txset_sha256_hex("aa11")?;

    let snapshot = harness.seed_active_snapshot(escrow_id_hex).await?;
    let snapshot_hash = nxms_signer::snapshot::canonical_hash_hex(&snapshot)?;
    let snapshot_hash_for_token = policy_hash_hex(&snapshot)?;

    let orchestrator_tempdir = TempDir::new()?;
    let orchestrator_db_path = orchestrator_tempdir.path().join("orchestrator.db");
    let (orchestrator_issuer_vault_dir, orchestrator_issuer_passphrase_file) =
        generate_action_token_issuer_vault(orchestrator_tempdir.path())?;
    let orchestrator_public_key =
        ActionTokenIssuerVault::load(&orchestrator_issuer_vault_dir, "correct horse battery")?
            .bundle()?
            .public_key_pem;
    std::fs::write(
        &harness
            .cfg
            .action_token
            .as_ref()
            .expect("action token config")
            .public_key_pem_path,
        orchestrator_public_key.as_bytes(),
    )?;

    let orchestrator_db = OrchestratorDb::new(orchestrator_db_path.clone());
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

    let agent = Arc::new(SignerAgent::from_config(harness.cfg.clone()).await?);
    let run_agent = Arc::clone(&agent);
    let agent_task = tokio::spawn(async move { run_agent.run().await });
    harness
        .push_sign_request(escrow_id_hex, &snapshot_hash, 1)
        .await?;

    let pending_id = harness.wait_for_pending_id().await?;
    let issue_sign_params = build_issue_params(ActionTokenCliInput {
        escrow_id_hex: escrow_id_hex.to_string(),
        txset_hash_hex: txset_hash_hex.clone(),
        role: ActionTokenRole::Arbiter,
        op: ActionTokenOp::SignMultisig,
        runtime_trust_bundle_path: None,
        issuer_vault_dir: Some(orchestrator_issuer_vault_dir.clone()),
        issuer_vault_passphrase_file: Some(orchestrator_issuer_passphrase_file.clone()),
        ttl_secs: Some(60),
        subject: Some("arbiter_operator".to_string()),
        wallet_id: Some(harness.cfg.wallet_id.clone()),
        sandbox_id: Some(harness.cfg.sandbox_id.clone()),
        audience: Some(format!("sandbox:{}", harness.cfg.sandbox_id)),
        nettype: Some(harness.cfg.nettype.clone()),
    })?;
    let issued_sign = issue_action_token(&orchestrator_db, &issue_sign_params).await?;
    let sign_jti = issued_sign.claims.jti.clone();
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

    let arbiter_req_id = sign_req_id(
        escrow_id_hex,
        "sign_multisig",
        "arbiter_first",
        &txset_hash_hex,
    );
    let seller_jti = "seller-proof-jti-root-e2e-orchestrated";
    let seller_req_id = sign_req_id(
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
            &sign_jti,
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

    let bundle = orchestrator_db
        .get_submit_multisig_proof_bundle(escrow_id_hex, &txset_hash_hex)
        .await?;
    assert_eq!(bundle.proof_arbiter_jti, sign_jti);
    assert_eq!(bundle.proof_arbiter_req_id, arbiter_req_id);
    assert_eq!(bundle.proof_seller_jti, seller_jti);
    assert_eq!(bundle.proof_seller_req_id, seller_req_id);

    let issue_params = build_issue_params(ActionTokenCliInput {
        escrow_id_hex: escrow_id_hex.to_string(),
        txset_hash_hex: txset_hash_hex.clone(),
        role: ActionTokenRole::Arbiter,
        op: ActionTokenOp::SubmitMultisig,
        runtime_trust_bundle_path: None,
        issuer_vault_dir: Some(orchestrator_issuer_vault_dir),
        issuer_vault_passphrase_file: Some(orchestrator_issuer_passphrase_file),
        ttl_secs: Some(60),
        subject: Some("arbiter_operator".to_string()),
        wallet_id: Some(harness.cfg.wallet_id.clone()),
        sandbox_id: Some(harness.cfg.sandbox_id.clone()),
        audience: Some(format!("sandbox:{}", harness.cfg.sandbox_id)),
        nettype: Some(harness.cfg.nettype.clone()),
    })?;
    let issued = issue_action_token(&orchestrator_db, &issue_params).await?;
    assert_eq!(issued.claims.op, "submit_multisig");
    assert_eq!(issued.claims.snapshot_hash, snapshot_hash_for_token);
    assert_eq!(
        issued.claims.proof_arbiter_jti.as_deref(),
        Some(sign_jti.as_str())
    );
    assert_eq!(issued.claims.proof_seller_jti.as_deref(), Some(seller_jti));

    let submitted = agent
        .submit_multisig_flow(
            escrow_id_hex,
            EscrowAction::Release,
            &signed_tx_data_hex,
            Some(&issued.token),
        )
        .await?;
    assert_eq!(submitted, vec!["submithash".to_string()]);

    orchestrator_db
        .transition_workflow(
            escrow_id_hex,
            WorkflowState::Submitted,
            Some("submit success"),
        )
        .await?;
    let workflow = orchestrator_db
        .get_workflow(escrow_id_hex)
        .await?
        .ok_or_else(|| anyhow!("workflow missing after submit"))?;
    assert_eq!(workflow.state, WorkflowState::Submitted);

    let integrity = orchestrator_db.check_integrity(50).await?;
    assert!(integrity.is_empty());
    let dead_letters = orchestrator_db.list_dead_letters(50).await?;
    assert!(
        dead_letters.is_empty(),
        "control-plane progress notes must not surface as dead letters"
    );

    let slo = orchestrator_db
        .slo_alert_report(60_000, 60_000, Default::default())
        .await?;
    assert!(
        slo.ok,
        "unexpected slo report: {}",
        serde_json::to_string_pretty(&slo)?
    );
    assert_eq!(slo.metrics.workflows_total, 1);
    assert_eq!(slo.metrics.outbox_pending, 0);
    assert_eq!(slo.metrics.dead_letter_window, 0);

    let signer_audit = harness.db.list_audit_logs(200).await?;
    assert!(signer_audit
        .iter()
        .any(|row| row.event_kind == "submit_success"));

    stop_agent_task(agent_task).await;
    Ok(())
}
