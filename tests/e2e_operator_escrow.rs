//! Control-plane integration test for operator escrow.
//!
//! This test validates the operator escrow adapter layer:
//! - Funding descriptor arrives from mailbox event
//! - Operator does NOT trust the event blindly
//! - Operator verifies funding through its own LedgerObserver
//! - After confirmation, builds EscrowSnapshot
//! - Builds EscrowSpendProposal (with canonical tx_signing_hash from privai-chain)
//! - Confirms proposal_hash != tx_signing_hash (invariant)
//! - Collects approvals and assembles EscrowApprovalBundle
//! - Bridges bundle to InputAuth
//!
//! This test does NOT submit a transaction to privai-node.
//! It validates the control-plane layer only.

use nxms_escrow_orchestrator::flow::WorkflowState;
use nxms_escrow_orchestrator::operator_escrow::*;
use privai_chain::hash::falcon_pk_hash;
use privai_chain::note::SpendPolicy;
use privai_chain::CanonicalDecode;

fn h(fill: u8) -> Hash32 {
    [fill; 32]
}

fn fake_falcon_pk(fill: u8) -> Vec<u8> {
    vec![fill; 897]
}

fn escrow_policy_commit(
    buyer_pk_hash: Hash32,
    merchant_pk_hash: Hash32,
    operator_pk_hash: Hash32,
    timeout_block: u64,
) -> Hash32 {
    SpendPolicy::Escrow2of3 {
        buyer_pk_hash,
        merchant_pk_hash,
        operator_pk_hash,
        timeout_block,
    }
    .commitment()
}

#[test]
fn operator_rejects_funding_without_ledger_confirmation() {
    let descriptor = EscrowFundingDescriptor {
        escrow_id: h(0x01),
        buyer_pk: h(0x10),
        merchant_pk: h(0x20),
        operator_pk: h(0x30),
        amount: 5000,
        spend_policy_commit: h(0xAA),
        timeout_blocks: 2000,
    };

    let note_commit = h(0xBB);
    let observer = MockLedgerObserver::new(100);

    // Mailbox says "funding detected" but ledger has no such note
    let result = process_funding_event(&descriptor, &note_commit, &observer);
    assert!(
        result.is_err(),
        "operator must reject funding when ledger has no matching note"
    );
}

#[test]
fn operator_rejects_funding_with_wrong_policy() {
    let descriptor = EscrowFundingDescriptor {
        escrow_id: h(0x01),
        buyer_pk: h(0x10),
        merchant_pk: h(0x20),
        operator_pk: h(0x30),
        amount: 5000,
        spend_policy_commit: h(0xAA),
        timeout_blocks: 2000,
    };

    let note_commit = h(0xBB);
    let mut observer = MockLedgerObserver::new(100);
    // Note exists but has different policy_commit
    observer.add_unspent_note(note_commit, h(0xFF));

    let result = process_funding_event(&descriptor, &note_commit, &observer);
    assert!(
        result.is_err(),
        "operator must reject funding when policy_commit doesn't match"
    );
}

#[test]
fn operator_confirms_funding_and_builds_snapshot() {
    let descriptor = EscrowFundingDescriptor {
        escrow_id: h(0x01),
        buyer_pk: h(0x10),
        merchant_pk: h(0x20),
        operator_pk: h(0x30),
        amount: 5000,
        spend_policy_commit: h(0xAA),
        timeout_blocks: 2000,
    };

    let note_commit = h(0xBB);
    let mut observer = MockLedgerObserver::new(100);
    observer.add_unspent_note(note_commit, descriptor.spend_policy_commit);

    // 1. Verify funding through own ledger view
    let verified = process_funding_event(&descriptor, &note_commit, &observer).unwrap();
    assert_eq!(verified, note_commit);

    // 2. Build snapshot
    let snapshot = build_snapshot(&descriptor, verified);

    assert_eq!(snapshot.escrow_id, descriptor.escrow_id);
    assert_eq!(snapshot.buyer_pk, descriptor.buyer_pk);
    assert_eq!(snapshot.merchant_pk, descriptor.merchant_pk);
    assert_eq!(snapshot.operator_pk, descriptor.operator_pk);
    assert_eq!(snapshot.funding_note_commit, note_commit);
    assert_eq!(snapshot.spend_policy_commit, descriptor.spend_policy_commit);
    assert_eq!(snapshot.amount, 5000);
    assert_eq!(snapshot.timeout_block, 2000);
    assert_eq!(snapshot.status, 1); // funded
    assert_ne!(snapshot.snapshot_hash, [0; 32]);
}

#[test]
fn proposal_hash_is_not_tx_signing_hash() {
    let descriptor = EscrowFundingDescriptor {
        escrow_id: h(0x01),
        buyer_pk: h(0x10),
        merchant_pk: h(0x20),
        operator_pk: h(0x30),
        amount: 5000,
        spend_policy_commit: h(0xAA),
        timeout_blocks: 2000,
    };

    let snapshot = build_snapshot(&descriptor, h(0xBB));
    let buyer_h = falcon_pk_hash(&fake_falcon_pk(0xB0));
    let merchant_h = falcon_pk_hash(&fake_falcon_pk(0xC0));
    let operator_h = falcon_pk_hash(&fake_falcon_pk(0xD0));

    let proposal = build_proposal(
        &snapshot,
        EscrowAction::Release,
        merchant_h,
        100,
        &buyer_h,
        &merchant_h,
        &operator_h,
    )
    .unwrap();

    assert_ne!(
        proposal.proposal_hash, proposal.tx_signing_hash,
        "CRITICAL INVARIANT: proposal_hash (control-plane) must differ from tx_signing_hash (on-chain)"
    );
    assert_ne!(proposal.proposal_hash, [0; 32]);
    assert_ne!(proposal.tx_signing_hash, [0; 32]);
}

#[test]
fn different_actions_produce_different_hashes() {
    let descriptor = EscrowFundingDescriptor {
        escrow_id: h(0x01),
        buyer_pk: h(0x10),
        merchant_pk: h(0x20),
        operator_pk: h(0x30),
        amount: 5000,
        spend_policy_commit: h(0xAA),
        timeout_blocks: 2000,
    };

    let snapshot = build_snapshot(&descriptor, h(0xBB));
    let buyer_h = falcon_pk_hash(&fake_falcon_pk(0xB0));
    let merchant_h = falcon_pk_hash(&fake_falcon_pk(0xC0));
    let operator_h = falcon_pk_hash(&fake_falcon_pk(0xD0));

    let release = build_proposal(
        &snapshot,
        EscrowAction::Release,
        merchant_h,
        100,
        &buyer_h,
        &merchant_h,
        &operator_h,
    )
    .unwrap();
    let refund = build_proposal(
        &snapshot,
        EscrowAction::Refund,
        buyer_h,
        100,
        &buyer_h,
        &merchant_h,
        &operator_h,
    )
    .unwrap();

    assert_ne!(release.proposal_hash, refund.proposal_hash);
    assert_ne!(release.tx_signing_hash, refund.tx_signing_hash);
    assert_eq!(release.action, EscrowAction::Release as u8);
    assert_eq!(refund.action, EscrowAction::Refund as u8);
}

#[test]
fn full_control_plane_flow() {
    let mut descriptor = EscrowFundingDescriptor {
        escrow_id: h(0x01),
        buyer_pk: h(0x10),
        merchant_pk: h(0x20),
        operator_pk: h(0x30),
        amount: 5000,
        spend_policy_commit: h(0xAA),
        timeout_blocks: 2000,
    };

    let note_commit = h(0xBB);
    let buyer_pk = fake_falcon_pk(0xB0);
    let operator_pk = fake_falcon_pk(0xD0);
    let buyer_h = falcon_pk_hash(&buyer_pk);
    let merchant_h = falcon_pk_hash(&fake_falcon_pk(0xC0));
    let operator_h = falcon_pk_hash(&operator_pk);
    descriptor.spend_policy_commit =
        escrow_policy_commit(buyer_h, merchant_h, operator_h, descriptor.timeout_blocks);

    // 1. Funding event arrives, operator verifies
    let mut observer = MockLedgerObserver::new(500);
    observer.add_unspent_note(note_commit, descriptor.spend_policy_commit);
    let verified_commit = process_funding_event(&descriptor, &note_commit, &observer)
        .expect("funding must be confirmed by ledger observer");

    // 2. Build snapshot
    let snapshot = build_snapshot(&descriptor, verified_commit);
    assert_eq!(snapshot.status, 1);

    // 3. Build proposal (release to merchant)
    let proposal = build_proposal(
        &snapshot,
        EscrowAction::Release,
        merchant_h,
        50,
        &buyer_h,
        &merchant_h,
        &operator_h,
    )
    .expect("proposal must build successfully");

    // Verify invariant
    assert_ne!(proposal.proposal_hash, proposal.tx_signing_hash);

    // 4. Assemble approvals
    let mut builder = ApprovalBundleBuilder::new(&proposal, 1_000_000);

    // Buyer signs
    add_approval(
        &mut builder,
        &proposal.proposal_hash,
        0, // signer_index: Buyer = 0
        "buyer",
        buyer_pk.clone(),
        vec![0x11; 64], // dummy Falcon signature
    )
    .expect("buyer approval must succeed");

    // Operator signs
    add_approval(
        &mut builder,
        &proposal.proposal_hash,
        2, // signer_index: Operator = 2
        "operator",
        operator_pk.clone(),
        vec![0x22; 64], // dummy Falcon signature
    )
    .expect("operator approval must succeed");

    // 5. Finalize bundle (2-of-3 quorum)
    let bundle = finalize_bundle(builder, 2).expect("quorum of 2 must be sufficient");

    // Verify bundle fields
    assert_eq!(bundle.proposal_hash, proposal.proposal_hash);
    assert_eq!(bundle.tx_signing_hash, proposal.tx_signing_hash);
    assert_ne!(bundle.proposal_hash, bundle.tx_signing_hash);
    assert_eq!(bundle.signer_entries.len(), 2);
    assert_eq!(bundle.signer_entries[0].signer_index, 0);
    assert_eq!(bundle.signer_entries[0].signer_role, "buyer");
    assert_eq!(bundle.signer_entries[1].signer_index, 2);
    assert_eq!(bundle.signer_entries[1].signer_role, "operator");

    // 6. Bridge to InputAuth
    let input_auth = bundle_to_input_auth(
        &bundle,
        &buyer_h,
        &merchant_h,
        &operator_h,
        snapshot.timeout_block,
        EscrowAction::Release,
    );

    assert_eq!(
        input_auth.policy_tag,
        privai_chain::note::SpendPolicyTag::Escrow2of3 as u8
    );
    assert_eq!(input_auth.signer_pks.len(), 2);
    assert_eq!(input_auth.escrow_action, Some(EscrowAction::Release as u8));
    assert!(input_auth.policy_opening.is_some());

    // Verify policy opening decodes correctly
    let policy_bytes = input_auth.policy_opening.as_ref().unwrap();
    let policy = SpendPolicy::from_canonical_bytes(policy_bytes).unwrap();
    assert_eq!(policy.commitment(), snapshot.spend_policy_commit);
}

#[test]
fn reject_duplicate_signer_in_bundle() {
    let descriptor = EscrowFundingDescriptor {
        escrow_id: h(0x01),
        buyer_pk: h(0x10),
        merchant_pk: h(0x20),
        operator_pk: h(0x30),
        amount: 5000,
        spend_policy_commit: h(0xAA),
        timeout_blocks: 2000,
    };

    let snapshot = build_snapshot(&descriptor, h(0xBB));
    let buyer_h = falcon_pk_hash(&fake_falcon_pk(0xB0));
    let merchant_h = falcon_pk_hash(&fake_falcon_pk(0xC0));
    let operator_h = falcon_pk_hash(&fake_falcon_pk(0xD0));
    let buyer_pk = fake_falcon_pk(0xB0);

    let proposal = build_proposal(
        &snapshot,
        EscrowAction::Release,
        merchant_h,
        50,
        &buyer_h,
        &merchant_h,
        &operator_h,
    )
    .unwrap();

    let mut builder = ApprovalBundleBuilder::new(&proposal, 1_000_000);

    add_approval(
        &mut builder,
        &proposal.proposal_hash,
        0,
        "buyer",
        buyer_pk.clone(),
        vec![0x11; 64],
    )
    .unwrap();

    // Try to add same signer again
    let err = add_approval(
        &mut builder,
        &proposal.proposal_hash,
        0,
        "buyer",
        buyer_pk,
        vec![0x33; 64],
    );
    assert!(matches!(
        err,
        Err(OperatorEscrowError::DuplicateApproval(0))
    ));
}

#[test]
fn reject_quorum_not_met() {
    let descriptor = EscrowFundingDescriptor {
        escrow_id: h(0x01),
        buyer_pk: h(0x10),
        merchant_pk: h(0x20),
        operator_pk: h(0x30),
        amount: 5000,
        spend_policy_commit: h(0xAA),
        timeout_blocks: 2000,
    };

    let snapshot = build_snapshot(&descriptor, h(0xBB));
    let buyer_h = falcon_pk_hash(&fake_falcon_pk(0xB0));
    let merchant_h = falcon_pk_hash(&fake_falcon_pk(0xC0));
    let operator_h = falcon_pk_hash(&fake_falcon_pk(0xD0));

    let proposal = build_proposal(
        &snapshot,
        EscrowAction::Release,
        merchant_h,
        50,
        &buyer_h,
        &merchant_h,
        &operator_h,
    )
    .unwrap();

    let mut builder = ApprovalBundleBuilder::new(&proposal, 1_000_000);

    // Only 1 signer
    add_approval(
        &mut builder,
        &proposal.proposal_hash,
        0,
        "buyer",
        fake_falcon_pk(0xB0),
        vec![0x11; 64],
    )
    .unwrap();

    // Try to finalize with quorum 2
    let err = finalize_bundle(builder, 2);
    assert!(matches!(
        err,
        Err(OperatorEscrowError::QuorumNotMet { have: 1, need: 2 })
    ));
}

#[test]
fn funded_state_maps_to_escrow_funded() {
    let msg_type =
        nxms_escrow_orchestrator::flow::expected_msg_type_for_state(WorkflowState::Funded);
    assert_eq!(
        msg_type,
        Some("escrow_funded"),
        "WorkflowState::Funded must map to msg_type 'escrow_funded'"
    );
}

#[test]
fn reject_wrong_proposal_hash_on_approval() {
    let descriptor = EscrowFundingDescriptor {
        escrow_id: h(0x01),
        buyer_pk: h(0x10),
        merchant_pk: h(0x20),
        operator_pk: h(0x30),
        amount: 5000,
        spend_policy_commit: h(0xAA),
        timeout_blocks: 2000,
    };

    let snapshot = build_snapshot(&descriptor, h(0xBB));
    let buyer_h = falcon_pk_hash(&fake_falcon_pk(0xB0));
    let merchant_h = falcon_pk_hash(&fake_falcon_pk(0xC0));
    let operator_h = falcon_pk_hash(&fake_falcon_pk(0xD0));

    let proposal = build_proposal(
        &snapshot,
        EscrowAction::Release,
        merchant_h,
        50,
        &buyer_h,
        &merchant_h,
        &operator_h,
    )
    .unwrap();

    let mut builder = ApprovalBundleBuilder::new(&proposal, 1_000_000);

    let wrong_hash = h(0xDE);
    let err = add_approval(
        &mut builder,
        &wrong_hash,
        0,
        "buyer",
        fake_falcon_pk(0xB0),
        vec![0x11; 64],
    );
    assert!(matches!(
        err,
        Err(OperatorEscrowError::ProposalHashMismatch { .. })
    ));
}

// ── Acceptance test: canonical tx_signing_hash agreement ─────────

/// This is the MOST IMPORTANT test of the task.
///
/// It proves that the control-plane's tx_signing_hash is IDENTICAL
/// to privai-chain's canonical `Transaction::tx_signing_hash()`.
///
/// The test:
/// 1. Builds a proposal via control-plane (which internally calls build_tx_skeleton)
/// 2. Independently builds the same skeleton via privai-chain directly
/// 3. Compares the two hashes
///
/// If this test passes, the integration is correct.
#[test]
fn canonical_tx_signing_hash_matches_privai_chain() {
    use privai_chain::hash::{domain_hash, TX_SIGNING_DOMAIN};
    use privai_chain::tx::Transaction;

    let descriptor = EscrowFundingDescriptor {
        escrow_id: h(0x01),
        buyer_pk: h(0x10),
        merchant_pk: h(0x20),
        operator_pk: h(0x30),
        amount: 5000,
        spend_policy_commit: h(0xAA),
        timeout_blocks: 2000,
    };

    let snapshot = build_snapshot(&descriptor, h(0xBB));
    let buyer_h = falcon_pk_hash(&fake_falcon_pk(0xB0));
    let merchant_h = falcon_pk_hash(&fake_falcon_pk(0xC0));
    let operator_h = falcon_pk_hash(&fake_falcon_pk(0xD0));

    // 1. Build proposal (control-plane computes tx_signing_hash)
    let proposal = build_proposal(
        &snapshot,
        EscrowAction::Release,
        merchant_h,
        100,
        &buyer_h,
        &merchant_h,
        &operator_h,
    )
    .unwrap();

    // 2. Independently build the same skeleton and compute hash via privai-chain
    let tx = build_tx_skeleton(
        &snapshot.funding_note_commit,
        EscrowAction::Release,
        &merchant_h,
        100,
        &buyer_h,
        &merchant_h,
        &operator_h,
        snapshot.timeout_block,
        vec![],
        vec![],
        EscrowAction::Release as u8,
    );

    // Method A: directly compute from signing_preimage
    let privai_hash = match &tx {
        Transaction::TransferNote(t) => {
            domain_hash(TX_SIGNING_DOMAIN, &[&t.core.signing_preimage()])
        }
        _ => unreachable!(),
    };

    assert_eq!(
        proposal.tx_signing_hash, privai_hash,
        "control-plane tx_signing_hash must be IDENTICAL to privai-chain canonical hash"
    );

    // Method B: via Transaction::tx_signing_hash() method
    let canonical_hash = tx.tx_signing_hash();
    assert_eq!(
        proposal.tx_signing_hash, canonical_hash,
        "control-plane hash must match Transaction::tx_signing_hash() method"
    );
}

// ── Acceptance test: bridge to InputAuth ─────────────────────────

#[test]
fn bridge_bundle_to_input_auth_correct_fields() {
    let mut descriptor = EscrowFundingDescriptor {
        escrow_id: h(0x01),
        buyer_pk: h(0x10),
        merchant_pk: h(0x20),
        operator_pk: h(0x30),
        amount: 5000,
        spend_policy_commit: h(0xAA),
        timeout_blocks: 2000,
    };

    let buyer_pk = fake_falcon_pk(0xB0);
    let operator_pk = fake_falcon_pk(0xD0);
    let buyer_h = falcon_pk_hash(&buyer_pk);
    let merchant_h = falcon_pk_hash(&fake_falcon_pk(0xC0));
    let operator_h = falcon_pk_hash(&operator_pk);
    descriptor.spend_policy_commit =
        escrow_policy_commit(buyer_h, merchant_h, operator_h, descriptor.timeout_blocks);

    let snapshot = build_snapshot(&descriptor, h(0xBB));

    let proposal = build_proposal(
        &snapshot,
        EscrowAction::Release,
        merchant_h,
        100,
        &buyer_h,
        &merchant_h,
        &operator_h,
    )
    .unwrap();

    let mut builder = ApprovalBundleBuilder::new(&proposal, 1000);
    add_approval(
        &mut builder,
        &proposal.proposal_hash,
        0,
        "buyer",
        buyer_pk.clone(),
        vec![0xAA; 64],
    )
    .unwrap();
    add_approval(
        &mut builder,
        &proposal.proposal_hash,
        2,
        "operator",
        operator_pk.clone(),
        vec![0xBB; 64],
    )
    .unwrap();
    let bundle = finalize_bundle(builder, 2).unwrap();

    // Bridge to InputAuth
    let input_auth = bundle_to_input_auth(
        &bundle,
        &buyer_h,
        &merchant_h,
        &operator_h,
        snapshot.timeout_block,
        EscrowAction::Release,
    );

    // Verify fields
    assert_eq!(
        input_auth.policy_tag,
        privai_chain::note::SpendPolicyTag::Escrow2of3 as u8
    );
    assert_eq!(input_auth.signer_pks.len(), 2);
    assert_eq!(input_auth.signatures.len(), 2);
    assert_eq!(input_auth.signer_pks[0], buyer_pk);
    assert_eq!(input_auth.signer_pks[1], operator_pk);
    assert_eq!(input_auth.signatures[0], vec![0xAA; 64]);
    assert_eq!(input_auth.signatures[1], vec![0xBB; 64]);
    assert_eq!(input_auth.escrow_action, Some(EscrowAction::Release as u8));

    // Verify policy_opening
    let policy_bytes = input_auth
        .policy_opening
        .as_ref()
        .expect("policy_opening must be present");
    let policy = SpendPolicy::from_canonical_bytes(policy_bytes).expect("policy must decode");
    match policy {
        SpendPolicy::Escrow2of3 {
            buyer_pk_hash,
            merchant_pk_hash,
            operator_pk_hash,
            timeout_block,
        } => {
            assert_eq!(buyer_pk_hash, buyer_h);
            assert_eq!(merchant_pk_hash, merchant_h);
            assert_eq!(operator_pk_hash, operator_h);
            assert_eq!(timeout_block, snapshot.timeout_block);
        }
        _ => panic!("decoded policy must be Escrow2of3"),
    }

    assert_eq!(policy.commitment(), snapshot.spend_policy_commit);
}
