//! Operator escrow control-plane adapter for nexum-core.
//!
//! This module bridges the orchestrator's workflow engine with the
//! privAI escrow object model (EscrowFundingDescriptor, EscrowSnapshot,
//! EscrowSpendProposal, EscrowApprovalBundle).
//!
//! Key invariants:
//! - Operator does NOT trust mailbox events blindly; it verifies
//!   funding through its own LedgerObserver view.
//! - `proposal_hash` (control-plane identity) and `tx_signing_hash`
//!   (on-chain signing object) are NEVER equal.
//! - `tx_signing_hash` is computed from a real privai-chain `Transaction`
//!   skeleton via `Transaction::tx_signing_hash()` — NOT from a local
//!   placeholder hash.

use serde::{Deserialize, Serialize};

pub type Hash32 = [u8; 32];

// ── Error types ──────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum OperatorEscrowError {
    #[error("ledger observer: funding not confirmed for note commit {0}")]
    FundingNotConfirmed(String),

    #[error("snapshot already built for escrow_id {0}")]
    SnapshotAlreadyBuilt(String),

    #[error("invalid action byte: {0}")]
    InvalidAction(u8),

    #[error("duplicate approval from signer index {0}")]
    DuplicateApproval(usize),

    #[error("quorum not met: have {have}, need {need}")]
    QuorumNotMet { have: usize, need: usize },

    #[error("proposal hash mismatch: expected {expected}, got {got}")]
    ProposalHashMismatch { expected: String, got: String },

    #[error("invariant violation: proposal_hash == tx_signing_hash")]
    HashCollisionInvariant,
}

// ── Action model ─────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EscrowAction {
    Release = 0x01,
    Refund = 0x02,
    RecoveryRelease = 0x03,
}

impl EscrowAction {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Release),
            0x02 => Some(Self::Refund),
            0x03 => Some(Self::RecoveryRelease),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Refund => "refund",
            Self::RecoveryRelease => "recovery_release",
        }
    }

    /// Convert to privai-chain EscrowAction.
    pub fn to_privai(self) -> privai_chain::escrow::EscrowAction {
        match self {
            Self::Release => privai_chain::escrow::EscrowAction::Release,
            Self::Refund => privai_chain::escrow::EscrowAction::Refund,
            Self::RecoveryRelease => privai_chain::escrow::EscrowAction::RecoveryRelease,
        }
    }

    /// Convert from privai-chain EscrowAction.
    pub fn from_privai(a: privai_chain::escrow::EscrowAction) -> Self {
        match a {
            privai_chain::escrow::EscrowAction::Release => Self::Release,
            privai_chain::escrow::EscrowAction::Refund => Self::Refund,
            privai_chain::escrow::EscrowAction::RecoveryRelease => Self::RecoveryRelease,
        }
    }
}

// ── Ledger observer trait ────────────────────────────────────────

/// Abstraction over on-chain state observation.
/// The operator must query its own view of the ledger to verify
/// funding — it never trusts mailbox events blindly.
pub trait LedgerObserver {
    /// Check whether a note with the given commit exists and is unspent.
    fn is_note_unspent(&self, note_commit: &Hash32) -> bool;

    /// Return the spend_policy_commit associated with a note, if it exists.
    fn note_spend_policy_commit(&self, note_commit: &Hash32) -> Option<Hash32>;

    /// Return the current block height (for timeout checks).
    fn current_block_height(&self) -> u64;
}

// ── Escrow objects (control-plane) ──────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscrowFundingDescriptor {
    pub escrow_id: Hash32,
    pub buyer_pk: Hash32,
    pub merchant_pk: Hash32,
    pub operator_pk: Hash32,
    pub amount: u64,
    pub spend_policy_commit: Hash32,
    pub timeout_blocks: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscrowSnapshot {
    pub escrow_id: Hash32,
    pub buyer_pk: Hash32,
    pub merchant_pk: Hash32,
    pub operator_pk: Hash32,
    pub funding_note_commit: Hash32,
    pub spend_policy_commit: Hash32,
    pub amount: u64,
    pub timeout_block: u64,
    pub snapshot_hash: Hash32,
    pub status: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscrowSpendProposal {
    pub proposal_hash: Hash32,
    pub escrow_id: Hash32,
    pub snapshot_hash: Hash32,
    pub action: u8,
    pub input_note_commits: Vec<Hash32>,
    pub output_recipient_pk: Hash32,
    pub fee: u64,
    /// NOT the same as proposal_hash. This is the on-chain signing object,
    /// computed from a real privai-chain Transaction skeleton.
    pub tx_signing_hash: Hash32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscrowApprovalBundle {
    pub proposal_hash: Hash32,
    pub tx_signing_hash: Hash32,
    pub signer_entries: Vec<SignerEntry>,
    pub created_at_ms: u64,
}

/// A signer entry in the approval bundle.
///
/// `signer_pk` contains the **raw Falcon public key bytes** (not a hash).
/// This is required because the privai-chain auth layer expects raw PK bytes
/// in `InputAuth.signer_pks`, and the ledger derives `falcon_pk_hash()` from them.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerEntry {
    pub signer_index: u8,
    pub signer_role: String,
    pub signer_pk: Vec<u8>,
    pub signature: Vec<u8>,
}

// ── Hash helpers ─────────────────────────────────────────────────

fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    update_len_prefixed(&mut hasher, domain);
    for part in parts {
        update_len_prefixed(&mut hasher, part);
    }
    *hasher.finalize().as_bytes()
}

fn update_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u32).to_le_bytes());
    hasher.update(bytes);
}

const SNAPSHOT_HASH_DOMAIN: &[u8] = b"privai:nxms:escrow-snapshot:v1";
const PROPOSAL_HASH_DOMAIN: &[u8] = b"privai:nxms:escrow-proposal:v1";

fn compute_snapshot_hash(
    escrow_id: &Hash32,
    buyer_pk: &Hash32,
    merchant_pk: &Hash32,
    operator_pk: &Hash32,
    funding_note_commit: &Hash32,
    spend_policy_commit: &Hash32,
    amount: u64,
    timeout_block: u64,
) -> Hash32 {
    domain_hash(
        SNAPSHOT_HASH_DOMAIN,
        &[
            escrow_id,
            buyer_pk,
            merchant_pk,
            operator_pk,
            funding_note_commit,
            spend_policy_commit,
            &amount.to_le_bytes(),
            &timeout_block.to_le_bytes(),
        ],
    )
}

fn compute_proposal_hash(
    escrow_id: &Hash32,
    snapshot_hash: &Hash32,
    action: u8,
    input_note_commits: &[Hash32],
    output_recipient_pk: &Hash32,
    fee: u64,
) -> Hash32 {
    let action_arr = [action];
    let fee_bytes = fee.to_le_bytes();
    let flat_inputs: Vec<u8> = input_note_commits
        .iter()
        .flat_map(|h| h.iter().copied())
        .collect();

    domain_hash(
        PROPOSAL_HASH_DOMAIN,
        &[
            escrow_id,
            snapshot_hash,
            &action_arr,
            &flat_inputs,
            output_recipient_pk,
            &fee_bytes,
        ],
    )
}

// ── privai-chain integration: tx skeleton builder ────────────────

/// Build a minimal `privai-chain::Transaction::TransferNote` skeleton from
/// escrow context.
///
/// This produces a canonical on-chain transaction object from which
/// `Transaction::tx_signing_hash()` can be computed.
///
/// The skeleton is NOT a final, submittable transaction — it lacks real
/// proof material and real output note construction. But it produces a
/// **canonical** `tx_signing_hash` that matches what the ledger will
/// recompute from the final transaction.
///
/// # Arguments
/// - `funding_note_commit`: the escrow input note commit
/// - `action`: the escrow action (release / refund / recovery_release)
/// - `recipient_pk_hash`: `falcon_pk_hash()` of the recipient's Falcon PK
/// - `fee`: transaction fee
/// - `buyer_pk_hash`: falcon_pk_hash of the buyer
/// - `merchant_pk_hash`: falcon_pk_hash of the merchant
/// - `operator_pk_hash`: falcon_pk_hash of the operator
/// - `timeout_block`: recovery timeout block from policy
/// - `signer_pks`: raw Falcon PK bytes of the signing parties
/// - `signatures`: Falcon signatures over the signing hash
/// - `escrow_action_byte`: the action as u8 (for InputAuth)
pub fn build_tx_skeleton(
    funding_note_commit: &Hash32,
    _action: EscrowAction,
    recipient_pk_hash: &Hash32,
    fee: u64,
    buyer_pk_hash: &Hash32,
    merchant_pk_hash: &Hash32,
    operator_pk_hash: &Hash32,
    timeout_block: u64,
    signer_pks: Vec<Vec<u8>>,
    signatures: Vec<Vec<u8>>,
    escrow_action_byte: u8,
) -> privai_chain::Transaction {
    use privai_chain::note::{OutputNote, RecipientBox, SpendPolicy, SpendPolicyTag};
    use privai_chain::primitives::{LweCiphertext, Nullifier};
    use privai_chain::tx::{
        InputAuth, InputRef, Transaction, TransferNoteTx, TxCore, TX_TYPE_TRANSFER_NOTE,
    };
    use privai_chain::CanonicalEncode;

    // Build the Escrow2of3 policy and its canonical opening bytes
    let policy = SpendPolicy::Escrow2of3 {
        buyer_pk_hash: *buyer_pk_hash,
        merchant_pk_hash: *merchant_pk_hash,
        operator_pk_hash: *operator_pk_hash,
        timeout_block,
    };
    let policy_bytes = policy.to_canonical_bytes();

    // Build a minimal placeholder output note for the recipient.
    // The spend_policy_commit binds to a Single policy for the recipient.
    let recipient_single = SpendPolicy::Single {
        falcon_pk_hash: *recipient_pk_hash,
    };
    let recipient_policy_commit = recipient_single.commitment();

    let placeholder_box = RecipientBox::new(vec![0u8], [0u8; 24], vec![0u8], [0u8; 16], [0u8; 16]);
    let output_note = OutputNote::new(
        recipient_policy_commit,
        LweCiphertext::default(),
        [0u8; 32],
        placeholder_box,
    );

    // Build the InputAuth for the escrow input
    let input_auth = InputAuth {
        policy_tag: SpendPolicyTag::Escrow2of3 as u8,
        signer_pks,
        signatures,
        policy_opening: Some(policy_bytes),
        escrow_action: Some(escrow_action_byte),
    };

    let tx_core = TxCore {
        version: privai_chain::PRIVAI_V0,
        tx_type: TX_TYPE_TRANSFER_NOTE,
        inputs: vec![InputRef {
            note_commit: *funding_note_commit,
        }],
        input_nullifiers: vec![Nullifier([0u8; 32])],
        outputs: vec![output_note],
        fee,
        statement_commit: [0u8; 32],
        auth: vec![input_auth],
    };

    Transaction::TransferNote(TransferNoteTx { core: tx_core })
}

// ── Bridge: EscrowApprovalBundle -> InputAuth ────────────────────

/// Convert an `EscrowApprovalBundle` + escrow context into a `privai_chain::InputAuth`.
///
/// This is the bridge between the control-plane approval bundle and the
/// on-chain auth envelope required by privai-chain ledger validation.
///
/// # Arguments
/// - `bundle`: the finalized approval bundle with signer keys and signatures
/// - `buyer_pk_hash`: `falcon_pk_hash()` of the buyer's Falcon public key
/// - `merchant_pk_hash`: `falcon_pk_hash()` of the merchant's Falcon public key
/// - `operator_pk_hash`: `falcon_pk_hash()` of the operator's Falcon public key
/// - `timeout_block`: recovery timeout block from the escrow policy
/// - `action`: the escrow action being authorized
pub fn bundle_to_input_auth(
    bundle: &EscrowApprovalBundle,
    buyer_pk_hash: &Hash32,
    merchant_pk_hash: &Hash32,
    operator_pk_hash: &Hash32,
    timeout_block: u64,
    action: EscrowAction,
) -> privai_chain::tx::InputAuth {
    use privai_chain::note::SpendPolicy;
    use privai_chain::CanonicalEncode;

    let policy = SpendPolicy::Escrow2of3 {
        buyer_pk_hash: *buyer_pk_hash,
        merchant_pk_hash: *merchant_pk_hash,
        operator_pk_hash: *operator_pk_hash,
        timeout_block,
    };

    privai_chain::tx::InputAuth {
        policy_tag: privai_chain::note::SpendPolicyTag::Escrow2of3 as u8,
        signer_pks: bundle
            .signer_entries
            .iter()
            .map(|e| e.signer_pk.clone())
            .collect(),
        signatures: bundle
            .signer_entries
            .iter()
            .map(|e| e.signature.clone())
            .collect(),
        policy_opening: Some(policy.to_canonical_bytes()),
        escrow_action: Some(action as u8),
    }
}

// ── Adapter: privai-nxms compatibility bridge ────────────────────
//
// The orchestrator stores raw Falcon PK bytes in SignerEntry (required for
// on-chain auth via InputAuth.signer_pks). The privai-nxms transport layer
// uses PK hashes (Hash32). These adapter functions bridge between the two
// representations without requiring a direct dependency on privai-nxms.
//
// TEMPORARY COMPATIBILITY BRIDGE: these functions exist because the
// orchestrator needs raw PK bytes for on-chain auth, while the NXMS wire
// protocol uses PK hashes. A future refactor may unify these representations.

/// Extract PK hashes from an EscrowApprovalBundle (for transport layer).
///
/// The privai-nxms `EscrowApprovalBundle` stores `signer_pks: Vec<Hash32>`,
/// which represents PK hashes. The orchestrator stores raw Falcon PK bytes.
/// This function hashes the raw PKs to produce the transport-layer representation.
pub fn bundle_signer_pk_hashes(bundle: &EscrowApprovalBundle) -> Vec<Hash32> {
    bundle
        .signer_entries
        .iter()
        .map(|e| privai_chain::hash::falcon_pk_hash(&e.signer_pk))
        .collect()
}

// ── Core control-plane functions ─────────────────────────────────

/// Step 1: Process a funding event.
///
/// The operator does NOT trust the event blindly. It verifies through
/// its own LedgerObserver that the funding note actually exists and
/// matches the descriptor.
pub fn process_funding_event(
    descriptor: &EscrowFundingDescriptor,
    funding_note_commit: &Hash32,
    observer: &dyn LedgerObserver,
) -> Result<Hash32, OperatorEscrowError> {
    if !observer.is_note_unspent(funding_note_commit) {
        return Err(OperatorEscrowError::FundingNotConfirmed(hex::encode(
            funding_note_commit,
        )));
    }

    if let Some(observed_policy) = observer.note_spend_policy_commit(funding_note_commit) {
        if observed_policy != descriptor.spend_policy_commit {
            return Err(OperatorEscrowError::FundingNotConfirmed(format!(
                "policy mismatch: descriptor={}, ledger={}",
                hex::encode(descriptor.spend_policy_commit),
                hex::encode(observed_policy)
            )));
        }
    }

    Ok(*funding_note_commit)
}

/// Step 2: Build snapshot after on-chain confirmation.
pub fn build_snapshot(
    descriptor: &EscrowFundingDescriptor,
    funding_note_commit: Hash32,
) -> EscrowSnapshot {
    let snapshot_hash = compute_snapshot_hash(
        &descriptor.escrow_id,
        &descriptor.buyer_pk,
        &descriptor.merchant_pk,
        &descriptor.operator_pk,
        &funding_note_commit,
        &descriptor.spend_policy_commit,
        descriptor.amount,
        descriptor.timeout_blocks,
    );

    EscrowSnapshot {
        escrow_id: descriptor.escrow_id,
        buyer_pk: descriptor.buyer_pk,
        merchant_pk: descriptor.merchant_pk,
        operator_pk: descriptor.operator_pk,
        funding_note_commit,
        spend_policy_commit: descriptor.spend_policy_commit,
        amount: descriptor.amount,
        timeout_block: descriptor.timeout_blocks,
        snapshot_hash,
        status: 1,
    }
}

/// Step 3: Build a spend proposal from a snapshot.
///
/// The `tx_signing_hash` is now computed from a real privai-chain
/// `Transaction` skeleton via `build_tx_skeleton` and
/// `Transaction::tx_signing_hash()` — NOT from a local placeholder.
///
/// # Arguments
/// - `buyer_pk_hash`: `falcon_pk_hash()` of buyer's Falcon PK
/// - `merchant_pk_hash`: `falcon_pk_hash()` of merchant's Falcon PK
/// - `operator_pk_hash`: `falcon_pk_hash()` of operator's Falcon PK
pub fn build_proposal(
    snapshot: &EscrowSnapshot,
    action: EscrowAction,
    output_recipient_pk: Hash32,
    fee: u64,
    buyer_pk_hash: &Hash32,
    merchant_pk_hash: &Hash32,
    operator_pk_hash: &Hash32,
) -> Result<EscrowSpendProposal, OperatorEscrowError> {
    use privai_chain::Transaction;

    let action_byte = action as u8;

    let proposal_hash = compute_proposal_hash(
        &snapshot.escrow_id,
        &snapshot.snapshot_hash,
        action_byte,
        &[snapshot.funding_note_commit],
        &output_recipient_pk,
        fee,
    );

    // Build a real privai-chain Transaction skeleton and derive the
    // canonical tx_signing_hash from it.
    let tx = build_tx_skeleton(
        &snapshot.funding_note_commit,
        action,
        &output_recipient_pk,
        fee,
        buyer_pk_hash,
        merchant_pk_hash,
        operator_pk_hash,
        snapshot.timeout_block,
        vec![], // no signer keys yet (skeleton only)
        vec![], // no signatures yet (skeleton only)
        action_byte,
    );

    let tx_signing_hash = match &tx {
        Transaction::TransferNote(t) => privai_chain::hash::domain_hash(
            privai_chain::hash::TX_SIGNING_DOMAIN,
            &[&t.core.signing_preimage()],
        ),
        _ => unreachable!("build_tx_skeleton always produces TransferNote"),
    };

    // INVARIANT: proposal_hash != tx_signing_hash
    if proposal_hash == tx_signing_hash {
        return Err(OperatorEscrowError::HashCollisionInvariant);
    }

    Ok(EscrowSpendProposal {
        proposal_hash,
        escrow_id: snapshot.escrow_id,
        snapshot_hash: snapshot.snapshot_hash,
        action: action_byte,
        input_note_commits: vec![snapshot.funding_note_commit],
        output_recipient_pk,
        fee,
        tx_signing_hash,
    })
}

/// Step 4: Add an approval to a bundle.
///
/// Maintains the separation between signer identity, proposal identity,
/// and signing object.
pub fn add_approval(
    bundle: &mut ApprovalBundleBuilder,
    proposal_hash: &Hash32,
    signer_index: u8,
    signer_role: &str,
    signer_pk: Vec<u8>,
    signature: Vec<u8>,
) -> Result<(), OperatorEscrowError> {
    if bundle.proposal_hash != *proposal_hash {
        return Err(OperatorEscrowError::ProposalHashMismatch {
            expected: hex::encode(&bundle.proposal_hash),
            got: hex::encode(proposal_hash),
        });
    }

    if bundle
        .signer_entries
        .iter()
        .any(|e| e.signer_index == signer_index)
    {
        return Err(OperatorEscrowError::DuplicateApproval(
            signer_index as usize,
        ));
    }

    bundle.signer_entries.push(SignerEntry {
        signer_index,
        signer_role: signer_role.to_string(),
        signer_pk,
        signature,
    });

    Ok(())
}

/// Step 5: Finalize the approval bundle.
///
/// Requires quorum (2-of-3 for escrow-2of3-v1).
pub fn finalize_bundle(
    builder: ApprovalBundleBuilder,
    quorum: usize,
) -> Result<EscrowApprovalBundle, OperatorEscrowError> {
    if builder.signer_entries.len() < quorum {
        return Err(OperatorEscrowError::QuorumNotMet {
            have: builder.signer_entries.len(),
            need: quorum,
        });
    }

    Ok(EscrowApprovalBundle {
        proposal_hash: builder.proposal_hash,
        tx_signing_hash: builder.tx_signing_hash,
        signer_entries: builder.signer_entries,
        created_at_ms: builder.created_at_ms,
    })
}

// ── Approval bundle builder ──────────────────────────────────────

/// In-progress approval bundle. Collects signatures before finalization.
pub struct ApprovalBundleBuilder {
    pub proposal_hash: Hash32,
    pub tx_signing_hash: Hash32,
    pub signer_entries: Vec<SignerEntry>,
    pub created_at_ms: u64,
}

impl ApprovalBundleBuilder {
    pub fn new(proposal: &EscrowSpendProposal, created_at_ms: u64) -> Self {
        Self {
            proposal_hash: proposal.proposal_hash,
            tx_signing_hash: proposal.tx_signing_hash,
            signer_entries: Vec::new(),
            created_at_ms,
        }
    }
}

// ── In-memory ledger observer (for tests) ────────────────────────

pub struct MockLedgerObserver {
    pub unspent_notes: std::collections::HashMap<Hash32, Hash32>,
    pub block_height: u64,
}

impl MockLedgerObserver {
    pub fn new(block_height: u64) -> Self {
        Self {
            unspent_notes: std::collections::HashMap::new(),
            block_height,
        }
    }

    pub fn add_unspent_note(&mut self, note_commit: Hash32, spend_policy_commit: Hash32) {
        self.unspent_notes.insert(note_commit, spend_policy_commit);
    }
}

impl LedgerObserver for MockLedgerObserver {
    fn is_note_unspent(&self, note_commit: &Hash32) -> bool {
        self.unspent_notes.contains_key(note_commit)
    }

    fn note_spend_policy_commit(&self, note_commit: &Hash32) -> Option<Hash32> {
        self.unspent_notes.get(note_commit).copied()
    }

    fn current_block_height(&self) -> u64 {
        self.block_height
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use privai_chain::hash::{domain_hash, falcon_pk_hash, TX_SIGNING_DOMAIN};
    use privai_chain::note::{SpendPolicy, SpendPolicyTag};
    use privai_chain::tx::Transaction;
    use privai_chain::{CanonicalDecode, CanonicalEncode};

    fn h(fill: u8) -> Hash32 {
        [fill; 32]
    }

    fn test_descriptor() -> EscrowFundingDescriptor {
        EscrowFundingDescriptor {
            escrow_id: h(0x01),
            buyer_pk: h(0x10),
            merchant_pk: h(0x20),
            operator_pk: h(0x30),
            amount: 1000,
            spend_policy_commit: h(0xAA),
            timeout_blocks: 1000,
        }
    }

    fn test_pks() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // Fake Falcon PK bytes (sufficiently long to look realistic)
        let buyer_pk = vec![0xB0; 897];
        let merchant_pk = vec![0xC0; 897];
        let operator_pk = vec![0xD0; 897];
        (buyer_pk, merchant_pk, operator_pk)
    }

    fn test_pk_hashes() -> (Hash32, Hash32, Hash32) {
        let (bp, mp, op) = test_pks();
        (
            falcon_pk_hash(&bp),
            falcon_pk_hash(&mp),
            falcon_pk_hash(&op),
        )
    }

    // ── Existing control-plane tests (updated for new signatures) ──

    #[test]
    fn funding_requires_ledger_confirmation() {
        let descriptor = test_descriptor();
        let note_commit = h(0xBB);
        let observer = MockLedgerObserver::new(500);

        let result = process_funding_event(&descriptor, &note_commit, &observer);
        assert!(result.is_err());
    }

    #[test]
    fn funding_succeeds_with_ledger_confirmation() {
        let descriptor = test_descriptor();
        let note_commit = h(0xBB);
        let mut observer = MockLedgerObserver::new(500);
        observer.add_unspent_note(note_commit, descriptor.spend_policy_commit);

        let result = process_funding_event(&descriptor, &note_commit, &observer);
        assert!(result.is_ok());
    }

    #[test]
    fn funding_rejects_policy_mismatch() {
        let descriptor = test_descriptor();
        let note_commit = h(0xBB);
        let mut observer = MockLedgerObserver::new(500);
        observer.add_unspent_note(note_commit, h(0xFF));

        let result = process_funding_event(&descriptor, &note_commit, &observer);
        assert!(result.is_err());
    }

    #[test]
    fn snapshot_contains_correct_fields() {
        let descriptor = test_descriptor();
        let note_commit = h(0xBB);
        let snapshot = build_snapshot(&descriptor, note_commit);

        assert_eq!(snapshot.escrow_id, descriptor.escrow_id);
        assert_eq!(snapshot.funding_note_commit, note_commit);
        assert_eq!(snapshot.spend_policy_commit, descriptor.spend_policy_commit);
        assert_eq!(snapshot.amount, 1000);
        assert_eq!(snapshot.status, 1);
        assert_ne!(snapshot.snapshot_hash, [0; 32]);
    }

    #[test]
    fn proposal_hash_differs_from_tx_signing_hash() {
        let descriptor = test_descriptor();
        let snapshot = build_snapshot(&descriptor, h(0xBB));
        let (buyer_h, merchant_h, operator_h) = test_pk_hashes();

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
            "proposal_hash and tx_signing_hash MUST differ"
        );
        assert_eq!(proposal.action, EscrowAction::Release as u8);
        assert_eq!(
            proposal.input_note_commits,
            vec![snapshot.funding_note_commit]
        );
    }

    #[test]
    fn different_actions_give_different_hashes() {
        let descriptor = test_descriptor();
        let snapshot = build_snapshot(&descriptor, h(0xBB));
        let (buyer_h, merchant_h, operator_h) = test_pk_hashes();

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
    }

    #[test]
    fn approval_bundle_assembly() {
        let descriptor = test_descriptor();
        let snapshot = build_snapshot(&descriptor, h(0xBB));
        let (buyer_h, merchant_h, operator_h) = test_pk_hashes();
        let (buyer_pk, _merchant_pk, operator_pk) = test_pks();

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

        assert_eq!(bundle.proposal_hash, proposal.proposal_hash);
        assert_eq!(bundle.tx_signing_hash, proposal.tx_signing_hash);
        assert_eq!(bundle.signer_entries.len(), 2);
        assert_eq!(bundle.signer_entries[0].signer_role, "buyer");
        assert_eq!(bundle.signer_entries[1].signer_role, "operator");
    }

    #[test]
    fn reject_duplicate_approval() {
        let descriptor = test_descriptor();
        let snapshot = build_snapshot(&descriptor, h(0xBB));
        let (buyer_h, merchant_h, operator_h) = test_pk_hashes();
        let (buyer_pk, _, _) = test_pks();

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

        let err = add_approval(
            &mut builder,
            &proposal.proposal_hash,
            0,
            "buyer",
            buyer_pk,
            vec![0xCC; 64],
        );
        assert!(matches!(
            err,
            Err(OperatorEscrowError::DuplicateApproval(0))
        ));
    }

    #[test]
    fn reject_quorum_not_met() {
        let descriptor = test_descriptor();
        let snapshot = build_snapshot(&descriptor, h(0xBB));
        let (buyer_h, merchant_h, operator_h) = test_pk_hashes();
        let (buyer_pk, _, _) = test_pks();

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
            buyer_pk,
            vec![0xAA; 64],
        )
        .unwrap();

        let err = finalize_bundle(builder, 2);
        assert!(matches!(
            err,
            Err(OperatorEscrowError::QuorumNotMet { have: 1, need: 2 })
        ));
    }

    #[test]
    fn reject_wrong_proposal_hash_on_approval() {
        let descriptor = test_descriptor();
        let snapshot = build_snapshot(&descriptor, h(0xBB));
        let (buyer_h, merchant_h, operator_h) = test_pk_hashes();
        let (buyer_pk, _, _) = test_pks();

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

        let wrong_hash = h(0xFF);
        let err = add_approval(
            &mut builder,
            &wrong_hash,
            0,
            "buyer",
            buyer_pk,
            vec![0xAA; 64],
        );
        assert!(matches!(
            err,
            Err(OperatorEscrowError::ProposalHashMismatch { .. })
        ));
    }

    #[test]
    fn full_flow_funding_to_bundle() {
        let descriptor = test_descriptor();
        let note_commit = h(0xBB);
        let (buyer_h, merchant_h, operator_h) = test_pk_hashes();
        let (buyer_pk, _merchant_pk, operator_pk) = test_pks();

        let mut observer = MockLedgerObserver::new(500);
        observer.add_unspent_note(note_commit, descriptor.spend_policy_commit);
        let verified_commit = process_funding_event(&descriptor, &note_commit, &observer).unwrap();

        let snapshot = build_snapshot(&descriptor, verified_commit);
        assert_eq!(snapshot.status, 1);

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
        assert_ne!(proposal.proposal_hash, proposal.tx_signing_hash);

        let mut builder = ApprovalBundleBuilder::new(&proposal, 2000);
        add_approval(
            &mut builder,
            &proposal.proposal_hash,
            0,
            "buyer",
            buyer_pk,
            vec![0x11; 64],
        )
        .unwrap();
        add_approval(
            &mut builder,
            &proposal.proposal_hash,
            2,
            "operator",
            operator_pk,
            vec![0x22; 64],
        )
        .unwrap();

        let bundle = finalize_bundle(builder, 2).unwrap();
        assert_eq!(bundle.signer_entries.len(), 2);
        assert_eq!(bundle.proposal_hash, proposal.proposal_hash);
        assert_eq!(bundle.tx_signing_hash, proposal.tx_signing_hash);
        assert_ne!(bundle.proposal_hash, bundle.tx_signing_hash);
    }

    // ── NEW: Canonical tx_signing_hash agreement test ─────────────

    /// Acceptance test: control-plane tx_signing_hash == privAI Transaction::tx_signing_hash()
    ///
    /// Builds a privai-chain `Transaction::TransferNote` skeleton from escrow context
    /// and verifies that the `tx_signing_hash` computed by the control-plane (via
    /// `build_proposal`) is IDENTICAL to `Transaction::tx_signing_hash()` computed
    /// from the same skeleton by privai-chain.
    #[test]
    fn canonical_tx_signing_hash_matches_privai_chain() {
        let descriptor = test_descriptor();
        let snapshot = build_snapshot(&descriptor, h(0xBB));
        let (buyer_h, merchant_h, operator_h) = test_pk_hashes();
        let (buyer_pk, _merchant_pk, operator_pk) = test_pks();

        // Build proposal (control-plane computes tx_signing_hash)
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

        // Independently build the same skeleton and compute the hash via privai-chain
        let tx = build_tx_skeleton(
            &snapshot.funding_note_commit,
            EscrowAction::Release,
            &merchant_h,
            100,
            &buyer_h,
            &merchant_h,
            &operator_h,
            snapshot.timeout_block,
            vec![], // skeleton without real sigs
            vec![],
            EscrowAction::Release as u8,
        );

        let privai_hash = match &tx {
            Transaction::TransferNote(t) => {
                domain_hash(TX_SIGNING_DOMAIN, &[&t.core.signing_preimage()])
            }
            _ => unreachable!(),
        };

        assert_eq!(
            proposal.tx_signing_hash,
            privai_hash,
            "control-plane tx_signing_hash must be IDENTICAL to privai-chain Transaction::tx_signing_hash()"
        );

        // Also verify via Transaction::tx_signing_hash() method
        let canonical_hash = tx.tx_signing_hash();
        assert_eq!(
            proposal.tx_signing_hash, canonical_hash,
            "control-plane hash must match Transaction::tx_signing_hash() method"
        );
    }

    /// Verify that the signing hash is canonical for different actions.
    #[test]
    fn canonical_hash_differs_per_action() {
        let descriptor = test_descriptor();
        let snapshot = build_snapshot(&descriptor, h(0xBB));
        let (buyer_h, merchant_h, operator_h) = test_pk_hashes();

        // Release: recipient = merchant
        let tx_release = build_tx_skeleton(
            &snapshot.funding_note_commit,
            EscrowAction::Release,
            &merchant_h,
            50,
            &buyer_h,
            &merchant_h,
            &operator_h,
            snapshot.timeout_block,
            vec![],
            vec![],
            EscrowAction::Release as u8,
        );

        // Refund: recipient = buyer
        let tx_refund = build_tx_skeleton(
            &snapshot.funding_note_commit,
            EscrowAction::Refund,
            &buyer_h,
            50,
            &buyer_h,
            &merchant_h,
            &operator_h,
            snapshot.timeout_block,
            vec![],
            vec![],
            EscrowAction::Refund as u8,
        );

        let hash_release = tx_release.tx_signing_hash();
        let hash_refund = tx_refund.tx_signing_hash();

        assert_ne!(
            hash_release, hash_refund,
            "different actions must produce different canonical signing hashes"
        );
    }

    // ── NEW: Bridge EscrowApprovalBundle -> InputAuth test ────────

    /// Test that `bundle_to_input_auth` produces a correctly populated `InputAuth`.
    #[test]
    fn bridge_bundle_to_input_auth() {
        let descriptor = test_descriptor();
        let snapshot = build_snapshot(&descriptor, h(0xBB));
        let (buyer_h, merchant_h, operator_h) = test_pk_hashes();
        let (buyer_pk, _merchant_pk, operator_pk) = test_pks();

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
        assert_eq!(input_auth.policy_tag, SpendPolicyTag::Escrow2of3 as u8);
        assert_eq!(input_auth.signer_pks.len(), 2);
        assert_eq!(input_auth.signatures.len(), 2);
        assert_eq!(input_auth.signer_pks[0], buyer_pk);
        assert_eq!(input_auth.signer_pks[1], operator_pk);
        assert_eq!(input_auth.signatures[0], vec![0xAA; 64]);
        assert_eq!(input_auth.signatures[1], vec![0xBB; 64]);
        assert_eq!(input_auth.escrow_action, Some(EscrowAction::Release as u8));

        // Verify policy_opening is present and decodes to Escrow2of3
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

        // Verify the policy commitment matches what's in the snapshot
        assert_eq!(policy.commitment(), snapshot.spend_policy_commit);
    }

    /// Test that the bridged InputAuth is valid for privai-chain signing preimage.
    #[test]
    fn bridged_input_auth_produces_correct_signing_preimage() {
        let descriptor = test_descriptor();
        let snapshot = build_snapshot(&descriptor, h(0xBB));
        let (buyer_h, merchant_h, operator_h) = test_pk_hashes();
        let (buyer_pk, _merchant_pk, operator_pk) = test_pks();

        // Build proposal → skeleton tx (no real signatures)
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

        // Build bridge InputAuth
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

        let input_auth = bundle_to_input_auth(
            &bundle,
            &buyer_h,
            &merchant_h,
            &operator_h,
            snapshot.timeout_block,
            EscrowAction::Release,
        );

        // Build a full tx skeleton with the bridged InputAuth
        let tx = build_tx_skeleton(
            &snapshot.funding_note_commit,
            EscrowAction::Release,
            &merchant_h,
            100,
            &buyer_h,
            &merchant_h,
            &operator_h,
            snapshot.timeout_block,
            input_auth.signer_pks.clone(),
            input_auth.signatures.clone(),
            EscrowAction::Release as u8,
        );

        // The signing hash from this tx must match the proposal's tx_signing_hash
        let hash_from_full_tx = tx.tx_signing_hash();
        assert_eq!(
            proposal.tx_signing_hash,
            hash_from_full_tx,
            "tx_signing_hash from proposal must match tx_signing_hash from skeleton with real InputAuth"
        );
    }

    // ── Adapter tests ────────────────────────────────────────────

    #[test]
    fn bundle_signer_pk_hashes_produces_correct_hashes() {
        let descriptor = test_descriptor();
        let snapshot = build_snapshot(&descriptor, h(0xBB));
        let (buyer_h, merchant_h, operator_h) = test_pk_hashes();
        let (buyer_pk, _merchant_pk, operator_pk) = test_pks();

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

        let hashes = bundle_signer_pk_hashes(&bundle);

        assert_eq!(hashes.len(), 2);
        // The hashes must match falcon_pk_hash of the raw PK bytes
        assert_eq!(hashes[0], falcon_pk_hash(&buyer_pk));
        assert_eq!(hashes[1], falcon_pk_hash(&operator_pk));
    }

    // ── EscrowAction conversion tests ────────────────────────────

    #[test]
    fn escrow_action_roundtrip_privai() {
        for action in [
            EscrowAction::Release,
            EscrowAction::Refund,
            EscrowAction::RecoveryRelease,
        ] {
            let pc = action.to_privai();
            let back = EscrowAction::from_privai(pc);
            assert_eq!(action, back);
        }
    }
}
