# Threat Model: NXMS Mailbox + Signer

Last update: 2026-02-18

## Scope
- `nxms-mailbox`: onion-exposed store-and-forward relay for encrypted NXMS envelopes.
- `nxms-signer`: local manual approval agent that decrypts, validates, queues, and (on operator action) signs multisig txsets.
- `monero-wallet-rpc`: local signing backend used only after snapshot-policy validation.

## Security Objectives
- Preserve confidentiality of escrow payloads outside signer host.
- Preserve integrity/authenticity of sender identity, envelope fields, and payload semantics.
- Prevent replay/reset/out-of-order message acceptance per `(escrow_id, from)`.
- Prevent accidental or malicious auto-signing without local operator approval.
- Prevent signing transactions that violate local contract snapshot policy.

## Assets
- NXMS private keys: KEM secret key, Falcon signing key.
- Snapshot policy database: active snapshot + quorum signatures.
- Pending transaction queue and operator decisions.
- Wallet credentials for `wallet-rpc`.
- Multisig txset blobs and their transfer descriptions.

## Trust Boundaries
- Public Tor/onion boundary terminates at mailbox HTTP API.
- Mailbox DB is untrusted for plaintext content; it stores ciphertext envelopes only.
- Signer host boundary: decrypted payloads, policy checks, and signing authority.
- Wallet boundary: signer treats `wallet-rpc` responses as untrusted input and validates before approval/sign.

## Adversaries
- Network attacker: can flood mailbox, replay captured ciphertexts, reorder delivery, and observe metadata timing.
- Malicious/compromised peer: can send syntactically valid but policy-violating `TxSignReq`.
- Mailbox compromise: can delete, delay, duplicate, or replay envelopes.
- Host-level attacker on signer machine: can steal keys or tamper DB (high impact).

## Assumptions
- NXMS cryptography primitives are implemented correctly and keys are generated securely.
- Operator verifies snapshot content before activation and protects signer host.
- Tor routing privacy is best-effort and does not replace endpoint hardening.

## Mitigations Implemented
- Envelope + payload consistency check (`escrow_id/from/to/seq/msg_type`) post-decrypt.
- Stable `msg_type` canonical keys via `msg_type_key()`.
- App protocol pinning (`app_proto = ESCROW/1`) in payload.
- Signer replay guard persisted in DB (`incoming_seen` monotonic enforcement).
- Outgoing sequence persisted in DB (`out_seq`) per `(escrow_id, from)`.
- Mailbox quotas: per inbox message count, per inbox bytes, global rows.
- Mailbox rate limit: per source IP and per target inbox with `429 Retry-After`.
- Manual approval only: `nxms-signer` enqueues `pending_tx_sign`; no auto-sign path.
- `describe_transfer` validation against active snapshot before pending/approval.
- Snapshot quorum activation (`snapshots` + `snapshot_sigs`) enforced in signer DB.

## Out of Scope
- Compromise of signer OS/root, kernel, firmware, or hardware wallet absence.
- Side-channel attacks on Falcon/Frodo implementations.
- Tor global passive adversary deanonymization resistance guarantees.
- Multi-datacenter mailbox replication consistency semantics.

## Residual Risks
- Message withholding or delay by mailbox remains possible (availability attack).
- Operator social-engineering risk during manual approval is not eliminated.
- If snapshot is misconfigured and activated, signer enforces wrong policy consistently.

## Operational Requirements
- Run mailbox and signer on separate hosts/users where possible.
- Bind mailbox HTTP to localhost only; expose exclusively via Tor onion service.
- Use onion client authorization and firewall default-deny.
- Store NXMS and wallet secrets on signer host with least privilege permissions.
