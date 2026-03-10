# Decisions (ADR-lite)

## 2026-02-14: PostgreSQL Over SQLite For Runtime
- Decision: production runs on PostgreSQL.
- Reason: row-level locking and predictable concurrent writes.
- Consequence: SQLite only as controlled dev fallback.

## 2026-02-14: TLS Client Cert For DB Transport/Auth
- Decision: use PostgreSQL TLS with client certs.
- Reason: remove password-only dependency and enforce secure DB transport.
- Consequence: certificate lifecycle and file permissions become operational requirements.

## 2026-02-14: Onion-Only Access Policy
- Decision: deny clearnet by default.
- Reason: privacy-first requirement and operator error reduction.
- Consequence: local testing needs explicit clearnet toggle when required.

## 2026-02-14: Escrow State Machine Hardened With Locks
- Decision: mutating escrow endpoints use row locks.
- Reason: avoid race conditions in multisig rounds and release/refund finalization.
- Consequence: requires PostgreSQL semantics for full effect.

## 2026-02-14: NX-TUNNEL Zero-Scanning Policy
- Decision: `nx_tunnel` never performs active scanning/probing of external networks.
- Reason: align with safety model and avoid hostile or ambiguous network behavior.
- Consequence: discovery is explicit/manual (`peer-add`) and egress is allowlist-only.

## 2026-02-14: NX-TUNNEL Own-Traffic-Only Telemetry And Cover
- Decision: telemetry and adaptive cover generation use only `nx_tunnel` self traffic metrics.
- Reason: preserve privacy boundary and prevent third-party network intelligence collection.
- Consequence: no measurements of non-peer hosts/services; cover traffic remains inside overlay paths only.

## 2026-02-14: NX-TUNNEL Crypto Suite Lock (Production)
- Decision: lock production crypto suite to `FrodoKEM-640-SHAKE` + `Falcon-1024-CT`.
- Reason: stable security profile, deterministic audit scope, and no downgrade surface.
- Consequence: no runtime algorithm negotiation; any suite mismatch is fail-closed.

## 2026-02-14: NX-TUNNEL Reference Implementation Policy
- Decision: use reference-backed implementations for Frodo/Falcon paths with pinned versions/commits.
- Reason: maximize reviewability and reproducibility for open-source audits.
- Consequence: release process must include dependency pinning, checksums, and traceable build metadata.

## 2026-02-14: NX-TUNNEL Final Transport Direction (QUIC-First)
- Decision: keep UDP datagram mode only as MVP compatibility; final transport path is QUIC-first.
- Reason: better stream multiplexing and link behavior under loss while preserving strong transport security.
- Consequence: roadmap includes migration to QUIC link/session runtime; QUIC 0-RTT remains disabled in production.

## 2026-02-15: NX-TUNNEL QUIC Session Enforcement
- Decision: QUIC mode requires successful PQ session handshake (`client_hello/server_hello/client_finish`) before accepting NXTP packets.
- Reason: fail-closed session gating and replay resistance are required for production-grade transport behavior.
- Consequence: QUIC data frames now carry session-bound integrity tag and sequence number; runtime rotates sessions by TTL and drops out-of-session traffic.

## 2026-02-15: NX-TUNNEL Explicit QUIC Session Policy And Doctor Checks
- Decision: expose QUIC session/replay controls in config and add runtime diagnostics command (`doctor`) as an operational gate.
- Reason: audited deployments require explicit, inspectable policy values and deterministic dependency checks before startup.
- Consequence: operators can tune/verify TTL, handshake retry/timeout, replay window, and dependency readiness without code changes.

## 2026-02-15: NX-TUNNEL Circuit Routing Foundation
- Decision: introduce explicit multi-hop circuits as ordered allowlisted peer routes, enabled only on QUIC transport.
- Reason: prepare production overlay topology with deterministic relay behavior and fail-closed route validation.
- Consequence: control-plane packets can traverse relays; ACK path uses reverse route; further hardening of relay frame authentication remains on roadmap.

## 2026-02-15: NX-TUNNEL QUIC Session Rotation And Resync Policy
- Decision: enforce explicit QUIC session lifecycle with proactive rekey and cooldown-limited forced resync on mismatch.
- Reason: reduce stale-session failures and define deterministic recovery behavior required by audited production operation.
- Consequence: runtime now rotates sessions before expiry and tracks per-peer rekey/resync counters; policy knobs are configurable (`rekey_before_expiry`, `resync_cooldown`).
