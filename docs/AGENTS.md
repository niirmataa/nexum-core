# AGENTS.md

## Project intent
NXMS Core is an auto-multisig escrow system.
Canonical runtime path:
- nxms-transport = only wire format
- nxms-mailbox = only relay/store-and-forward
- nxms-signer = signing/execution node
- nxms-escrow-orchestrator = workflow control-plane
- nxms-monero-core = Monero/multisig domain logic
- tools/nexum-cli = manual user-auth/crypto tooling only; not operator UI, not runtime escrow surface

## Hard rules
- Do not introduce a second parallel flow.
- Do not make legacy HTTP paths part of runtime core.
- Do not use nexum-cli as a required runtime dependency.
- Prefer removal of legacy code over adding compatibility layers.
- Default to Tor-only assumptions in docs and runtime decisions.
- Prefer OpenRC over systemd for Alpine targets.

## Architecture tags
Every change must be classified as one of:
- CORE
- OPS
- MANUAL

## Required outputs for code changes
When editing code, always provide:
1. what changed
2. why it belongs to CORE / OPS / MANUAL
3. tests or checks added
4. whether it removes or preserves legacy behavior

## Review priorities
Prioritize:
1. one canonical flow
2. replay / req_id / seq integrity
3. signer and orchestrator consistency
4. Alpine/OpenRC operability
5. removal of shadow/break-glass defaults
