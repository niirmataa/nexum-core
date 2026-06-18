# Project Status

Last checked: 2026-06-17

Repository: `niirmataa/nexum-core`

## Git State

Remote:

- `origin`: `https://github.com/niirmataa/nexum-core.git`
- default branch: `main`
- latest remote commit: `bc3046c` - `chore: remove accidental Zone.Identifier ADS files (Windows artifact)`

Local workspace:

- branch: `main`
- latest local commit: `c50c1e6` - `add mesh bootstrap, secure-ping tooling and Dockerfiles`
- local branch is `ahead 4, behind 1`
- untracked local file currently present: `ios/NexumVault/AGENT_RUNBOOK.md`

Local commits not on `origin/main`:

- `2d7d3ee` - `fix: restore full workspace, implement run_responder, add secure_ping API`
- `891e00d` - `vendor/falcon: replace Falcon reference impl with enc/fft/keygen/sign/vrfy split`
- `094478b` - `tools/nexum-cli: sync source and build scripts`
- `c50c1e6` - `add mesh bootstrap, secure-ping tooling and Dockerfiles`

Remote commit not in local branch:

- `bc3046c` - `chore: remove accidental Zone.Identifier ADS files (Windows artifact)`

## Current Scope

This repository is the Rust/core workspace for Nexum/NXMS experiments.

Current local work includes:

- secure ping / transport work,
- mesh bootstrap tooling,
- Dockerfiles for node and secure-ping flows,
- Nexum CLI source and build script sync,
- Falcon vendor changes,
- iOS vault directory that has now also been split into `lukasz82338233/nexum-vault-ios`.

## Current Role In The Nexum Stack

Treat this repository as experimental core infrastructure.

It is not currently the clean public integration point for the rewritten stack. The cleaner direction is:

- `nexum-network` for protocol packages, fixtures, skills, and docs,
- `nexum-vault-ios` for iOS vault,
- future `nexum-falcon-wasm` for reproducible WASM verifier,
- future `nexum-service-wrapper` for the CLI/API service boundary.

## Risk Notes

- The branch is diverged from remote and should not be force-pushed casually.
- The Falcon vendor changes touch cryptographic code and need review.
- Transport/responder behavior must be checked before it is described as production-ready.
- Do not rewrite crypto, key management, contracts, or withdrawal-related logic without audit.
- Do not lose the four local commits; they contain meaningful experimental work.

## Recommended Next Step

Before any push:

1. Save or commit `ios/NexumVault/AGENT_RUNBOOK.md` if it is still needed.
2. Create a backup branch from current local `main`.
3. Merge or rebase the remote Zone.Identifier cleanup commit carefully.
4. Run the intended Rust test suite.
5. Document which crates are production, experimental, or archived.

Suggested safe branch name:

```text
backup/local-main-2026-06-17
```
