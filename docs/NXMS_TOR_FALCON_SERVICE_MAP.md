# NXMS Tor + Falcon Service Map (Alpine/OpenRC Runtime)

Last update: 2026-02-22  
Status: Active reference (runtime/service naming and deployment map)

## Purpose

This document maps:

- logical component names used in NXMS docs and `nexum-cli` orchestration,
- repo paths and binaries,
- current host service names (Alpine/OpenRC),
- target service layout we want to standardize.

This is a runtime/deployment map. It does not change security boundaries.

## Scope and Assumptions

- Host OS: Alpine Linux + OpenRC
- Repo path: `/opt/freeforum/nexum`
- Web app source tree for operator UI (`/escrow`) is in repo at `server/` (observed host source path: `/mnt/sdb/nexum/server`; current work treats repo `server/` as the correct source tree for `freeforum` UI code).
- Current `freeforum` OpenRC unit is configured for `/opt/freeforum/server` (missing on this host at check time).
- Goal: final operator path is `nexum-cli` + `/escrow` over Tor, with NXMS backend services preserved

## Naming Rule (Important)

- `nxms-serv` = logical name for the operator web/backend service (UI `/escrow`).
- Current host OpenRC service implementing this is `freeforum`.
- In docs and `nexum-cli` preflight, use logical name `nxms-serv`, but always map to actual service/unit name on the host.

## Service Map (Logical -> Runtime)

| Logical component | Current host service/unit | Repo path | Binary / command | Config / env | Notes |
|---|---|---|---|---|---|
| `nxms-serv` (web UI incl. `/escrow`) | `freeforum` (OpenRC) | `server/` | `uvicorn app.main:app` | `/etc/init.d/freeforum`, `/etc/conf.d/freeforum` | Serves `/escrow` page and auth/session UI. Current OpenRC config points to `/opt/freeforum/server` (missing on this host), so service start currently fails. |
| `escrow-http` (`monero-arbitra`) | `nx-escrow-rs` (OpenRC) | `escrow/monero-arbitra/` | `monero-arbitra serve-escrow` | `/etc/init.d/nx-escrow-rs`, `/etc/conf.d/nx-escrow-rs` | Escrow API `/escrows/*`, multisig rounds, release/refund endpoints. |
| `monerod-stagenet` | `monerod-stagenet` (OpenRC) | system | `/usr/bin/monerod` | `/etc/init.d/monerod-stagenet`, `/etc/conf.d/monerod-stagenet`, `/etc/monero/stagenet.conf` | Chain daemon. |
| `wallet-rpc-arbiter` | `monero-wallet-rpc-stagenet` (OpenRC) | system | `/usr/bin/monero-wallet-rpc` | `/etc/init.d/monero-wallet-rpc-stagenet`, `/etc/conf.d/monero-wallet-rpc-stagenet`, `/etc/monero/wallet-rpc-stagenet.conf` | Arbiter wallet-rpc endpoint (`XMR_WALLET_RPC_*`). |
| `wallet-rpc-party` (buyer/seller/funding path) | `monero-wallet-rpc-party` (OpenRC) | system | `/usr/bin/monero-wallet-rpc` | `/etc/init.d/monero-wallet-rpc-party`, `/etc/monero/wallet-rpc-party.conf` | Party/funding endpoint (`XMR_PARTY_WALLET_RPC_*`). |
| `redis` | `redis` (OpenRC) | system | `/usr/bin/redis-server` | `/etc/init.d/redis`, `/etc/conf.d/redis`, `/etc/redis.conf` | Escrow rate limit/runtime backend. |
| `tor` | `tor` (OpenRC) | system | `/usr/bin/tor` | `/etc/init.d/tor`, `/etc/conf.d/tor`, `/etc/tor/torrc` | SOCKS5 + onion ingress. |
| `nxms-escrow-orchestrator` | (not installed as host service yet) | `escrow/nxms-escrow-orchestrator/` | `nxms-escrow-orchestrator` | runtime env / DB path | Workflow authority. Release binary is now built locally, but no host service unit is installed on this host. |
| `nxms-signer` | (not installed as host service yet on this host) | `escrow/nxms-signer/` | `nxms-signer` | signer config + tokens | Repo contains systemd unit example. |
| `nxms-mailbox` | (not installed as host service yet on this host) | `escrow/nxms-mailbox/` | `nxms-mailbox serve` | mailbox env/config | Repo contains systemd unit example. |
| `nxms-mailbox-client` | library/client binary (not service) | `escrow/nxms-mailbox-client/` | `nxms-mailbox-client` | integration-specific | Used by services; not a standalone required daemon in normal operator flow. |

## Current Host Snapshot (Observed 2026-02-22)

OpenRC statuses observed:

- `freeforum`: stopped (start failure: `/opt/freeforum/server/venv/bin/uvicorn` missing; configured app path missing)
- `nx-escrow-rs`: started (after `redis` start)
- `monerod-stagenet`: started
- `monero-wallet-rpc-stagenet`: started
- `monero-wallet-rpc-party`: started
- `redis`: started
- `tor`: started

Observed listeners at check time:

- `127.0.0.1:9050` (Tor SOCKS)
- `127.0.0.1:9000` (`monero-arbitra` / escrow HTTP)
- `127.0.0.1:38081` (`monerod` stagenet)
- `127.0.0.1:38083` (arbiter wallet-rpc)
- `127.0.0.1:38084` (party wallet-rpc)
- `127.0.0.1:6379` (`redis`)
- `127.0.0.1:8080` (nginx/freeforum onion frontend path; currently returns `502`)

Observed Tor hidden services:

- `/var/lib/tor/freeforum/hostname` -> present (`freeforum` onion to `127.0.0.1:8080`)
- `/var/lib/tor/escrow-http/hostname` -> present (`escrow-http` onion to `127.0.0.1:9000`)

Observed local binaries / build artifacts:

- `nexum_cli/nexum`: present
- `escrow/monero-arbitra/target/release/monero-arbitra`: present
- `escrow/nxms-escrow-orchestrator/target/debug/nxms-escrow-orchestrator`: present
- `escrow/nxms-signer/target/release/nxms-signer`: present
- `escrow/nxms-escrow-orchestrator/target/release/nxms-escrow-orchestrator`: present (built locally)
- `escrow/nxms-mailbox/target/release/nxms-mailbox`: present (built locally)
- `escrow/nxms-mailbox-client/target/release/`: library artifact present (`libnxms_mailbox_client.rlib`); no standalone client binary observed from current crate build
- web app source tree `server/`: present in repo checkout (`/mnt/sdb/nexum/server`)
- web app virtualenv for OpenRC path (`/opt/freeforum/server/venv`): missing on this host

Notes:

- `escrow-http` Tor path is now verifiable over onion (`/health` via `socks5h` succeeded).
- Arbiter wallet-rpc capability check passed on current host: auth challenge + `open_wallet` + `is_multisig` + `refresh` (tested with `arb_escrow_77`, multisig ready `2/3`).
- Party wallet-rpc capability check passed: auth challenge + `open_wallet` + `refresh` + `get_balance/get_address` + `transfer` dry-run (`do_not_relay=true`, self-transfer `1` atomic) all succeeded (transfer needed longer timeout budget).
- `nx-escrow-rs` logs still contain `tracing-subscriber` write errors (`No space left on device`) from earlier failures; investigate log target/rotation if evidence logging reliability matters.
- Manual/local P0 runtime checks completed:
  - `nxms-mailbox serve` health OK on `127.0.0.1:4010`
  - `nxms-signer serve` health OK on `127.0.0.1:28090` using temporary P0 config with required action-token + service-auth runtime boundary
  - `nxms-signer run` + local `nxms-mailbox serve` concurrency check OK for 5s (both alive, no mailbox pull connection warnings)
  - `nxms-escrow-orchestrator init-db` + `run --once` OK on local test DB (`/tmp/nxms-p0/orchestrator/nxms_orchestrator.db`)
- Legacy note: local `worker-route` checks were historical interoperability probes, not the target NXMS runtime path.

## Local Run Log (Manual / Host-Specific)

Purpose:

- Keep a clean, factual record of commands used during local runtime bring-up and validation.
- `LOCAL` entries are host-specific execution notes (not canonical production deployment instructions).

Recorded local/manual commands (2026-02-22):

- `[LOCAL/P0]` `rc-service redis start` (required before `nx-escrow-rs` secure runtime would stay up)
- `[LOCAL/P0]` `rc-service nx-escrow-rs restart` and `/health` check on `http://127.0.0.1:9000/health`
- `[LOCAL/P0]` `rc-service tor restart` after hidden-service update for `escrow-http -> 127.0.0.1:9000`
- `[LOCAL/P0]` `curl --socks5-hostname 127.0.0.1:9050 http://<escrow-onion>/health` (Tor onion ingress validation)
- `[LOCAL/P0]` `./nexum_cli/nexum tor-check --base http://<escrow-onion> --socks5 socks5h://127.0.0.1:9050` (Tor path validation; also tested expected fail modes separately)
- `[LOCAL/P0]` wallet-rpc capability checks (JSON-RPC on `127.0.0.1:38083` and `127.0.0.1:38084`): `open_wallet`, `refresh`, `is_multisig`, `get_balance`, `get_address`, `transfer` dry-run (`do_not_relay=true`)
- `[LOCAL/P0]` `escrow/nxms-mailbox/target/release/nxms-mailbox serve --bind 127.0.0.1:4010` + local `/health` check (manual runtime availability)
- `[LOCAL/P0]` `escrow/nxms-signer/target/release/nxms-signer serve` and `run` using temporary local config under `/tmp/nxms-p0/` (fail-closed action-token runtime check)
- `[LOCAL/P0]` `escrow/nxms-escrow-orchestrator/target/release/nxms-escrow-orchestrator init-db` and `run --once` on `/tmp/nxms-p0/orchestrator/nxms_orchestrator.db`
- `[LOCAL/P0][LEGACY]` `./nexum_cli/nexum worker-route-set` / `worker-route-show` against local orchestrator test DB (`seller`, `arbiter`)
- `[LOCAL/P1]` `./nexum_cli/nexum --help` (captured current command surface for matrix inventory; current binary prints help and exits with code `1`)
- `[LOCAL/P1]` `./nexum_cli/nexum preflight escrow --base http://<escrow-onion> --ui-base http://<nxms-serv-onion> --socks5 socks5h://127.0.0.1:9050 --run-dir commit/final_gate/operator_preflight/20260222T203202Z --verbose`
  - Result: `NOT_READY` (expected for backend/operator preflight on current host runtime state)
  - PASS examples: Tor SOCKS, escrow `/health` over Tor, monerod RPC+sync probe (with warnings), wallet-rpc arbiter/party TCP + auth challenge, redis
  - WARN examples: `nxms-serv` `/escrow` onion path `502`, monerod bootstrap/sync status (without strict flags)
  - FAIL examples: `nxms-mailbox`/`nxms-signer` not running, orchestrator binary not in `PATH`, legacy worker-route flags not exported in current shell
  - Artifacts written: `preflight/summary.txt`, `preflight/checks.tsv`, `preflight/manifest.json`
- `[LOCAL/P1]` `./nexum_cli/nexum preflight escrow ... --json --strict-wallet-multisig --check-transfer-dry-run --escrow-id-hex 00112233445566778899aabbccddeeff`
  - Test run artifact root: `commit/final_gate/operator_preflight/20260222T204540Z/` (JSON captured in sibling file during local test)
  - `--json` output validated as parseable JSON (`format=nexum_cli_preflight_output_v1`)
  - Deep probe results (current host/runtime): party transfer dry-run probe `PASS`; arbiter multisig probe reached `is_multisig` and returned `FAIL` (`WALLET_RPC_ARBITER_NOT_MULTISIG`) on current active wallet/runtime context
  - Per-escrow worker-route probe (`seller`, `arbiter`) `PASS` against local test orchestrator DB (`/tmp/nxms-p0/orchestrator/nxms_orchestrator.db`) as legacy/operator evidence only
  - Overall verdict remained `NOT_READY` (other runtime components still down / UI path `502`)
- `[LOCAL/P1]` P1 preflight fix loop (`preflight -> runtime fixes -> rerun`) with deep probes over Tor/onion and local NXMS runtime
  - Build discipline applied before runtime changes and again after parser fix/retest (`nexum_cli`, `monero-arbitra`, `nxms-mailbox`, `nxms-signer`, `nxms-escrow-orchestrator`)
  - Local runtime bring-up for preflight:
    - `nxms-mailbox serve --bind 127.0.0.1:4010 --db-path /tmp/nxms-p0/mailbox/nxms_mailbox.db`
    - `NXMS_SIGNER_ORCH_BRIDGE_TOKEN=<32+ chars> nxms-signer serve --config /tmp/nxms-p0/signer/nxms-signer.toml --bind 127.0.0.1:28090`
    - `mailbox` + `signer` health confirmed on `127.0.0.1:4010/health` and `127.0.0.1:28090/healthz`
  - Deep probe context correction:
    - arbiter `open_wallet` enabled via env (`NXMS_PREFLIGHT_ARBITER_WALLET_NAME`, `XMR_ARBITER_WALLET_PASS`)
    - strict profile env flags exported for preflight shell (`NXMS_ESCROW_HTTP_*_STRICT/REQUIRED`)
    - explicit orchestrator binary path passed via `--orch-bin`
  - Wallet runtime finding:
    - `arb_escrow_77` is not a valid multisig-ready strict probe target on current arbiter wallet-rpc context
    - manual wallet-rpc check confirmed `arb_escrow_74` returns `is_multisig=true, ready=true`
  - Preflight parser fix validated:
    - `nexum_cli` `pf_wallet_rpc_is_multisig_true()` updated to tolerate whitespace in wallet-rpc JSON (`\"multisig\": true`)
  - Final successful preflight run:
    - Artifact root: `commit/final_gate/operator_preflight/20260222T212245Z/` (JSON: sibling file `20260222T212245Z.preflight.json`)
    - Result: `READY_WITH_WARNINGS` (`pass=31`, `warn=3`, `fail=0`, `skip=1`)
    - Remaining warnings only: `nxms-serv` `/escrow` onion path `502`, `monerod` sync/bootstrap status
- `[LOCAL/P1]` `./nexum_cli/nexum escrow-create --base http://<escrow-onion> --buyer-nick buyerp1a --seller-nick sellerp1a --amount-atomic 100000000000 --idempotency-key p1.create.<ts> --run-dir commit/final_gate/operator_flow/20260222T213617Z --socks5 socks5h://127.0.0.1:9050`
  - Result: `PASS` (real onion create via `escrow-http`)
  - Created escrow: `id=78`, state `XMR_MSIG_R1`
  - API create response reported `required_funding_atomic=102500000000` for `amount_atomic=100000000000`
  - `seller_token` not returned (expected current API behavior); `buyer_token` returned and used for follow-up status check
  - Artifacts written: `flow/create.request.json`, `flow/create.response.json`, `flow/status.initial.json`, `meta.txt`, `manifest.json`
- `[LOCAL/P1]` `./nexum_cli/nexum escrow-status --base http://<escrow-onion> --id 78 --nick buyerp1a --token <buyer_token> --run-dir commit/final_gate/operator_flow/20260222T213617Z --socks5 socks5h://127.0.0.1:9050`
  - Result: `PASS` (real onion status via `GET /escrows/:id`)
  - State observed: `XMR_MSIG_R1`, `deposit_address=null`, `required_funding_atomic=102500000000`
  - Artifact written: `flow/status.latest.json` (same run_dir, with updated `meta.txt` / `manifest.json`)

This snapshot is informational only; operator preflight should verify runtime state each run.

## Code-Level Validation (Why `nxms-serv` maps to `freeforum`)

- UI route `GET /escrow` exists in web app:
  - `server/app/routers/dm.py` (`@router.get("/escrow")`)
- UI renders `escrow.html` with Challenge/Falcon panel and auto-refresh header
- Escrow API backend routes (`/escrows/*`) are in `monero-arbitra`:
  - `escrow/monero-arbitra/src/escrow_http/mod.rs`

Therefore:

- `freeforum` (web app) is the current host service for logical `nxms-serv`
- `nx-escrow-rs` is the current host service for logical `escrow-http` (`monero-arbitra`)

## Target Service Layout (What We Standardize Next)

We standardize docs and `nexum-cli` preflight around logical names and map them to host-specific units.

Required runtime set for real Tor flow:

1. `nxms-serv` (currently `freeforum`)
2. `tor`
3. `escrow-http` / `monero-arbitra` (currently `nx-escrow-rs`)
4. `monerod-stagenet`
5. `wallet-rpc-arbiter`
6. `wallet-rpc-party`
7. `redis`
8. `nxms-signer`
9. `nxms-mailbox`

`nxms-escrow-orchestrator` remains control-plane/manual tooling, not a mandatory cross-host data-plane hop for canonical NXMS transport flow.

Optional/support:

- `nxms-mailbox-client` (not a daemon by default)

## Startup and Dependency Order (Operator-Oriented)

Recommended order (preflight/startup expectations):

1. `tor`
2. `redis`
3. `monerod-stagenet`
4. wallet-rpc services (`arbiter`, `party`)
5. `escrow-http` (`monero-arbitra`)
6. NXMS backend services (`nxms-mailbox`, `nxms-signer`, `nxms-escrow-orchestrator`)
7. `nxms-serv` (`freeforum`) for `/escrow` UI

Rationale:

- `/escrow` UI should report runtime state even if degraded, but “ready for real flow” requires all backend services.
- `nexum-cli` preflight should check dependencies and return actionable failures before flow start.

## Repo Deployment Artifacts (Current)

Present in repo:

- OpenRC example:
  - `escrow/deploy/openrc/nexum-escrow` (legacy/example naming for escrow API)
- systemd examples:
  - `escrow/deploy/systemd/nxms-signer.service`
  - `escrow/deploy/systemd/nxms-mailbox.service`

Missing (as repo-managed service units/examples for this Alpine/OpenRC target):

- OpenRC units for `nxms-escrow-orchestrator`, `nxms-signer`, `nxms-mailbox`
- OpenRC unit naming convention docs for logical `nxms-serv` vs current `freeforum`

## `nexum-cli` Preflight Contract (Service Naming)

`nexum-cli` preflight should report both:

- logical service name (portable docs UX), and
- actual host service/unit name (OpenRC/systemd/local process)

Example output semantics:

- `nxms-serv (freeforum): UP`
- `escrow-http (nx-escrow-rs): UP`
- `nxms-escrow-orchestrator (process/manual): DOWN`

This avoids doc/runtime naming drift.

Spec reference:

- `docs/NXMS_NEXUM_CLI_PREFLIGHT_ESCROW_SPEC.md` (check groups, output contract, failure taxonomy)

## Next Steps (P0 Runtime)

1. Add OpenRC-oriented runtime runbook section (or dedicated doc) for NXMS services not yet managed on this host.
2. Add `nexum-cli` real preflight checks using logical names + host mappings from this file.
3. Install/manage runtime services for `nxms-mailbox`, `nxms-signer`, `nxms-escrow-orchestrator` (OpenRC/manual) and document runtime mode; `nxms-mailbox-client` currently appears as a library artifact in this checkout (not a standalone daemon binary).
