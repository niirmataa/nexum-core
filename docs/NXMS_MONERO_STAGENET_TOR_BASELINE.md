# NXMS Monero Stagenet Tor Baseline

Last update: 2026-03-10
Scope: canonical Monero runtime prerequisite for `nxms-signer run` on Alpine/OpenRC.

## Rule
- `nxms-signer run` is not a meaningful runtime gate without real Monero services.
- The minimum Monero runtime for signer is:
  - `monerod --stagenet`
  - `monero-wallet-rpc --stagenet`
  - real wallet material on disk
- `wallet-rpc` must stay loopback-only.
- `monerod` should use Tor for network path.
- This Monero layer is a prerequisite for signer startup and all later `sign/submit` runtime gates.

## Why This Is P0
`nxms-signer` does real startup work in `SignerAgent::from_config()`:
- loads `peers.json`
- loads `keys.json`
- opens signer DB
- opens wallet through `wallet-rpc`
- checks `is_multisig`

So a signer host without real `monerod` and `wallet-rpc` is not a truthful runtime stage.

## Runtime Topology
- `monerod-stagenet`
  - local daemon on Host B
  - RPC loopback-only on `127.0.0.1:38081`
  - network path routed over Tor
- `monero-wallet-rpc`
  - loopback-only on `127.0.0.1:38088`
  - points only to local `monerod`
  - never exposed cross-host
- `nxms-signer`
  - loopback-only to `wallet-rpc`
  - cross-host path only through `nxms-mailbox` onion + `nxms-transport`

## Canonical Security Boundary
- `Tor` is the network path for `monerod` peer connectivity.
- `wallet-rpc` is not a cross-host service in NXMS runtime.
- `wallet-rpc` stays local capability only for signer host.
- `nxms-transport` still remains the only end-to-end security layer for NXMS payloads.

## Baseline Ports
- `38080` Monero stagenet P2P
- `38081` Monero stagenet daemon RPC
- `38084` Monero stagenet Tor P2P / anonymous inbound
- `38088` Monero wallet-rpc

## Required Monero Posture

### `monerod`
- `--stagenet`
- local RPC on `127.0.0.1:38081`
- Tor-routed network path
- preferred posture:
  - `tx-proxy=tor,127.0.0.1:9050,disable_noise`
  - `anonymous-inbound=<node-onion>:38084,127.0.0.1:38084`
- if full Tor-only peer routing is enforced on the host, document it explicitly and keep it separate from wallet-rpc.

### `monero-wallet-rpc`
- `--stagenet`
- `--rpc-bind-ip 127.0.0.1`
- `--rpc-bind-port 38088`
- `--daemon-address 127.0.0.1:38081`
- authenticated
- no remote bind
- no Tor exposure

## What Must Exist Before Signer Start
- `monerod` started and reachable on `127.0.0.1:38081`
- `monero-wallet-rpc` started and reachable on `127.0.0.1:38088`
- signer wallet present on disk
- wallet-rpc credentials stored as secret refs
- signer `keys.json`
- signer `peers.json`
- signer action-token public key PEM
- signer mailbox `.onion` URL and scoped mailbox tokens

## Stage Order
1. `mailbox over Tor`
   Already proven separately.
2. `monerod stagenet over Tor-only`
   Prove daemon boot, RPC loopback and Tor-routed posture.
3. `wallet-rpc loopback-only`
   Prove wallet-rpc boot and auth against local daemon.
4. `nxms-signer startup over Tor`
   Only after Monero baseline is green.
5. `sign / submit / orchestrated flow`
   Only after signer startup is green.

## Out Of Scope For This Stage
- full multisig ceremony
- real escrow sign flow
- real submit flow
- orchestrator proof flow

Those come later, but they must build on this Monero baseline instead of bypassing it.

## Next Repo Work
- add repo-managed OpenRC unit for `monerod-stagenet`
- add repo-managed OpenRC unit for `monero-wallet-rpc-stagenet`
- add repo-managed config example for `monerod` stagenet over Tor-only
- add repo-managed config example for `wallet-rpc` loopback-only
- add runtime gate docs for:
  - daemon boot
  - RPC health
  - Tor-routed Monero posture
  - wallet-rpc auth
