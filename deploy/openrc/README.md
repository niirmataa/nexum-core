# NXMS OpenRC Baseline

Repo-managed OpenRC runtime baseline for Alpine:

- `nxms-mailbox`
  Canonical mailbox daemon.
  Runs `nxms-mailbox serve --config /etc/nxms/mailbox.toml` on loopback only.
  Mailbox secrets live in mailbox TOML as `vault:` / `file:` / `env:` refs, not in OpenRC env or argv.
  For `vault:` refs, keep `/etc/nxms/mailbox.toml` readable by `nxms` (`root:nxms 0640`) and the secret files owner-readable only by the daemon user (`nxms:nxms 0600`).

- `nxms-signer`
  Canonical signer daemon.
  Runs `nxms-signer run --config /etc/nxms/signer.toml`.
  Signer secrets stay in TOML secret refs (`vault:` / `file:`) and optional orchestrator bridge uses `NXMS_SIGNER_ORCH_BRIDGE_TOKEN_REF`.
  For `vault:` refs, keep `/etc/nxms/signer.toml` readable by `nxms` (`root:nxms 0640`) and the referenced secret files `nxms:nxms 0600`.

- `monerod-stagenet`
  Canonical Monero daemon baseline for truthful signer runtime.
  Runs `/opt/monero/current/monerod --config-file /etc/monero/stagenet.conf`.
  RPC stays loopback-only on `127.0.0.1:38081`.
  P2P listener stays on `127.0.0.1:38084` behind a dedicated Tor hidden service.
  Config must enforce Tor-only peer posture (`proxy=127.0.0.1:9050`, `tx-proxy=tor,127.0.0.1:9050,disable_noise`) and a real `anonymous-inbound=...`.

- `monero-wallet-rpc-stagenet`
  Canonical local Monero wallet capability for signer host.
  Runs `/opt/monero/current/monero-wallet-rpc --config-file /etc/monero/wallet-rpc-stagenet.conf`.
  Wallet RPC stays loopback-only on `127.0.0.1:38088` and targets only local `monerod`.
  Because Monero CLI does not support NXMS-style `vault:` refs, keep `/etc/monero/wallet-rpc-stagenet.conf` as `root:monero 0640` and place `rpc-login` only in that local config file, never in OpenRC argv or `.confd`.

Not managed as an OpenRC daemon here:

- `nxms-escrow-orchestrator`
  Current binary is control-plane/manual tooling, not a long-running service.
  This repo intentionally does not ship an OpenRC unit that would pretend otherwise.

Related Tor ingress example:

- `deploy/tor/nxms-mailbox-hidden-service.conf.example`
- `deploy/tor/monerod-stagenet-hidden-service.conf.example`

Legacy note:

- `deploy/README_wallet_rpc_ultra_paranoid.md` and `deploy/monero/wallet-rpc-split-role.conf.example` are historical/operator material.
  They are not the canonical baseline for the current NXMS runtime path.
