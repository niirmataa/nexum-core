# NXMS OpenRC + Tor Runtime Baseline

Last update: 2026-03-10
Scope: Alpine/OpenRC deploy baseline for the canonical `nxms-transport -> nxms-mailbox -> nxms-signer` runtime.

## Rule
- Cross-host path is `Tor hidden service` only.
- `nxms-transport` remains the only end-to-end security layer.
- Local HTTP is only a loopback process adapter boundary.
- OpenRC units must not reintroduce legacy worker/direct-flow assumptions.
- Secrets must not be carried in argv or committed plaintext config.

## Repo-Managed Baseline
- [deploy/openrc/nxms-mailbox](/home/nxms-server/nexum-core/deploy/openrc/nxms-mailbox)
- [deploy/openrc/nxms-mailbox.confd](/home/nxms-server/nexum-core/deploy/openrc/nxms-mailbox.confd)
- [deploy/openrc/nxms-signer](/home/nxms-server/nexum-core/deploy/openrc/nxms-signer)
- [deploy/openrc/nxms-signer.confd](/home/nxms-server/nexum-core/deploy/openrc/nxms-signer.confd)
- [deploy/tor/nxms-mailbox-hidden-service.conf.example](/home/nxms-server/nexum-core/deploy/tor/nxms-mailbox-hidden-service.conf.example)

## Runtime Topology
- Host A:
  `nxms-mailbox` on `127.0.0.1:4010` behind Tor hidden service.
- Host B:
  `nxms-signer run` with `.onion` mailbox URL and `socks5h://127.0.0.1:9050`.
  Local `monero-wallet-rpc` stays loopback-only.
- `nxms-escrow-orchestrator`:
  current repo baseline is manual/control-plane tooling, not a long-running OpenRC daemon.

## Secret Model
- Mailbox:
  OpenRC points only to `/etc/nxms/mailbox.toml`.
  Mailbox bearer tokens live in mailbox TOML as `vault:` / `file:` / `env:` refs.
  Production baseline is `vault:` refs backed by `/run/secrets/nxms/...`.
- Signer:
  main secrets stay in signer TOML via `vault:` / `file:` refs.
  Optional orchestrator bridge token, if enabled, is passed as `NXMS_SIGNER_ORCH_BRIDGE_TOKEN_REF=vault:/...`.
- Do not place mailbox bearer values or bridge token values directly in `.confd`.
- Do not pass secrets in `start-stop-daemon` argv.

## OpenRC Install Shape
1. Install binaries to `/opt/nxms/bin/`.
2. Install units:
   - `/etc/init.d/nxms-mailbox`
   - `/etc/conf.d/nxms-mailbox`
   - `/etc/init.d/nxms-signer`
   - `/etc/conf.d/nxms-signer`
3. Install signer config:
   - `/etc/nxms/signer.toml`
   - `/etc/nxms/mailbox.toml`
4. Install Tor hidden service fragment:
   - `/etc/tor/torrc.d/nxms-mailbox.conf`
5. Create secret files under `/run/secrets/nxms/`.

## Tor Ingress
- Mailbox hidden service publishes:
  `HiddenServicePort 80 127.0.0.1:4010`
- Signer must target mailbox onion URL, not loopback mailbox URL.
- Signer must use `socks5h://127.0.0.1:9050`.

## Operational Notes
- `nxms-mailbox` OpenRC unit is the canonical daemon baseline for mailbox.
- `nxms-signer` OpenRC unit runs only canonical `run` mode.
- Worker HTTP capability mode is intentionally not the default OpenRC signer service.
- No OpenRC unit is shipped for orchestrator because current orchestrator binary is not a daemon.

## Validation Boundary
These files define deploy baseline and startup truth.
They do not by themselves prove a live Tor deployment.
Live Tor/onion validation must be executed separately as deploy/runtime P0.
