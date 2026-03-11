# NXMS OpenRC + Tor Runtime Baseline

Last update: 2026-03-10
Scope: Alpine/OpenRC deploy baseline for the canonical `nxms-transport -> nxms-mailbox -> nxms-signer` runtime.

## Rule
- Cross-host path is `Tor hidden service` only.
- `nxms-transport` remains the only end-to-end security layer.
- The runtime stack assumes the host already satisfies the crypto/build baseline:
  pinned `liboqs`, vendored Falcon CT path, and successful NXMS release build.
- Local HTTP is only a loopback process adapter boundary.
- OpenRC units must not reintroduce legacy worker/direct-flow assumptions.
- Secrets must not be carried in argv or committed plaintext config.

## Repo-Managed Baseline
- [deploy/openrc/nxms-mailbox](/home/nxms-server/nexum-core/deploy/openrc/nxms-mailbox)
- [deploy/openrc/nxms-mailbox.confd](/home/nxms-server/nexum-core/deploy/openrc/nxms-mailbox.confd)
- [deploy/openrc/monerod-stagenet](/home/nxms-server/nexum-core/deploy/openrc/monerod-stagenet)
- [deploy/openrc/monerod-stagenet.confd](/home/nxms-server/nexum-core/deploy/openrc/monerod-stagenet.confd)
- [deploy/openrc/monero-wallet-rpc-stagenet](/home/nxms-server/nexum-core/deploy/openrc/monero-wallet-rpc-stagenet)
- [deploy/openrc/monero-wallet-rpc-stagenet.confd](/home/nxms-server/nexum-core/deploy/openrc/monero-wallet-rpc-stagenet.confd)
- [deploy/openrc/nxms-signer](/home/nxms-server/nexum-core/deploy/openrc/nxms-signer)
- [deploy/openrc/nxms-signer.confd](/home/nxms-server/nexum-core/deploy/openrc/nxms-signer.confd)
- [deploy/tor/nxms-mailbox-hidden-service.conf.example](/home/nxms-server/nexum-core/deploy/tor/nxms-mailbox-hidden-service.conf.example)
- [deploy/tor/monerod-stagenet-hidden-service.conf.example](/home/nxms-server/nexum-core/deploy/tor/monerod-stagenet-hidden-service.conf.example)
- [deploy/monero/monerod-stagenet.conf.example](/home/nxms-server/nexum-core/deploy/monero/monerod-stagenet.conf.example)
- [deploy/monero/wallet-rpc-stagenet.conf.example](/home/nxms-server/nexum-core/deploy/monero/wallet-rpc-stagenet.conf.example)
- [docs/NXMS_ALPINE_VM_V3_23_BOOTSTRAP.md](/home/nxms-server/nexum-core/docs/NXMS_ALPINE_VM_V3_23_BOOTSTRAP.md)
- [docs/NXMS_MONERO_STAGENET_TOR_BASELINE.md](/home/nxms-server/nexum-core/docs/NXMS_MONERO_STAGENET_TOR_BASELINE.md)

## Runtime Topology
- Host A:
  `nxms-mailbox` on `127.0.0.1:4010` behind Tor hidden service.
- Host B:
  `nxms-signer run` with `.onion` mailbox URL and `socks5h://127.0.0.1:9050`.
  Local `monerod-stagenet` is Tor-routed and keeps daemon RPC on `127.0.0.1:38081`.
  Local `monero-wallet-rpc-stagenet` stays loopback-only on `127.0.0.1:38088`.
- `nxms-escrow-orchestrator`:
  current repo baseline is manual/control-plane tooling, not a long-running OpenRC daemon.

## Secret Model
- Mailbox:
  OpenRC points only to `/etc/nxms/mailbox.toml`.
  Mailbox bearer tokens live in mailbox TOML as `vault:` / `file:` / `env:` refs.
  Production baseline is `vault:` refs backed by `/run/secrets/nxms/...`.
  Ownership baseline: `/etc/nxms/mailbox.toml` as `root:nxms 0640`, mailbox secret files as `nxms:nxms 0600`, secret directory as `root:nxms 0750`.
- Signer:
  main secrets stay in signer TOML via `vault:` / `file:` refs.
  Optional orchestrator bridge token, if enabled, is passed as `NXMS_SIGNER_ORCH_BRIDGE_TOKEN_REF=vault:/...`.
  Ownership baseline: `/etc/nxms/signer.toml` as `root:nxms 0640`; signer secret files referenced via `vault:` must be `nxms:nxms 0600`.
- Monero:
  `monerod` config is plain local config at `/etc/monero/stagenet.conf` with no secrets in argv.
  `wallet-rpc` auth stays only in `/etc/monero/wallet-rpc-stagenet.conf`.
  Because Monero CLI does not support secret refs, keep that config `root:monero 0640` and never mirror `rpc-login` into OpenRC `.confd`.
- Do not place mailbox bearer values or bridge token values directly in `.confd`.
- Do not pass secrets in `start-stop-daemon` argv.

## OpenRC Install Shape
1. Install binaries to `/opt/nxms/bin/`.
2. Install units:
   - `/etc/init.d/nxms-mailbox`
   - `/etc/conf.d/nxms-mailbox`
   - `/etc/init.d/monerod-stagenet`
   - `/etc/conf.d/monerod-stagenet`
   - `/etc/init.d/monero-wallet-rpc-stagenet`
   - `/etc/conf.d/monero-wallet-rpc-stagenet`
   - `/etc/init.d/nxms-signer`
   - `/etc/conf.d/nxms-signer`
3. Install config:
   - `/etc/monero/stagenet.conf`
   - `/etc/monero/wallet-rpc-stagenet.conf`
   - `/etc/nxms/signer.toml`
   - `/etc/nxms/mailbox.toml`
4. Install Tor hidden service fragments:
   - `/etc/tor/torrc.d/nxms-mailbox.conf`
   - `/etc/tor/torrc.d/monerod-stagenet.conf`
5. Create secret files under `/run/secrets/nxms/`.

## Tor Ingress
- Mailbox hidden service publishes:
  `HiddenServicePort 80 127.0.0.1:4010`
- Signer must target mailbox onion URL, not loopback mailbox URL.
- Signer must use `socks5h://127.0.0.1:9050`.

## Operational Notes
- `nxms-mailbox` OpenRC unit is the canonical daemon baseline for mailbox.
- `monerod-stagenet` and `monero-wallet-rpc-stagenet` are prerequisites for truthful signer runtime validation.
- `nxms-signer` OpenRC unit runs only canonical `run` mode.
- Worker HTTP capability mode is intentionally not the default OpenRC signer service.
- No OpenRC unit is shipped for orchestrator because current orchestrator binary is not a daemon.

## Validation Boundary
These files define deploy baseline and startup truth.
They do not by themselves prove a live Tor deployment.
Live Tor/onion validation must be executed separately as deploy/runtime P0.
Use a second Tor client or a second host for onion ingress validation; do not rely only on self-testing a hidden service through the same Tor instance that publishes it.
