# NXMS Monero Stagenet Tor Baseline

Last update: 2026-03-10
Scope: canonical Monero runtime prerequisite for `nxms-signer run` on Alpine/OpenRC.

## Rule
- This stage assumes the NXMS crypto baseline is already in place:
  - pinned `liboqs`
  - vendored Falcon CT reference code used by `nxms-transport`
  - successful NXMS release build on the target host
- `nxms-signer run` is not a meaningful runtime gate without real Monero services.
- The minimum Monero runtime for signer is:
  - `monerod --stagenet`
  - `monero-wallet-rpc --stagenet`
  - real wallet material on disk
- `wallet-rpc` must stay loopback-only.
- `monerod` should use Tor for network path.
- This Monero layer is a prerequisite for signer startup and all later `sign/submit` runtime gates.
- On Alpine/musl, do not assume the verified upstream `linux-x64` tarball is directly runnable.
  Treat it as provenance input unless the runtime ABI is proven compatible.

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

## Repo-Managed Baseline
- [deploy/openrc/monerod-stagenet](/home/nxms-server/nexum-core/deploy/openrc/monerod-stagenet)
- [deploy/openrc/monerod-stagenet.confd](/home/nxms-server/nexum-core/deploy/openrc/monerod-stagenet.confd)
- [deploy/openrc/monero-wallet-rpc-stagenet](/home/nxms-server/nexum-core/deploy/openrc/monero-wallet-rpc-stagenet)
- [deploy/openrc/monero-wallet-rpc-stagenet.confd](/home/nxms-server/nexum-core/deploy/openrc/monero-wallet-rpc-stagenet.confd)
- [deploy/monero/monerod-stagenet.conf.example](/home/nxms-server/nexum-core/deploy/monero/monerod-stagenet.conf.example)
- [deploy/monero/wallet-rpc-stagenet.conf.example](/home/nxms-server/nexum-core/deploy/monero/wallet-rpc-stagenet.conf.example)
- [deploy/tor/monerod-stagenet-hidden-service.conf.example](/home/nxms-server/nexum-core/deploy/tor/monerod-stagenet-hidden-service.conf.example)

## Canonical Security Boundary
- `Tor` is the network path for `monerod` peer connectivity.
- `wallet-rpc` is not a cross-host service in NXMS runtime.
- `wallet-rpc` stays local capability only for signer host.
- `nxms-transport` still remains the only end-to-end security layer for NXMS payloads.
- Falcon CT and `liboqs` are not optional side details here; they are part of the cryptographic baseline beneath every later signer/runtime gate.

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
  - `proxy=127.0.0.1:9050`
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
- config file ownership baseline:
  - `/etc/monero/wallet-rpc-stagenet.conf` as `root:monero 0640`
  - keep `rpc-login` only in that local config file
  - do not place wallet-rpc auth in OpenRC `.confd` or argv

## OpenRC Install Shape
1. Install Monero binaries to `/opt/monero/<version>/`.
2. Maintain `/opt/monero/current` symlink to the active verified version.
3. Install units:
   - `/etc/init.d/monerod-stagenet`
   - `/etc/conf.d/monerod-stagenet`
   - `/etc/init.d/monero-wallet-rpc-stagenet`
   - `/etc/conf.d/monero-wallet-rpc-stagenet`
4. Install config:
   - `/etc/monero/stagenet.conf`
   - `/etc/monero/wallet-rpc-stagenet.conf`
5. Install Tor fragment:
   - `/etc/tor/torrc.d/monerod-stagenet.conf`
6. Create runtime layout:
   - `/var/lib/monero/stagenet`
   - `/var/lib/monero/wallets`
   - `/var/log/monero`

## Alpine ABI Reality
- The upstream Monero `linux-x64` tarball is glibc-linked.
- A real Alpine/musl runtime may fail with:
  - `No such file or directory` from `start-stop-daemon`
  - missing interpreter `/lib64/ld-linux-x86-64.so.2`
  - relocation failures for glibc symbols
- If that happens, the OpenRC unit is not the bug.
- The correct fix is a musl-compatible Monero build for Alpine, preferably built from the intended Monero source tag.

## What Must Exist Before Signer Start
- host crypto baseline green:
  - pinned `liboqs` installed
  - vendored Falcon CT path intact
  - NXMS release build completed on this host
- `monerod` started and reachable on `127.0.0.1:38081`
- `monero-wallet-rpc` started and reachable on `127.0.0.1:38088`
- signer wallet present on disk
- wallet-rpc credentials stored as secret refs
- signer `keys.json`
- signer `peers.json`
- signer action-token public key PEM
- signer mailbox `.onion` URL and scoped mailbox tokens

## Stage Order
0. `crypto/build baseline`
   Prove pinned `liboqs`, vendored Falcon CT path and successful NXMS release build on the target host.
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
Immediate runtime gate to execute on Alpine/OpenRC host:
- verify official Monero release before install
- `rc-service tor restart`
- `rc-service monerod-stagenet restart`
- `rc-service monero-wallet-rpc-stagenet restart`
- `rc-service monerod-stagenet status`
- `rc-service monero-wallet-rpc-stagenet status`
- `curl -fsS http://127.0.0.1:38081/get_info`
- `curl --digest -u walletrpc:<password> -fsS -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' http://127.0.0.1:38088/json_rpc`
- confirm `proxy=127.0.0.1:9050`, `tx-proxy=tor,127.0.0.1:9050,disable_noise` and real `anonymous-inbound=...` in `/etc/monero/stagenet.conf`
