# NXMS Tor Runtime P0 Test Matrix

Last update: 2026-03-10
Scope: real deploy/runtime validation of the canonical cross-host path over Tor hidden service.

## Rule
- This matrix is separate from workspace E2E.
- Workspace tests prove component truth.
- This matrix proves deploy truth: OpenRC units, Tor hidden service, onion reachability and runtime startup assumptions.
- A stage is not deploy-real until these checks pass on the actual Alpine/OpenRC host.
- Onion reachability must be validated from a second Tor client or a second host.
- Do not treat `service-host Tor -> service-host own .onion` as a reliable gate by itself.

## P0 Coverage
- `Stage 0: crypto/build baseline`
  Prove pinned `liboqs`, vendored Falcon CT path and successful NXMS release build on the target Alpine/OpenRC host.
- `Stage 1: mailbox over Tor`
  Bring up only `tor` + `nxms-mailbox` and prove loopback health, hidden service publication and onion reachability.
- `Stage 2: monerod stagenet over Tor-only`
  Add verified `monerod-stagenet`, prove loopback RPC and Tor-routed P2P posture.
- `Stage 3: wallet-rpc loopback-only`
  Add `monero-wallet-rpc-stagenet`, prove authenticated local RPC against the local daemon.
- `Stage 4: signer startup over Tor`
  Add `nxms-signer`, prove config hardening and daemon startup against the real mailbox onion and local Monero runtime.
- `Stage 5: canonical runtime flows over Tor`
  Repeat smoke/sign/submit/orchestrated scenarios through the real onion path.

- `mailbox daemon`
  `rc-service nxms-mailbox start`
  `rc-service nxms-mailbox status`
- `crypto/build baseline`
  `cargo check --workspace`
  `cargo build --release -p nxms-mailbox -p nxms-signer -p nxms-escrow-orchestrator`
  verify pinned `liboqs` and vendored Falcon CT prerequisites from bootstrap doc
- `signer daemon`
  `rc-service nxms-signer start`
  `rc-service nxms-signer status`
- `monerod daemon`
  `rc-service monerod-stagenet start`
  `rc-service monerod-stagenet status`
- `wallet-rpc daemon`
  `rc-service monero-wallet-rpc-stagenet start`
  `rc-service monero-wallet-rpc-stagenet status`
- `mailbox loopback health`
  `curl -fsS http://127.0.0.1:4010/health`
- `monerod loopback RPC`
  `curl -fsS http://127.0.0.1:38081/get_info`
- `wallet-rpc auth`
  `curl --digest -u walletrpc:<password> -fsS -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' http://127.0.0.1:38088/json_rpc`
- `hidden service publication`
  `cat /var/lib/tor/nxms-mailbox/hostname`
- `monerod hidden service publication`
  `cat /var/lib/tor/monerod-stagenet/hostname`
- `mailbox onion ingress`
  from a second Tor client:
  `curl --socks5-hostname 127.0.0.1:<second-socks-port> -fsS http://<mailbox-onion>/health`
- `monerod Tor-only posture`
  verify `/etc/monero/stagenet.conf` contains `proxy=127.0.0.1:9050`, `tx-proxy=tor,127.0.0.1:9050,disable_noise`, and a real `anonymous-inbound=...`
- `signer config hardening`
  `nxms-signer security check --config /etc/nxms/signer.toml`
- `Tor smoke`
  repeat canonical smoke over the real mailbox onion
- `Tor sign`
  repeat real sign flow over the real mailbox onion
- `Tor submit`
  repeat real submit flow over the real mailbox onion
- `Tor orchestrated flow`
  repeat orchestrated submit-token flow over the real mailbox onion
- `restart / recovery`
  restart `tor`, `nxms-mailbox`, `nxms-signer` separately and verify recovery without config drift

## Real Gate For This Stage
Run at minimum on the target Alpine/OpenRC host:

```bash
cargo check --workspace
cargo build --release -p nxms-mailbox -p nxms-signer -p nxms-escrow-orchestrator
rc-service tor restart
rc-service nxms-mailbox restart
rc-service monerod-stagenet restart
rc-service monero-wallet-rpc-stagenet restart
rc-service tor status
rc-service monerod-stagenet status
rc-service monero-wallet-rpc-stagenet status
rc-service nxms-signer restart
rc-service nxms-mailbox status
rc-service nxms-signer status
cat /var/lib/tor/nxms-mailbox/hostname
cat /var/lib/tor/monerod-stagenet/hostname
curl -fsS http://127.0.0.1:4010/health
curl -fsS http://127.0.0.1:38081/get_info
curl --digest -u walletrpc:<password> -fsS -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' http://127.0.0.1:38088/json_rpc
curl --socks5-hostname 127.0.0.1:<second-socks-port> -fsS http://<mailbox-onion>/health
nxms-signer security check --config /etc/nxms/signer.toml
```

After that, rerun the canonical smoke/sign/submit/orchestrated scenarios through the real onion path.

## Immediate Next Gate
Before touching `nxms-signer`, pass this mailbox-only gate on the real Alpine/OpenRC host:

```bash
rc-service tor restart
rc-service nxms-mailbox restart
rc-service tor status
rc-service nxms-mailbox status
cat /var/lib/tor/nxms-mailbox/hostname
curl -fsS http://127.0.0.1:4010/health
curl --socks5-hostname 127.0.0.1:<second-socks-port> -fsS "http://$(cat /var/lib/tor/nxms-mailbox/hostname)/health"
```

Example second Tor client on the same Alpine VM:

```bash
mkdir -p /home/operator/tor-client-test
cat > /home/operator/tor-client-test/torrc <<'EOF'
SocksPort 127.0.0.1:19050
DataDirectory /home/operator/tor-client-test/data
PidFile /home/operator/tor-client-test/tor.pid
Log notice file /home/operator/tor-client-test/tor.log
EOF
tor -f /home/operator/tor-client-test/torrc --RunAsDaemon 1
curl --socks5-hostname 127.0.0.1:19050 -fsS "http://$(cat /var/lib/tor/nxms-mailbox/hostname)/health"
```
