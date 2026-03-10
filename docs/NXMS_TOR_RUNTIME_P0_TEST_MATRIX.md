# NXMS Tor Runtime P0 Test Matrix

Last update: 2026-03-10
Scope: real deploy/runtime validation of the canonical cross-host path over Tor hidden service.

## Rule
- This matrix is separate from workspace E2E.
- Workspace tests prove component truth.
- This matrix proves deploy truth: OpenRC units, Tor hidden service, onion reachability and runtime startup assumptions.
- A stage is not deploy-real until these checks pass on the actual Alpine/OpenRC host.

## P0 Coverage
- `Stage 1: mailbox over Tor`
  Bring up only `tor` + `nxms-mailbox` and prove loopback health, hidden service publication and onion reachability.
- `Stage 2: signer startup over Tor`
  Add `nxms-signer`, prove config hardening and daemon startup against the real mailbox onion.
- `Stage 3: canonical runtime flows over Tor`
  Repeat smoke/sign/submit/orchestrated scenarios through the real onion path.

- `mailbox daemon`
  `rc-service nxms-mailbox start`
  `rc-service nxms-mailbox status`
- `signer daemon`
  `rc-service nxms-signer start`
  `rc-service nxms-signer status`
- `mailbox loopback health`
  `curl -fsS http://127.0.0.1:4010/health`
- `hidden service publication`
  `cat /var/lib/tor/nxms-mailbox/hostname`
- `mailbox onion ingress`
  `curl --socks5-hostname 127.0.0.1:9050 -fsS http://<mailbox-onion>/health`
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
rc-service tor restart
rc-service nxms-mailbox restart
rc-service tor status
rc-service nxms-signer restart
rc-service nxms-mailbox status
rc-service nxms-signer status
cat /var/lib/tor/nxms-mailbox/hostname
curl -fsS http://127.0.0.1:4010/health
curl --socks5-hostname 127.0.0.1:9050 -fsS http://<mailbox-onion>/health
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
curl --socks5-hostname 127.0.0.1:9050 -fsS "http://$(cat /var/lib/tor/nxms-mailbox/hostname)/health"
```
