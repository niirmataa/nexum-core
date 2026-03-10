# nxms-mailbox

Store-and-forward mailbox for `NxmsEnvelope` messages.

Designed to be exposed as a Tor onion service (HTTP), while keeping payloads end-to-end encrypted/authenticated by NXMS.

Runtime model:
- Cross-host path is `Tor hidden service` only.
- `nxms-transport` remains the only end-to-end security layer.
- Local HTTP is only a loopback process adapter boundary.

## Run

Local development example:

```sh
cd /home/nxms-server/nexum-core/crates/nxms-mailbox
cargo run --release -- serve \
  --bind 127.0.0.1:4010 \
  --db-path /tmp/nxms-mailbox.db
```

Legacy/manual env example:

```sh
NXMS_MAILBOX_PUSH_TOKEN='push-secret' \
NXMS_MAILBOX_PULL_TOKENS='buyer=pull-buyer,seller=pull-seller,arbiter=pull-arbiter' \
NXMS_MAILBOX_ACK_TOKENS='buyer=ack-buyer,seller=ack-seller,arbiter=ack-arbiter' \
NXMS_MAILBOX_ADMIN_TOKEN='admin-secret' \
  cargo run --release -- serve --bind 127.0.0.1:4010 --db-path /tmp/nxms-mailbox.db
```

`pull` and `ack` are fail-closed per inbox scope. A token for `seller` must not be accepted for `buyer`, and `ack` deletes only a leased receipt that belongs to the authorized inbox.

Production/OpenRC baseline:
- use [docs/NXMS_MAILBOX_CONFIG.example.toml](/home/nxms-server/nexum-core/docs/NXMS_MAILBOX_CONFIG.example.toml)
- use [deploy/openrc/nxms-mailbox](/home/nxms-server/nexum-core/deploy/openrc/nxms-mailbox)
- use `vault:` refs instead of bearer values in env/argv
- keep `/etc/nxms/mailbox.toml` as `root:nxms 0640`
- keep mailbox secret files as `nxms:nxms 0600`

## Tor onion service (example)

Example `torrc` snippet:

```
HiddenServiceDir /var/lib/tor/nxms-mailbox
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:4010
```

Smoke:

```sh
curl -fsS http://127.0.0.1:4010/health
```

For deploy-real onion ingress proof, use a second Tor client or a second host.
Example second local Tor client:

```sh
mkdir -p /tmp/tor-client-mailbox
cat > /tmp/tor-client-mailbox/torrc <<'EOF'
SocksPort 127.0.0.1:19050
DataDirectory /tmp/tor-client-mailbox/data
PidFile /tmp/tor-client-mailbox/tor.pid
Log notice file /tmp/tor-client-mailbox/tor.log
EOF
tor -f /tmp/tor-client-mailbox/torrc --RunAsDaemon 1
curl --socks5-hostname 127.0.0.1:19050 -fsS "http://$(cat /var/lib/tor/nxms-mailbox/hostname)/health"
```

## API

- `GET /health`
- `POST /v1/push` body: `{ "envelope": <NxmsEnvelope>, "ttl_secs": 86400 }`
- `POST /v1/pull` body: `{ "to": "buyer", "max": 10, "wait_ms": 20000 }`
- `POST /v1/ack`  body: `{ "receipt": "<receipt>" }`

Delivery semantics:

- `pull` leases messages for `NXMS_MAILBOX_LEASE_SECS` and returns a `receipt`.
- `ack` deletes the message for that receipt only within the inbox scope bound to the presented ack token.
- If the client dies after `pull` but before `ack`, the message becomes visible again after the lease expires.

## Replay / Idempotency

`NxmsEnvelope` includes `seq` (monotonic per `(escrow_id, from)`), and the NXMS crypto layer binds it into the signature/tag.
Receivers should persist and reject already-processed `(escrow_id, from, seq)` to get anti-replay behavior.
