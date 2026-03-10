# nxms-mailbox

Store-and-forward mailbox for `NxmsEnvelope` messages.

Designed to be exposed as a Tor onion service (HTTP), while keeping payloads end-to-end encrypted/authenticated by NXMS.

## Run

```sh
cd /opt/freeforum/nexum/escrow/nxms-mailbox
cargo run --release -- serve \
  --bind 127.0.0.1:4010 \
  --db-path /var/lib/nxms-mailbox/mailbox.db
```

Optional auth (bearer token):

```sh
NXMS_MAILBOX_TOKEN='supersecret' \
  cargo run --release -- serve --bind 127.0.0.1:4010 --db-path /var/lib/nxms-mailbox/mailbox.db
```

## Tor onion service (example)

Example `torrc` snippet:

```
HiddenServiceDir /var/lib/tor/nxms_mailbox/
HiddenServicePort 4010 127.0.0.1:4010
```

## API

- `GET /health`
- `POST /v1/push` body: `{ "envelope": <NxmsEnvelope>, "ttl_secs": 86400 }`
- `POST /v1/pull` body: `{ "to": "buyer", "max": 10, "wait_ms": 20000 }`
- `POST /v1/ack`  body: `{ "receipt": "<receipt>" }`

Delivery semantics:

- `pull` leases messages for `NXMS_MAILBOX_LEASE_SECS` and returns a `receipt`.
- `ack` deletes the message for that receipt.
- If the client dies after `pull` but before `ack`, the message becomes visible again after the lease expires.

## Replay / Idempotency

`NxmsEnvelope` includes `seq` (monotonic per `(escrow_id, from)`), and the NXMS crypto layer binds it into the signature/tag.
Receivers should persist and reject already-processed `(escrow_id, from, seq)` to get anti-replay behavior.
