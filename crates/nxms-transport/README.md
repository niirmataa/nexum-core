# nxms-transport

Library crate containing the NXMS transport primitives:

- `wire`: envelope/payload types (`NxmsEnvelope`, `NxmsPayload`) + validations
- `crypto`: FFI wrapper for NXMS packet encryption/decryption (FrodoKEM-640-SHAKE + Falcon-1024-CT)
- `peers`: allowlist types (`Peer`, `PeerBook`)
- `tor_net`: optional framed TCP helpers (direct P2P over SOCKS5h)

## Notes

- The native crypto build links against `liboqs` (`-loqs`).
- The mailbox relay does **not** need `crypto`; it can store/forward `NxmsEnvelope` without decryption.
- `seq` is part of the cryptographic binding (anti-replay/idempotency). Keep it monotonic per `(escrow_id, from)`.

## Features

- Default features include `crypto`.
- To depend on `wire` only (no native build, no `liboqs`/`libsodium`): use `default-features = false`.
