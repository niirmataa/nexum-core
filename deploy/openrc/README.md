# NXMS OpenRC Baseline

Repo-managed OpenRC runtime baseline for Alpine:

- `nxms-mailbox`
  Canonical mailbox daemon.
  Runs `nxms-mailbox serve --config /etc/nxms/mailbox.toml` on loopback only.
  Mailbox secrets live in mailbox TOML as `vault:` / `file:` / `env:` refs, not in OpenRC env or argv.

- `nxms-signer`
  Canonical signer daemon.
  Runs `nxms-signer run --config /etc/nxms/signer.toml`.
  Signer secrets stay in TOML secret refs (`vault:` / `file:`) and optional orchestrator bridge uses `NXMS_SIGNER_ORCH_BRIDGE_TOKEN_REF`.

Not managed as an OpenRC daemon here:

- `nxms-escrow-orchestrator`
  Current binary is control-plane/manual tooling, not a long-running service.
  This repo intentionally does not ship an OpenRC unit that would pretend otherwise.

Related Tor ingress example:

- `deploy/tor/nxms-mailbox-hidden-service.conf.example`
