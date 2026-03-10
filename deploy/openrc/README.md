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

Not managed as an OpenRC daemon here:

- `nxms-escrow-orchestrator`
  Current binary is control-plane/manual tooling, not a long-running service.
  This repo intentionally does not ship an OpenRC unit that would pretend otherwise.

Related Tor ingress example:

- `deploy/tor/nxms-mailbox-hidden-service.conf.example`
