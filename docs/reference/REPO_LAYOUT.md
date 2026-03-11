# Repo Layout

To repo jest podzielone na trzy strefy:

- `crates/` — runtime core
- `tools/` — narzędzia ręczne
- `docs/` i `deploy/` — wiedza operacyjna i deployment

---

## Drzewo główne

```text
nxms-core/
├── crates/
│   ├── nxms-transport/
│   ├── nxms-mailbox/
│   ├── nxms-mailbox-client/
│   ├── nxms-monero-core/
│   ├── nxms-escrow-orchestrator/
│   └── nxms-signer/
├── tools/
│   └── nexum-cli/
├── docs/
├── deploy/
├── tests/
└── legacy-archive/