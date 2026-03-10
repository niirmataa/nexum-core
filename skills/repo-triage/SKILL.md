---
name: repo-triage
description: Classify repo modules into CORE, OPS, MANUAL, LEGACY and propose exact file moves for the new NXMS architecture.
---

# repo-triage

Use this skill when:
- the repository contains multiple historical flows
- you need to identify the canonical runtime path
- you need a file-by-file migration plan

## Goals
- classify modules and files as CORE / OPS / MANUAL / LEGACY
- identify architecture conflicts
- propose exact moves into:
  - crates/
  - tools/
  - docs/
  - deploy/
  - legacy-archive/

## NXMS architecture rules
- nxms-transport is the only wire format
- nxms-mailbox is the only relay/store-and-forward
- nxms-signer is execution/signing node
- nxms-escrow-orchestrator is workflow control-plane
- nxms-monero-core is domain logic only
- nexum-cli is manual tooling only
- legacy HTTP-first paths do not belong in runtime core

## Output format
1. summary
2. classification table
3. exact move plan
4. top risks