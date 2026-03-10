---
name: security-review
description: Review NXMS code for replay integrity, token enforcement, break-glass paths, bind policies, mailbox trust boundaries, and legacy flow leaks.
---

# security-review

Use this skill when:
- reviewing signer/orchestrator/mailbox boundaries
- checking replay protection and request integrity
- auditing shadow mode and break-glass behavior

## Focus areas
- replay protection
- req_id / jti integrity
- action token enforcement
- shadow mode
- break-glass paths
- local bind vs remote bind
- mailbox authorization boundaries
- legacy HTTP paths
- signer/orchestrator consistency

## NXMS assumptions
- Tor-only communication
- nxms-transport as the only wire format
- nxms-mailbox as relay only
- nxms-signer as execution node
- nxms-escrow-orchestrator as workflow control-plane
- nexum-cli is manual tooling only

## Output format
1. findings by severity
2. exact files involved
3. why each issue matters
4. whether it is CORE / OPS / MANUAL / LEGACY
5. minimal fix plan