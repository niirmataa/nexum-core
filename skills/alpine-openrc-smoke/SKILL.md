---
name: alpine-openrc-smoke
description: Review and prepare NXMS crates for Alpine Linux + OpenRC build and local smoke testing.
---

# alpine-openrc-smoke

Use this skill when:
- preparing Alpine Linux builds
- checking musl/native crypto compatibility
- setting up OpenRC service boundaries
- preparing local smoke tests before VM deployment

## Environment assumptions
- Alpine Linux
- OpenRC, not systemd
- Tor-only runtime
- local loopback APIs where possible
- services expected:
  - nxms-mailbox
  - nxms-signer
  - nxms-escrow-orchestrator

## Tasks
- inspect Rust crate dependencies and native code assumptions
- identify likely Alpine/musl build issues
- identify runtime assumptions that conflict with OpenRC
- propose service boundaries and smoke tests
- prefer minimal, staging-ready runtime

## Output format
1. build risks
2. runtime risks
3. package/dependency notes
4. OpenRC notes
5. smoke test plan