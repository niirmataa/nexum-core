# Security Proof (1-3)

Cold technical summary. No marketing.

## 1) Transparent Code and Process
- Source of truth is the repo. No out-of-band binaries.
- Every release points to a specific commit hash and tag.
- Changes are reviewable as diffs. No hidden patches.
- CLI does not auto-download or self-modify.

## 2) Reproducible Builds (Requirement)
- Build inputs are pinned: compiler, flags, libsodium, libcurl, liboqs.
- Release publishes the exact build command and environment.
- Release publishes sha256 of `nexum`.
- Verification rule: a user build must match the release checksum.
- Failure condition: mismatch = no release.

## 3) Signed Releases (Requirement)
- All distributed binaries are signed (minisign/GPG/sigstore).
- Public key is published in the repo and in the release notes.
- Verification command is documented and short.
- Failure condition: unsigned artifact = no release.

## 4) Access Policy (Onion-only, gated)
- Single onion entry (no clearnet by default).
- Access is gated by: proof-of-work + token + rate-limit.
- Captcha is optional and deferred until the end of the project.
- Rationale: stable UX with hard gatekeeping and low operational complexity.
