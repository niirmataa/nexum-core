# NXMS Runtime Hardening and Key Rotation Runbook

Last update: 2026-02-20
Scope: systemd hardening evidence, signer key ACL policy, periodic key/credential rotation, and Tor/firewall operational checks.

## 1. Hardened Service Unit Baseline
Reference examples:
- `escrow/deploy/systemd/nxms-signer.service`
- `escrow/deploy/systemd/nxms-mailbox.service`

Required controls:
- `MemoryMax`
- `TasksMax`
- `NoNewPrivileges=true`
- `CapabilityBoundingSet=`

Additional baseline controls in examples:
- `AmbientCapabilities=`
- `PrivateTmp=true`
- `PrivateDevices=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `ProtectKernelTunables=true`
- `ProtectKernelModules=true`
- `ProtectControlGroups=true`
- `LockPersonality=true`
- `RestrictRealtime=true`
- `RestrictSUIDSGID=true`
- `SystemCallArchitectures=native`
- `UMask=0077`

Verification commands:
```bash
systemctl show nxms-signer \
  -p MemoryMax -p TasksMax -p NoNewPrivileges -p CapabilityBoundingSet
systemctl show nxms-mailbox \
  -p MemoryMax -p TasksMax -p NoNewPrivileges -p CapabilityBoundingSet
systemctl cat nxms-signer
systemctl cat nxms-mailbox
```

## 2. Signer Key ACL Policy
Minimum file ownership and mode policy:
- Private keys (`*.pem`, `*.key`, JWT signing keys): `root:nxms-signer`, mode `0640` (or stricter).
- Public keys: `root:nxms-signer`, mode `0644`.
- Key directories: mode `0750` or stricter.
- Never allow group/world write on key material.

Example audit command:
```bash
find /etc/nxms -maxdepth 3 -type f \( -name '*.pem' -o -name '*.key' \) \
  -exec stat -c '%n %U:%G %a' {} \;
```

## 3. Periodic Rotation Policy
Rotation cadence (maximum interval):
- Action-token signing key pair (auth/orchestrator): every 90 days.
- Mailbox API token and mailbox admin token: every 30 days.
- Orchestrator bridge token (`NXMS_SIGNER_ORCH_BRIDGE_TOKEN_REF` source secret): every 30 days.
- Wallet-rpc RPC/password credentials per sandbox: every 90 days.
- Immediate rotation required after incident, credential leak suspicion, or operator offboarding.

Execution sequence:
1. Generate new secret/key material in secret store (do not put secrets in git/argv).
2. Update signer/auth/orchestrator references (`vault:` refs only in production hardening).
3. Restart affected service in controlled order: auth/orchestrator -> signer -> mailbox.
4. Validate runtime with health checks and one signed dry-run request.
5. Revoke old credentials/keys after successful cutover.
6. Archive evidence bundle (Section 6).

## 4. Tor Client-Auth Operational Checks
Required:
- Hidden service has client authorization enabled.
- Auth files are present and not world-readable.

Example checks:
```bash
grep -n 'HiddenServiceAuthorizeClient' /etc/tor/torrc
ls -l /var/lib/tor/nxms-mailbox/
ls -l /var/lib/tor/nxms-mailbox/authorized_clients/
```

## 5. Firewall Operational Checks
Required:
- Wallet-rpc ports are loopback-only and blocked from non-loopback ingress.
- Orchestrator host cannot directly route to wallet-rpc ports.

Example checks:
```bash
ss -lntp | grep -E ':(18088|28088|38088|38083|38084) '
iptables -S | grep -E '18088|28088|38088|38083|38084'
nft list ruleset | grep -E '18088|28088|38088|38083|38084'
```

Network isolation helper:
```bash
WALLET_RPC_PORT=18088 scripts/verify_nxms_network_isolation.sh
```

## 6. Evidence Pack Contract
Archive each rotation/audit run in:
- `commit/final_gate/runtime_hardening/<UTC_TS>/`

Minimum artifacts:
- `systemd_show_nxms_signer.txt`
- `systemd_show_nxms_mailbox.txt`
- `signer_key_acl_snapshot.txt`
- `tor_client_auth_checks.txt`
- `firewall_snapshot.txt`
- `rotation_summary.md`

`rotation_summary.md` should include:
- reason for rotation (`periodic` or incident id),
- services restarted,
- verification result,
- revocation timestamp of old credentials.
