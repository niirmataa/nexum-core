# NXMS Sandbox Network Isolation (P0.3)

Last update: 2026-02-18

Goal: ensure `wallet-rpc` is reachable only from its local sandbox worker and never from orchestrator or external hosts.

## Mandatory Rules
1. `wallet-rpc` listens only on loopback (`127.0.0.1` or `::1`) or UNIX socket.
2. Orchestrator has no route to sandbox `wallet-rpc` ports.
3. Secrets for wallet/rpc are mounted from runtime secret store (env/file mount), not hardcoded in repo.

## Runtime Verification
Use:
`scripts/verify_nxms_network_isolation.sh`

Examples:
`WALLET_RPC_PORT=18088 scripts/verify_nxms_network_isolation.sh`
`WALLET_RPC_PORT=18088 STRICT_NO_CONNECTIONS=1 scripts/verify_nxms_network_isolation.sh`

The script fails if:
- wallet-rpc listener is non-loopback
- an active non-loopback TCP connection targets wallet-rpc port

## Container/Kubernetes Baseline
- Run signer + wallet-rpc in same pod/namespace.
- Expose only signer API/mailbox egress, never wallet-rpc service.
- Deny all ingress to wallet-rpc container except pod-local loopback/socket.

Minimal policy intent:
- `default deny ingress`
- allow ingress only to signer API port from orchestrator/auth
- do not define any service for wallet-rpc

## Host Firewall Baseline (VM/Bare Metal)
- Block inbound to wallet-rpc port from non-loopback:
`iptables -A INPUT -p tcp --dport 18088 ! -s 127.0.0.1 -j DROP`
- Deny forwarding from orchestrator net to wallet-rpc net.

## Audit Evidence
Capture and store:
1. Output of `scripts/verify_nxms_network_isolation.sh`.
2. Listener snapshot (`ss -lntp | grep wallet-rpc`).
3. Firewall/policy snapshot (iptables/nftables or NetworkPolicy YAML).
