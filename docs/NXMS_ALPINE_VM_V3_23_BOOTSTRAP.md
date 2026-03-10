# NXMS Alpine VM v3.23 Bootstrap

Last update: 2026-03-10
Scope: full VM bootstrap for a real Alpine Linux 3.23 guest used for NXMS OpenRC + Tor runtime validation.

Related:
- [docs/NXMS_MONERO_STAGENET_TOR_BASELINE.md](/home/nxms-server/nexum-core/docs/NXMS_MONERO_STAGENET_TOR_BASELINE.md)

## Rule
- This document is for a real VM, not WSL2.
- The VM must boot Alpine normally with OpenRC as init.
- Stage order matters:
  first the NXMS crypto/build baseline (`liboqs` + vendored Falcon CT path + release build),
  then Monero runtime,
  then signer runtime.
- This is the minimum baseline to avoid the surprises already observed on WSL2:
  - `rc-service` without real OpenRC boot
  - Tor service missing
  - musl/static link failures for `liboqs` and `libsodium`

## 1. VM Shape

Use a real VM, for example VMware, VirtualBox or QEMU/KVM.

Recommended minimum:
- 2 vCPU
- 4 GB RAM
- 40 GB disk
- NAT networking is enough for bootstrap
- one clean Alpine 3.23 install per test path

Do not use WSL2 as the final deploy/runtime proof host.

## 2. Alpine Install

Boot Alpine 3.23 ISO and run:

```bash
setup-alpine
```

Recommended choices:
- keyboard/layout as needed
- hostname: `nxms-a3`
- network: default DHCP is fine
- mirror: official
- user: create your operator user
- ssh server: optional, but useful
- disk mode: `sys`
- filesystem: `ext4`

After reboot, verify OpenRC is real:

```bash
rc-status
rc-service --help >/dev/null
```

If `rc-service` says OpenRC did not boot, stop. That host is not valid for final runtime proof.

## 3. Base Packages

Install the baseline packages first:

```bash
doas apk update
doas apk add --no-cache \
  bash \
  ca-certificates \
  curl \
  doas \
  git \
  gnupg \
  openssl \
  openssl-dev \
  build-base \
  cmake \
  ninja \
  pkgconf \
  linux-headers \
  sqlite-dev \
  libsodium \
  libsodium-dev \
  tor \
  cargo \
  rust \
  rustfmt
```

Notes:
- `libsodium-dev` on Alpine 3.23 does not provide `libsodium.a`. We handle that explicitly below.
- `tor` must exist both as binary and OpenRC service.

Verify:

```bash
command -v tor
command -v cargo
command -v rustfmt
rc-service tor status || true
```

## 3.1 Verified Monero CLI

Monero download can start early because sync takes time, but do not treat it as a substitute for the NXMS crypto/build baseline in section 5.

Download and verify official Monero CLI before wiring OpenRC services:

```bash
mkdir -p ~/downloads/monero
cd ~/downloads/monero
curl -L -o monero-linux-x64.tar.bz2 https://downloads.getmonero.org/cli/linux64
curl -LO https://www.getmonero.org/downloads/hashes.txt
curl -LO https://raw.githubusercontent.com/monero-project/monero/master/utils/gpg_keys/binaryfate.asc
gpg --import binaryfate.asc
gpg --verify hashes.txt
sha256sum monero-linux-x64.tar.bz2
grep "$(sha256sum monero-linux-x64.tar.bz2 | cut -d' ' -f1)" hashes.txt
tar xjf monero-linux-x64.tar.bz2
```

Install verified binaries:

```bash
cd ~/downloads/monero
MONERO_DIR="$(find . -maxdepth 1 -type d -name 'monero-*' | head -n1)"
doas mkdir -p /opt/monero/0.18.4.5
doas install -m 0755 "${MONERO_DIR}/monerod" /opt/monero/0.18.4.5/monerod
doas install -m 0755 "${MONERO_DIR}/monero-wallet-rpc" /opt/monero/0.18.4.5/monero-wallet-rpc
doas ln -sfn /opt/monero/0.18.4.5 /opt/monero/current
```

## 4. Repo Checkout

```bash
mkdir -p ~/src
cd ~/src
git clone <YOUR-REPO-REMOTE> nexum-core
cd nexum-core
```

## 5. Static Crypto Prerequisites

NXMS release build on Alpine/musl needs:
- `liboqs.so` and `liboqs.a`
- `libsodium.so` and `libsodium.a`

### 5.1 liboqs 0.15.0

```bash
mkdir -p /tmp/liboqs-build
cd /tmp/liboqs-build
curl -L -o liboqs-0.15.0.tar.gz https://github.com/open-quantum-safe/liboqs/archive/refs/tags/0.15.0.tar.gz
echo "3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c  liboqs-0.15.0.tar.gz" | sha256sum -c -
tar -xzf liboqs-0.15.0.tar.gz
cd liboqs-0.15.0
cmake -S . -B build-shared -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build-shared
doas cmake --install build-shared
cmake -S . -B build-static -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build-static
doas cmake --install build-static
```

Verify:

```bash
ls /usr/local/lib/liboqs.so
ls /usr/local/lib/liboqs.a
```

### 5.2 libsodium static

Alpine package gives shared library, but final musl static link also needs `libsodium.a`.

```bash
mkdir -p /tmp/libsodium-build
cd /tmp/libsodium-build
curl -L -o libsodium-1.0.20.tar.gz https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz
tar -xzf libsodium-1.0.20.tar.gz
cd libsodium-1.0.20
./configure --prefix=/usr/local --disable-shared --enable-static
make -j"$(nproc)"
doas make install
```

Verify:

```bash
ls /usr/lib/libsodium.so
ls /usr/local/lib/libsodium.a
```

### 5.3 Build Environment

Before release builds, export:

```bash
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/lib/pkgconfig
export LIBRARY_PATH=/usr/local/lib:/usr/lib
```

Persist if you want:

```bash
echo 'export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/lib/pkgconfig' >> ~/.profile
echo 'export LIBRARY_PATH=/usr/local/lib:/usr/lib' >> ~/.profile
```

## 6. Build NXMS Release Binaries

Inside repo:

```bash
cargo fmt --all
cargo check --workspace
cargo build --release -p nxms-mailbox -p nxms-signer -p nxms-escrow-orchestrator
```

Verify:

```bash
ls -l target/release/nxms-mailbox
ls -l target/release/nxms-signer
ls -l target/release/nxms-escrow-orchestrator
```

## 7. Host Runtime Layout

Create the runtime layout:

```bash
doas addgroup -S nxms || true
doas adduser -S -D -H -h /var/lib/nxms -s /sbin/nologin -G nxms nxms || true
doas addgroup -S monero || true
doas adduser -S -D -H -h /var/lib/monero -s /sbin/nologin -G monero monero || true

doas mkdir -p /opt/nxms/bin
doas mkdir -p /opt/monero
doas mkdir -p /etc/nxms
doas mkdir -p /etc/monero
doas mkdir -p /var/lib/nxms/mailbox
doas mkdir -p /var/lib/nxms/signer
doas mkdir -p /var/lib/nxms/orchestrator
doas mkdir -p /var/lib/monero/stagenet
doas mkdir -p /var/lib/monero/wallets
doas mkdir -p /var/log/nxms
doas mkdir -p /var/log/monero
doas mkdir -p /run/secrets/nxms

doas chown -R nxms:nxms /var/lib/nxms
doas chown -R nxms:nxms /var/log/nxms
doas chown -R monero:monero /var/lib/monero
doas chown -R monero:monero /var/log/monero
doas chmod 0750 /var/lib/nxms /var/lib/nxms/mailbox /var/lib/nxms/signer /var/lib/nxms/orchestrator
doas chmod 0750 /var/log/nxms
doas chmod 0750 /var/lib/monero /var/lib/monero/stagenet /var/lib/monero/wallets
doas chmod 0750 /var/log/monero
doas chown root:nxms /run/secrets/nxms
doas chmod 0750 /run/secrets/nxms
```

Install binaries:

```bash
doas install -m 0755 target/release/nxms-mailbox /opt/nxms/bin/nxms-mailbox
doas install -m 0755 target/release/nxms-signer /opt/nxms/bin/nxms-signer
doas install -m 0755 target/release/nxms-escrow-orchestrator /opt/nxms/bin/nxms-escrow-orchestrator
```

## 8. Install OpenRC Units

```bash
doas install -m 0755 deploy/openrc/nxms-mailbox /etc/init.d/nxms-mailbox
doas install -m 0644 deploy/openrc/nxms-mailbox.confd /etc/conf.d/nxms-mailbox
doas install -m 0755 deploy/openrc/nxms-signer /etc/init.d/nxms-signer
doas install -m 0644 deploy/openrc/nxms-signer.confd /etc/conf.d/nxms-signer
```

There is intentionally no OpenRC daemon for orchestrator in current repo baseline.

## 9. Mailbox Config

Install the repo baseline:

```bash
doas install -m 0640 docs/NXMS_MAILBOX_CONFIG.example.toml /etc/nxms/mailbox.toml
doas chown root:nxms /etc/nxms/mailbox.toml
```

Create real mailbox secrets:

```bash
doas sh -c 'umask 077 && openssl rand -hex 32 > /run/secrets/nxms/mailbox_push_token && chown nxms:nxms /run/secrets/nxms/mailbox_push_token'
doas sh -c 'umask 077 && openssl rand -hex 32 > /run/secrets/nxms/mailbox_admin_token && chown nxms:nxms /run/secrets/nxms/mailbox_admin_token'
doas sh -c 'umask 077 && openssl rand -hex 32 > /run/secrets/nxms/mailbox_pull_token_buyer && chown nxms:nxms /run/secrets/nxms/mailbox_pull_token_buyer'
doas sh -c 'umask 077 && openssl rand -hex 32 > /run/secrets/nxms/mailbox_pull_token_seller && chown nxms:nxms /run/secrets/nxms/mailbox_pull_token_seller'
doas sh -c 'umask 077 && openssl rand -hex 32 > /run/secrets/nxms/mailbox_pull_token_arbiter && chown nxms:nxms /run/secrets/nxms/mailbox_pull_token_arbiter'
doas sh -c 'umask 077 && openssl rand -hex 32 > /run/secrets/nxms/mailbox_ack_token_buyer && chown nxms:nxms /run/secrets/nxms/mailbox_ack_token_buyer'
doas sh -c 'umask 077 && openssl rand -hex 32 > /run/secrets/nxms/mailbox_ack_token_seller && chown nxms:nxms /run/secrets/nxms/mailbox_ack_token_seller'
doas sh -c 'umask 077 && openssl rand -hex 32 > /run/secrets/nxms/mailbox_ack_token_arbiter && chown nxms:nxms /run/secrets/nxms/mailbox_ack_token_arbiter'
```

Verify:

```bash
doas ls -l /run/secrets/nxms
```

Expected ownership/modes:
- `/etc/nxms/mailbox.toml` -> `root:nxms 0640`
- `/run/secrets/nxms` -> `root:nxms 0750`
- `/run/secrets/nxms/mailbox_*` -> `nxms:nxms 0600`

## 10. Tor Hidden Service

Install fragment:

```bash
doas mkdir -p /etc/tor/torrc.d
doas install -m 0644 deploy/tor/nxms-mailbox-hidden-service.conf.example /etc/tor/torrc.d/nxms-mailbox.conf
```

If `/etc/tor/torrc` does not include `torrc.d`, add it explicitly:

```bash
doas sh -c 'printf "\n%storrc.d/*.conf\n" "%include /etc/tor/" >> /etc/tor/torrc'
```

Enable services:

```bash
doas rc-update add tor default
doas rc-update add nxms-mailbox default
```

Start Tor first:

```bash
doas rc-service tor restart
doas rc-service tor status
```

After Tor starts, verify hidden service hostname exists:

```bash
doas ls -l /var/lib/tor/nxms-mailbox
doas cat /var/lib/tor/nxms-mailbox/hostname
```

## 11. Start Mailbox

```bash
doas rc-service nxms-mailbox start
doas rc-service nxms-mailbox status
curl -fsS http://127.0.0.1:4010/health
```

Do not use the same Tor service instance as the only onion ingress proof for its own hidden service.
Use a second Tor client or a second host.

Example second Tor client on the same Alpine VM:

```bash
mkdir -p /home/operator/tor-client-test
cat > /home/operator/tor-client-test/torrc <<'EOF'
SocksPort 127.0.0.1:19050
DataDirectory /home/operator/tor-client-test/data
PidFile /home/operator/tor-client-test/tor.pid
Log notice file /home/operator/tor-client-test/tor.log
EOF
tor -f /home/operator/tor-client-test/torrc --RunAsDaemon 1
tail -n 80 /home/operator/tor-client-test/tor.log
curl --socks5-hostname 127.0.0.1:19050 -fsS "http://$(doas cat /var/lib/tor/nxms-mailbox/hostname)/health"
```

If these fail, stop and fix mailbox/Tor before touching signer.

## 12. Signer Config

Install the example:

```bash
doas install -m 0640 docs/NXMS_SIGNER_CONFIG.example.toml /etc/nxms/signer.toml
doas chown root:nxms /etc/nxms/signer.toml
```

Then edit `/etc/nxms/signer.toml` and set real values:
- `mailbox_url = "http://<mailbox-onion>"`
- valid `peers_path`
- valid `keys_path`
- valid `db_path`
- valid local wallet-rpc endpoint
- valid wallet credentials
- valid action-token public key path

Create signer secrets referenced by TOML:

```bash
doas sh -c 'umask 077 && openssl rand -hex 32 > /run/secrets/nxms/worker_service_token && chown nxms:nxms /run/secrets/nxms/worker_service_token'
doas sh -c 'umask 077 && cp /run/secrets/nxms/mailbox_push_token /run/secrets/nxms/mailbox_push_token_signer && chown nxms:nxms /run/secrets/nxms/mailbox_push_token_signer'
doas sh -c 'umask 077 && cp /run/secrets/nxms/mailbox_pull_token_arbiter /run/secrets/nxms/mailbox_pull_token && chown nxms:nxms /run/secrets/nxms/mailbox_pull_token'
doas sh -c 'umask 077 && cp /run/secrets/nxms/mailbox_ack_token_arbiter /run/secrets/nxms/mailbox_ack_token && chown nxms:nxms /run/secrets/nxms/mailbox_ack_token'
```

Expected ownership/modes:
- `/etc/nxms/signer.toml` -> `root:nxms 0640`
- signer `vault:` files under `/run/secrets/nxms` -> `nxms:nxms 0600`

Important:
- signer will not fully validate `sign/submit` paths without real `peers.json`, `keys.json`, action-token pubkey and local `monero-wallet-rpc`
- this is expected

Enable signer:

```bash
doas rc-update add nxms-signer default
```

## 13. Start Signer

```bash
doas rc-service nxms-signer start
doas rc-service nxms-signer status
/opt/nxms/bin/nxms-signer security check --config /etc/nxms/signer.toml
```

## 14. No-Surprises Reality Check

This VM bootstrap gives you a valid Alpine/OpenRC/Tor baseline for NXMS.

It does **not** magically provide:
- Monero chain daemon
- local `monero-wallet-rpc`
- real signer keys/peerbook
- real action-token issuer keys

Therefore:
- mailbox + Tor onion health can be proven immediately
- signer startup hardening can be proven immediately
- full `sign / submit / orchestrated flow` over Tor requires the Monero/runtime material above

## 15. Final Runtime Gate

Use:
- [docs/NXMS_OPENRC_TOR_RUNTIME_BASELINE.md](/home/nxms-server/nexum-core/docs/NXMS_OPENRC_TOR_RUNTIME_BASELINE.md)
- [docs/NXMS_TOR_RUNTIME_P0_TEST_MATRIX.md](/home/nxms-server/nexum-core/docs/NXMS_TOR_RUNTIME_P0_TEST_MATRIX.md)
- [docs/NXMS_MONERO_STAGENET_TOR_BASELINE.md](/home/nxms-server/nexum-core/docs/NXMS_MONERO_STAGENET_TOR_BASELINE.md)

Run at minimum:

```bash
doas rc-service tor restart
doas rc-service nxms-mailbox restart
doas rc-service nxms-signer restart
doas rc-service nxms-mailbox status
doas rc-service nxms-signer status
curl -fsS http://127.0.0.1:4010/health
curl --socks5-hostname 127.0.0.1:19050 -fsS "http://$(doas cat /var/lib/tor/nxms-mailbox/hostname)/health"
/opt/nxms/bin/nxms-signer security check --config /etc/nxms/signer.toml
```

Only after that move to real Tor smoke/sign/submit/orchestrated scenarios.
