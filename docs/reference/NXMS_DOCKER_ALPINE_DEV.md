# Alpine development container on Debian

Classification: **OPS**. This is a local development environment, not evidence
of a real Alpine/OpenRC deployment. The architecture in
`../NXMS_STACK_SOURCE_OF_TRUTH.md` remains authoritative.

The Debian host needs Docker Engine. Rust, Cargo, native build dependencies,
Monero tools and Tor are installed inside Alpine 3.23 containers. Installing
only the development tools does not start Monero or create wallets. The combined
project setup starts a separate stagenet synchronization container afterwards.

## Combined project setup

After selecting and mounting the data partition read-write, run from this repo:

```sh
sudo bash tools/setup-alpine-project.sh /path/on/second-partition/nexum-docker
```

This creates the dedicated directory, installs Docker if absent, prepares the
Alpine toolchain, starts development stagenet synchronization and checks the project manifests.
It uses the real dependency source snapshot in `_incoming/privAI` by default.
Installation needs the owner's sudo authentication in their terminal.

The development container is limited to 2 CPU equivalents and 3 GiB RAM; the
sync container to 1 CPU equivalent and 2 GiB RAM. These are ceilings rather
than reservations. Both retain their data when stopped. The full Rust test
suite is not automatically run by setup.

## Approved Micron storage

On 2026-10-12 the owner selected `/var/lib/nexum-docker` on the new Micron
system filesystem, UUID `09929a1b-d005-4a5a-9fe3-29ab45851965` (ext4).
Docker uses `/var/lib/nexum-docker/docker`; containerd uses
`/var/lib/nexum-docker/containerd`.

This is a narrow exception to the previous separate-filesystem rule.
The broker requires both exact paths, the selected UUID/type, protected
root-owned parent directories and volume mountpoints inside the configured
Docker root. Other directories on `/` remain refused. The wrappers use the
fixed local Docker socket and compare its actual root with the approved path.
`storage-check` validates configuration without starting Docker or containers.

Status on 2026-10-13: both storage roots were copied to the Micron and the
host configuration, startup guards and reviewed broker were installed.
The two stopped containers had restart policy `no`. Copying used a private
read-only bind of the source, sequential low-priority rsync with numeric
owners, ACLs, extended attributes, hard links and sparse files, and a
32 MiB/s transfer ceiling. Both metadata dry runs were empty; this was not
a separate full-file checksum audit. The original disk's mount remains
read-write; the migration did not remove or rewrite its Docker data.

After starting the daemons, the broker validated both containers' actual
volume mountpoints, workspace binds, isolation and resource limits against
the new layout. The development container runs with the recovered Rust/Cargo
1.94.0 and rustfmt 1.8.0 toolchain. Offline locked Cargo metadata passed for
all eight workspace members. No Rust rebuild or test suite was run during
migration. Optional Clippy is absent; the current combined `dev versions`
probe exits at its rustup shim, so metadata was checked separately.

The old Monero LMDB failed with SIGBUS and has FreeDB roots beyond its file
boundary. Its destination copy, including `data.mdb` and `lock.mdb`, is
preserved at `/var/lib/nexum-docker/quarantine/stagenet-lmdb-2026-10-13`.
The source copy is also retained. Tor state was preserved; stagenet started
with a fresh LMDB. RPC confirmed `nettype=stagenet`, `status=OK`,
`busy_syncing=true`, height 1341 and target 2228169 at the initial check;
these heights are a dated observation, not the current sync status.
Synchronization is incomplete.

Configuration backups, copy logs and migration state are root-readable under
`/var/lib/nexum-docker/migration-2026-10-13`. Docker, its socket and containerd
retain their previous disabled-at-boot setting; they are currently active
after a controlled start. Do not run the fresh-only installer against this
existing installation or blindly rerun the one-time migration.

The current repo, uncommitted dashboard/OPS files and dependency snapshot
have local backups in `_incoming`; recovery from the old disk must not
overwrite newer project work.

```sh
sudo sh tools/alpine-stagenet.sh status
sudo sh tools/alpine-stagenet.sh logs
sudo sh tools/alpine-stagenet.sh stop
```

On 2026-10-13 the owner selected direct development synchronization of the
public chain, with Tor reserved for later NXMS operation and own transaction
submission. This is the OPS exception recorded in the primary source of truth,
not a change to the Tor-only NXMS runtime contract. Do not attach wallets or
NXMS execution roles to the direct synchronization profile. Monero P2P may
also exchange public mempool transactions; this is not a blocks-only wire filter.

`tools/alpine-stagenet.sh` supports `NXMS_STAGENET_NETWORK=direct` (default)
and `tor`. Direct mode starts Monero without Tor or `--proxy`, exposing the
node's IP to peers. Tor mode waits for bootstrap, routes P2P through its SOCKS
proxy and stops Monero if Tor exits; it never falls back to direct mode.
Unknown mode values are refused before startup. A container's explicit
network mode is fixed at creation; a conflicting host request is refused.
The retained legacy container has no explicit network setting and adopts the
script's direct default. Changing an explicit setting requires controlled
container recreation with the same data volume, not deletion of chain data.

Both modes use pruning, one CPU, 2 GiB RAM and four outbound peers. At the
owner's request, the earlier 2048 KiB/s download ceiling was replaced with
104857600 KiB/s (100 GiB/s), a practically nonbinding threshold for this
laptop and connection. Monero 0.18.5.0 does not interpret zero as unlimited;
its throttle divides by the configured target speed, so use a large positive
value. The upload ceiling remains 128 KiB/s. The new setting is
`NXMS_STAGENET_DOWNLOAD_KIB`; the retired `NXMS_STAGENET_DOWN=2048` stored in
the retained container is ignored. An explicit new setting is fixed at
creation, and a conflicting host start request is refused. The source for
the pinned version is `src/p2p/net_node.inl` (`set_rate_down_limit`) and
`contrib/epee/src/network_throttle-detail.cpp` (`set_target_speed` and
`calculate_times`); its `network_speed_kbps` type is `double`.
RPC is accessed inside the
container on loopback; no ports are published. The node does not create
wallets. Sync completion must be checked through local RPC status.

The retained container was stopped with exit code 0 and restarted in direct
mode without recreating its volume or resetting LMDB. The live process check
confirmed Monero without `--proxy` or `--tx-proxy` and no Tor process in that
container. RPC returned `status=OK`, `busy_syncing=true` and height 132605
at the first direct-mode check, above the last pre-switch observation of
132252. Shell syntax, valid mode selection and rejection of an unknown mode
were checked; no Rust compilation or real wallet operation was performed.

## Agent access to existing containers

The owner chose a root-owned broker instead of docker-group membership or
sharing an administrator password. Hard rule: no script, installer or
assistant may add the owner (or any user) to the `docker` group, including
convenience steps inside install blocks; the broker is the only granted
access path and the group may exist empty. After review, install it once:

```sh
sudo bash tools/install-docker-agent.sh
```

The installer pins the helper bytes by SHA-256, copies them into a protected
root-owned directory and grants `footfalcon` passwordless sudo for that helper
only. This authorization belongs to the Unix account, not just this chat.
It does not grant arbitrary Docker commands or a host shell. The broker checks
the expected container identities, mounts, isolation and resource ceilings;
Cargo runs as UID/GID 1000 inside the existing Alpine development container.

```sh
sudo -n /usr/local/libexec/nexum-docker-agent services-start
sudo -n /usr/local/libexec/nexum-docker-agent storage-check
sudo -n /usr/local/libexec/nexum-docker-agent status
sudo -n /usr/local/libexec/nexum-docker-agent logs stagenet
sudo -n /usr/local/libexec/nexum-docker-agent dev versions
sudo -n /usr/local/libexec/nexum-docker-agent dev cargo check --workspace --locked
```

Only the existing `nexum-alpine-dev` and `nexum-alpine-stagenet` containers are
managed. Creating new containers or changing mounts requires a separate setup
step. Changing the installed helper also requires a reviewed administrator
installation. After a reboot, a separate selected data partition must be
mounted before `services-start`. The approved Micron layout is on the system
filesystem and does not require the old external disk. The broker can start
only Docker and containerd and verifies both storage filesystems first. It
then supports starting the two retained containers. The filesystem checks use root-controlled daemon configuration and
the actual volume mountpoints, avoiding the daemon's potentially slow `/info`.
To revoke new broker calls:

```sh
sudo rm /etc/sudoers.d/nexum-docker-agent
```

## Fresh installation on a separate filesystem

Choose an existing, writable directory on a mounted ext4 or XFS filesystem
separate from `/`. Keep it separate from existing research and system files.
The installer does not format, mount or migrate disks.

Run the installer from the repository, supplying the chosen directory:

```sh
sudo bash tools/install-docker-debian.sh /path/on/second-partition/nexum-docker
```

The installer is for a fresh Docker installation on Debian 13. It configures
both Docker's `data-root` and containerd's `root`, since changing only
`data-root` does not relocate the containerd image store. Service mount checks
prevent startup when the selected filesystem is unavailable. Debian packages
and their package-manager metadata still occupy some space on `/`.

The partition must be mounted before the services start after reboot. The
installer does not edit `/etc/fstab`. For a persistent installation, establish
a stable mount separately before enabling unattended use.

## Development environment

The wrapper uses an official Rust 1.94.0 / Alpine 3.23 image pinned by digest.
It configures a single container with default limits of 2 CPU equivalents,
3 GiB RAM, no additional swap, and one compilation job. Package installation
and native compilation happen inside that limited container, without an
unlimited `docker build` stage.

```sh
sudo bash tools/alpine-dev.sh setup
sudo bash tools/alpine-dev.sh versions
sudo bash tools/alpine-dev.sh shell
sudo bash tools/alpine-dev.sh stop
```

The container has no published ports. Cargo cache and compilation outputs use
a Docker volume on the configured data filesystem. Stopping the container
preserves its packages and cache. Docker logs rotate to limit their growth.

Native prerequisites include the provenance-locked liboqs 0.15.0, whose source
archive is checked against the repository's SHA-256, and Alpine's shared and
static libsodium packages. This does not change the cryptographic protocol or
vendored Falcon sources.

## Workspace dependency

The full NXMS workspace needs real sources from `niirmataa/privAI`, containing
`privai-chain` and its parent workspace manifest. NXMS's lockfile does not
record the original privAI commit. An ignored partial snapshot is prepared at
`_incoming/privAI`, from commit `0fb08a7b0d94fc0411a235caef1909863c579989`.
Its 19 unchanged source files have verified Git blob hashes and SHA-256 hashes;
`SOURCE_SNAPSHOT.txt` records the scope and provenance. Other privAI workspace
members were not copied. The complete NXMS workspace built successfully
against this external dependency on Alpine on 2026-10-11; the partial snapshot
is not a standalone full privAI workspace.

The wrapper detects this snapshot automatically. To use a different real
checkout, set `PRIVAI_DIR` before creating the container and for later calls:

```sh
sudo env PRIVAI_DIR=/path/to/privAI bash tools/alpine-dev.sh setup
sudo env PRIVAI_DIR=/path/to/privAI bash tools/alpine-dev.sh cargo test --locked
```

The checkout is mounted read-only at `/work/privAI`; NXMS is at
`/work/nexum-core`, preserving the existing relative dependency paths. Setup
and version checks can run without privAI, but workspace builds cannot.

## Disk and runtime checks

```sh
sudo docker system df
sudo docker stats --no-stream
```

The owner has requested stagenet synchronization alongside environment setup.
Wallet provisioning, authenticated wallet-rpc, signer configuration and actual
escrow execution are later runtime steps. OpenRC boot and service integration
still require a real Alpine runtime validation.

Primary operational references:

- https://docs.docker.com/engine/install/debian/
- https://docs.docker.com/engine/daemon/
- https://docs.docker.com/engine/containers/resource_constraints/
- https://pkgs.alpinelinux.org/package/v3.23/community/x86_64/monero
