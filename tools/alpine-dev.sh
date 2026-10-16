#!/usr/bin/env bash
# OPS: keep the Alpine development toolchain and build data inside Docker.
set -euo pipefail

die() { printf 'alpine-dev: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: tools/alpine-dev.sh {setup|shell|cargo <args...>|versions|stop}

setup     Create/start the container and install development dependencies.
shell     Open a shell as your host UID/GID after setup.
cargo     Run Cargo as your host UID/GID after setup.
versions  Show installed versions without bootstrapping dependencies.
stop      Stop this workspace's container; preserve container and cache.

Optional: PRIVAI_DIR=/absolute/path/to/privAI (real sources and parent manifest).
If present, this repository's _incoming/privAI source snapshot is used by default.
Set it before creating the container. Build/test require privai-chain/Cargo.toml.
Mount changes require stopping and manually removing the old container, then setup.

Defaults: NXMS_DEV_CONTAINER=nexum-alpine-dev, NXMS_DEV_VOLUME=nexum-alpine-dev-cache
NXMS_DEV_CPUS=2, NXMS_DEV_MEMORY=3g, NXMS_DEV_MEMORY_SWAP=3g,
NXMS_DEV_PIDS_LIMIT=256, NXMS_CARGO_BUILD_JOBS=1,
NXMS_CMAKE_BUILD_PARALLEL_LEVEL=1, NXMS_MAKE_JOBS=1.
NXMS_DEV_UID/NXMS_DEV_GID override the host user (SUDO_UID/SUDO_GID are respected).
Storage must use a separate filesystem or the explicitly approved Micron layout.
The Micron layout requires the reviewed root-owned broker's storage-check.
EOF
}

command=${1:-}
case "$command" in
    setup|shell|cargo|versions|stop) shift ;;
    -h|--help|help|'') usage; exit 0 ;;
    *) usage >&2; die "Unknown command: $command" ;;
esac
if [[ "$command" == cargo ]]; then
    (( $# > 0 )) || die 'Pass Cargo arguments, for example: cargo test --workspace'
elif (( $# > 0 )); then
    die "Unexpected arguments for $command"
fi

workspace=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
container=${NXMS_DEV_CONTAINER:-nexum-alpine-dev}
volume=${NXMS_DEV_VOLUME:-nexum-alpine-dev-cache}
image='rust:1.94.0-alpine3.23@sha256:ff0adc35894eb79586ce752a1b5a9eadc88b938c56d8f2b4b537b6258ff3fa10'
dev_uid=${NXMS_DEV_UID:-${SUDO_UID:-$(id -u)}}
dev_gid=${NXMS_DEV_GID:-${SUDO_GID:-$(id -g)}}
[[ "$dev_uid" =~ ^[0-9]+$ && "$dev_uid" -gt 0 ]] || die 'Set NXMS_DEV_UID to a non-root host UID, or run with sudo from your normal account.'
[[ "$dev_gid" =~ ^[0-9]+$ ]] || die 'NXMS_DEV_GID must be a numeric host GID.'

privai=''
privai_input=${PRIVAI_DIR:-}
if [[ -z "$privai_input" && -f "$workspace/_incoming/privAI/privai-chain/Cargo.toml" ]]; then
    privai_input=$workspace/_incoming/privAI
fi
if [[ -n "$privai_input" ]]; then
    [[ -f "$privai_input/Cargo.toml" && -f "$privai_input/privai-chain/Cargo.toml" ]] || die 'PRIVAI_DIR must contain real privai-chain sources and the parent Cargo.toml.'
    privai=$(cd -- "$privai_input" && pwd -P)
fi
[[ "$workspace$privai" != *','* && "$workspace$privai" != *$'\n'* ]] || die 'Docker bind paths must not contain commas or newlines.'

cargo_needs_privai=false
if [[ "$command" == cargo ]]; then
    for arg in "$@"; do
        case "$arg" in
            build|test|check|clippy|run|bench|doc|fetch|metadata|tree|update|generate-lockfile)
                cargo_needs_privai=true
                break
                ;;
        esac
    done
    if [[ "$cargo_needs_privai" == true && -z "$privai" ]]; then
        die 'This workspace requires ../privAI/privai-chain. Set PRIVAI_DIR to the full existing privAI repository before creating the container. No stub is created.'
    fi
fi

command -v docker >/dev/null 2>&1 || die 'Docker is not installed. Configure Docker/containerd storage on the data filesystem first.'
[[ -x /usr/bin/docker ]] || die 'The reviewed Docker CLI must be installed at /usr/bin/docker.'
docker() {
    env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
        /usr/bin/docker --host unix:///var/run/docker.sock "$@"
}

check_storage() {
    local docker_root containerd_root='' line root_fs docker_fs containerd_fs
    docker_root=$(docker info --format '{{.DockerRootDir}}') || die 'Cannot read docker info. Start Docker or run this wrapper through sudo.'
    [[ "$docker_root" == /* ]] || die 'DockerRootDir is not a local absolute path.'
    root_fs=$(stat -c %d /) || die 'Cannot identify the root filesystem.'
    docker_fs=$(stat -c %d -- "$docker_root") || die 'Cannot inspect DockerRootDir. Run this wrapper through sudo if access is restricted.'
    if [[ "$docker_fs" == "$root_fs" ]]; then
        [[ $docker_root == /var/lib/nexum-docker/docker ]] || die 'The running daemon is outside the approved Micron Docker directory.'
        local helper=/usr/local/libexec/nexum-docker-agent helper_mode
        [[ -f "$helper" && ! -L "$helper" && -x "$helper" && $(stat -c %u "$helper") == 0 ]] \
            || die 'Storage on / requires the reviewed root-owned broker after Micron migration.'
        helper_mode=$(stat -c %a "$helper")
        (( (8#$helper_mode & 0022) == 0 )) || die 'The storage checker is writable by group/others.'
        "$helper" storage-check >/dev/null || die 'The owner-approved Micron storage policy did not pass.'
    fi

    [[ -r /etc/containerd/config.toml ]] || die 'Cannot read /etc/containerd/config.toml. Configure containerd storage explicitly, or run this wrapper through sudo.'
    # Only the top-level root controls containerd storage; ignore plugin sections.
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*\[ ]] && break
        if [[ "$line" =~ ^[[:space:]]*root[[:space:]]*=[[:space:]]*\"([^\"]+)\"[[:space:]]*(#.*)?$ ]]; then
            containerd_root=${BASH_REMATCH[1]}
        elif [[ "$line" =~ ^[[:space:]]*root[[:space:]]*=[[:space:]]*\'([^\']+)\'[[:space:]]*(#.*)?$ ]]; then
            containerd_root=${BASH_REMATCH[1]}
        fi
    done < /etc/containerd/config.toml
    [[ "$containerd_root" == /* ]] || die 'Set an explicit top-level root in /etc/containerd/config.toml on the Docker data filesystem first.'
    containerd_fs=$(stat -c %d -- "$containerd_root") || die 'Cannot inspect containerd root. Configure its data directory first, or run through sudo.'
    [[ "$containerd_fs" == "$docker_fs" ]] || die "containerd root ($containerd_root) must be on the same data filesystem as DockerRootDir ($docker_root)."
}

container_exists() { docker container inspect "$container" >/dev/null 2>&1; }

check_container() {
    local actual actual_privai actual_user
    actual=$(docker container inspect --format '{{index .Config.Labels "io.nexum.dev.workspace"}}' "$container")
    [[ "$actual" == "$workspace" ]] || die "Container $container belongs to another workspace. Choose NXMS_DEV_CONTAINER/NXMS_DEV_VOLUME names for this workspace."
    [[ "$command" == stop ]] && return 0
    actual_privai=$(docker container inspect --format '{{index .Config.Labels "io.nexum.dev.privai"}}' "$container")
    [[ "$actual_privai" == "$privai" ]] || die "PRIVAI_DIR differs from container $container. Stop and manually remove that container, then run setup again. The cache volume can be kept."
    actual_user=$(docker container inspect --format '{{index .Config.Labels "io.nexum.dev.user"}}' "$container")
    [[ "$actual_user" == "$dev_uid:$dev_gid" ]] || die "Container $container was configured for another UID/GID. Use the original user or manually recreate it with a separate cache volume."
}

ensure_container() {
    check_storage
    if container_exists; then
        check_container
    else
        local -a mounts=(--mount "type=bind,source=$workspace,target=/work/nexum-core" --mount "type=volume,source=$volume,target=/cache")
        if [[ -n "$privai" ]]; then
            mounts+=(--mount "type=bind,source=$privai,target=/work/privAI,readonly")
        fi
        docker create --name "$container" \
            --label "io.nexum.dev.workspace=$workspace" \
            --label "io.nexum.dev.privai=$privai" \
            --label "io.nexum.dev.user=$dev_uid:$dev_gid" \
            --cpus "${NXMS_DEV_CPUS:-2}" \
            --memory "${NXMS_DEV_MEMORY:-3g}" \
            --memory-swap "${NXMS_DEV_MEMORY_SWAP:-3g}" \
            --pids-limit "${NXMS_DEV_PIDS_LIMIT:-256}" \
            --log-driver local --log-opt max-size=5m --log-opt max-file=2 \
            --workdir /work/nexum-core \
            --env RUSTUP_TOOLCHAIN=1.94.0 \
            --env CARGO_HOME=/cache/cargo --env CARGO_TARGET_DIR=/cache/target \
            --env HOME=/cache/home --env XDG_CACHE_HOME=/cache/xdg --env TMPDIR=/cache/tmp \
            "${mounts[@]}" --entrypoint /bin/sh "$image" -c 'exec sleep infinity' >/dev/null
    fi
    if [[ "$(docker container inspect --format '{{.State.Running}}' "$container")" != true ]]; then
        docker start "$container" >/dev/null
    fi
}

exec_user() {
    local -a interactive=()
    if [[ "$command" == shell ]]; then
        interactive=(-i)
        [[ -t 0 && -t 1 ]] && interactive+=(-t)
    fi
    docker exec "${interactive[@]}" --user "$dev_uid:$dev_gid" --workdir /work/nexum-core \
        --env RUSTUP_TOOLCHAIN=1.94.0 \
        --env CARGO_BUILD_JOBS="${NXMS_CARGO_BUILD_JOBS:-1}" \
        --env CMAKE_BUILD_PARALLEL_LEVEL="${NXMS_CMAKE_BUILD_PARALLEL_LEVEL:-1}" \
        --env MAKEFLAGS="-j${NXMS_MAKE_JOBS:-1}" \
        --env CFLAGS="${NXMS_CFLAGS:--I/usr/local/include}" \
        --env RUSTFLAGS="${NXMS_RUSTFLAGS:--L native=/usr/local/lib}" \
        --env LD_LIBRARY_PATH=/usr/local/lib "$container" "$@"
}

require_setup() {
    docker exec "$container" test -f /usr/local/share/nxms-alpine-dev/bootstrap-v1 \
        || die 'Dependencies are not bootstrapped. Run: tools/alpine-dev.sh setup'
}

case "$command" in
    stop)
        if container_exists; then
            check_container
            docker stop "$container" >/dev/null
        fi
        ;;
    setup)
        ensure_container
        docker exec --user 0:0 --env NXMS_DEV_UID="$dev_uid" --env NXMS_DEV_GID="$dev_gid" \
            "$container" /bin/sh /work/nexum-core/tools/alpine-dev-bootstrap.sh
        ;;
    shell)
        ensure_container
        require_setup
        exec_user /bin/bash
        ;;
    cargo)
        ensure_container
        require_setup
        if [[ "$cargo_needs_privai" == true ]]; then
            docker exec "$container" test -f /work/privAI/privai-chain/Cargo.toml \
                || die 'Missing privai-chain mount. Stop and manually recreate this container with PRIVAI_DIR set to the existing full privAI repository, then run setup. No stub is created.'
        fi
        exec_user cargo "$@"
        ;;
    versions)
        ensure_container
        exec_user /bin/sh -c '
            rustc --version
            cargo --version
            for tool in rustfmt cargo-clippy cmake; do
                if command -v "$tool" >/dev/null 2>&1; then "$tool" --version; fi
            done
            if command -v pkg-config >/dev/null 2>&1; then
                pkg-config --modversion libsodium 2>/dev/null || :
                pkg-config --modversion liboqs 2>/dev/null || :
            fi
            if command -v monerod >/dev/null 2>&1; then monerod --version; fi
            if command -v monero-wallet-rpc >/dev/null 2>&1; then monero-wallet-rpc --version; fi
            if command -v tor >/dev/null 2>&1; then tor --version; fi
        '
        ;;
esac
