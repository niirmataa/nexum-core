#!/bin/sh
# OPS: bounded, pruned Monero stagenet sync; no wallets or mining.
# Owner-approved direct development sync is separate from Tor-only NXMS runtime.
# Flags checked against monero-project/monero tag v0.18.5.0:
# src/{daemon/command_line_args.h,p2p/net_node.cpp,p2p/net_node.inl}
# contrib/epee/src/network_throttle-detail.cpp (rate units are 1024 bytes/s).
# https://docs.getmonero.org/interacting/monerod-reference/
set -eu
die() { printf 'alpine-stagenet: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Usage: sudo sh tools/alpine-stagenet.sh {start|status|logs|stop}
start installs Alpine packages inside the container and starts synchronization.
status reads local RPC via docker exec; logs follows bounded Docker logs.
stop preserves the container and named volume, allowing sync to resume.
Limits: 1 CPU, 2 GiB RAM, no additional swap, 4 outbound peers, no inbound.
Data: a Docker volume on verified storage; no published ports.
Network: NXMS_STAGENET_NETWORK=direct (default) or tor (no clearnet fallback).
direct is for development synchronization without a wallet or NXMS runtime.
It exposes the node IP to Monero peers. Use Tor for later NXMS operation.
Optional names: NXMS_STAGENET_CONTAINER=nexum-alpine-stagenet
NXMS_STAGENET_VOLUME=nexum-alpine-stagenet-data
Optional rates: NXMS_STAGENET_DOWNLOAD_KIB=104857600, NXMS_STAGENET_UP=128.
Units: KiB/s. Download defaults to 100 GiB/s (practically unrestricted).
The old NXMS_STAGENET_DOWN key is retired; its stored 2048 value is ignored.
Names, rates and network mode are fixed at container creation.
Legacy containers without a network setting use the current direct default.
Recreate manually with the same data volume to change an explicit setting.
Docker/containerd must use a separate data filesystem or the approved Micron
layout validated by the installed root-owned broker's storage-check.
EOF
}

network=${NXMS_STAGENET_NETWORK:-direct}
case "$network" in direct|tor) ;; *) die 'NXMS_STAGENET_NETWORK must be direct or tor.' ;; esac
default_down=104857600
down=${NXMS_STAGENET_DOWNLOAD_KIB:-$default_down}
up=${NXMS_STAGENET_UP:-128}
for rate in "$down" "$up"; do
    case "$rate" in ''|*[!0-9]*) die 'Rates must be positive integer KiB/s.' ;; esac
    [ "$rate" -gt 0 ] || die 'Rates must be positive.'
done

# Internal entrypoints are only for this script's isolated Docker container.
case ${1:-} in
    __run|__supervise)
        [ "${NXMS_STAGENET_INTERNAL:-}" = 1 ] && [ -f /.dockerenv ] || die 'Internal command.'
        if [ "$1" = __run ]; then
            [ "$(id -u)" = 0 ] || die 'Bootstrap requires container root.'
            apk info -e monero tor curl ca-certificates su-exec >/dev/null 2>&1 ||
                apk add --no-cache monero=0.18.5.0-r0 tor curl ca-certificates su-exec
            id nxms >/dev/null 2>&1 || adduser -D -u 10001 nxms
            mkdir -p /state/monero /state/tor
            chown nxms:nxms /state /state/monero /state/tor
            chmod 700 /state /state/monero /state/tor
            exec su-exec nxms /bin/sh "$0" __supervise
        fi
        [ "$(id -u)" != 0 ] || die 'Daemons must run unprivileged.'
        tor_pid= monero_pid= logger_pid=
        cleanup() {
            trap - EXIT INT TERM
            for pid in "$monero_pid" "$tor_pid"; do
                [ -z "$pid" ] || kill -TERM "$pid" 2>/dev/null || true
            done
            for pid in "$monero_pid" "$tor_pid" "$logger_pid"; do
                [ -z "$pid" ] || wait "$pid" 2>/dev/null || true
            done
        }
        trap cleanup EXIT
        trap 'exit 0' INT TERM
        printf 'alpine-stagenet: network=%s; development synchronization, no wallet.\n' "$network"
        printf 'alpine-stagenet: download=%s KiB/s; upload=%s KiB/s.\n' "$down" "$up"
        if [ "$network" = tor ]; then
            rm -f /tmp/nxms-tor-ready /tmp/nxms-tor-log
            mkfifo /tmp/nxms-tor-log
            tor_config=$(mktemp /tmp/nxms-torrc.XXXXXX)
            cat > "$tor_config" <<'EOF'
DataDirectory /state/tor
SocksPort 127.0.0.1:9050
RunAsDaemon 0
Log notice stdout
EOF
            # Stream Tor notices to Docker's rotating log; keep no growing log file.
            while IFS= read -r line; do
                printf '%s\n' "$line"
                case "$line" in *'Bootstrapped 100%'*) touch /tmp/nxms-tor-ready ;; esac
            done < /tmp/nxms-tor-log &
            logger_pid=$!
            tor -f "$tor_config" > /tmp/nxms-tor-log 2>&1 &
            tor_pid=$!
            attempts=0
            until [ -f /tmp/nxms-tor-ready ]; do
                kill -0 "$tor_pid" 2>/dev/null || die 'Tor exited before bootstrap.'
                attempts=$((attempts + 1))
                [ "$attempts" -le 300 ] || die 'Tor bootstrap timed out; no clearnet fallback.'
                sleep 2
            done
        fi
        # --proxy covers ALL P2P. --tx-proxy alone covers local tx, and adds an
        # extra onion zone/peer budget; do not add it to this sync-only node.
        set -- monerod --stagenet --non-interactive --data-dir /state/monero \
            --prune-blockchain --sync-pruned-blocks --max-concurrency 1 \
            --prep-blocks-threads 1 \
            --p2p-bind-ip 127.0.0.1 --p2p-bind-port 38080 \
            --no-igd --hide-my-port --in-peers 0 --out-peers 4 \
            --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38081 --restricted-rpc --no-zmq \
            --check-updates disabled --disable-dns-checkpoints \
            --limit-rate-down "$down" --limit-rate-up "$up" \
            --log-level 0 --log-file /state/monero/monerod.log \
            --max-log-file-size 10485760 --max-log-files 3
        if [ "$network" = tor ]; then
            set -- "$@" --proxy socks5://127.0.0.1:9050
        fi
        "$@" &
        monero_pid=$!
        while kill -0 "$monero_pid" 2>/dev/null; do
            if [ "$network" = tor ] && ! kill -0 "$tor_pid" 2>/dev/null; then
                tor_status=0
                wait "$tor_pid" || tor_status=$?
                tor_pid=
                die "Tor exited (status $tor_status); stopping monerod."
            fi
            sleep 2
        done
        monero_status=0
        wait "$monero_pid" || monero_status=$?
        monero_pid=
        die "monerod exited (status $monero_status); stopping supervisor."
        ;;
esac

action=${1:-help}
case "$action" in start|status|logs|stop) ;; -h|--help|help) usage; exit 0 ;; *) usage >&2; exit 2 ;; esac
[ "$#" -eq 1 ] || die 'Unexpected arguments.'
self=$(readlink -f -- "$0")
workspace=$(cd -- "$(dirname -- "$self")/.." && pwd -P)
case "$self" in *','*|*'
'*) die 'The script path must not contain commas or newlines.' ;; esac
container=${NXMS_STAGENET_CONTAINER:-nexum-alpine-stagenet}
volume=${NXMS_STAGENET_VOLUME:-nexum-alpine-stagenet-data}
for name in "$container" "$volume"; do
    case "$name" in ''|[!a-zA-Z0-9]*|*[!a-zA-Z0-9_.-]*) die 'Invalid container/volume name.' ;; esac
done
command -v docker >/dev/null 2>&1 || die 'Install/configure Docker on the data disk first.'
dock() {
    env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
        /usr/bin/docker --host unix:///var/run/docker.sock "$@"
}
dock info >/dev/null 2>&1 || die 'Cannot reach the local Docker API. Check that Docker is running and use sudo if socket access is restricted.'
label=io.nexum.stagenet.workspace
exists() { dock container inspect "$container" >/dev/null 2>&1; }
check_owner() {
    actual=$(dock container inspect --format "{{index .Config.Labels \"$label\"}}" "$container")
    [ "$actual" = "$workspace" ] || die "Container $container belongs to another workspace; choose another name."
}
check_storage() {
    docker_root=$(dock info --format '{{.DockerRootDir}}') || die 'Cannot inspect local Docker; run with sudo after installation.'
    root_fs=$(stat -c %d /)
    docker_fs=$(stat -c %d -- "$docker_root") || die 'Cannot inspect DockerRootDir; use sudo.'
    if [ "$docker_fs" = "$root_fs" ]; then
        [ "$docker_root" = /var/lib/nexum-docker/docker ] || die 'The running daemon is outside the approved Micron Docker directory.'
        helper=/usr/local/libexec/nexum-docker-agent
        [ -f "$helper" ] && [ ! -L "$helper" ] && [ -x "$helper" ] && [ "$(stat -c %u "$helper")" = 0 ] \
            || die 'Storage on / requires the reviewed root-owned broker after Micron migration.'
        helper_mode=$(stat -c %a "$helper")
        [ "$((0$helper_mode & 022))" = 0 ] || die 'The storage checker is writable by group/others.'
        "$helper" storage-check >/dev/null || die 'The owner-approved Micron storage policy did not pass.'
    fi
    [ -r /etc/containerd/config.toml ] || die 'Configure /etc/containerd/config.toml with an explicit root on the data filesystem.'
    containerd_root=$(containerd --config /etc/containerd/config.toml config dump |
        awk '/^\[/ { exit } $1 == "root" && $2 == "=" { gsub(/["\047]/, "", $3); print $3 }')
    case "$containerd_root" in /*) ;; *) die 'Cannot verify the effective containerd root.' ;; esac
    containerd_fs=$(stat -c %d -- "$containerd_root") || die 'Cannot inspect containerd root; use sudo.'
    [ "$containerd_fs" = "$docker_fs" ] || die 'containerd root must share Docker data filesystem.'
}
case "$action" in
    start)
        check_storage
        if exists; then
            check_owner
            actual_volume=$(dock container inspect --format '{{index .Config.Labels "io.nexum.stagenet.volume"}}' "$container")
            [ "$actual_volume" = "$volume" ] || die 'Volume name differs from the existing container.'
            actual_network=$(dock container inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container" |
                awk '/^NXMS_STAGENET_NETWORK=/ { sub(/^NXMS_STAGENET_NETWORK=/, ""); print }')
            [ -n "$actual_network" ] || actual_network=direct
            [ "$actual_network" = "$network" ] \
                || die 'Network mode differs from the existing container; preserve its volume when recreating it.'
            actual_down=$(dock container inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container" |
                awk '/^NXMS_STAGENET_DOWNLOAD_KIB=/ { sub(/^NXMS_STAGENET_DOWNLOAD_KIB=/, ""); print }')
            [ -n "$actual_down" ] || actual_down=$default_down
            [ "$actual_down" = "$down" ] \
                || die 'Download rate differs from the existing container; preserve its volume when recreating it.'
        else
            if dock volume inspect "$volume" >/dev/null 2>&1; then
                actual=$(dock volume inspect --format "{{index .Labels \"$label\"}}" "$volume")
                [ "$actual" = "$workspace" ] || die "Volume $volume belongs to another workspace; choose another name."
            else
                dock volume create --label "$label=$workspace" "$volume" >/dev/null
            fi
            dock create --name "$container" --label "$label=$workspace" \
                --label "io.nexum.stagenet.volume=$volume" \
                --cpus=1 --memory=2g --memory-swap=2g --pids-limit=256 \
                --log-driver=local --log-opt=max-size=10m --log-opt=max-file=3 \
                --stop-timeout=120 --security-opt=no-new-privileges \
                --tmpfs /tmp:rw,nosuid,nodev,size=32m \
                --mount "type=volume,source=$volume,target=/state" \
                --mount "type=bind,source=$self,target=/opt/alpine-stagenet.sh,readonly" \
                --env NXMS_STAGENET_INTERNAL=1 --env "NXMS_STAGENET_DOWNLOAD_KIB=$down" \
                --env "NXMS_STAGENET_UP=$up" --env "NXMS_STAGENET_NETWORK=$network" --entrypoint /bin/sh \
                alpine:3.23 /opt/alpine-stagenet.sh __run >/dev/null
        fi
        [ "$(dock container inspect --format '{{.State.Running}}' "$container")" = true ] || dock start "$container" >/dev/null
        printf 'Container %s is running; network=%s; verify Monero readiness with status/logs.\n' "$container" "$network"
        ;;
    status)
        exists || die 'Container does not exist; run start after Docker setup.'
        check_owner
        dock container inspect --format 'State={{.State.Status}} OOMKilled={{.State.OOMKilled}} ExitCode={{.State.ExitCode}}' "$container"
        [ "$(dock container inspect --format '{{.State.Running}}' "$container")" = true ] || exit 0
        dock exec --user nxms "$container" curl --fail --silent --show-error --max-time 10 \
            --noproxy '*' http://127.0.0.1:38081/get_info || die 'Local RPC is not ready; inspect logs (Tor/bootstrap/sync).'
        printf '\n'
        ;;
    logs)
        exists || die 'Container does not exist.'
        check_owner
        exec env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
            /usr/bin/docker --host unix:///var/run/docker.sock logs --follow --tail 100 "$container"
        ;;
    stop)
        if exists; then check_owner; dock stop --time 120 "$container" >/dev/null; fi
        printf 'Stopped; container and volume retained.\n'
        ;;
esac
