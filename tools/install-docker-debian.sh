#!/usr/bin/env bash
# Manual, fresh-install-only setup. Never invoke this from a build script.
# Sources: https://docs.docker.com/engine/install/debian/
#          https://docs.docker.com/engine/daemon/
set -Eeuo pipefail
umask 022

usage() {
    cat <<'EOF'
Usage: sudo bash tools/install-docker-debian.sh /absolute/existing/data-directory

Install Docker Engine, Compose and Buildx from Docker's official apt repository
on Debian 13 (trixie). Run manually as root, after reviewing this script.

The supplied directory must already exist on a mounted, writable ext4 or XFS
filesystem DIFFERENT from /. Docker uses DIRECTORY/docker and containerd uses
DIRECTORY/containerd. Both directories must be absent. The containing mount
must remain available; systemd guards prevent service startup without it.
For predictable startup after reboot, configure that mount separately first.
Paths must contain only ASCII letters, digits, /, ., _, and -.

This is only for a fresh installation. Existing Docker/containerd packages,
data, configuration, service overrides or conflicting packages cause refusal.
Nothing is mounted, remounted, formatted, migrated, or uninstalled. No images
are downloaded and no user is added to the docker group. Storage stays owned
by root even when this script is called through sudo.

Docker container logs use the local driver, capped at 3 x 10 MiB per container.
This does not cap images, volumes, build cache or service journal logs. Installed
system packages, apt metadata and /etc configuration still consume space on /.
An interrupted installation requires manual inspection; do not blindly rerun.
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    usage
    exit 0
fi
[[ $# == 1 ]] || { usage >&2; exit 2; }
[[ $EUID == 0 ]] || die 'Run this script as root (sudo bash ...).'
[[ $1 == /* && $1 =~ ^/[A-Za-z0-9._/-]+$ ]] || die 'Supply an absolute directory with only letters, digits, /, ., _, and -.'

for cmd in apt-get dpkg dpkg-query findmnt mountpoint readlink systemctl systemd-escape install awk grep df; do
    command -v "$cmd" >/dev/null || die "Required command is missing: $cmd"
done
[[ -d /run/systemd/system ]] || die 'This installer requires a running systemd host.'
[[ -f /etc/os-release ]] || die 'Missing /etc/os-release.'
# shellcheck source=/etc/os-release
. /etc/os-release
[[ ${ID:-} == debian && ${VERSION_ID:-} == 13 && ${VERSION_CODENAME:-} == trixie ]] || die 'Only Debian 13 (trixie) is supported.'
architecture=$(dpkg --print-architecture)
case "$architecture" in
    amd64|arm64|armhf|ppc64el) ;;
    *) die "Unsupported Docker repository architecture: $architecture" ;;
esac

[[ -d $1 ]] || die 'The data directory must already exist; this script does not prepare mounts.'
data_base=$(readlink -e -- "$1")
[[ $data_base =~ ^/[A-Za-z0-9._/-]+$ ]] || die 'The resolved data directory contains unsupported characters.'
mount_path=$(findmnt --noheadings --raw --output TARGET --target "$data_base")
mount_device=$(findmnt --noheadings --raw --output MAJ:MIN --target "$data_base")
root_device=$(findmnt --noheadings --raw --output MAJ:MIN --target /)
filesystem=$(findmnt --noheadings --raw --output FSTYPE --target "$data_base")
[[ $mount_path =~ ^/[A-Za-z0-9._/-]+$ ]] || die 'The mount point contains unsupported characters.'
[[ $mount_device != "$root_device" && $mount_path != / ]] || die 'Refusing to put Docker data on the filesystem containing /.'
case "$filesystem" in
    ext4) ;;
    xfs)
        command -v xfs_info >/dev/null || die 'Install xfsprogs separately to verify this XFS filesystem.'
        xfs_info "$mount_path" | grep -Eq 'ftype=1([[:space:]]|$)' || die 'XFS must have ftype=1 for overlay storage.'
        ;;
    *) die "Only ext4 and XFS are supported; found $filesystem." ;;
esac

verify_mount() {
    local current_target current_device current_options
    mountpoint --quiet -- "$mount_path" || die "Required filesystem is not mounted: $mount_path"
    current_target=$(findmnt --noheadings --raw --output TARGET --target "$data_base")
    current_device=$(findmnt --noheadings --raw --output MAJ:MIN --target "$data_base")
    current_options=$(findmnt --noheadings --raw --output OPTIONS --target "$data_base")
    [[ $current_target == "$mount_path" && $current_device == "$mount_device" && $current_device != "$root_device" ]] || die 'The data mount changed; refusing to continue.'
    [[ ,$current_options, == *,rw,* && ,$current_options, != *,ro,* ]] || die 'The data filesystem is read-only; this script will not remount it.'
    [[ -w $data_base ]] || die 'The data directory is not writable.'
}
verify_mount

# Refuse leftovers, including symlinks and removed packages with configuration.
for package in docker-ce docker-ce-cli docker-ce-rootless-extras containerd.io docker-buildx-plugin docker-compose-plugin docker.io docker-compose docker-compose-v2 docker-doc docker-buildx podman-docker containerd runc; do
    package_state=$(dpkg-query --show --showformat='${db:Status-Status}' "$package" 2>/dev/null || true)
    [[ -z $package_state || $package_state == not-installed ]] || die "Existing/conflicting package: $package ($package_state). Inspect it manually."
done
for binary in docker dockerd containerd ctr runc; do
    ! command -v "$binary" >/dev/null || die "Existing binary: $binary. Fresh installation only."
done
for existing in /etc/docker /etc/containerd /etc/default/docker /etc/default/containerd /var/lib/docker /var/lib/containerd /run/docker /run/docker.sock /run/containerd /etc/apt/keyrings/docker.asc /etc/apt/keyrings/docker.gpg /etc/apt/trusted.gpg.d/docker.gpg "$data_base/docker" "$data_base/containerd"; do
    [[ ! -e $existing && ! -L $existing ]] || die "Existing Docker/containerd path: $existing"
done
for unit in docker.service docker.socket containerd.service; do
    unit_state=$(systemctl show --property=LoadState --value "$unit" 2>/dev/null || true)
    [[ $unit_state == not-found ]] || die "Existing systemd unit: $unit ($unit_state)"
    for unit_dir in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        [[ ! -e $unit_dir/$unit.d && ! -L $unit_dir/$unit.d ]] || die "Existing service overrides: $unit_dir/$unit.d"
    done
done
if grep -Eqs 'download\.docker\.com|packages\.docker\.com' /etc/apt/sources.list 2>/dev/null ||
    grep -REqs 'download\.docker\.com|packages\.docker\.com' /etc/apt/sources.list.d 2>/dev/null; then
    die 'An existing Docker apt repository was found. Inspect it manually.'
fi
[[ ! -e /etc/apt/sources.list.d/docker.sources && ! -L /etc/apt/sources.list.d/docker.sources ]] || die 'docker.sources already exists.'

printf 'Install Docker on Debian 13; filesystem: %s, mount: %s\n' "$filesystem" "$mount_path"
printf 'Docker data: %s/docker\ncontainerd data: %s/containerd\n' "$data_base" "$data_base"
df -h -- / "$data_base"

installation_started=false
installation_complete=false
on_exit() {
    local status=$?
    if [[ $installation_started == true && $installation_complete == false ]]; then
        # Retain persistent masks on failure, including across a host reboot.
        systemctl mask docker.service docker.socket containerd.service >/dev/null 2>&1 || true
        systemctl stop docker.socket docker.service containerd.service >/dev/null 2>&1 || true
        printf 'Installation incomplete. Services are blocked/stopped. Inspect the configuration and mount manually before starting them. No data was deleted.\n' >&2
    fi
    exit "$status"
}
trap on_exit EXIT

# Packages may start daemons in postinst. Mask them before apt, then configure
# both storage roots and mount dependencies before explicitly starting anything.
installation_started=true
systemctl mask docker.service docker.socket containerd.service
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get --yes --no-remove --no-install-recommends install ca-certificates curl
install -d -m 0755 /etc/apt/keyrings
curl --fail --silent --show-error --location --proto '=https' \
    https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod 0644 /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: trixie
Components: stable
Architectures: $architecture
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt-get update
apt-get --yes --no-remove --no-install-recommends install \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl stop docker.socket docker.service containerd.service
verify_mount

# Deliberately use root, not SUDO_UID/SUDO_GID, for daemon storage ownership.
install -d -o 0 -g 0 -m 0711 "$data_base/docker" "$data_base/containerd"
install -d -m 0755 /etc/docker /etc/containerd
cat > /etc/docker/daemon.json <<EOF
{
  "data-root": "$data_base/docker",
  "log-driver": "local",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
EOF
# Docker Engine 29+ keeps its image store in the system containerd root.
# A minimal version-2 config is supported by containerd 1.x and 2.x.
cat > /etc/containerd/config.toml <<EOF
version = 2
root = "$data_base/containerd"
state = "/run/containerd"
EOF
mount_unit=$(systemd-escape --path --suffix=mount "$mount_path")
for unit in docker.service containerd.service; do
    install -d -m 0755 "/etc/systemd/system/$unit.d"
    cat > "/etc/systemd/system/$unit.d/10-data-mount.conf" <<EOF
[Unit]
RequiresMountsFor=$data_base
ConditionPathIsMountPoint=$mount_path
BindsTo=$mount_unit
After=$mount_unit
EOF
done

dockerd --validate --config-file=/etc/docker/daemon.json
configured_containerd_root=$(containerd --config /etc/containerd/config.toml config dump | awk '$1 == "root" && $2 == "=" { gsub(/["\047]/, "", $3); print $3 }')
[[ $configured_containerd_root == "$data_base/containerd" ]] || die 'containerd did not accept the requested storage root.'
systemctl daemon-reload
verify_mount
systemctl unmask docker.service docker.socket containerd.service
systemctl enable containerd.service docker.service
systemctl start containerd.service docker.service
for unit in containerd.service docker.service; do
    systemctl is-active --quiet "$unit" || die "Service did not start: $unit"
done
verify_mount

# Use the local daemon explicitly, ignoring any caller's DOCKER_HOST/context.
actual_docker_root=$(env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host unix:///var/run/docker.sock info --format '{{.DockerRootDir}}')
[[ $actual_docker_root == "$data_base/docker" ]] || die "Unexpected DockerRootDir: $actual_docker_root"
configured_containerd_root=$(containerd --config /etc/containerd/config.toml config dump | awk '$1 == "root" && $2 == "=" { gsub(/["\047]/, "", $3); print $3 }')
[[ $configured_containerd_root == "$data_base/containerd" ]] || die 'Unexpected containerd root.'
installation_complete=true
printf '\nVerified DockerRootDir: %s\nVerified containerd root: %s\n' "$actual_docker_root" "$configured_containerd_root"
printf 'Docker is ready. No images were pulled; use sudo for Docker commands.\n'
