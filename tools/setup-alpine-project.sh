#!/usr/bin/env bash
# OPS: manual host installation followed by bounded Alpine development/stagenet.
set -Eeuo pipefail

die() { printf 'setup-alpine-project: %s\n' "$*" >&2; exit 1; }
if [[ ${1:-} == --help || ${1:-} == -h || $# == 0 ]]; then
    cat <<'EOF'
Usage: sudo bash tools/setup-alpine-project.sh /absolute/data-directory

The directory's parent must already exist on a writable, mounted filesystem
separate from /. The approved /var/lib/nexum-docker Micron layout is also
accepted after migration and installation of the reviewed storage checker.
A new dedicated directory is created if needed. This script
does not mount, format or remove anything. Run it after choosing the data disk.

Install Docker if absent, prepare the limited Alpine development container,
then start limited Monero STAGENET development synchronization. Network mode
defaults to direct; NXMS_STAGENET_NETWORK=tor uses Tor without fallback.
No wallets are created. PRIVAI_DIR may specify a source checkout/snapshot; the default is this
repository's ignored _incoming/privAI directory.
EOF
    exit 0
fi
[[ $# == 1 && $EUID == 0 ]] || die 'Run with sudo and one absolute data-directory argument.'
[[ ${SUDO_UID:-0} -gt 0 ]] || die 'Run sudo from your regular user account.'
[[ $1 =~ ^/[A-Za-z0-9._/-]+$ ]] || die 'Use an absolute data path without spaces or special characters.'

workspace=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
export PRIVAI_DIR=${PRIVAI_DIR:-$workspace/_incoming/privAI}
[[ -f $PRIVAI_DIR/Cargo.toml && -f $PRIVAI_DIR/privai-chain/Cargo.toml ]] \
    || die 'Set PRIVAI_DIR to the real privAI source checkout/snapshot before project setup.'
data_base=$(realpath -m -- "$1")
parent=$(dirname -- "$data_base")
[[ -d $parent ]] || die 'The parent directory must already exist on the selected mounted partition.'
if [[ $(stat -c %d -- "$parent") == "$(stat -c %d /)" ]]; then
    [[ $data_base == /var/lib/nexum-docker ]] || die 'Only the owner-approved Micron directory is allowed on /.'
    helper=/usr/local/libexec/nexum-docker-agent
    [[ -f "$helper" && ! -L "$helper" && -x "$helper" && $(stat -c %u "$helper") == 0 ]] \
        || die 'Configure the Micron migration and install the reviewed root-owned broker first.'
    helper_mode=$(stat -c %a "$helper")
    (( (8#$helper_mode & 0022) == 0 )) || die 'The storage checker is writable by group/others.'
    "$helper" storage-check >/dev/null || die 'The owner-approved Micron storage policy did not pass.'
fi
mount_options=$(findmnt -rn -o OPTIONS --target "$parent")
[[ ,$mount_options, == *,rw,* && ,$mount_options, != *,ro,* ]] || die 'The selected partition must be mounted read-write first.'
[[ ! -L $1 ]] || die 'The data directory must not be a symlink.'

if command -v docker >/dev/null 2>&1; then
    actual_root=$(docker --host unix:///var/run/docker.sock info --format '{{.DockerRootDir}}')
    [[ $actual_root == "$data_base/docker" ]] || die "Existing Docker uses $actual_root; expected $data_base/docker. No migration is performed."
else
    install -d -o 0 -g 0 -m 0711 -- "$data_base"
    bash "$workspace/tools/install-docker-debian.sh" "$data_base"
fi

bash "$workspace/tools/alpine-dev.sh" setup
bash "$workspace/tools/alpine-dev.sh" versions
bash "$workspace/tools/alpine-stagenet.sh" start

printf '\nChecking the project manifests with the installed Alpine toolchain...\n'
bash "$workspace/tools/alpine-dev.sh" cargo metadata --locked --no-deps --format-version 1 >/dev/null
printf '\nAlpine tools and project manifests are ready; stagenet container started; verify RPC status.\n'
printf 'Status: sudo bash tools/alpine-stagenet.sh status\n'
printf 'Stop sync: sudo bash tools/alpine-stagenet.sh stop\n'
printf 'Stop development container: sudo bash tools/alpine-dev.sh stop\n'
