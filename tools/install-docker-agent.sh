#!/usr/bin/env bash
# OPS: install a reviewed, root-owned broker for this workspace's containers.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

die() { printf 'install-docker-agent: %s\n' "$*" >&2; exit 1; }
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    cat <<'EOF'
Usage: sudo bash tools/install-docker-agent.sh [--upgrade]

Install the pinned Nexum Docker broker as a root-owned program and allow
footfalcon to invoke ONLY that program through sudo without a password.
It manages the existing nexum-alpine-dev/nexum-alpine-stagenet containers and
can start only the Docker/containerd services after validating the data disk.
Cargo commands run as UID/GID 1000 inside the verified development container.

No docker-group membership, socket ACL, Docker API exposure or general
passwordless sudo is configured. The rule applies to this Unix account.
Revoke new broker calls with:
  sudo rm /etc/sudoers.d/nexum-docker-agent

An upgrade requires --upgrade and the exact previously reviewed helper hash
pinned below. Any other existing installation is refused. Container data and
the scope of the sudo rule are preserved.
EOF
    exit 0
fi
upgrade_requested=false
if [[ $# == 1 && $1 == --upgrade ]]; then
    upgrade_requested=true
    shift
fi
[[ $# == 0 && $EUID == 0 ]] || die 'Run as root (sudo bash ...), optionally with --upgrade.'

expected_helper_sha256=fac56a3fe39078def53be658bb7096fe300c16149b00ce465b2e93d0e00d9665
previous_helper_sha256=8fb743445beaf76cf60a8dee6b49ff0cce8ae2a635da025e1ba7574bf237ef20
workspace='/home/footfalcon/Dokumenty/ChatGPT/nexum-core 2'
account=footfalcon
helper=/usr/local/libexec/nexum-docker-agent
sudoers=/etc/sudoers.d/nexum-docker-agent
source_file=$workspace/tools/nexum-docker-agent.py
[[ $(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P) == "$workspace" ]] \
    || die 'Run the installer from the reviewed Nexum workspace.'
[[ -f $source_file && ! -L $source_file ]] || die 'The reviewed helper source must be a regular file.'
[[ $(id -u "$account") == 1000 && $(id -g "$account") == 1000 ]] \
    || die 'The helper is pinned to footfalcon UID/GID 1000; review any identity change.'

for required in /usr/bin/docker /usr/bin/python3 /usr/sbin/visudo; do
    [[ -x $required ]] || die "Missing prerequisite: $required"
done

check_root_directory() {
    local directory=$1 mode
    [[ -d $directory && ! -L $directory ]] || die "Unsafe directory: $directory"
    [[ $(stat -c %u -- "$directory") == 0 ]] || die "Directory must be owned by root: $directory"
    mode=$(stat -c %a -- "$directory")
    (( (8#$mode & 0022) == 0 )) || die "Directory is writable by group/others: $directory"
}
for directory in / /usr /usr/local /etc; do check_root_directory "$directory"; done
for directory in /usr/local/libexec /etc/sudoers.d; do
    if [[ ! -e $directory && ! -L $directory ]]; then
        install -d -o 0 -g 0 -m 0755 -- "$directory"
    fi
    check_root_directory "$directory"
done

staging=$(mktemp -d /usr/local/libexec/.nexum-agent-install.XXXXXX)
rule_installed=false
helper_installed=false
helper_upgraded=false
complete=false
cleanup() {
    local result=$?
    if [[ $rule_installed == true && $complete == false ]]; then
        rm -f -- "$sudoers"
        printf 'Installation failed; the new sudo rule was removed.\n' >&2
    fi
    if [[ $helper_installed == true && $complete == false ]]; then
        rm -f -- "$helper"
    fi
    if [[ $helper_upgraded == true && $complete == false ]]; then
        mv -fT -- "$staging/previous-helper" "$helper"
        printf 'Upgrade failed; the previous reviewed helper was restored.\n' >&2
    fi
    rm -rf -- "$staging"
    exit "$result"
}
trap cleanup EXIT

# Validate the root-owned staged bytes, not a racy user-writable source file.
install -o 0 -g 0 -m 0755 -- "$source_file" "$staging/helper"
actual_sha256=$(sha256sum "$staging/helper")
[[ ${actual_sha256%% *} == "$expected_helper_sha256" ]] \
    || die 'Helper bytes differ from the reviewed SHA-256. Review and pin the source before installation.'
/usr/bin/python3 -I -m py_compile "$staging/helper"
cat > "$staging/sudoers" <<'EOF'
# Nexum: only the root-owned, allowlisted broker. No general Docker/shell grant.
footfalcon ALL=(root) NOPASSWD: /usr/local/libexec/nexum-docker-agent
EOF
chmod 0440 "$staging/sudoers"
/usr/sbin/visudo -cf "$staging/sudoers"

if [[ -e $helper || -L $helper || -e $sudoers || -L $sudoers ]]; then
    for existing in "$helper" "$sudoers"; do
        [[ -f $existing && ! -L $existing && $(stat -c %u -- "$existing") == 0 ]] \
            || die "Unexpected existing installation: $existing"
        mode=$(stat -c %a -- "$existing")
        (( (8#$mode & 0022) == 0 )) || die "Existing file is writable by group/others: $existing"
    done
    cmp -s -- "$staging/sudoers" "$sudoers" || die 'The existing sudo rule differs; review it separately.'
    if cmp -s -- "$staging/helper" "$helper"; then
        printf 'The exact reviewed broker and sudo rule are already installed.\n'
        complete=true
        exit 0
    fi
    [[ $upgrade_requested == true ]] || die 'The helper differs; use the reviewed --upgrade installation explicitly.'
    installed_sha256=$(sha256sum "$helper")
    [[ ${installed_sha256%% *} == "$previous_helper_sha256" ]] \
        || die 'Existing helper does not match the reviewed previous version.'
    install -o 0 -g 0 -m 0755 -- "$helper" "$staging/previous-helper"
    # Same-filesystem rename keeps the executable whole for concurrent callers.
    mv -fT -- "$staging/helper" "$helper"
    helper_upgraded=true
    /usr/sbin/visudo -c
    complete=true
    printf 'Upgraded the reviewed broker; the existing sudo rule is unchanged.\n'
    exit 0
fi

[[ $upgrade_requested == false ]] || die 'There is no existing installation to upgrade.'
install -o 0 -g 0 -m 0755 -- "$staging/helper" "$helper"
helper_installed=true
install -o 0 -g 0 -m 0440 -- "$staging/sudoers" "$sudoers"
rule_installed=true
/usr/sbin/visudo -c
complete=true
printf 'Installed reviewed Nexum broker for %s.\n' "$account"
printf 'Verify from the normal account: sudo -n %s status\n' "$helper"
