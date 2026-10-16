#!/usr/bin/env bash
# OPS: one administrator action to add rustfmt to the existing Alpine toolchain.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    printf 'Usage: sudo bash tools/install-alpine-rustfmt.sh\nInstalls only rustfmt for Rust 1.94.0 inside the validated Alpine dev container.\n'
    exit 0
fi
[[ $# == 0 && $EUID == 0 ]] || { printf 'Run as root without arguments.\n' >&2; exit 1; }

/usr/bin/python3 -I - <<'PY'
import hashlib
import os
import runpy
import stat
import sys

broker = "/usr/local/libexec/nexum-docker-agent"
expected = "fac56a3fe39078def53be658bb7096fe300c16149b00ce465b2e93d0e00d9665"
metadata = os.stat(broker, follow_symlinks=False)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
    sys.exit("The installed broker must be a protected root-owned regular file.")
with open(broker, "rb") as source:
    if hashlib.sha256(source.read()).hexdigest() != expected:
        sys.exit("Installed broker differs from the reviewed version; review this installer first.")

api = runpy.run_path(broker)
item = api["inspect"]("dev", api["check_storage"]())
api["require"](item["State"].get("Running") is True, "Start the dev container before installing rustfmt.")

# The official Rust image allows the development user to update its toolchain.
# Run rustup as that user, never root, even during this administrator action.
# No new persistent broker operation is granted.
result = api["dev_exec"](
    item, ["/usr/local/cargo/bin/rustup", "component", "add", "--toolchain", "1.94.0", "rustfmt"],
    timeout=None,
)
if result:
    sys.exit(result)
sys.exit(api["dev_exec"](item, ["/usr/local/cargo/bin/cargo", "fmt", "--version"], timeout=60))
PY
