#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  tools/git-pack-repo.sh [OUTPUT]

Packs only files tracked by git from the current repository into a single
tar.gz archive. Untracked files, .git metadata, target/, and other local
artifacts are not included.

Arguments:
  OUTPUT    Output archive path.
            Default: ./nexum-core.tar.gz

Examples:
  tools/git-pack-repo.sh
  tools/git-pack-repo.sh /tmp/nexum-core-o1.tar.gz
EOF
}

if [[ "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ $# -gt 1 ]]; then
    usage >&2
    exit 1
fi

if ! command -v git >/dev/null 2>&1; then
    echo "git not found." >&2
    exit 1
fi

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "not inside a git repository." >&2
    exit 1
}

output="${1:-$repo_root/nexum-core.tar.gz}"
output_dir="$(dirname "$output")"
output_base="$(basename "$output")"

mkdir -p "$output_dir"

tmpdir="$(mktemp -d /tmp/nexum-pack.XXXXXX)"
cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT

list_file="$tmpdir/tracked-files.txt"
git -C "$repo_root" ls-files -z >"$list_file"

if [[ ! -s "$list_file" ]]; then
    echo "repository has no tracked files." >&2
    exit 1
fi

tar \
    -C "$repo_root" \
    --null \
    --files-from="$list_file" \
    -czf "$output"

echo "archive: $output"
echo "repo_root: $repo_root"
echo "tracked_files: $(git -C "$repo_root" ls-files | wc -l | tr -d ' ')"
echo "size_bytes: $(wc -c <"$output" | tr -d ' ')"
