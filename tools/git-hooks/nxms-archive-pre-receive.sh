#!/usr/bin/env bash
set -euo pipefail

archive_dir="$(git rev-parse --git-dir)"
guard_dir="$archive_dir/nxms-guard"
allow_file="$guard_dir/allow_rewrite_once"
allow_rewrite=0

is_zero_oid() {
    local oid="$1"
    [[ "$oid" =~ ^0+$ ]]
}

if [[ -f "$allow_file" ]]; then
    expiry="$(tr -d '[:space:]' <"$allow_file" || true)"
    now="$(date +%s)"
    if [[ -n "$expiry" && "$expiry" =~ ^[0-9]+$ && "$expiry" -ge "$now" ]]; then
        allow_rewrite=1
    fi
    rm -f "$allow_file"
fi

while read -r old_oid new_oid ref_name; do
    if is_zero_oid "$old_oid"; then
        continue
    fi

    if is_zero_oid "$new_oid"; then
        if [[ "$allow_rewrite" -eq 1 ]]; then
            continue
        fi
        echo "nxms archive rejected deletion of $ref_name" >&2
        echo "Use ./tools/nxms-archive-guard.sh force-push <refspec> after setting a rewrite secret." >&2
        exit 1
    fi

    if git merge-base --is-ancestor "$old_oid" "$new_oid"; then
        continue
    fi

    if [[ "$allow_rewrite" -eq 1 ]]; then
        continue
    fi

    echo "nxms archive rejected non-fast-forward update of $ref_name" >&2
    echo "Use ./tools/nxms-archive-guard.sh force-push <refspec> after setting a rewrite secret." >&2
    exit 1
done
