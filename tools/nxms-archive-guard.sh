#!/usr/bin/env bash
set -euo pipefail

ARCHIVE_REMOTE_DEFAULT="archive"
ARCHIVE_DIR_DEFAULT=".git-archive"
ALLOW_REWRITE_WINDOW_SECS=60

usage() {
    cat <<'EOF'
Usage:
  tools/nxms-archive-guard.sh init [archive_dir]
  tools/nxms-archive-guard.sh status
  tools/nxms-archive-guard.sh auto-push
  tools/nxms-archive-guard.sh set-secret
  tools/nxms-archive-guard.sh allow-rewrite
  tools/nxms-archive-guard.sh force-push <refspec>...

Environment:
  NXMS_ARCHIVE_SECRET   Optional non-interactive secret source for set-secret/allow-rewrite/force-push.
EOF
}

repo_root() {
    git rev-parse --show-toplevel
}

archive_remote() {
    git config --local --get nxms.archiveRemote 2>/dev/null || echo "$ARCHIVE_REMOTE_DEFAULT"
}

archive_dir() {
    local root
    root="$(repo_root)"
    local configured
    configured="$(git config --local --get nxms.archivePath 2>/dev/null || true)"
    if [[ -n "$configured" ]]; then
        echo "$configured"
    else
        echo "$root/$ARCHIVE_DIR_DEFAULT"
    fi
}

guard_dir() {
    echo "$(archive_dir)/nxms-guard"
}

secret_file() {
    echo "$(guard_dir)/rewrite_secret.sha256"
}

allow_file() {
    echo "$(guard_dir)/allow_rewrite_once"
}

ensure_repo() {
    git rev-parse --is-inside-work-tree >/dev/null
}

ensure_archive_initialized() {
    local dir
    dir="$(archive_dir)"
    if [[ ! -d "$dir" ]]; then
        echo "nxms archive is not initialized: $dir" >&2
        echo "Run: ./tools/nxms-archive-guard.sh init" >&2
        exit 1
    fi
}

install_archive_hook() {
    local root dir
    root="$(repo_root)"
    dir="$(archive_dir)"
    install -d -m 0700 "$dir/hooks"
    install -m 0755 \
        "$root/tools/git-hooks/nxms-archive-pre-receive.sh" \
        "$dir/hooks/pre-receive"
}

configure_archive_repo() {
    local dir
    dir="$(archive_dir)"
    git -C "$dir" config receive.denyDeletes true
    git -C "$dir" config receive.denyNonFastforwards true
    git -C "$dir" config core.logallrefupdates true
    git -C "$dir" config gc.reflogExpire never
    git -C "$dir" config gc.reflogExpireUnreachable never
    git -C "$dir" config gc.pruneExpire never
    install -d -m 0700 "$(guard_dir)"
    install_archive_hook
}

configure_worktree_repo() {
    local remote dir
    remote="$(archive_remote)"
    dir="$(archive_dir)"
    git config --local core.hooksPath .githooks
    git config --local nxms.archiveRemote "$remote"
    git config --local nxms.archivePath "$dir"
    if git remote get-url "$remote" >/dev/null 2>&1; then
        git remote set-url "$remote" "$dir"
    else
        git remote add "$remote" "$dir"
    fi
}

current_branch() {
    git symbolic-ref --quiet --short HEAD 2>/dev/null || true
}

archive_refspec() {
    local branch
    branch="$(current_branch)"
    if [[ -z "$branch" ]]; then
        return 1
    fi
    echo "HEAD:refs/heads/$branch"
}

push_to_archive() {
    local remote refspec
    remote="$(archive_remote)"
    refspec="$(archive_refspec)" || return 0
    if ! git remote get-url "$remote" >/dev/null 2>&1; then
        return 0
    fi
    git push --quiet "$remote" "$refspec"
}

hash_secret() {
    sha256sum | awk '{print $1}'
}

read_secret_once() {
    if [[ -n "${NXMS_ARCHIVE_SECRET:-}" ]]; then
        printf '%s' "$NXMS_ARCHIVE_SECRET"
        return 0
    fi
    if [[ ! -t 0 ]]; then
        echo "NXMS_ARCHIVE_SECRET is required in non-interactive mode." >&2
        exit 1
    fi
    local secret
    read -r -s -p "Archive rewrite secret: " secret
    echo >&2
    printf '%s' "$secret"
}

read_secret_twice() {
    if [[ -n "${NXMS_ARCHIVE_SECRET:-}" ]]; then
        printf '%s' "$NXMS_ARCHIVE_SECRET"
        return 0
    fi
    if [[ ! -t 0 ]]; then
        echo "NXMS_ARCHIVE_SECRET is required in non-interactive mode." >&2
        exit 1
    fi
    local first second
    read -r -s -p "New archive rewrite secret: " first
    echo >&2
    read -r -s -p "Repeat archive rewrite secret: " second
    echo >&2
    if [[ "$first" != "$second" ]]; then
        echo "Secrets do not match." >&2
        exit 1
    fi
    printf '%s' "$first"
}

verify_secret() {
    local secret hash expected
    if [[ ! -f "$(secret_file)" ]]; then
        echo "Archive rewrite secret is not configured yet." >&2
        echo "Run: ./tools/nxms-archive-guard.sh set-secret" >&2
        exit 1
    fi
    secret="$(read_secret_once)"
    hash="$(printf '%s' "$secret" | hash_secret)"
    expected="$(tr -d '[:space:]' <"$(secret_file)")"
    if [[ "$hash" != "$expected" ]]; then
        echo "Archive rewrite secret is invalid." >&2
        exit 1
    fi
}

cmd_init() {
    local dir
    dir="${1:-$(archive_dir)}"
    if [[ ! -d "$dir" ]]; then
        git init --bare --initial-branch=main "$dir" >/dev/null
    fi
    git config --local nxms.archivePath "$dir"
    configure_archive_repo
    configure_worktree_repo
    push_to_archive || true
    if git -C "$dir" show-ref --verify --quiet refs/heads/main; then
        git -C "$dir" symbolic-ref HEAD refs/heads/main
    fi
    echo "Initialized append-only archive at $dir"
}

cmd_status() {
    local dir remote branch
    dir="$(archive_dir)"
    remote="$(archive_remote)"
    branch="$(current_branch)"
    echo "archive_remote=$remote"
    echo "archive_dir=$dir"
    echo "hooks_path=$(git config --local --get core.hooksPath 2>/dev/null || echo '<unset>')"
    echo "current_branch=${branch:-<detached>}"
    if [[ -f "$(secret_file)" ]]; then
        echo "rewrite_secret=configured"
    else
        echo "rewrite_secret=unset"
    fi
}

cmd_auto_push() {
    if ! git config --local --get nxms.archivePath >/dev/null 2>&1; then
        exit 0
    fi
    if push_to_archive; then
        exit 0
    fi
    echo "warning: append-only archive push failed; local history may be ahead of archive" >&2
    echo "warning: inspect with ./tools/nxms-archive-guard.sh status" >&2
    exit 0
}

cmd_set_secret() {
    ensure_archive_initialized
    local secret hash
    secret="$(read_secret_twice)"
    hash="$(printf '%s' "$secret" | hash_secret)"
    install -d -m 0700 "$(guard_dir)"
    umask 077
    printf '%s\n' "$hash" >"$(secret_file)"
    chmod 0600 "$(secret_file)"
    echo "Archive rewrite secret configured."
}

cmd_allow_rewrite() {
    ensure_archive_initialized
    verify_secret
    local expiry
    expiry="$(( $(date +%s) + ALLOW_REWRITE_WINDOW_SECS ))"
    umask 077
    printf '%s\n' "$expiry" >"$(allow_file)"
    chmod 0600 "$(allow_file)"
    echo "Archive rewrite window opened for ${ALLOW_REWRITE_WINDOW_SECS}s."
}

cmd_force_push() {
    ensure_archive_initialized
    if [[ "$#" -eq 0 ]]; then
        echo "force-push requires at least one refspec." >&2
        exit 1
    fi
    cmd_allow_rewrite
    git push --force "$(archive_remote)" "$@"
}

main() {
    ensure_repo
    local cmd="${1:-}"
    shift || true
    case "$cmd" in
        init) cmd_init "$@" ;;
        status) cmd_status ;;
        auto-push) cmd_auto_push ;;
        set-secret) cmd_set_secret ;;
        allow-rewrite) cmd_allow_rewrite ;;
        force-push) cmd_force_push "$@" ;;
        ""|-h|--help|help) usage ;;
        *)
            echo "Unknown command: $cmd" >&2
            usage >&2
            exit 1
            ;;
    esac
}

main "$@"
