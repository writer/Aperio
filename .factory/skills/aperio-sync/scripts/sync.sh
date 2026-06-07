#!/usr/bin/env bash
# Keep the local Aperio clone in sync with origin/main.
# Non-destructive: never touches uncommitted work, never rewrites history.
# Worktree-aware: if main is checked out in another worktree, this script
# fast-forwards that worktree instead of trying to update a checked-out ref.

set -euo pipefail

REMOTE="origin"
BRANCH="main"

# Resolve the repository root from this script's own location so the script
# works in any clone without hardcoded paths.
script_dir="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${script_dir}/../../../.." && pwd)"

# Use git's own check, which works for both regular checkouts and linked
# worktrees (where ${repo}/.git is a file, not a directory).
if ! git -C "${repo}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "aperio-sync: ${repo} is not a git work tree" >&2
  exit 1
fi

cd "${repo}"

local_main_before="$(git rev-parse --verify --quiet "${BRANCH}" || echo "missing")"

# Let git's own diagnostics go to stderr so launchd / systemd log routing
# works as advertised; the `if !` check still detects non-zero exit codes.
if ! git fetch --prune --tags "${REMOTE}"; then
  echo "aperio-sync: failed to fetch from ${REMOTE}" >&2
  exit 1
fi

if ! git rev-parse --verify --quiet "${REMOTE}/${BRANCH}" >/dev/null; then
  echo "aperio-sync: ${REMOTE}/${BRANCH} does not exist" >&2
  exit 1
fi

# Find which worktree (if any) currently has BRANCH checked out. git refuses
# to update any branch checked out in a linked worktree, so we must locate
# it and pull there instead.
main_worktree=""
current_worktree=""
while IFS= read -r line; do
  case "${line}" in
    "worktree "*) current_worktree="${line#worktree }" ;;
    "branch refs/heads/${BRANCH}") main_worktree="${current_worktree}"; break ;;
  esac
done < <(git worktree list --porcelain)

if [[ -n "${main_worktree}" ]]; then
  # main is checked out somewhere -- pull there with --ff-only so uncommitted
  # work and divergence both fail loudly instead of being clobbered.
  if ! git -C "${main_worktree}" pull --ff-only "${REMOTE}" "${BRANCH}"; then
    echo "aperio-sync: fast-forward pull in ${main_worktree} failed (uncommitted changes or diverged history)" >&2
    exit 1
  fi
else
  # main is not checked out anywhere -- update the local ref directly. The
  # main:main refspec refuses non-fast-forward updates, so divergent history
  # surfaces as a clear error without touching any working tree.
  if [[ "${local_main_before}" == "missing" ]]; then
    git branch "${BRANCH}" "${REMOTE}/${BRANCH}"
  else
    if ! git fetch "${REMOTE}" "${BRANCH}:${BRANCH}"; then
      echo "aperio-sync: local ${BRANCH} has diverged from ${REMOTE}/${BRANCH}; resolve manually" >&2
      exit 1
    fi
  fi
fi

local_main_after="$(git rev-parse --verify "${BRANCH}")"

if [[ "${local_main_before}" == "${local_main_after}" ]]; then
  echo "aperio-sync: already up to date at $(git rev-parse --short "${BRANCH}") on branch ${BRANCH}"
  exit 0
fi

if [[ "${local_main_before}" == "missing" ]]; then
  echo "aperio-sync: created local ${BRANCH} at $(git rev-parse --short "${BRANCH}")"
  exit 0
fi

count="$(git rev-list --count "${local_main_before}..${local_main_after}")"
echo "aperio-sync: fast-forwarded ${BRANCH} $(git rev-parse --short "${local_main_before}") -> $(git rev-parse --short "${local_main_after}") (${count} commits)"
