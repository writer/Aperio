#!/usr/bin/env bash
# Keep the local Aperio clone in sync with origin/main.
# Non-destructive: never touches uncommitted work, never rewrites history.

set -euo pipefail

REMOTE="origin"
BRANCH="main"

# Resolve the repository root from this script's own location so the script
# works in any clone without hardcoded paths.
script_dir="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${script_dir}/../../../.." && pwd)"

if [[ ! -d "${repo}/.git" ]]; then
  echo "aperio-sync: ${repo} is not a git repository" >&2
  exit 1
fi

cd "${repo}"

current_branch="$(git rev-parse --abbrev-ref HEAD)"
local_main_before="$(git rev-parse --verify --quiet "${BRANCH}" || echo "missing")"

if ! git fetch --prune --tags "${REMOTE}" 2>&1; then
  echo "aperio-sync: failed to fetch from ${REMOTE}" >&2
  exit 1
fi

if ! git rev-parse --verify --quiet "${REMOTE}/${BRANCH}" >/dev/null; then
  echo "aperio-sync: ${REMOTE}/${BRANCH} does not exist" >&2
  exit 1
fi

if [[ "${current_branch}" == "${BRANCH}" ]]; then
  # main is checked out: fast-forward-only pull so uncommitted work and
  # diverged history both fail loudly instead of being clobbered.
  if ! git pull --ff-only "${REMOTE}" "${BRANCH}"; then
    echo "aperio-sync: fast-forward pull failed (uncommitted changes or diverged history)" >&2
    exit 1
  fi
else
  # main is not checked out: update the local ref directly. The main:main
  # refspec refuses non-fast-forward updates, so divergent history surfaces
  # as a clear error without touching the working tree.
  if [[ "${local_main_before}" == "missing" ]]; then
    git branch "${BRANCH}" "${REMOTE}/${BRANCH}"
  else
    if ! git fetch "${REMOTE}" "${BRANCH}:${BRANCH}" 2>&1; then
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
