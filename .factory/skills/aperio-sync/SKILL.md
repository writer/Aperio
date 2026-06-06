---
name: aperio-sync
description: Keep the local clone of this Aperio repository in sync with origin/main. Use whenever the user asks to pull, refresh, update, or sync the Aperio repo, or when working in the repo and the local main branch may be stale.
---

# Aperio sync

## Purpose

Keep the local clone of this Aperio repository continuously aligned with `origin/main`. The skill does a safe, non-destructive fetch + fast-forward update — it never rewrites history, never touches uncommitted work, and never overwrites a checked-out feature branch.

## When to use this skill

Invoke whenever:

- The user asks to **pull**, **refresh**, **update**, or **sync** the Aperio repo.
- The user mentions that someone else (or a CI bot) pushed to `origin`.
- The user starts a new task inside the repo and the local `main` may be stale.
- The user reports "git pull", "behind origin", or "out of date" symptoms locally.
- A scheduled launchd / cron job triggers (see [Scheduled invocation](#scheduled-invocation) below).

Do NOT use this skill to:

- Push local commits to GitHub (do that explicitly via PR workflows).
- Resolve merge conflicts (the script refuses non-fast-forward updates and surfaces them for manual handling).
- Mirror anything from a separate upstream into this repo.

## How it works

The companion script `scripts/sync.sh` performs:

1. Resolves the repository root from its own location (`<repo>/.factory/skills/aperio-sync/scripts/sync.sh` → `<repo>`), so it works in any clone without hardcoded paths.
2. `git fetch --prune --tags origin`
3. If the working tree is on a branch **other than** `main`, it updates the local `main` ref **without** checking it out, using `git fetch origin main:main` (refuses on non-fast-forward).
4. If `main` is currently checked out, it runs `git pull --ff-only origin main`.
5. Logs the before → after commit SHAs and the number of pulled commits.

The script is idempotent — running it twice in a row is safe. It never touches uncommitted files, never force-pushes, and never deletes branches.

## Manual invocation

From any working directory:

```bash
bash "$(git rev-parse --show-toplevel)/.factory/skills/aperio-sync/scripts/sync.sh"
```

Or from the repo root:

```bash
.factory/skills/aperio-sync/scripts/sync.sh
```

## Scheduled invocation

### macOS (launchd)

The template at `scripts/com.aperio.sync.plist.template` runs the script every hour. Substitute your absolute paths and install it as a per-user LaunchAgent:

```bash
TEMPLATE=".factory/skills/aperio-sync/scripts/com.aperio.sync.plist.template"
TARGET="$HOME/Library/LaunchAgents/com.aperio.sync.plist"

sed \
  -e "s|__SCRIPT_PATH__|$(pwd)/.factory/skills/aperio-sync/scripts/sync.sh|g" \
  -e "s|__LOG_DIR__|$HOME/Library/Logs|g" \
  -e "s|__HOME__|$HOME|g" \
  "$TEMPLATE" > "$TARGET"

launchctl load -w "$TARGET"
```

To uninstall:

```bash
launchctl unload -w ~/Library/LaunchAgents/com.aperio.sync.plist
rm ~/Library/LaunchAgents/com.aperio.sync.plist
```

Logs land at `~/Library/Logs/aperio-sync.log` (stdout) and `~/Library/Logs/aperio-sync.err.log` (stderr).

### Linux (systemd user timer)

The template at `scripts/aperio-sync.service.template` + `scripts/aperio-sync.timer.template` runs the script every hour. Substitute your absolute path and install:

```bash
mkdir -p ~/.config/systemd/user

REPO="$(git rev-parse --show-toplevel)"

sed "s|__SCRIPT_PATH__|$REPO/.factory/skills/aperio-sync/scripts/sync.sh|g" \
  "$REPO/.factory/skills/aperio-sync/scripts/aperio-sync.service.template" \
  > ~/.config/systemd/user/aperio-sync.service

cp "$REPO/.factory/skills/aperio-sync/scripts/aperio-sync.timer.template" \
   ~/.config/systemd/user/aperio-sync.timer

systemctl --user daemon-reload
systemctl --user enable --now aperio-sync.timer
```

### cron (portable fallback)

```bash
( crontab -l 2>/dev/null; \
  echo "0 * * * * /bin/bash $(pwd)/.factory/skills/aperio-sync/scripts/sync.sh >> $HOME/.aperio-sync.log 2>&1" \
) | crontab -
```

## Inputs

- None. The script discovers the repo root from its own filesystem location.

## Outputs

- Stdout: a one-line "already up to date" message, or a "fast-forwarded `abc1234` → `def5678` (N commits)" summary.
- Exit code `0` on success or "already up to date".
- Exit code `1` if the remote is unreachable, the local repo has uncommitted changes blocking a checked-out `main` pull, or the update would not be a fast-forward (history diverged).

## When invoked by Droid

Run the script, then summarize the result in 1–2 lines: whether the repo was already up to date, or how many commits were pulled and the new HEAD SHA. If the script exits non-zero, surface the exact stderr so the user knows whether it was a network issue, uncommitted changes, or divergent history.
