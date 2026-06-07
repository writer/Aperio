---
name: aperio-sync
description: Keep the local clone of this Aperio repository in sync with origin/main. Use whenever the user asks to pull, refresh, update, or sync the Aperio repo, or when working in the repo and the local main branch may be stale.
---

# Aperio sync

## Purpose

Keep the local clone of this Aperio repository continuously aligned with `origin/main`. The skill does a safe, non-destructive fetch + fast-forward update — it never rewrites history, never touches uncommitted work, and never overwrites a checked-out feature branch. It is also worktree-aware: if `main` is checked out in another `git worktree`, the script fast-forwards that worktree instead of trying to update a checked-out ref.

## When to use this skill

Invoke whenever:

- The user asks to **pull**, **refresh**, **update**, or **sync** the Aperio repo.
- The user mentions that someone else (or a CI bot) pushed to `origin`.
- The user starts a new task inside the repo and the local `main` may be stale.
- The user reports "git pull", "behind origin", or "out of date" symptoms locally.
- A scheduled launchd / systemd job triggers (see [Scheduled invocation](#scheduled-invocation) below).

Do NOT use this skill to:

- Push local commits to GitHub (do that explicitly via PR workflows).
- Resolve merge conflicts (the script refuses non-fast-forward updates and surfaces them for manual handling).
- Mirror anything from a separate upstream into this repo.

## How it works

The companion script `scripts/sync.sh` performs:

1. Resolves the repository root from its own filesystem location, so it works in any clone (including linked worktrees) without hardcoded paths.
2. Verifies the resolved path with `git rev-parse --is-inside-work-tree` (this also succeeds in worktrees where `.git` is a file rather than a directory).
3. `git fetch --prune --tags origin`
4. Enumerates `git worktree list --porcelain` to find any worktree that currently has `main` checked out.
   - If one exists, runs `git -C <that worktree> pull --ff-only origin main` there.
   - Otherwise, runs `git fetch origin main:main` to update the local `main` ref directly — this refspec **refuses non-fast-forward updates**, so divergent history surfaces as a clear error.
5. Logs a one-line summary on stdout (`already up to date` or `fast-forwarded abc1234 -> def5678 (N commits)`). Git's own progress and any failure reasons stay on stderr, so launchd / systemd log routing works as advertised.

The script is idempotent — running it twice in a row is safe. It never force-pushes, never resets, never touches your working tree on other branches.

## Inputs

- None. The script discovers the repo root from its own filesystem location.

## Outputs

- Stdout: a one-line "already up to date" message, or a "fast-forwarded `abc1234` → `def5678` (N commits)" summary.
- Stderr: git's own fetch/pull diagnostics, plus any failure message.
- Exit code `0` on success or "already up to date".
- Exit code `1` if the remote is unreachable, the fast-forward pull fails because of uncommitted changes, or the update would not be a fast-forward (history diverged).

## Manual invocation

`cd` into your Aperio clone first, then run the script with its repo-relative path:

```bash
cd /path/to/your/Aperio
.factory/skills/aperio-sync/scripts/sync.sh
```

The script self-locates regardless of the caller's current directory, so passing the absolute path from anywhere also works:

```bash
bash /path/to/your/Aperio/.factory/skills/aperio-sync/scripts/sync.sh
```

## Scheduled invocation

Two installers are provided. Both compute the script path from their own filesystem location, escape `&`/`\`/`|` in paths before templating, create the directories systemd/launchd will not create on their own, and are safe to re-run.

### macOS (launchd, hourly)

```bash
cd /path/to/your/Aperio
.factory/skills/aperio-sync/scripts/install-launchd.sh
```

This installs `~/Library/LaunchAgents/com.aperio.sync.plist` and loads it. Logs land at `~/Library/Logs/aperio-sync.log` (stdout, sync summaries) and `~/Library/Logs/aperio-sync.err.log` (stderr, git diagnostics and failures).

Uninstall:

```bash
launchctl unload -w ~/Library/LaunchAgents/com.aperio.sync.plist
rm ~/Library/LaunchAgents/com.aperio.sync.plist
```

### Linux (systemd user timer, hourly)

```bash
cd /path/to/your/Aperio
.factory/skills/aperio-sync/scripts/install-systemd.sh
```

This creates `~/.local/state/` if needed (systemd does not auto-create parent directories for `StandardOutput=append:` targets), installs `~/.config/systemd/user/aperio-sync.{service,timer}`, reloads the user daemon, and enables the timer. Logs land at `~/.local/state/aperio-sync.log` and `~/.local/state/aperio-sync.err.log` (or `$XDG_STATE_HOME` if set).

Check status:

```bash
systemctl --user status aperio-sync.timer
journalctl --user -u aperio-sync.service
```

Uninstall:

```bash
systemctl --user disable --now aperio-sync.timer
rm ~/.config/systemd/user/aperio-sync.{service,timer}
```

### cron (portable fallback)

```bash
cd /path/to/your/Aperio
( crontab -l 2>/dev/null; \
  echo "0 * * * * /bin/bash $(pwd)/.factory/skills/aperio-sync/scripts/sync.sh >> $HOME/.aperio-sync.log 2>&1" \
) | crontab -
```

## When invoked by Droid

Run the script, then summarize the result in 1–2 lines: whether the repo was already up to date, or how many commits were pulled and the new HEAD SHA. If the script exits non-zero, surface the exact stderr so the user knows whether it was a network issue, uncommitted changes, divergent history, or a fast-forward failure in a worktree.
