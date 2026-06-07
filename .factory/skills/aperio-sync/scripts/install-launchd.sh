#!/usr/bin/env bash
# Install aperio-sync as an hourly macOS LaunchAgent.
# Generates the plist programmatically via plistlib so paths containing
# &, <, >, ', " survive correctly (sed templating of an XML plist does not
# guarantee that). Safe to re-run: replaces the existing agent if installed.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${script_dir}/../../../.." && pwd)"

SYNC_SCRIPT="${repo}/.factory/skills/aperio-sync/scripts/sync.sh"
TARGET="${HOME}/Library/LaunchAgents/com.aperio.sync.plist"
LOG_DIR="${HOME}/Library/Logs"
AGENT_DIR="$(dirname "${TARGET}")"

if [[ ! -x "${SYNC_SCRIPT}" ]]; then
  echo "install-launchd: ${SYNC_SCRIPT} is missing or not executable" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "install-launchd: python3 is required (preinstalled on macOS 12.3+)" >&2
  exit 1
fi
if ! command -v launchctl >/dev/null 2>&1; then
  echo "install-launchd: launchctl not found; this installer is macOS only" >&2
  exit 1
fi

mkdir -p "${LOG_DIR}" "${AGENT_DIR}"

python3 - "${SYNC_SCRIPT}" "${LOG_DIR}" "${HOME}" "${TARGET}" <<'PY'
import os
import plistlib
import sys

sync_script, log_dir, home, target = sys.argv[1:5]
plist = {
    "Label": "com.aperio.sync",
    "ProgramArguments": ["/bin/bash", sync_script],
    "StartInterval": 3600,
    "RunAtLoad": True,
    "StandardOutPath": os.path.join(log_dir, "aperio-sync.log"),
    "StandardErrorPath": os.path.join(log_dir, "aperio-sync.err.log"),
    "EnvironmentVariables": {
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        "HOME": home,
    },
}
with open(target, "wb") as out:
    plistlib.dump(plist, out)
PY

# Reload cleanly if already loaded.
launchctl unload "${TARGET}" >/dev/null 2>&1 || true
launchctl load -w "${TARGET}"

echo "install-launchd: installed ${TARGET}"
echo "install-launchd: hourly sync running; logs at ${LOG_DIR}/aperio-sync.log and ${LOG_DIR}/aperio-sync.err.log"
echo "install-launchd: uninstall with: launchctl unload -w '${TARGET}' && rm '${TARGET}'"
