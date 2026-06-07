#!/usr/bin/env bash
# Install aperio-sync as an hourly systemd user timer on Linux.
# Safe to re-run: overwrites the existing unit files.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${script_dir}/../../../.." && pwd)"

SYNC_SCRIPT="${repo}/.factory/skills/aperio-sync/scripts/sync.sh"
SERVICE_TEMPLATE="${script_dir}/aperio-sync.service.template"
TIMER_TEMPLATE="${script_dir}/aperio-sync.timer.template"
USER_UNIT_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/systemd/user"
STATE_DIR="${XDG_STATE_HOME:-${HOME}/.local/state}"

if [[ ! -x "${SYNC_SCRIPT}" ]]; then
  echo "install-systemd: ${SYNC_SCRIPT} is missing or not executable" >&2
  exit 1
fi
if [[ ! -f "${SERVICE_TEMPLATE}" || ! -f "${TIMER_TEMPLATE}" ]]; then
  echo "install-systemd: service/timer template missing in ${script_dir}" >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "install-systemd: systemctl not found; this installer is Linux/systemd only" >&2
  exit 1
fi

# systemd does NOT create parent directories for append: log targets, so
# create the state and unit dirs up front.
mkdir -p "${USER_UNIT_DIR}" "${STATE_DIR}"

sed_escape() { printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g' -e 's/"/\\\\\\"/g'; }

sed -e "s|__SCRIPT_PATH__|$(sed_escape "${SYNC_SCRIPT}")|g" \
  "${SERVICE_TEMPLATE}" > "${USER_UNIT_DIR}/aperio-sync.service"

cp "${TIMER_TEMPLATE}" "${USER_UNIT_DIR}/aperio-sync.timer"

systemctl --user daemon-reload
systemctl --user enable --now aperio-sync.timer

echo "install-systemd: installed ${USER_UNIT_DIR}/aperio-sync.{service,timer}"
echo "install-systemd: hourly sync running; logs at ${STATE_DIR}/aperio-sync.log and ${STATE_DIR}/aperio-sync.err.log"
echo "install-systemd: check status with: systemctl --user status aperio-sync.timer"
echo "install-systemd: uninstall with: systemctl --user disable --now aperio-sync.timer && rm ${USER_UNIT_DIR}/aperio-sync.{service,timer}"
