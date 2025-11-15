#!/usr/bin/env bash
set -euo pipefail

# Installs the Ubuntu guest agent, shared libraries, and supporting directories
# into system locations. The script configures systemd to launch the agent on
# startup and ensures log directories exist with secure permissions.

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILD_DIR=${BUILD_DIR:-"${REPO_ROOT}/build/ubuntu"}
AGENT_BINARY="${BUILD_DIR}/ubuntu/wsl_monitor"
MASTER_REPORT_BINARY="${BUILD_DIR}/tools/master_report/master_report"
INSTALL_ROOT=${INSTALL_ROOT:-/usr/local}
BIN_DIR="${INSTALL_ROOT}/sbin"
MASTER_REPORT_TARGET="${INSTALL_ROOT}/bin/wsl-master-report"
SERVICE_UNIT=ubuntu/systemd/wsl-monitor.service
LOG_DIR=/var/log/wsl-monitor
CHAIN_STATE_DIR=${CHAIN_STATE_DIR:-/var/lib/wsl-monitor}
SECRET_TARGET=/etc/wsl-monitor/ipc.key
SECRET_SOURCE=${SECRET_SOURCE:-/mnt/c/ProgramData/WslMonitor/ipc.key}
SECRET_DIR=/etc/wsl-monitor
RUNTIME_DIR=/var/run/wsl-monitor

require_root() {
  if [[ $(id -u) -ne 0 ]]; then
    echo "[deploy] This script must run with root privileges." >&2
    exit 1
  fi
}

build_if_needed() {
  if [[ ! -x "${AGENT_BINARY}" ]]; then
    echo "[deploy] Compiled binaries not found. Triggering build..."
    BUILD_DIR="${BUILD_DIR}" BUILD_TYPE=${BUILD_TYPE:-Release} "${REPO_ROOT}/scripts/ubuntu/build.sh"
  fi
}

install_binary() {
  echo "[deploy] Installing guest agent to ${BIN_DIR}/wsl-monitor"
  if [[ ! -x "${AGENT_BINARY}" ]]; then
    echo "[deploy] Guest agent binary missing after build. Expected at ${AGENT_BINARY}." >&2
    exit 1
  fi

  install -D -m 0750 "${AGENT_BINARY}" "${BIN_DIR}/wsl-monitor"

  if [[ -x "${MASTER_REPORT_BINARY}" ]]; then
    echo "[deploy] Installing master_report CLI to ${MASTER_REPORT_TARGET}"
    install -D -m 0755 "${MASTER_REPORT_BINARY}" "${MASTER_REPORT_TARGET}"
  fi
}

prepare_directories() {
  echo "[deploy] Preparing log directory at ${LOG_DIR}"
  install -d -m 0750 -o root -g root "${LOG_DIR}"

  echo "[deploy] Preparing chain state directory at ${CHAIN_STATE_DIR}"
  install -d -m 0750 -o root -g root "${CHAIN_STATE_DIR}"

  echo "[deploy] Preparing IPC secret directory at ${SECRET_DIR}"
  install -d -m 0750 -o root -g root "${SECRET_DIR}"

  echo "[deploy] Preparing runtime directory at ${RUNTIME_DIR}"
  install -d -m 0750 -o root -g root "${RUNTIME_DIR}"
}

sync_secret() {
  if [[ -f "${SECRET_SOURCE}" ]]; then
    echo "[deploy] Syncing IPC secret from Windows host"
    install -m 0640 -o root -g root "${SECRET_SOURCE}" "${SECRET_TARGET}"
  else
    echo "[deploy] Generating new IPC secret"
    head -c 32 /dev/urandom > "${SECRET_TARGET}.tmp"
    install -m 0640 -o root -g root "${SECRET_TARGET}.tmp" "${SECRET_TARGET}"
    rm -f "${SECRET_TARGET}.tmp"
    if [[ -d "/mnt/c/ProgramData/WslMonitor" ]]; then
      echo "[deploy] Writing IPC secret to Windows share"
      cp "${SECRET_TARGET}" "${SECRET_SOURCE}" 2>/dev/null || true
      chmod 0640 "${SECRET_SOURCE}" 2>/dev/null || true
    fi
  fi
}

install_service() {
  echo "[deploy] Installing systemd unit"
  install -D -m 0644 "${REPO_ROOT}/${SERVICE_UNIT}" \
    "/etc/systemd/system/wsl-monitor.service"

  if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
    echo "[deploy] Reloading systemd daemon"
    systemctl daemon-reload

    echo "[deploy] Enabling and starting wsl-monitor.service"
    systemctl enable --now wsl-monitor.service
  else
    cat <<'EOF'
[deploy] systemd is not active in this environment. The unit file has been installed
[deploy] but was not enabled automatically. To launch the agent manually, execute:
[deploy]   sudo /usr/local/sbin/wsl-monitor
[deploy] Once systemd is available, run:
[deploy]   sudo systemctl enable --now wsl-monitor.service
EOF
  fi
}

main() {
  require_root
  build_if_needed
  install_binary
  prepare_directories
  sync_secret
  install_service
  echo "[deploy] Deployment completed successfully."
}

main "$@"
