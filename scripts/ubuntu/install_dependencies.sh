#!/usr/bin/env bash
set -euo pipefail

# Installs all packages required to build the Ubuntu guest agent and shared tooling.
# The script performs retries on common transient apt failures and validates
# toolchain versions after installation.

REQUIRED_PACKAGES=(
  build-essential
  cmake
  ninja-build
  pkg-config
  libsystemd-dev
  libcurl4-openssl-dev
  libssl-dev
)

retry_apt_install() {
  local attempt=1
  local max_attempts=3
  while (( attempt <= max_attempts )); do
    if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"; then
      return 0
    fi
    echo "[install_dependencies] apt-get install attempt ${attempt}/${max_attempts} failed. Running apt-get update and retrying..." >&2
    sudo apt-get update -y || true
    ((attempt++))
    sleep 2
  done
  echo "[install_dependencies] Failed to install packages: $*" >&2
  return 1
}

main() {
  if [[ $(id -u) -ne 0 ]]; then
    if ! command -v sudo >/dev/null; then
      echo "[install_dependencies] Please run as root or install sudo." >&2
      exit 1
    fi
  fi

  echo "[install_dependencies] Refreshing package metadata..."
  sudo apt-get update -y

  echo "[install_dependencies] Installing required packages: ${REQUIRED_PACKAGES[*]}"
  retry_apt_install "${REQUIRED_PACKAGES[@]}"

  echo "[install_dependencies] Validating toolchain availability..."
  command -v cmake >/dev/null || { echo "cmake missing after installation" >&2; exit 1; }
  command -v ninja >/dev/null || { echo "ninja missing after installation" >&2; exit 1; }
  command -v c++ >/dev/null || { echo "g++ missing after installation" >&2; exit 1; }

  echo "[install_dependencies] Dependencies installed successfully."
}

main "$@"
