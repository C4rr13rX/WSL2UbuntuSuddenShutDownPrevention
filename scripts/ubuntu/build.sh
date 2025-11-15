#!/usr/bin/env bash
set -euo pipefail

# Builds all native components for Ubuntu, including the guest agent and
# shared master report CLI. The script ensures dependencies are available and
# falls back to re-running CMake configuration when build directories change.

BUILD_TYPE=${BUILD_TYPE:-Release}
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILD_DIR=${BUILD_DIR:-"${REPO_ROOT}/build/ubuntu"}

configure() {
  echo "[build] Configuring CMake project in ${BUILD_DIR}"
  cmake -S "${REPO_ROOT}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" -G Ninja
}

main() {
  if ! command -v cmake >/dev/null || ! command -v ninja >/dev/null; then
    echo "[build] Missing required build tools. Run scripts/ubuntu/install_dependencies.sh first." >&2
    exit 1
  fi

  mkdir -p "${BUILD_DIR}"

  if [[ ! -f "${BUILD_DIR}/build.ninja" ]]; then
    configure
  fi

  echo "[build] Building targets with Ninja"
  cmake --build "${BUILD_DIR}" --config "${BUILD_TYPE}"

  echo "[build] Build completed successfully."
}

main "$@"
