#!/usr/bin/env bash
# Build Veriphi Python wheels for macOS, Linux, and produce the sdist.
# Prerequisites:
#   - rustup with stable toolchain plus targets:
#       rustup target add aarch64-apple-darwin x86_64-apple-darwin
#   - maturin installed in the active Python environment: pip install maturin
#   - Docker installed and running for the manylinux builds.
#   - Python 3.10+ available locally (set PYTHON_BIN to override the default).

set -euo pipefail

PYTHON_BIN="$(python -c 'import sys; print(sys.executable)')"


ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT/dist"
CARGO_MANIFEST="$ROOT/rust/veriphi-core-py/Cargo.toml"

info() {
  printf '\n==> %s\n' "$1"
}

require_bin() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: $1 is not available on PATH" >&2
    exit 1
  fi
}

test_wheel_local() {
  local wheel_path="$1"

  info "Testing wheel $(basename "$wheel_path") locally"
  local venv_dir
  venv_dir="$(mktemp -d)"
  "$PYTHON_BIN" -m venv "$venv_dir"
  source "$venv_dir/bin/activate"
  local venv_python="$venv_dir/bin/python"
  "$venv_python" -m pip install --upgrade pip >/dev/null
  "$venv_python" -m pip install "$wheel_path" >/dev/null
  "$venv_python" -m pip install pytest >/dev/null
  (cd "$ROOT" && "$venv_python" -m pytest python/tests -q)
  deactivate
  rm -rf "$venv_dir"
}

test_wheel_in_docker() {
  local wheel_glob="$1"
  local platform="$2"

  local wheel_path
  wheel_path=$(basename "$(ls "$DIST_DIR"/$wheel_glob | sort | tail -n1)")
  info "Testing $wheel_path inside $platform container"
  local docker_python="/opt/python/cp310-cp310/bin/python"
  docker run --rm --platform="$platform" -v "$ROOT":/io \
    --entrypoint bash \
    ghcr.io/pyo3/maturin:latest -c "${docker_python} -m pip install /io/dist/$wheel_path >/dev/null && ${docker_python} -m pip install pytest >/dev/null && cd /io && ${docker_python} -m pytest python/tests -q"
}

main() {
  require_bin maturin
  require_bin "$PYTHON_BIN"

  mkdir -p "$DIST_DIR"

  info "Building macOS universal2 wheel"
  maturin build --release --strip --target universal2-apple-darwin \
    -m "$CARGO_MANIFEST" --out "$DIST_DIR"
  mac_wheel=$(ls "$DIST_DIR"/veriphi_core-*-macosx*.whl | sort | tail -n1)
  test_wheel_local "$mac_wheel"

  info "Building source distribution"
  maturin sdist -m "$CARGO_MANIFEST" --out "$DIST_DIR"

  if command -v docker >/dev/null 2>&1; then
    info "Building manylinux2014 aarch64 wheel"
    docker run --rm --platform=linux/arm64 -v "$ROOT":/io \
      ghcr.io/pyo3/maturin:latest build --release --strip \
      -m /io/rust/veriphi-core-py/Cargo.toml --out /io/dist --manylinux 2014
    test_wheel_in_docker 'veriphi_core-*manylinux*_aarch64.whl' 'linux/arm64'

    info "Building manylinux2014 x86_64 wheel"
    docker run --rm --platform=linux/amd64 -v "$ROOT":/io \
      ghcr.io/pyo3/maturin:latest build --release --strip \
      -m /io/rust/veriphi-core-py/Cargo.toml --out /io/dist --manylinux 2014
    test_wheel_in_docker 'veriphi_core-*manylinux*_x86_64.whl' 'linux/amd64'
  else
    echo "Skipping manylinux wheels: Docker not found on PATH" >&2
  fi

  info "All artifacts written to $DIST_DIR"
}

main "$@"
