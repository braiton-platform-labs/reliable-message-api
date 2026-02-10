#!/usr/bin/env bash
set -euo pipefail

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

cd "${repo_root}"

if ! command -v make >/dev/null 2>&1; then
  die "missing 'make' in WSL. Run from Windows: powershell -ExecutionPolicy Bypass -File .\\scripts\\wsl_bootstrap.ps1"
fi

say "==> Bootstrapping pinned tools into ./bin (WSL, no sudo; idempotent)..."

# Keep this non-interactive and repo-local by default.
export BOOTSTRAP_INSTALL_MODE="${BOOTSTRAP_INSTALL_MODE:-local}"
export BOOTSTRAP_ENFORCE_GLOBAL_BIN="${BOOTSTRAP_ENFORCE_GLOBAL_BIN:-0}"
export BOOTSTRAP_APT_MAINTENANCE="${BOOTSTRAP_APT_MAINTENANCE:-0}"
export BOOTSTRAP_TUNE_SYSCTL="${BOOTSTRAP_TUNE_SYSCTL:-0}"
export BOOTSTRAP_SYSCTL_PERSIST="${BOOTSTRAP_SYSCTL_PERSIST:-0}"
export BOOTSTRAP_AUTO_CONFIRM="${BOOTSTRAP_AUTO_CONFIRM:-1}"

# In WSL + Docker Desktop, docker might not be running at the time the bootstrap is executed.
# We still want to install kubectl/kind/jq/etc and let dev_kind fail later with a clearer message.
export BOOTSTRAP_DOCKER_REQUIRED="${BOOTSTRAP_DOCKER_REQUIRED:-0}"

chmod +x setup/ubuntu-22.04/setup.sh >/dev/null 2>&1 || true
./setup/ubuntu-22.04/setup.sh bootstrap

# Make repo-local tools visible to the current process (bootstrap modifies PATH only in its own process).
export PATH="${repo_root}/bin:${PATH}"

say
say "==> Toolchain check (doctor):"
./setup/ubuntu-22.04/setup.sh doctor || true

say
say "==> Next:"
say "  powershell -ExecutionPolicy Bypass -File .\\scripts\\dev_kind.ps1 up"
