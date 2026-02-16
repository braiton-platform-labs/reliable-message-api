#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Reliable Message API - kind dev wrapper

Usage:
  ./scripts/dev_kind.sh up [--cluster NAME] [--workers N|auto] [--foreground] [--hosts] [--no-bootstrap] [--skip-verify]
  ./scripts/dev_kind.sh reload [--cluster NAME]
  ./scripts/dev_kind.sh verify [--cluster NAME]
  ./scripts/dev_kind.sh status [--cluster NAME]
  ./scripts/dev_kind.sh logs [--cluster NAME]
  ./scripts/dev_kind.sh down [--cluster NAME]
  ./scripts/dev_kind.sh clean [--cluster NAME]

Notes:
  - Prefer running this inside WSL (Ubuntu 22.04). It relies on the repo Makefile (POSIX shell).
  - KIND_CLUSTER_NAME / KIND_WORKERS can also be set via environment variables.
  - --hosts runs 'make dev-hosts-apply' (may require sudo inside WSL).
  - 'up' uses the Datadog-enabled flow (make dev-dd-bg/dev-dd-fg) and requires DD_API_KEY in .env.
EOF
}

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

is_wsl() {
  [ -r /proc/version ] && grep -qi microsoft /proc/version
}

require_cmd() {
  local c="$1"
  if command -v "$c" >/dev/null 2>&1; then
    return 0
  fi

  if [ "$c" = "make" ]; then
    die "missing 'make' in PATH. Recommended (Windows): powershell -ExecutionPolicy Bypass -File .\\scripts\\wsl_bootstrap.ps1  (or in WSL: sudo apt-get update && sudo apt-get install -y make)"
  fi

  die "missing '$c' in PATH"
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

cmd="${1:-up}"
shift || true

cluster="${KIND_CLUSTER_NAME:-}"
workers="${KIND_WORKERS:-}"
foreground=0
with_hosts=0
no_bootstrap=0
skip_verify=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --cluster) shift; [ "${1:-}" != "" ] || die "--cluster requires a value"; cluster="$1" ;;
    --workers) shift; [ "${1:-}" != "" ] || die "--workers requires a value"; workers="$1" ;;
    --foreground) foreground=1 ;;
    --hosts) with_hosts=1 ;;
    --no-bootstrap) no_bootstrap=1 ;;
    --skip-verify) skip_verify=1 ;;
    *) die "unknown arg: $1 (try --help)" ;;
  esac
  shift || true
done

cd "$repo_root"

if ! is_wsl; then
  say "WARN: not detected as WSL; continuing anyway."
fi

require_cmd make
require_cmd docker

if ! docker info >/dev/null 2>&1; then
  die "Docker daemon not reachable. Is Docker Desktop running and WSL integration enabled?"
fi

export KIND_CLUSTER_NAME="${cluster:-${KIND_CLUSTER_NAME:-bpl-dev}}"
if [ -n "${workers:-}" ]; then
  export KIND_WORKERS="$workers"
fi

case "$cmd" in
  up)
    if [ "$with_hosts" -eq 1 ]; then
      say "==> Applying /etc/hosts entries (api.local.dev, kong.local.dev)..."
      make dev-hosts-apply
    fi

    if [ "$no_bootstrap" -eq 0 ]; then
      say "==> Bootstrapping pinned tools into ./bin (idempotent)..."
      make bootstrap
    fi

    if [ "$foreground" -eq 1 ]; then
      say "==> Bringing up dev + Datadog (foreground port-forward)..."
      make dev-dd-fg
    else
      say "==> Bringing up dev + Datadog (background port-forward)..."
      make dev-dd-bg
    fi

    if [ "$skip_verify" -eq 0 ]; then
      say "==> Verifying cluster/proxy/health..."
      make dev-verify
    fi

    cat <<'EOF'

==> Quick test:
curl -H 'Host: api.local.dev' http://localhost:8080/health

If you access from Windows (Postman/Browser on host), also run (Admin):
make dev-hosts-apply-win
EOF
    ;;

  reload)
    make dev-reload
    ;;

  verify)
    make dev-verify
    ;;

  status)
    make dev-status
    ;;

  logs)
    make dev-logs
    ;;

  down)
    # Best-effort: stop port-forward then delete kind.
    make dev-port-stop >/dev/null 2>&1 || true
    make kind-down
    ;;

  clean)
    make dev-clean
    ;;

  *)
    usage
    die "unknown command: $cmd"
    ;;
esac
