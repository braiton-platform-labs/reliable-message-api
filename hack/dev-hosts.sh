#!/usr/bin/env bash
set -euo pipefail

# Idempotent /etc/hosts management for local dev.
# We only manage a clearly delimited block to avoid touching unrelated entries.

HOSTS_FILE="${HOSTS_FILE:-/etc/hosts}"

BEGIN_MARKER="# BEGIN reliable-message-api dev"
END_MARKER="# END reliable-message-api dev"

ENTRIES=(
  "127.0.0.1 api.local.dev"
  "127.0.0.1 kong.local.dev"
)

usage() {
  cat <<'EOF'
Usage: hack/dev-hosts.sh <command>

Commands:
  status   Show whether the dev block exists and current name resolution.
  apply    Add/replace the dev block in /etc/hosts (requires sudo).
  remove   Remove the dev block from /etc/hosts (requires sudo).

Environment:
  HOSTS_FILE  Override hosts file path (default: /etc/hosts)
EOF
}

need_root_or_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    exec sudo HOSTS_FILE="${HOSTS_FILE}" "$0" "$@"
  fi
  echo "ERROR: requires root to modify ${HOSTS_FILE} (sudo not found)." >&2
  exit 1
}

strip_block() {
  awk -v begin="${BEGIN_MARKER}" -v end="${END_MARKER}" '
    $0 == begin {inblock=1; next}
    $0 == end {inblock=0; next}
    !inblock {print}
  ' "${HOSTS_FILE}"
}

check_conflicts() {
  # Fail if api.local.dev or kong.local.dev already map to a non-local IP outside our block.
  awk -v begin="${BEGIN_MARKER}" -v end="${END_MARKER}" '
    $0 == begin {inblock=1; next}
    $0 == end {inblock=0; next}
    inblock {next}
    {
      line=$0
      sub(/#.*/, "", line)
      if (line ~ /^[[:space:]]*$/) next
      n=split(line, a, /[[:space:]]+/)
      ip=a[1]
      for (i=2; i<=n; i++) {
        if (a[i] == "api.local.dev" || a[i] == "kong.local.dev") {
          if (ip != "127.0.0.1") {
            print $0
          }
        }
      }
    }
  ' "${HOSTS_FILE}"
}

cmd="${1:-}"
case "${cmd}" in
  status)
    if [ ! -f "${HOSTS_FILE}" ]; then
      echo "ERROR: hosts file not found: ${HOSTS_FILE}" >&2
      exit 1
    fi
    if grep -Fq "${BEGIN_MARKER}" "${HOSTS_FILE}" 2>/dev/null; then
      echo "hosts block: present"
    else
      echo "hosts block: missing"
    fi
    if command -v getent >/dev/null 2>&1; then
      echo
      echo "Resolution:"
      getent hosts api.local.dev || true
      getent hosts kong.local.dev || true
    else
      echo
      echo "Resolution: getent not found (skip)"
    fi
    ;;

  apply)
    if [ ! -f "${HOSTS_FILE}" ]; then
      echo "ERROR: hosts file not found: ${HOSTS_FILE}" >&2
      exit 1
    fi
    need_root_or_sudo apply

    conflicts="$(check_conflicts || true)"
    if [ -n "${conflicts}" ]; then
      echo "ERROR: found conflicting entries for api.local.dev/kong.local.dev in ${HOSTS_FILE}:" >&2
      echo "${conflicts}" >&2
      echo "Fix the conflict (or remove those lines) and retry." >&2
      exit 1
    fi

    backup="${HOSTS_FILE}.bak.reliable-message-api.$(date +%s)"
    cp -f "${HOSTS_FILE}" "${backup}"

    tmp="$(mktemp)"
    strip_block >"${tmp}"
    {
      echo
      echo "${BEGIN_MARKER}"
      for entry in "${ENTRIES[@]}"; do
        echo "${entry}"
      done
      echo "${END_MARKER}"
      echo
    } >>"${tmp}"

    cat "${tmp}" >"${HOSTS_FILE}"
    rm -f "${tmp}"

    echo "Updated ${HOSTS_FILE}"
    echo "Backup: ${backup}"
    ;;

  remove)
    if [ ! -f "${HOSTS_FILE}" ]; then
      echo "ERROR: hosts file not found: ${HOSTS_FILE}" >&2
      exit 1
    fi
    need_root_or_sudo remove

    if ! grep -Fq "${BEGIN_MARKER}" "${HOSTS_FILE}" 2>/dev/null; then
      echo "No dev block found in ${HOSTS_FILE} (nothing to do)."
      exit 0
    fi

    backup="${HOSTS_FILE}.bak.reliable-message-api.$(date +%s)"
    cp -f "${HOSTS_FILE}" "${backup}"

    tmp="$(mktemp)"
    strip_block >"${tmp}"
    cat "${tmp}" >"${HOSTS_FILE}"
    rm -f "${tmp}"

    echo "Removed dev block from ${HOSTS_FILE}"
    echo "Backup: ${backup}"
    ;;

  -h|--help|help|"")
    usage
    exit 0
    ;;

  *)
    echo "ERROR: unknown command: ${cmd}" >&2
    usage >&2
    exit 2
    ;;
esac

