#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-${ROOT_DIR}/bin}"
VERSIONS_FILE="${VERSIONS_FILE:-${ROOT_DIR}/setup/ubuntu-22.04/tool-versions.env}"

# Prefer repo-local tools when present (kubectl/kind/jq/etc installed into ${BIN_DIR}).
case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *) export PATH="${BIN_DIR}:${PATH}" ;;
esac

if [ -f "${VERSIONS_FILE}" ]; then
  # shellcheck disable=SC1090
  set -a
  . "${VERSIONS_FILE}"
  set +a
fi

KUBECTL_VERSION="${KUBECTL_VERSION:-v1.35.0}"
KIND_VERSION="${KIND_VERSION:-v0.30.0}"
JQ_VERSION="${JQ_VERSION:-1.8.1}"
MKCERT_VERSION="${MKCERT_VERSION:-1.4.4}"
KUSTOMIZE_VERSION="${KUSTOMIZE_VERSION:-5.8.0}"
KUBECONFORM_VERSION="${KUBECONFORM_VERSION:-0.7.0}"
DOCKER_ENGINE_MIN_VERSION="${DOCKER_ENGINE_MIN_VERSION:-28.0.0}"
DOCKER_DESKTOP_MIN_VERSION="${DOCKER_DESKTOP_MIN_VERSION:-4.56.0}"
GIT_VERSION="${GIT_VERSION:-2.34.0}"
MAKE_VERSION="${MAKE_VERSION:-4.3}"
PYTHON_VERSION="${PYTHON_VERSION:-3.8.0}"
OPENSSL_MIN_VERSION="${OPENSSL_MIN_VERSION:-1.1.1}"
CURL_MIN_VERSION="${CURL_MIN_VERSION:-7.68.0}"
WGET_MIN_VERSION="${WGET_MIN_VERSION:-1.20.0}"
UNZIP_MIN_VERSION="${UNZIP_MIN_VERSION:-6.0}"
BOOTSTRAP_INSTALL_MODE="${BOOTSTRAP_INSTALL_MODE:-system}"
BOOTSTRAP_GLOBAL_BIN_DIR="${BOOTSTRAP_GLOBAL_BIN_DIR:-/usr/local/bin}"
BOOTSTRAP_ENFORCE_GLOBAL_BIN="${BOOTSTRAP_ENFORCE_GLOBAL_BIN:-1}"
BOOTSTRAP_DOCKER_REQUIRED="${BOOTSTRAP_DOCKER_REQUIRED:-1}"
BOOTSTRAP_APT_MAINTENANCE="${BOOTSTRAP_APT_MAINTENANCE:-1}"
BOOTSTRAP_APT_UPGRADE="${BOOTSTRAP_APT_UPGRADE:-0}"
BOOTSTRAP_APT_FULL_UPGRADE="${BOOTSTRAP_APT_FULL_UPGRADE:-0}"
BOOTSTRAP_APT_AUTOREMOVE="${BOOTSTRAP_APT_AUTOREMOVE:-0}"
BOOTSTRAP_APT_CLEAN="${BOOTSTRAP_APT_CLEAN:-1}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-bpl-dev}"
BOOTSTRAP_EXPECTED_KUBE_CONTEXT="${BOOTSTRAP_EXPECTED_KUBE_CONTEXT:-kind-${KIND_CLUSTER_NAME}}"
BOOTSTRAP_AUTO_KUBECONTEXT="${BOOTSTRAP_AUTO_KUBECONTEXT:-1}"
BOOTSTRAP_TUNE_SYSCTL="${BOOTSTRAP_TUNE_SYSCTL:-1}"
BOOTSTRAP_SYSCTL_PERSIST="${BOOTSTRAP_SYSCTL_PERSIST:-1}"
BOOTSTRAP_INOTIFY_MAX_USER_INSTANCES="${BOOTSTRAP_INOTIFY_MAX_USER_INSTANCES:-1024}"
BOOTSTRAP_INOTIFY_MAX_USER_WATCHES="${BOOTSTRAP_INOTIFY_MAX_USER_WATCHES:-1048576}"
APT_LOCK_TIMEOUT="${APT_LOCK_TIMEOUT:-120}"
APT_RETRIES="${APT_RETRIES:-3}"
APT_RETRY_DELAY="${APT_RETRY_DELAY:-5}"

log() {
  echo "[bootstrap] $*"
}

declare -A SUMMARY_MAP
SUMMARY_ORDER=(apt-system sysctl network-tools curl wget unzip git make python3 openssl docker mkcert kubectl kind kube-context jq kustomize kubeconform)
FAILED=0
BOOTSTRAP_PRINTED=0

log_duration() {
  local name="$1"
  local start="$2"
  local end
  end="$(date +%s)"
  log "${name} took $((end - start))s"
}

log_kv() {
  local name="$1"
  local value="$2"
  if [ -n "${value}" ]; then
    log "${name}: ${value}"
  else
    log "${name}: not found"
  fi
}

is_tty() {
  [ -t 0 ]
}

confirm_reinstall() {
  local name="$1"
  local current="$2"
  local desired="$3"
  if [ "${BOOTSTRAP_AUTO_CONFIRM:-}" = "1" ] || [ "${BOOTSTRAP_AUTO_CONFIRM:-}" = "true" ]; then
    log "auto-confirm enabled; proceeding to reinstall ${name}"
    return 0
  fi
  if ! is_tty; then
    log "non-interactive shell; set BOOTSTRAP_AUTO_CONFIRM=1 to allow reinstall"
    exit 1
  fi
  echo
  log "${name} version mismatch: current=${current:-unknown}, desired=${desired}"
  log "Reinstalling improves security and compatibility. Proceed? [y/N]"
  read -r reply
  case "${reply}" in
    [Yy]|[Yy][Ee][Ss]) return 0 ;;
    *) log "aborting; user declined ${name} reinstall"; exit 1 ;;
  esac
}

version_ge() {
  local min="$1"
  local current="$2"
  [ "$(printf '%s\n' "${min}" "${current}" | sort -V | head -n1)" = "${min}" ]
}

os_id() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "${ID:-unknown}"
  else
    echo "unknown"
  fi
}

is_root() {
  [ "$(id -u)" -eq 0 ]
}

can_use_noninteractive_sudo() {
  have_cmd sudo && sudo -n true >/dev/null 2>&1
}

can_use_interactive_sudo() {
  have_cmd sudo && is_tty
}

run_privileged() {
  if is_root; then
    "$@"
    return $?
  fi
  if can_use_noninteractive_sudo; then
    sudo -n "$@"
    return $?
  fi
  if can_use_interactive_sudo; then
    sudo "$@"
    return $?
  fi
  return 125
}

run_apt() {
  local cmd=(apt-get
    -o "DPkg::Lock::Timeout=${APT_LOCK_TIMEOUT}"
    -o "Acquire::Retries=3"
    -o "Dpkg::Options::=--force-confold"
    "$@")

  if is_root; then
    DEBIAN_FRONTEND=noninteractive "${cmd[@]}"
    return $?
  fi
  if can_use_noninteractive_sudo; then
    sudo -n env DEBIAN_FRONTEND=noninteractive "${cmd[@]}"
    return $?
  fi
  if can_use_interactive_sudo; then
    sudo env DEBIAN_FRONTEND=noninteractive "${cmd[@]}"
    return $?
  fi
  return 125
}

run_apt_with_retry() {
  local attempt=1
  local rc=0
  while [ "${attempt}" -le "${APT_RETRIES}" ]; do
    if run_apt "$@"; then
      return 0
    fi
    rc=$?
    if [ "${rc}" -eq 125 ]; then
      return 125
    fi
    log "apt command failed (attempt ${attempt}/${APT_RETRIES}): apt-get $*"
    if [ "${attempt}" -lt "${APT_RETRIES}" ]; then
      sleep "${APT_RETRY_DELAY}"
    fi
    attempt=$((attempt + 1))
  done
  return "${rc}"
}

apt_install_packages() {
  run_apt_with_retry install -y "$@"
}

ensure_apt_maintenance() {
  if [ "${BOOTSTRAP_APT_MAINTENANCE}" != "1" ] && [ "${BOOTSTRAP_APT_MAINTENANCE}" != "true" ]; then
    log "apt maintenance disabled (BOOTSTRAP_APT_MAINTENANCE=${BOOTSTRAP_APT_MAINTENANCE})"
    return 2
  fi
  if ! have_cmd apt-get; then
    log "apt-get not found; skipping apt maintenance"
    return 0
  fi
  if ! is_root && ! can_use_noninteractive_sudo && ! can_use_interactive_sudo; then
    log "apt maintenance skipped: requires root or passwordless sudo"
    log "tip: run with sudo, configure passwordless sudo, or run from an interactive terminal"
    return 2
  fi

  log "running safe apt maintenance for current release (no release upgrade)"
  run_apt_with_retry update || return 1

  if [ "${BOOTSTRAP_APT_FULL_UPGRADE}" = "1" ] || [ "${BOOTSTRAP_APT_FULL_UPGRADE}" = "true" ]; then
    log "running apt full-upgrade"
    run_apt_with_retry full-upgrade -y || return 1
  elif [ "${BOOTSTRAP_APT_UPGRADE}" = "1" ] || [ "${BOOTSTRAP_APT_UPGRADE}" = "true" ]; then
    log "running apt upgrade"
    run_apt_with_retry upgrade -y || return 1
  fi

  if [ "${BOOTSTRAP_APT_AUTOREMOVE}" = "1" ] || [ "${BOOTSTRAP_APT_AUTOREMOVE}" = "true" ]; then
    log "running apt autoremove"
    run_apt_with_retry autoremove -y || return 1
  fi

  if [ "${BOOTSTRAP_APT_CLEAN}" = "1" ] || [ "${BOOTSTRAP_APT_CLEAN}" = "true" ]; then
    log "running apt clean"
    run_apt clean || true
  fi

  return 0
}

summary_set() {
  local name="$1"
  local status="$2"
  SUMMARY_MAP["${name}"]="${status}"
}

run_step() {
  local name="$1"
  shift
  local start
  local rc
  start="$(date +%s)"
  if (
    set +e
    # Prevent global EXIT trap from firing inside per-step subshells.
    trap - EXIT
    "$@"
  ); then
    rc=0
  else
    rc=$?
  fi
  case "${rc}" in
    0) summary_set "${name}" "OK" ;;
    2) summary_set "${name}" "WARN" ;;
    *) summary_set "${name}" "FAIL"; FAILED=1 ;;
  esac
  log_duration "${name}" "${start}"
  return 0
}

summary_init() {
  local s
  for s in "${SUMMARY_ORDER[@]}"; do
    SUMMARY_MAP["${s}"]="PENDING"
  done
}

print_summary() {
  log "summary:"
  local s
  for s in "${SUMMARY_ORDER[@]}"; do
    log "  ${s}:${SUMMARY_MAP[${s}]-MISSING}"
  done
}

status_exact() {
  local name="$1"
  local current="$2"
  local desired="$3"
  if [ -z "${current}" ]; then
    summary_set "${name}" "FAIL"
  elif [ "${current}" = "${desired}" ]; then
    summary_set "${name}" "OK"
  else
    summary_set "${name}" "WARN"
  fi
}

status_min() {
  local name="$1"
  local current="$2"
  local min="$3"
  if [ -z "${current}" ]; then
    summary_set "${name}" "FAIL"
  elif version_ge "${min}" "${current}"; then
    summary_set "${name}" "OK"
  else
    summary_set "${name}" "WARN"
  fi
}

finalize() {
  local exit_code="${1:-0}"
  if [ "${BOOTSTRAP_PRINTED}" -eq 1 ]; then
    return
  fi
  BOOTSTRAP_PRINTED=1
  # Non-bootstrap subcommands (doctor/hosts) do not initialize the summary map.
  if [ "${#SUMMARY_MAP[@]}" -eq 0 ]; then
    return
  fi
  if [ "${SUMMARY_MAP[apt-system]-}" = "PENDING" ]; then
    if have_cmd apt-get; then
      summary_set "apt-system" "WARN"
    else
      summary_set "apt-system" "OK"
    fi
  fi
  if [ "${SUMMARY_MAP[network-tools]-}" = "PENDING" ]; then
    summary_set "network-tools" "FAIL"
  fi
  if [ "${SUMMARY_MAP[curl]-}" = "PENDING" ]; then
    status_min "curl" "$(get_curl_version || true)" "${CURL_MIN_VERSION}"
  fi
  if [ "${SUMMARY_MAP[wget]-}" = "PENDING" ]; then
    status_min "wget" "$(get_wget_version || true)" "${WGET_MIN_VERSION}"
  fi
  if [ "${SUMMARY_MAP[unzip]-}" = "PENDING" ]; then
    status_min "unzip" "$(get_unzip_version || true)" "${UNZIP_MIN_VERSION}"
  fi
  if [ "${SUMMARY_MAP[git]-}" = "PENDING" ]; then
    status_min "git" "$(get_git_version || true)" "${GIT_VERSION}"
  fi
  if [ "${SUMMARY_MAP[make]-}" = "PENDING" ]; then
    status_min "make" "$(get_make_version || true)" "${MAKE_VERSION}"
  fi
  if [ "${SUMMARY_MAP[python3]-}" = "PENDING" ]; then
    status_min "python3" "$(get_python_version || true)" "${PYTHON_VERSION}"
  fi
  if [ "${SUMMARY_MAP[openssl]-}" = "PENDING" ]; then
    status_min "openssl" "$(get_openssl_version || true)" "${OPENSSL_MIN_VERSION}"
  fi
  if [ "${SUMMARY_MAP[docker]-}" = "PENDING" ]; then
    status_min "docker" "$(get_docker_version || true)" "${DOCKER_ENGINE_MIN_VERSION}"
  fi
  if [ "${SUMMARY_MAP[mkcert]-}" = "PENDING" ]; then
    status_exact "mkcert" "$(get_mkcert_version || true)" "${MKCERT_VERSION}"
  fi
  if [ "${SUMMARY_MAP[kubectl]-}" = "PENDING" ]; then
    status_exact "kubectl" "$(get_kubectl_version "${BIN_DIR}/kubectl" || true)" "${KUBECTL_VERSION}"
  fi
  if [ "${SUMMARY_MAP[kind]-}" = "PENDING" ]; then
    status_exact "kind" "$(get_kind_version "${BIN_DIR}/kind" || true)" "${KIND_VERSION}"
  fi
  if [ "${SUMMARY_MAP[kube-context]-}" = "PENDING" ]; then
    if ! have_cmd kubectl; then
      summary_set "kube-context" "WARN"
    elif [ "$(get_current_kube_context || true)" = "${BOOTSTRAP_EXPECTED_KUBE_CONTEXT}" ]; then
      summary_set "kube-context" "OK"
    else
      summary_set "kube-context" "WARN"
    fi
  fi
  if [ "${SUMMARY_MAP[jq]-}" = "PENDING" ]; then
    status_exact "jq" "$(get_jq_version "${BIN_DIR}/jq" || true)" "${JQ_VERSION}"
  fi
  if [ "${SUMMARY_MAP[kustomize]-}" = "PENDING" ]; then
    status_exact "kustomize" "$(get_kustomize_version "${BIN_DIR}/kustomize" || true)" "${KUSTOMIZE_VERSION}"
  fi
  if [ "${SUMMARY_MAP[kubeconform]-}" = "PENDING" ]; then
    status_exact "kubeconform" "$(get_kubeconform_version "${BIN_DIR}/kubeconform" || true)" "${KUBECONFORM_VERSION}"
  fi
  log "final versions:"
  log_kv "kubectl" "$(get_kubectl_version "${BIN_DIR}/kubectl" || true)"
  log_kv "kind" "$(get_kind_version "${BIN_DIR}/kind" || true)"
  log_kv "kube-context" "$(get_current_kube_context || true)"
  log_kv "kube-context expected" "${BOOTSTRAP_EXPECTED_KUBE_CONTEXT}"
  log_kv "jq" "$(get_jq_version "${BIN_DIR}/jq" || true)"
  log_kv "mkcert" "$(get_mkcert_version || true)"
  log_kv "kustomize" "$(get_kustomize_version "${BIN_DIR}/kustomize" || true)"
  log_kv "kubeconform" "$(get_kubeconform_version "${BIN_DIR}/kubeconform" || true)"
  log_kv "docker" "$(get_docker_version || true)"
  log_kv "git" "$(get_git_version || true)"
  log_kv "make" "$(get_make_version || true)"
  log_kv "python3" "$(get_python_version || true)"
  log_kv "openssl" "$(get_openssl_version || true)"
  log_kv "curl" "$(get_curl_version || true)"
  log_kv "wget" "$(get_wget_version || true)"
  log_kv "unzip" "$(get_unzip_version || true)"
  print_summary
  if [ "${FAILED}" -ne 0 ] || [ "${exit_code}" -ne 0 ]; then
    if [ "${BOOTSTRAP_STRICT:-}" = "1" ] || [ "${BOOTSTRAP_STRICT:-}" = "true" ]; then
      log "bootstrap failed (strict mode)"
      exit 1
    fi
    log "bootstrap completed with failures (set BOOTSTRAP_STRICT=1 to fail)"
  fi
}

ensure_path_entry() {
  local entry="$1"
  if [ ! -d "${entry}" ]; then
    return 0
  fi
  if ! echo "${PATH}" | tr ':' '\n' | grep -qx "${entry}"; then
    log "add to PATH: export PATH=${entry}:\$PATH"
    export PATH="${entry}:${PATH}"
  fi
}

ensure_bin_dir() {
  mkdir -p "${BIN_DIR}"
  ensure_path_entry "${BOOTSTRAP_GLOBAL_BIN_DIR}"
  if [ "${BOOTSTRAP_ENFORCE_GLOBAL_BIN}" = "1" ] || [ "${BOOTSTRAP_ENFORCE_GLOBAL_BIN}" = "true" ]; then
    return 0
  fi
  ensure_path_entry "${BIN_DIR}"
}

refresh_shell_command_cache() {
  hash -r 2>/dev/null || true
  rehash 2>/dev/null || true
}

print_terminal_refresh_hint() {
  local login_shell="${SHELL:-/bin/bash}"
  log "shell command cache refresh attempted (hash -r / rehash)"
  log "if your current terminal still does not find a command, run: hash -r"
  log "if needed, reload your shell session: exec ${login_shell} -l"
}

install_binary_target() {
  local src="$1"
  local name="$2"
  local target="${BIN_DIR}/${name}"
  local target_dir="${BIN_DIR}"
  local enforce_global=0
  if [ "${BOOTSTRAP_INSTALL_MODE}" = "system" ] || [ "${BOOTSTRAP_ENFORCE_GLOBAL_BIN}" = "1" ] || [ "${BOOTSTRAP_ENFORCE_GLOBAL_BIN}" = "true" ]; then
    enforce_global=1
  fi

  if [ "${enforce_global}" -eq 1 ]; then
    if [ ! -d "${BOOTSTRAP_GLOBAL_BIN_DIR}" ]; then
      run_privileged install -d "${BOOTSTRAP_GLOBAL_BIN_DIR}" >/dev/null 2>&1 || true
    fi

    target="${BOOTSTRAP_GLOBAL_BIN_DIR}/${name}"
    target_dir="${BOOTSTRAP_GLOBAL_BIN_DIR}"

    if install -m 0755 "${src}" "${target}" >/dev/null 2>&1 || run_privileged install -m 0755 "${src}" "${target}" >/dev/null 2>&1; then
      cp "${src}" "${BIN_DIR}/${name}" >/dev/null 2>&1 || true
      chmod +x "${BIN_DIR}/${name}" >/dev/null 2>&1 || true
      return 0
    fi

    if [ "${BOOTSTRAP_ENFORCE_GLOBAL_BIN}" = "1" ] || [ "${BOOTSTRAP_ENFORCE_GLOBAL_BIN}" = "true" ]; then
      log "failed to install ${name} into ${BOOTSTRAP_GLOBAL_BIN_DIR}"
      log "re-run with sudo or grant write permission to ${BOOTSTRAP_GLOBAL_BIN_DIR}"
      return 1
    fi
    log "warning: cannot install ${name} in ${BOOTSTRAP_GLOBAL_BIN_DIR}; falling back to ${BIN_DIR}"
  fi

  install -m 0755 "${src}" "${target}"
  if [ "${target_dir}" != "${BIN_DIR}" ]; then
    cp "${src}" "${BIN_DIR}/${name}" >/dev/null 2>&1 || true
    chmod +x "${BIN_DIR}/${name}" >/dev/null 2>&1 || true
  fi
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

cmd_path() {
  command -v "$1" 2>/dev/null || true
}

allow_local_bin_fallback() {
  [ "${BOOTSTRAP_ENFORCE_GLOBAL_BIN}" != "1" ] && [ "${BOOTSTRAP_ENFORCE_GLOBAL_BIN}" != "true" ]
}

download() {
  local url="$1"
  local out="$2"
  if have_cmd curl; then
    curl -fsSL --retry 3 --retry-delay 2 -o "${out}" "${url}"
  elif have_cmd wget; then
    wget -q --tries=3 -O "${out}" "${url}"
  else
    log "curl or wget required"
    exit 1
  fi
  if [ ! -s "${out}" ]; then
    log "download failed or empty: ${url}"
    exit 1
  fi
}

download_optional() {
  local url="$1"
  local out="$2"
  if have_cmd curl; then
    curl -fsSL --retry 2 --retry-delay 1 -o "${out}" "${url}" >/dev/null 2>&1 || return 1
  elif have_cmd wget; then
    wget -q --tries=2 -O "${out}" "${url}" >/dev/null 2>&1 || return 1
  else
    return 1
  fi
  [ -s "${out}" ]
}

sha256_tool() {
  if have_cmd sha256sum; then
    echo "sha256sum"
  elif have_cmd shasum; then
    echo "shasum -a 256"
  else
    log "sha256 tool not found (sha256sum or shasum required)"
    exit 1
  fi
}

verify_sha256_simple() {
  local checksum_url="$1"
  local file="$2"
  local checksum_file="/tmp/checksum.$$"
  local cmd
  cmd="$(sha256_tool)"
  download "${checksum_url}" "${checksum_file}"
  local expected
  expected="$(awk '{print $1}' "${checksum_file}" | tr -d '\r' | head -n1)"
  if [ -z "${expected}" ]; then
    log "checksum not found at ${checksum_url}"
    exit 1
  fi
  local actual
  actual="$(${cmd} "${file}" | awk '{print $1}')"
  if [ "${expected}" != "${actual}" ]; then
    log "checksum mismatch for ${file}"
    log "expected: ${expected}"
    log "actual:   ${actual}"
    exit 1
  fi
  rm -f "${checksum_file}"
}

verify_sha256_checksums() {
  local checksums_url="$1"
  local file="$2"
  local filename="${3:-$(basename "${file}")}"
  local checksum_file="/tmp/checksums.$$"
  local cmd
  cmd="$(sha256_tool)"
  download "${checksums_url}" "${checksum_file}"
  local expected
  expected="$(grep " ${filename}\$" "${checksum_file}" | awk '{print $1}' | tr -d '\r' | head -n1)"
  if [ -z "${expected}" ]; then
    log "checksum for ${filename} not found at ${checksums_url}"
    exit 1
  fi
  local actual
  actual="$(${cmd} "${file}" | awk '{print $1}')"
  if [ "${expected}" != "${actual}" ]; then
    log "checksum mismatch for ${file}"
    log "expected: ${expected}"
    log "actual:   ${actual}"
    exit 1
  fi
  rm -f "${checksum_file}"
}

get_git_version() {
  if have_cmd git; then
    git --version 2>/dev/null | awk '{print $3}'
  fi
}

get_make_version() {
  if have_cmd make; then
    make --version 2>/dev/null | head -n1 | awk '{print $3}'
  fi
}

get_python_version() {
  if have_cmd python3; then
    python3 --version 2>/dev/null | awk '{print $2}'
  fi
}

get_openssl_version() {
  if have_cmd openssl; then
    openssl version 2>/dev/null | awk '{print $2}'
  fi
}

get_curl_version() {
  if have_cmd curl; then
    curl --version 2>/dev/null | head -n1 | awk '{print $2}'
  fi
}

get_wget_version() {
  if have_cmd wget; then
    wget --version 2>/dev/null | head -n1 | awk '{print $3}'
  fi
}

get_unzip_version() {
  if have_cmd unzip; then
    unzip -v 2>/dev/null | head -n1 | awk '{print $2}'
  fi
}

get_sysctl_value() {
  local key="$1"
  if have_cmd sysctl; then
    sysctl -n "${key}" 2>/dev/null || true
  fi
}

ensure_sysctl_inotify() {
  if [ "${BOOTSTRAP_TUNE_SYSCTL}" != "1" ] && [ "${BOOTSTRAP_TUNE_SYSCTL}" != "true" ]; then
    log "sysctl tuning disabled (BOOTSTRAP_TUNE_SYSCTL=${BOOTSTRAP_TUNE_SYSCTL})"
    return 2
  fi
  if [ "$(os_name)" != "linux" ]; then
    log "sysctl tuning skipped (non-linux)"
    return 2
  fi
  if ! have_cmd sysctl; then
    log "sysctl not found; skipping sysctl tuning"
    return 2
  fi

  local cur_instances cur_watches
  cur_instances="$(get_sysctl_value fs.inotify.max_user_instances)"
  cur_watches="$(get_sysctl_value fs.inotify.max_user_watches)"
  log "sysctl detected: fs.inotify.max_user_instances=${cur_instances:-unknown} fs.inotify.max_user_watches=${cur_watches:-unknown}"

  local need=0
  if [ -z "${cur_instances}" ] || [ "${cur_instances}" -lt "${BOOTSTRAP_INOTIFY_MAX_USER_INSTANCES}" ] 2>/dev/null; then
    need=1
  fi
  if [ -z "${cur_watches}" ] || [ "${cur_watches}" -lt "${BOOTSTRAP_INOTIFY_MAX_USER_WATCHES}" ] 2>/dev/null; then
    need=1
  fi

  if [ "${need}" -eq 0 ]; then
    log "sysctl inotify OK"
    return 0
  fi

  if ! is_root && ! can_use_noninteractive_sudo && ! can_use_interactive_sudo; then
    log "sysctl tuning requires root or sudo; skipping"
    log "apply manually:"
    log "  sudo sysctl -w fs.inotify.max_user_instances=${BOOTSTRAP_INOTIFY_MAX_USER_INSTANCES}"
    log "  sudo sysctl -w fs.inotify.max_user_watches=${BOOTSTRAP_INOTIFY_MAX_USER_WATCHES}"
    return 2
  fi

  log "tuning sysctl for kind/kube-proxy stability (inotify)"
  run_privileged sysctl -w "fs.inotify.max_user_instances=${BOOTSTRAP_INOTIFY_MAX_USER_INSTANCES}" >/dev/null
  run_privileged sysctl -w "fs.inotify.max_user_watches=${BOOTSTRAP_INOTIFY_MAX_USER_WATCHES}" >/dev/null

  if [ "${BOOTSTRAP_SYSCTL_PERSIST}" = "1" ] || [ "${BOOTSTRAP_SYSCTL_PERSIST}" = "true" ]; then
    local conf="/etc/sysctl.d/99-reliable-message-api-dev.conf"
    log "persisting sysctl to ${conf}"
    run_privileged tee "${conf}" >/dev/null <<EOF
fs.inotify.max_user_instances=${BOOTSTRAP_INOTIFY_MAX_USER_INSTANCES}
fs.inotify.max_user_watches=${BOOTSTRAP_INOTIFY_MAX_USER_WATCHES}
EOF
    run_privileged sysctl --system >/dev/null 2>&1 || true
  fi

  return 0
}

get_current_kube_context() {
  if have_cmd kubectl; then
    kubectl config current-context 2>/dev/null || true
  fi
}

ensure_kube_context() {
  local expected="${BOOTSTRAP_EXPECTED_KUBE_CONTEXT}"
  local current

  if ! have_cmd kubectl; then
    log "kubectl not found; skipping kube context validation"
    return 2
  fi

  if ! kubectl config get-contexts -o name 2>/dev/null | grep -qx "${expected}"; then
    log "kube context ${expected} not found yet"
    log "create cluster/context with: kind create cluster --name ${KIND_CLUSTER_NAME}"
    return 2
  fi

  current="$(get_current_kube_context)"
  if [ "${current}" = "${expected}" ]; then
    log "kube context OK: ${current}"
    return 0
  fi

  if [ "${BOOTSTRAP_AUTO_KUBECONTEXT}" = "1" ] || [ "${BOOTSTRAP_AUTO_KUBECONTEXT}" = "true" ]; then
    log "switching kube context to ${expected}"
    if kubectl config use-context "${expected}" >/dev/null 2>&1; then
      log "kube context switched to ${expected}"
      return 0
    fi
    log "failed to switch kube context automatically"
    return 2
  fi

  log "current kube context is ${current:-none}; expected ${expected}"
  log "run: kubectl config use-context ${expected}"
  log "or set BOOTSTRAP_AUTO_KUBECONTEXT=1 to auto-switch during bootstrap"
  return 2
}

os_name() {
  local uname_s
  uname_s="$(uname -s)"
  case "${uname_s}" in
    Linux*) echo "linux" ;;
    Darwin*) echo "darwin" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) echo "unknown" ;;
  esac
}

arch_name() {
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) echo "${arch}" ;;
  esac
}

install_kubectl() {
  local os="$1" arch="$2"
  local url="https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/${os}/${arch}/kubectl"
  local tmp="/tmp/kubectl.$$"
  log "installing kubectl ${KUBECTL_VERSION}"
  download "${url}" "${tmp}"
  verify_sha256_simple "${url}.sha256" "${tmp}"
  install_binary_target "${tmp}" "kubectl"
  rm -f "${tmp}"
  local got
  got="$(get_kubectl_version "${BIN_DIR}/kubectl" || true)"
  if [ "${got}" != "${KUBECTL_VERSION}" ]; then
    log "kubectl install failed (got ${got:-unknown}, expected ${KUBECTL_VERSION})"
    exit 1
  fi
}

install_kind() {
  local os="$1" arch="$2"
  local url="https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-${os}-${arch}"
  local tmp="/tmp/kind.$$"
  log "installing kind ${KIND_VERSION}"
  download "${url}" "${tmp}"
  verify_sha256_simple "${url}.sha256sum" "${tmp}"
  install_binary_target "${tmp}" "kind"
  rm -f "${tmp}"
  local got
  got="$(get_kind_version "${BIN_DIR}/kind" || true)"
  if [ "${got}" != "${KIND_VERSION}" ]; then
    log "kind install failed (got ${got:-unknown}, expected ${KIND_VERSION})"
    exit 1
  fi
}

install_jq() {
  local os="$1" arch="$2"
  local jq_os="${os}"
  if [ "${os}" = "darwin" ]; then
    jq_os="macos"
  fi
  local url="https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-${jq_os}-${arch}"
  local checksums="https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/sha256sum.txt"
  local tmp="/tmp/jq.$$"
  log "installing jq ${JQ_VERSION}"
  download "${url}" "${tmp}"
  verify_sha256_checksums "${checksums}" "${tmp}" "jq-${jq_os}-${arch}"
  install_binary_target "${tmp}" "jq"
  rm -f "${tmp}"
  local got
  got="$(get_jq_version "${BIN_DIR}/jq" || true)"
  if [ "${got}" != "${JQ_VERSION}" ]; then
    log "jq install failed (got ${got:-unknown}, expected ${JQ_VERSION})"
    exit 1
  fi
}

install_kustomize() {
  local os="$1" arch="$2"
  local k_os="${os}"
  local k_arch="${arch}"
  local archive_name="kustomize_v${KUSTOMIZE_VERSION}_${k_os}_${k_arch}.tar.gz"
  local url="https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v${KUSTOMIZE_VERSION}/${archive_name}"
  local checksums="https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v${KUSTOMIZE_VERSION}/checksums.txt"
  log "installing kustomize ${KUSTOMIZE_VERSION}"
  rm -f /tmp/kustomize.tar.gz
  download "${url}" "/tmp/kustomize.tar.gz"
  verify_sha256_checksums "${checksums}" "/tmp/kustomize.tar.gz" "${archive_name}"
  tar -xzf /tmp/kustomize.tar.gz -C /tmp kustomize
  install_binary_target "/tmp/kustomize" "kustomize"
  rm -f /tmp/kustomize
  local got
  got="$(get_kustomize_version "${BIN_DIR}/kustomize" || true)"
  if [ "${got}" != "${KUSTOMIZE_VERSION}" ]; then
    log "kustomize install failed (got ${got:-unknown}, expected ${KUSTOMIZE_VERSION})"
    exit 1
  fi
}

install_kubeconform() {
  local os="$1" arch="$2"
  local kc_os="${os}"
  local kc_arch="${arch}"
  local archive_name="kubeconform-${kc_os}-${kc_arch}.tar.gz"
  local url="https://github.com/yannh/kubeconform/releases/download/v${KUBECONFORM_VERSION}/${archive_name}"
  local checksums="https://github.com/yannh/kubeconform/releases/download/v${KUBECONFORM_VERSION}/CHECKSUMS"
  log "installing kubeconform ${KUBECONFORM_VERSION}"
  rm -f /tmp/kubeconform.tar.gz
  download "${url}" "/tmp/kubeconform.tar.gz"
  verify_sha256_checksums "${checksums}" "/tmp/kubeconform.tar.gz" "${archive_name}"
  tar -xzf /tmp/kubeconform.tar.gz -C /tmp kubeconform
  install_binary_target "/tmp/kubeconform" "kubeconform"
  rm -f /tmp/kubeconform
  local got
  got="$(get_kubeconform_version "${BIN_DIR}/kubeconform" || true)"
  if [ "${got}" != "${KUBECONFORM_VERSION}" ]; then
    log "kubeconform install failed (got ${got:-unknown}, expected ${KUBECONFORM_VERSION})"
    exit 1
  fi
}

install_system_package() {
  local name="$1"
  if have_cmd apt-get; then
    apt_install_packages "${name}" >/dev/null 2>&1 || true
  elif have_cmd dnf; then
    sudo -n dnf install -y "${name}" >/dev/null 2>&1 || sudo dnf install -y "${name}" >/dev/null 2>&1 || true
  elif have_cmd yum; then
    sudo -n yum install -y "${name}" >/dev/null 2>&1 || sudo yum install -y "${name}" >/dev/null 2>&1 || true
  elif have_cmd pacman; then
    sudo -n pacman -S --noconfirm "${name}" >/dev/null 2>&1 || sudo pacman -S --noconfirm "${name}" >/dev/null 2>&1 || true
  elif have_cmd apk; then
    sudo -n apk add --no-cache "${name}" >/dev/null 2>&1 || sudo apk add --no-cache "${name}" >/dev/null 2>&1 || true
  elif have_cmd brew; then
    brew install "${name}" || brew upgrade "${name}"
  fi
}

install_git_ubuntu_ppa() {
  if ! have_cmd apt-get; then
    return 1
  fi
  local distro
  distro="$(os_id)"
  if [ "${distro}" != "ubuntu" ]; then
    return 1
  fi
  log "attempting git-core PPA for newer git"
  if ! have_cmd add-apt-repository; then
    install_system_package software-properties-common
  fi
  if have_cmd add-apt-repository; then
    run_privileged add-apt-repository -y ppa:git-core/ppa >/dev/null 2>&1 || true
    run_apt_with_retry update >/dev/null 2>&1 || true
    apt_install_packages git >/dev/null 2>&1 || true
    return 0
  fi
  return 1
}

install_curl_ubuntu_ppa() {
  if ! have_cmd apt-get; then
    return 1
  fi
  local distro
  distro="$(os_id)"
  if [ "${distro}" != "ubuntu" ]; then
    return 1
  fi
  log "attempting curl PPA for newer curl"
  if ! have_cmd add-apt-repository; then
    install_system_package software-properties-common
  fi
  if have_cmd add-apt-repository; then
    run_privileged add-apt-repository -y ppa:curl/curl >/dev/null 2>&1 || true
    run_apt_with_retry update >/dev/null 2>&1 || true
    apt_install_packages curl >/dev/null 2>&1 || true
    return 0
  fi
  return 1
}

install_wget_ubuntu_ppa() {
  if ! have_cmd apt-get; then
    return 1
  fi
  local distro
  distro="$(os_id)"
  if [ "${distro}" != "ubuntu" ]; then
    return 1
  fi
  log "attempting wget PPA for newer wget"
  if ! have_cmd add-apt-repository; then
    install_system_package software-properties-common
  fi
  if have_cmd add-apt-repository; then
    run_privileged add-apt-repository -y ppa:ubuntu-wget/wget >/dev/null 2>&1 || true
    run_apt_with_retry update >/dev/null 2>&1 || true
    apt_install_packages wget >/dev/null 2>&1 || true
    return 0
  fi
  return 1
}

ensure_git() {
  local current
  local start
  start="$(date +%s)"
  current="$(get_git_version || true)"
  log_kv "git detected" "${current}"
  if [ -n "${current}" ] && version_ge "${GIT_VERSION}" "${current}"; then
    log "git ${current} OK (min ${GIT_VERSION})"
    log_duration "git check" "${start}"
    return
  fi
  confirm_reinstall "git" "${current}" "${GIT_VERSION}"
  install_system_package git
  current="$(get_git_version || true)"
  log_kv "git installed" "${current}"
  if [ -z "${current}" ] || ! version_ge "${GIT_VERSION}" "${current}"; then
    install_git_ubuntu_ppa
    current="$(get_git_version || true)"
    log_kv "git installed (after PPA)" "${current}"
    if [ -z "${current}" ] || ! version_ge "${GIT_VERSION}" "${current}"; then
      log "git version too old (current=${current:-unknown}, min=${GIT_VERSION})"
      log "continuing with warning; upgrade OS or install newer git manually"
      log_duration "git install" "${start}"
      return 2
    fi
  fi
  log_duration "git install" "${start}"
}

ensure_make() {
  local current
  local start
  start="$(date +%s)"
  current="$(get_make_version || true)"
  log_kv "make detected" "${current}"
  if [ -n "${current}" ] && version_ge "${MAKE_VERSION}" "${current}"; then
    log "make ${current} OK (min ${MAKE_VERSION})"
    log_duration "make check" "${start}"
    return
  fi
  confirm_reinstall "make" "${current}" "${MAKE_VERSION}"
  install_system_package make
  current="$(get_make_version || true)"
  log_kv "make installed" "${current}"
  if [ -z "${current}" ] || ! version_ge "${MAKE_VERSION}" "${current}"; then
    log "make version too old (current=${current:-unknown}, min=${MAKE_VERSION})"
    exit 1
  fi
  log_duration "make install" "${start}"
}

ensure_python() {
  local current
  local start
  start="$(date +%s)"
  current="$(get_python_version || true)"
  log_kv "python3 detected" "${current}"
  if [ -n "${current}" ] && version_ge "${PYTHON_VERSION}" "${current}"; then
    log "python3 ${current} OK (min ${PYTHON_VERSION})"
    log_duration "python3 check" "${start}"
    return
  fi
  confirm_reinstall "python3" "${current}" "${PYTHON_VERSION}"
  install_system_package python3
  current="$(get_python_version || true)"
  log_kv "python3 installed" "${current}"
  if [ -z "${current}" ] || ! version_ge "${PYTHON_VERSION}" "${current}"; then
    log "python3 version too old (current=${current:-unknown}, min=${PYTHON_VERSION})"
    exit 1
  fi
  log_duration "python3 install" "${start}"
}

ensure_openssl() {
  local current
  local start
  start="$(date +%s)"
  current="$(get_openssl_version || true)"
  log_kv "openssl detected" "${current}"
  if [ -n "${current}" ] && version_ge "${OPENSSL_MIN_VERSION}" "${current}"; then
    log "openssl ${current} OK (min ${OPENSSL_MIN_VERSION})"
    log_duration "openssl check" "${start}"
    return
  fi
  confirm_reinstall "openssl" "${current}" "${OPENSSL_MIN_VERSION}"
  install_system_package openssl
  current="$(get_openssl_version || true)"
  log_kv "openssl installed" "${current}"
  if [ -z "${current}" ] || ! version_ge "${OPENSSL_MIN_VERSION}" "${current}"; then
    log "openssl version too old (current=${current:-unknown}, min=${OPENSSL_MIN_VERSION})"
    exit 1
  fi
  log_duration "openssl install" "${start}"
}

ensure_network_tools() {
  local start
  start="$(date +%s)"
  local curl_ver
  local wget_ver
  local unzip_ver

  curl_ver="$(get_curl_version || true)"
  wget_ver="$(get_wget_version || true)"
  unzip_ver="$(get_unzip_version || true)"

  if [ -n "${curl_ver}" ]; then
    log_kv "curl detected" "${curl_ver}"
    if ! version_ge "${CURL_MIN_VERSION}" "${curl_ver}"; then
      confirm_reinstall "curl" "${curl_ver}" "${CURL_MIN_VERSION}"
      install_system_package curl
      curl_ver="$(get_curl_version || true)"
      if ! version_ge "${CURL_MIN_VERSION}" "${curl_ver}"; then
        install_curl_ubuntu_ppa
        curl_ver="$(get_curl_version || true)"
      fi
    fi
  fi

  if [ -n "${wget_ver}" ]; then
    log_kv "wget detected" "${wget_ver}"
    if ! version_ge "${WGET_MIN_VERSION}" "${wget_ver}"; then
      confirm_reinstall "wget" "${wget_ver}" "${WGET_MIN_VERSION}"
      install_system_package wget
      wget_ver="$(get_wget_version || true)"
      if ! version_ge "${WGET_MIN_VERSION}" "${wget_ver}"; then
        install_wget_ubuntu_ppa
        wget_ver="$(get_wget_version || true)"
      fi
    fi
  fi

  if [ -z "${curl_ver}" ] && [ -z "${wget_ver}" ]; then
    log "curl/wget not found; attempting to install curl"
    install_system_package curl
    curl_ver="$(get_curl_version || true)"
    if [ -z "${curl_ver}" ] || ! version_ge "${CURL_MIN_VERSION}" "${curl_ver}"; then
      install_curl_ubuntu_ppa
      curl_ver="$(get_curl_version || true)"
    fi
  fi

  if [ -z "${curl_ver}" ] && [ -z "${wget_ver}" ]; then
    log "curl or wget is required"
    exit 1
  fi

  if [ -n "${unzip_ver}" ]; then
    log_kv "unzip detected" "${unzip_ver}"
    if ! version_ge "${UNZIP_MIN_VERSION}" "${unzip_ver}"; then
      confirm_reinstall "unzip" "${unzip_ver}" "${UNZIP_MIN_VERSION}"
      install_system_package unzip
      unzip_ver="$(get_unzip_version || true)"
    fi
  else
    log "unzip not found; attempting to install"
    install_system_package unzip
    unzip_ver="$(get_unzip_version || true)"
  fi

  if [ -z "${unzip_ver}" ]; then
    log "unzip is required"
    exit 1
  fi
  if [ -n "${curl_ver}" ]; then
    if version_ge "${CURL_MIN_VERSION}" "${curl_ver}"; then
      summary_set "curl" "OK"
    else
      summary_set "curl" "WARN"
    fi
  else
    summary_set "curl" "FAIL"
  fi
  if [ -n "${wget_ver}" ]; then
    if version_ge "${WGET_MIN_VERSION}" "${wget_ver}"; then
      summary_set "wget" "OK"
    else
      summary_set "wget" "WARN"
    fi
  else
    summary_set "wget" "FAIL"
  fi
  if [ -n "${unzip_ver}" ]; then
    if version_ge "${UNZIP_MIN_VERSION}" "${unzip_ver}"; then
      summary_set "unzip" "OK"
    else
      summary_set "unzip" "WARN"
    fi
  else
    summary_set "unzip" "FAIL"
  fi
  log_duration "network tools check" "${start}"
}

wait_for_docker() {
  local tries="${1:-30}"
  local delay="${2:-2}"
  local i
  for i in $(seq 1 "${tries}"); do
    if docker info >/dev/null 2>&1; then
      return 0
    fi
    sleep "${delay}"
  done
  return 1
}

start_docker_daemon() {
  local os="$1"
  case "${os}" in
    linux)
      if have_cmd systemctl; then
        systemctl start docker >/dev/null 2>&1 || sudo -n systemctl start docker >/dev/null 2>&1 || true
      elif have_cmd service; then
        service docker start >/dev/null 2>&1 || sudo -n service docker start >/dev/null 2>&1 || true
      fi
      ;;
    darwin)
      if have_cmd open; then
        open -a Docker >/dev/null 2>&1 || true
      fi
      ;;
  esac
}

ensure_docker_running() {
  local os="$1"
  if ! have_cmd docker; then
    log "docker not found; install Docker Desktop or Docker Engine"
    exit 1
  fi
  if docker info >/dev/null 2>&1; then
    local docker_ver
    docker_ver="$(get_docker_version || true)"
    log_kv "docker detected" "${docker_ver}"
    if [ -n "${docker_ver}" ] && ! version_ge "${DOCKER_ENGINE_MIN_VERSION}" "${docker_ver}"; then
      log "docker version too old (current=${docker_ver}, min=${DOCKER_ENGINE_MIN_VERSION})"
      confirm_reinstall "docker" "${docker_ver}" "${DOCKER_ENGINE_MIN_VERSION}"
      log "please update Docker Engine/Desktop to at least ${DOCKER_ENGINE_MIN_VERSION} and re-run"
      exit 1
    fi
    if [ "${os}" = "darwin" ]; then
      local desktop_ver
      desktop_ver="$(defaults read /Applications/Docker.app/Contents/Info CFBundleShortVersionString 2>/dev/null || true)"
      if [ -n "${desktop_ver}" ]; then
        log_kv "docker desktop detected" "${desktop_ver}"
        if ! version_ge "${DOCKER_DESKTOP_MIN_VERSION}" "${desktop_ver}"; then
          log "docker desktop too old (current=${desktop_ver}, min=${DOCKER_DESKTOP_MIN_VERSION})"
          confirm_reinstall "docker desktop" "${desktop_ver}" "${DOCKER_DESKTOP_MIN_VERSION}"
          log "please update Docker Desktop to at least ${DOCKER_DESKTOP_MIN_VERSION} and re-run"
          exit 1
        fi
      fi
    fi
    log "docker running"
    return
  fi
  log "docker not running; attempting to start"
  start_docker_daemon "${os}"
  log "waiting for docker to be ready..."
  if wait_for_docker; then
    local docker_ver
    docker_ver="$(get_docker_version || true)"
    log_kv "docker detected" "${docker_ver}"
    if [ -n "${docker_ver}" ] && ! version_ge "${DOCKER_ENGINE_MIN_VERSION}" "${docker_ver}"; then
      log "docker version too old (current=${docker_ver}, min=${DOCKER_ENGINE_MIN_VERSION})"
      confirm_reinstall "docker" "${docker_ver}" "${DOCKER_ENGINE_MIN_VERSION}"
      log "please update Docker Engine/Desktop to at least ${DOCKER_ENGINE_MIN_VERSION} and re-run"
      exit 1
    fi
    if [ "${os}" = "darwin" ]; then
      local desktop_ver
      desktop_ver="$(defaults read /Applications/Docker.app/Contents/Info CFBundleShortVersionString 2>/dev/null || true)"
      if [ -n "${desktop_ver}" ]; then
        log_kv "docker desktop detected" "${desktop_ver}"
        if ! version_ge "${DOCKER_DESKTOP_MIN_VERSION}" "${desktop_ver}"; then
          log "docker desktop too old (current=${desktop_ver}, min=${DOCKER_DESKTOP_MIN_VERSION})"
          confirm_reinstall "docker desktop" "${desktop_ver}" "${DOCKER_DESKTOP_MIN_VERSION}"
          log "please update Docker Desktop to at least ${DOCKER_DESKTOP_MIN_VERSION} and re-run"
          exit 1
        fi
      fi
    fi
    log "docker running"
    return
  fi
  log "docker daemon did not start; start it manually and re-run"
  exit 1
}

ensure_mkcert() {
  local os="${1:-}"
  local arch="${2:-}"
  if ! have_cmd mkcert; then
    log "mkcert not found; attempting install"
    install_mkcert "${os}" "${arch}"
  fi
  if ! have_cmd mkcert; then
    log "mkcert install failed; install mkcert for local TLS"
    exit 1
  fi
  local current
  current="$(get_mkcert_version || true)"
  log_kv "mkcert detected" "${current}"
  if [ -n "${current}" ] && [ "${current}" != "${MKCERT_VERSION}" ]; then
    confirm_reinstall "mkcert" "${current}" "${MKCERT_VERSION}"
    install_mkcert "${os}" "${arch}" "1"
    current="$(get_mkcert_version || true)"
    log_kv "mkcert installed" "${current}"
    if [ -n "${current}" ] && [ "${current}" != "${MKCERT_VERSION}" ]; then
      log "mkcert version mismatch: ${current:-unknown} (expected ${MKCERT_VERSION})"
      exit 1
    fi
  fi
  local caroot
  caroot="$(mkcert -CAROOT 2>/dev/null || true)"
  if [ -n "${caroot}" ] && [ -f "${caroot}/rootCA.pem" ]; then
    log "mkcert found (CA installed)"
    return
  fi
  log "mkcert found, but CA not installed; running mkcert -install"
  if ! mkcert -install >/dev/null 2>&1; then
    if have_cmd sudo && sudo -n mkcert -install >/dev/null 2>&1; then
      :
    else
      log "mkcert -install failed (likely permission issue); continuing with warning"
      log "run manually: mkcert -install"
      return 2
    fi
  fi
  caroot="$(mkcert -CAROOT 2>/dev/null || true)"
  if [ -n "${caroot}" ] && [ -f "${caroot}/rootCA.pem" ]; then
    log "mkcert CA installed"
    return
  fi
  log "mkcert CA install did not complete; continuing with warning"
  log "run manually: mkcert -install"
  return 2
}

install_mkcert() {
  local os="$1"
  local arch="$2"
  local force_binary="${3:-0}"
  case "${os}" in
    linux)
      if [ "${force_binary}" != "1" ] && have_cmd apt-get; then
        run_apt_with_retry update >/dev/null 2>&1 || true
        apt_install_packages mkcert libnss3-tools >/dev/null 2>&1 || true
      elif [ "${force_binary}" != "1" ] && have_cmd dnf; then
        sudo -n dnf install -y mkcert nss-tools >/dev/null 2>&1 || true
      elif [ "${force_binary}" != "1" ] && have_cmd yum; then
        sudo -n yum install -y mkcert nss-tools >/dev/null 2>&1 || true
      elif [ "${force_binary}" != "1" ] && have_cmd pacman; then
        sudo -n pacman -S --noconfirm mkcert nss >/dev/null 2>&1 || true
      elif [ "${force_binary}" != "1" ] && have_cmd apk; then
        sudo -n apk add --no-cache mkcert nss-tools >/dev/null 2>&1 || true
      fi
      ;;
    darwin)
      if [ "${force_binary}" != "1" ] && have_cmd brew; then
        brew install mkcert || brew upgrade mkcert
      fi
      ;;
  esac

  if [ "${force_binary}" = "1" ] || ! have_cmd mkcert; then
    local mkcert_os="${os}"
    local mkcert_arch="${arch}"
    case "${mkcert_arch}" in
      amd64) mkcert_arch="amd64" ;;
      arm64) mkcert_arch="arm64" ;;
    esac
    local url="https://github.com/FiloSottile/mkcert/releases/download/v${MKCERT_VERSION}/mkcert-v${MKCERT_VERSION}-${mkcert_os}-${mkcert_arch}"
    log "downloading mkcert ${MKCERT_VERSION} from ${url}"
    local tmp="/tmp/mkcert.$$"
    local checksum_tmp="/tmp/mkcert.sha256.$$"
    download "${url}" "${tmp}"
    if download_optional "${url}.sha256" "${checksum_tmp}"; then
      verify_sha256_simple "${url}.sha256" "${tmp}"
      rm -f "${checksum_tmp}"
    else
      log "warning: mkcert release does not provide ${url}.sha256; proceeding without checksum verification for this artifact"
      rm -f "${checksum_tmp}"
    fi
    install_binary_target "${tmp}" "mkcert"
    rm -f "${tmp}"
  fi
}
get_kubectl_version() {
  local bin="$1"
  if have_cmd kubectl; then
    kubectl version --client -o yaml 2>/dev/null | awk -F': ' '/gitVersion:/ {print $2; exit}'
  elif allow_local_bin_fallback && [ -x "${bin}" ]; then
    "${bin}" version --client -o yaml 2>/dev/null | awk -F': ' '/gitVersion:/ {print $2; exit}'
  fi
}

get_kind_version() {
  local bin="$1"
  if have_cmd kind; then
    kind version 2>/dev/null | awk '{print $2}'
  elif allow_local_bin_fallback && [ -x "${bin}" ]; then
    "${bin}" version 2>/dev/null | awk '{print $2}'
  fi
}

get_jq_version() {
  local bin="$1"
  if have_cmd jq; then
    jq --version 2>/dev/null | sed 's/^jq-//'
  elif allow_local_bin_fallback && [ -x "${bin}" ]; then
    "${bin}" --version 2>/dev/null | sed 's/^jq-//'
  fi
}

get_mkcert_version() {
  if have_cmd mkcert; then
    mkcert -version 2>/dev/null | head -n1 | awk '{print $1}' | sed 's/^v//'
  fi
}

get_kustomize_version() {
  local bin="$1"
  if have_cmd kustomize; then
    kustomize version 2>/dev/null | grep -Eo 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | sed 's/^v//'
  elif allow_local_bin_fallback && [ -x "${bin}" ]; then
    "${bin}" version 2>/dev/null | grep -Eo 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | sed 's/^v//'
  fi
}

get_kubeconform_version() {
  local bin="$1"
  if have_cmd kubeconform; then
    kubeconform -v 2>/dev/null | head -n1 | sed 's/^v//'
  elif allow_local_bin_fallback && [ -x "${bin}" ]; then
    "${bin}" -v 2>/dev/null | head -n1 | sed 's/^v//'
  fi
}

get_docker_version() {
  if have_cmd docker; then
    docker version --format '{{.Server.Version}}' 2>/dev/null | sed 's/[^0-9.].*$//'
  fi
}

warn_path_precedence() {
  local tool="$1"
  local expected="${BIN_DIR}/${tool}"
  local resolved
  if [ "${BOOTSTRAP_ENFORCE_GLOBAL_BIN}" = "1" ] || [ "${BOOTSTRAP_ENFORCE_GLOBAL_BIN}" = "true" ]; then
    expected="${BOOTSTRAP_GLOBAL_BIN_DIR}/${tool}"
  fi
  resolved="$(cmd_path "${tool}")"
  if [ -n "${resolved}" ] && [ "${resolved}" != "${expected}" ]; then
    log "warning: ${tool} resolves to ${resolved}; expected ${expected} first in PATH"
  fi
}

ensure_kubectl() {
  local current
  local start
  start="$(date +%s)"
  current="$(get_kubectl_version "${BIN_DIR}/kubectl" || true)"
  log_kv "kubectl detected" "${current}"
  if [ "${current}" = "${KUBECTL_VERSION}" ]; then
    log "kubectl ${current} already available"
    warn_path_precedence kubectl
    log_duration "kubectl check" "${start}"
    return
  fi
  if [ -x "${BIN_DIR}/kubectl" ]; then
    confirm_reinstall "kubectl" "${current}" "${KUBECTL_VERSION}"
    log "removing kubectl ${current:-unknown} from ${BIN_DIR}"
    rm -f "${BIN_DIR}/kubectl"
  fi
  install_kubectl "$@"
  current="$(get_kubectl_version "${BIN_DIR}/kubectl" || true)"
  log_kv "kubectl installed" "${current}"
  warn_path_precedence kubectl
  log_duration "kubectl install" "${start}"
}

ensure_kind() {
  local current
  local start
  start="$(date +%s)"
  current="$(get_kind_version "${BIN_DIR}/kind" || true)"
  log_kv "kind detected" "${current}"
  if [ "${current}" = "${KIND_VERSION}" ]; then
    log "kind ${current} already available"
    warn_path_precedence kind
    log_duration "kind check" "${start}"
    return
  fi
  if [ -x "${BIN_DIR}/kind" ]; then
    confirm_reinstall "kind" "${current}" "${KIND_VERSION}"
    log "removing kind ${current:-unknown} from ${BIN_DIR}"
    rm -f "${BIN_DIR}/kind"
  fi
  install_kind "$@"
  current="$(get_kind_version "${BIN_DIR}/kind" || true)"
  log_kv "kind installed" "${current}"
  warn_path_precedence kind
  log_duration "kind install" "${start}"
}

ensure_jq() {
  local current
  local start
  start="$(date +%s)"
  current="$(get_jq_version "${BIN_DIR}/jq" || true)"
  log_kv "jq detected" "${current}"
  if [ "${current}" = "${JQ_VERSION}" ]; then
    log "jq ${current} already available"
    warn_path_precedence jq
    log_duration "jq check" "${start}"
    return
  fi
  if [ -x "${BIN_DIR}/jq" ]; then
    confirm_reinstall "jq" "${current}" "${JQ_VERSION}"
    log "removing jq ${current:-unknown} from ${BIN_DIR}"
    rm -f "${BIN_DIR}/jq"
  fi
  install_jq "$@"
  current="$(get_jq_version "${BIN_DIR}/jq" || true)"
  log_kv "jq installed" "${current}"
  warn_path_precedence jq
  log_duration "jq install" "${start}"
}

ensure_kustomize() {
  local current
  local start
  start="$(date +%s)"
  current="$(get_kustomize_version "${BIN_DIR}/kustomize" || true)"
  log_kv "kustomize detected" "${current}"
  if [ "${current}" = "${KUSTOMIZE_VERSION}" ]; then
    log "kustomize ${current} already available"
    warn_path_precedence kustomize
    log_duration "kustomize check" "${start}"
    return
  fi
  if [ -x "${BIN_DIR}/kustomize" ]; then
    confirm_reinstall "kustomize" "${current}" "${KUSTOMIZE_VERSION}"
    log "removing kustomize ${current:-unknown} from ${BIN_DIR}"
    rm -f "${BIN_DIR}/kustomize"
  fi
  install_kustomize "$@"
  current="$(get_kustomize_version "${BIN_DIR}/kustomize" || true)"
  log_kv "kustomize installed" "${current}"
  warn_path_precedence kustomize
  log_duration "kustomize install" "${start}"
}

ensure_kubeconform() {
  local current
  local start
  start="$(date +%s)"
  current="$(get_kubeconform_version "${BIN_DIR}/kubeconform" || true)"
  log_kv "kubeconform detected" "${current}"
  if [ "${current}" = "${KUBECONFORM_VERSION}" ]; then
    log "kubeconform ${current} already available"
    warn_path_precedence kubeconform
    log_duration "kubeconform check" "${start}"
    return
  fi
  if [ -x "${BIN_DIR}/kubeconform" ]; then
    confirm_reinstall "kubeconform" "${current}" "${KUBECONFORM_VERSION}"
    log "removing kubeconform ${current:-unknown} from ${BIN_DIR}"
    rm -f "${BIN_DIR}/kubeconform"
  fi
  install_kubeconform "$@"
  current="$(get_kubeconform_version "${BIN_DIR}/kubeconform" || true)"
  log_kv "kubeconform installed" "${current}"
  warn_path_precedence kubeconform
  log_duration "kubeconform install" "${start}"
}

main() {
  local os arch
  local start_all
  start_all="$(date +%s)"
  os="$(os_name)"
  arch="$(arch_name)"

  if [ "${os}" = "unknown" ]; then
    log "unsupported OS"
    exit 1
  fi

  ensure_bin_dir
  summary_init
  trap 'finalize $?' EXIT
  log "runtime user: $(id -un) (uid=$(id -u))"
  log "target versions (security/compat): kubectl=${KUBECTL_VERSION}, kind=${KIND_VERSION}, jq=${JQ_VERSION}, mkcert=${MKCERT_VERSION}, kustomize=${KUSTOMIZE_VERSION}, kubeconform=${KUBECONFORM_VERSION}, docker>=${DOCKER_ENGINE_MIN_VERSION}, git>=${GIT_VERSION}, make>=${MAKE_VERSION}, python3>=${PYTHON_VERSION}, openssl>=${OPENSSL_MIN_VERSION}, curl>=${CURL_MIN_VERSION}, wget>=${WGET_MIN_VERSION}, unzip>=${UNZIP_MIN_VERSION}"
  log "global binary mode: BOOTSTRAP_ENFORCE_GLOBAL_BIN=${BOOTSTRAP_ENFORCE_GLOBAL_BIN}, BOOTSTRAP_GLOBAL_BIN_DIR=${BOOTSTRAP_GLOBAL_BIN_DIR}"
  log "kube context controls: BOOTSTRAP_EXPECTED_KUBE_CONTEXT=${BOOTSTRAP_EXPECTED_KUBE_CONTEXT}, BOOTSTRAP_AUTO_KUBECONTEXT=${BOOTSTRAP_AUTO_KUBECONTEXT}"
  log "sysctl controls: BOOTSTRAP_TUNE_SYSCTL=${BOOTSTRAP_TUNE_SYSCTL}, BOOTSTRAP_SYSCTL_PERSIST=${BOOTSTRAP_SYSCTL_PERSIST}"
  log "apt maintenance controls: BOOTSTRAP_APT_MAINTENANCE=${BOOTSTRAP_APT_MAINTENANCE}, BOOTSTRAP_APT_UPGRADE=${BOOTSTRAP_APT_UPGRADE}, BOOTSTRAP_APT_FULL_UPGRADE=${BOOTSTRAP_APT_FULL_UPGRADE}, BOOTSTRAP_APT_AUTOREMOVE=${BOOTSTRAP_APT_AUTOREMOVE}, BOOTSTRAP_APT_CLEAN=${BOOTSTRAP_APT_CLEAN}"
  log "docker requirement: BOOTSTRAP_DOCKER_REQUIRED=${BOOTSTRAP_DOCKER_REQUIRED} (set 0 to skip docker check and continue installing other tools)"
  log "sha256 verification enabled for kubectl, kind, jq, kustomize, kubeconform, mkcert"
  log "set BOOTSTRAP_AUTO_CONFIRM=1 to auto-accept reinstalls"
  if have_cmd apt-get; then
    run_step "apt-system" ensure_apt_maintenance
  else
    summary_set "apt-system" "OK"
  fi
  run_step "sysctl" ensure_sysctl_inotify
  run_step "network-tools" ensure_network_tools
  run_step "git" ensure_git
  run_step "make" ensure_make
  run_step "python3" ensure_python
  run_step "openssl" ensure_openssl
  if [ "${BOOTSTRAP_DOCKER_REQUIRED}" = "0" ] || [ "${BOOTSTRAP_DOCKER_REQUIRED}" = "false" ]; then
    if have_cmd docker && docker info >/dev/null 2>&1; then
      run_step "docker" ensure_docker_running "${os}"
    else
      log "docker not available/running; skipping docker check (BOOTSTRAP_DOCKER_REQUIRED=0)"
      summary_set "docker" "SKIP"
    fi
  else
    run_step "docker" ensure_docker_running "${os}"
  fi
  run_step "mkcert" ensure_mkcert "${os}" "${arch}"

  run_step "kubectl" ensure_kubectl "${os}" "${arch}"
  run_step "kind" ensure_kind "${os}" "${arch}"
  run_step "kube-context" ensure_kube_context
  run_step "jq" ensure_jq "${os}" "${arch}"
  run_step "kustomize" ensure_kustomize "${os}" "${arch}"
  run_step "kubeconform" ensure_kubeconform "${os}" "${arch}"

  refresh_shell_command_cache
  print_terminal_refresh_hint
  log_duration "bootstrap total" "${start_all}"
  finalize 0
  log "bootstrap complete"
}

usage() {
  cat <<'EOF'
Usage: setup/ubuntu-22.04/setup.sh <command>

Commands:
  bootstrap   Install pinned dev tools into ./bin (default).
  doctor      Check local toolchain + basic repo readiness.
  hosts       Manage /etc/hosts dev block (requires sudo for apply/remove).

Examples:
  ./setup/ubuntu-22.04/setup.sh bootstrap
  ./setup/ubuntu-22.04/setup.sh doctor
  ./setup/ubuntu-22.04/setup.sh hosts status
  ./setup/ubuntu-22.04/setup.sh hosts apply
EOF
}

cmd_doctor() {
  # Lightweight copy of the old hack/doctor.sh, kept as a subcommand to minimize script count.
  version_ge() {
    local min="$1"
    local current="$2"
    [ "$(printf '%s\n' "${min}" "${current}" | sort -V | head -n1)" = "${min}" ]
  }

  detect_source() {
    local cmd="$1"
    local path
    path="$(command -v "${cmd}" 2>/dev/null || true)"
    if [ -z "${path}" ]; then
      echo "missing"
      return
    fi
    if [ "${path#${HOME}/}" != "${path}" ]; then
      echo "binary"
      return
    fi
    if [[ "${path}" == /usr/local/bin/* ]] || [[ "${path}" == /opt/* ]]; then
      echo "binary"
      return
    fi
    if [[ "${path}" == /usr/bin/* ]] || [[ "${path}" == /bin/* ]] || [[ "${path}" == /sbin/* ]] || [[ "${path}" == /usr/sbin/* ]]; then
      if command -v dpkg >/dev/null 2>&1 && dpkg -S "${path}" >/dev/null 2>&1; then
        echo "apt"
      else
        echo "unknown"
      fi
      return
    fi
    echo "unknown"
  }

  check_exact() {
    local name="$1"
    local cmd="$2"
    local current="$3"
    local desired="$4"
    local source
    source="$(detect_source "${cmd}")"
    if [ -z "${current}" ]; then
      printf "%-12s %-8s FAIL (not found)\n" "${name}" "${source}"
      return 1
    fi
    if [ "${current}" = "${desired}" ]; then
      printf "%-12s %-8s OK   %s\n" "${name}" "${source}" "${current}"
      return 0
    fi
    printf "%-12s %-8s WARN %s (expected %s)\n" "${name}" "${source}" "${current}" "${desired}"
    return 2
  }

  check_min() {
    local name="$1"
    local cmd="$2"
    local current="$3"
    local min="$4"
    local source
    source="$(detect_source "${cmd}")"
    if [ -z "${current}" ]; then
      printf "%-12s %-8s FAIL (not found)\n" "${name}" "${source}"
      return 1
    fi
    if version_ge "${min}" "${current}"; then
      printf "%-12s %-8s OK   %s\n" "${name}" "${source}" "${current}"
      return 0
    fi
    printf "%-12s %-8s WARN %s (min %s)\n" "${name}" "${source}" "${current}" "${min}"
    return 2
  }

  get_kubectl_version() { command -v kubectl >/dev/null 2>&1 && kubectl version --client -o yaml 2>/dev/null | awk -F': ' '/gitVersion:/ {print $2; exit}'; }
  get_kind_version() { command -v kind >/dev/null 2>&1 && kind version 2>/dev/null | awk '{print $2}'; }
  get_jq_version() { command -v jq >/dev/null 2>&1 && jq --version 2>/dev/null | sed 's/^jq-//'; }
  get_mkcert_version() { command -v mkcert >/dev/null 2>&1 && mkcert -version 2>/dev/null | head -n1 | awk '{print $1}' | sed 's/^v//'; }
  get_kustomize_version() {
    # Prefer repo-local pinned binary when present to avoid PATH / Windows interop edge cases.
    if [ -x "${ROOT_DIR}/bin/kustomize" ]; then
      "${ROOT_DIR}/bin/kustomize" version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1
      return
    fi
    command -v kustomize >/dev/null 2>&1 && kustomize version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1
  }
  get_kubeconform_version() { command -v kubeconform >/dev/null 2>&1 && kubeconform -v 2>/dev/null | head -n1 | sed 's/^v//'; }
  get_docker_version() { command -v docker >/dev/null 2>&1 && docker version --format '{{.Server.Version}}' 2>/dev/null | sed 's/[^0-9.].*$//'; }
  get_git_version() { command -v git >/dev/null 2>&1 && git --version 2>/dev/null | awk '{print $3}'; }
  get_make_version() { command -v make >/dev/null 2>&1 && make --version 2>/dev/null | head -n1 | awk '{print $3}'; }
  get_python_version() { command -v python3 >/dev/null 2>&1 && python3 --version 2>/dev/null | awk '{print $2}'; }
  get_openssl_version() { command -v openssl >/dev/null 2>&1 && openssl version 2>/dev/null | awk '{print $2}'; }
  get_curl_version() { command -v curl >/dev/null 2>&1 && curl --version 2>/dev/null | head -n1 | awk '{print $2}'; }
  get_wget_version() { command -v wget >/dev/null 2>&1 && wget --version 2>/dev/null | head -n1 | awk '{print $3}'; }
  get_unzip_version() { command -v unzip >/dev/null 2>&1 && unzip -v 2>/dev/null | head -n1 | awk '{print $2}'; }

  echo "Tool check:"
  printf "%-12s %-8s %s\n" "component" "source" "status"
  check_min "docker" "docker" "$(get_docker_version)" "${DOCKER_ENGINE_MIN_VERSION}" || true
  check_min "git" "git" "$(get_git_version)" "${GIT_VERSION}" || true
  check_min "make" "make" "$(get_make_version)" "${MAKE_VERSION}" || true
  check_min "python3" "python3" "$(get_python_version)" "${PYTHON_VERSION}" || true
  check_min "openssl" "openssl" "$(get_openssl_version)" "${OPENSSL_MIN_VERSION}" || true
  check_min "curl" "curl" "$(get_curl_version)" "${CURL_MIN_VERSION}" || true
  check_min "wget" "wget" "$(get_wget_version)" "${WGET_MIN_VERSION}" || true
  check_min "unzip" "unzip" "$(get_unzip_version)" "${UNZIP_MIN_VERSION}" || true

  check_exact "kubectl" "kubectl" "$(get_kubectl_version)" "${KUBECTL_VERSION}" || true
  check_exact "kind" "kind" "$(get_kind_version)" "${KIND_VERSION}" || true
  check_exact "jq" "jq" "$(get_jq_version)" "${JQ_VERSION}" || true
  check_exact "mkcert" "mkcert" "$(get_mkcert_version)" "${MKCERT_VERSION}" || true
  check_exact "kustomize" "kustomize" "$(get_kustomize_version)" "${KUSTOMIZE_VERSION}" || true
  check_exact "kubeconform" "kubeconform" "$(get_kubeconform_version)" "${KUBECONFORM_VERSION}" || true

  echo
  if [ -f "${ROOT_DIR}/.env" ]; then
    echo ".env present"
  else
    echo ".env missing (run: make dev-env-init)"
  fi

  if command -v kubectl >/dev/null 2>&1 && kubectl get ns dev >/dev/null 2>&1; then
    if kubectl -n dev get secret app-secrets >/dev/null 2>&1; then
      echo "app-secrets present in dev namespace"
    else
      echo "app-secrets not found in dev namespace"
    fi
  else
    echo "dev namespace not found"
  fi
}

cmd_hosts() {
  local HOSTS_FILE="${HOSTS_FILE:-/etc/hosts}"
  local BEGIN_MARKER="# BEGIN reliable-message-api dev"
  local END_MARKER="# END reliable-message-api dev"
  local -a ENTRIES=("127.0.0.1 api.local.dev" "127.0.0.1 kong.local.dev")

  hosts_usage() {
    cat <<'EOF'
Usage: setup/ubuntu-22.04/setup.sh hosts <command>

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
      exec sudo HOSTS_FILE="${HOSTS_FILE}" "$0" hosts "$@"
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
            if (ip != "127.0.0.1") print $0
          }
        }
      }
    ' "${HOSTS_FILE}"
  }

  local sub="${1:-}"
  case "${sub}" in
    status)
      if [ ! -f "${HOSTS_FILE}" ]; then
        echo "ERROR: hosts file not found: ${HOSTS_FILE}" >&2
        return 1
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
      fi
      ;;

    apply)
      if [ ! -f "${HOSTS_FILE}" ]; then
        echo "ERROR: hosts file not found: ${HOSTS_FILE}" >&2
        return 1
      fi
      need_root_or_sudo apply

      local conflicts
      conflicts="$(check_conflicts || true)"
      if [ -n "${conflicts}" ]; then
        echo "ERROR: found conflicting entries for api.local.dev/kong.local.dev in ${HOSTS_FILE}:" >&2
        echo "${conflicts}" >&2
        return 1
      fi

      local backup tmp
      backup="${HOSTS_FILE}.bak.reliable-message-api.$(date +%s)"
      cp -f "${HOSTS_FILE}" "${backup}"
      tmp="$(mktemp)"
      strip_block >"${tmp}"
      {
        echo
        echo "${BEGIN_MARKER}"
        for entry in "${ENTRIES[@]}"; do echo "${entry}"; done
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
        return 1
      fi
      need_root_or_sudo remove
      if ! grep -Fq "${BEGIN_MARKER}" "${HOSTS_FILE}" 2>/dev/null; then
        echo "No dev block found in ${HOSTS_FILE} (nothing to do)."
        return 0
      fi
      local backup tmp
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
      hosts_usage
      ;;

    *)
      echo "ERROR: unknown hosts subcommand: ${sub}" >&2
      hosts_usage >&2
      return 2
      ;;
  esac
}

cmd="${1:-bootstrap}"
case "${cmd}" in
  bootstrap)
    shift || true
    main "$@"
    ;;
  doctor)
    shift || true
    cmd_doctor "$@"
    ;;
  hosts)
    shift || true
    cmd_hosts "$@"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    echo "ERROR: unknown command: ${cmd}" >&2
    usage >&2
    exit 2
    ;;
esac
