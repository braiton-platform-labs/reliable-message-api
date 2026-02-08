#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSIONS_FILE="${VERSIONS_FILE:-${ROOT_DIR}/hack/tool-versions.env}"

if [ -f "${VERSIONS_FILE}" ]; then
  # shellcheck disable=SC1090
  set -a
  . "${VERSIONS_FILE}"
  set +a
fi

KUBECTL_VERSION="${KUBECTL_VERSION:-v1.35.0}"
KIND_VERSION="${KIND_VERSION:-v0.30.0}"
JQ_VERSION="${JQ_VERSION:-1.8.1}"
AWSCLI_VERSION="${AWSCLI_VERSION:-2.33.17}"
MKCERT_VERSION="${MKCERT_VERSION:-1.4.4}"
KUSTOMIZE_VERSION="${KUSTOMIZE_VERSION:-5.8.0}"
KUBECONFORM_VERSION="${KUBECONFORM_VERSION:-0.7.0}"
DOCKER_ENGINE_MIN_VERSION="${DOCKER_ENGINE_MIN_VERSION:-28.0.0}"
GIT_VERSION="${GIT_VERSION:-2.34.0}"
MAKE_VERSION="${MAKE_VERSION:-4.3}"
PYTHON_VERSION="${PYTHON_VERSION:-3.8.0}"
OPENSSL_MIN_VERSION="${OPENSSL_MIN_VERSION:-1.1.1}"
CURL_MIN_VERSION="${CURL_MIN_VERSION:-7.68.0}"
WGET_MIN_VERSION="${WGET_MIN_VERSION:-1.20.0}"
UNZIP_MIN_VERSION="${UNZIP_MIN_VERSION:-6.0}"

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
    if dpkg -S "${path}" >/dev/null 2>&1; then
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

get_kubectl_version() {
  if command -v kubectl >/dev/null 2>&1; then
    kubectl version --client -o yaml 2>/dev/null | awk -F': ' '/gitVersion:/ {print $2; exit}'
  fi
}
get_kind_version() {
  if command -v kind >/dev/null 2>&1; then
    kind version 2>/dev/null | awk '{print $2}'
  fi
}
get_jq_version() {
  if command -v jq >/dev/null 2>&1; then
    jq --version 2>/dev/null | sed 's/^jq-//'
  fi
}
get_awscli_version() {
  if command -v aws >/dev/null 2>&1; then
    local first
    first="$(aws --version 2>/dev/null | awk '{print $1}')"
    echo "${first#aws-cli/}"
  fi
}
get_mkcert_version() {
  if command -v mkcert >/dev/null 2>&1; then
    mkcert -version 2>/dev/null | head -n1 | awk '{print $1}' | sed 's/^v//'
  fi
}
get_kustomize_version() {
  if command -v kustomize >/dev/null 2>&1; then
    kustomize version 2>/dev/null | grep -Eo 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | sed 's/^v//'
  fi
}
get_kubeconform_version() {
  if command -v kubeconform >/dev/null 2>&1; then
    kubeconform -v 2>/dev/null | head -n1 | sed 's/^v//'
  fi
}
get_docker_version() {
  if command -v docker >/dev/null 2>&1; then
    docker version --format '{{.Server.Version}}' 2>/dev/null | sed 's/[^0-9.].*$//'
  fi
}
get_git_version() {
  if command -v git >/dev/null 2>&1; then
    git --version 2>/dev/null | awk '{print $3}'
  fi
}
get_make_version() {
  if command -v make >/dev/null 2>&1; then
    make --version 2>/dev/null | head -n1 | awk '{print $3}'
  fi
}
get_python_version() {
  if command -v python3 >/dev/null 2>&1; then
    python3 --version 2>/dev/null | awk '{print $2}'
  fi
}
get_openssl_version() {
  if command -v openssl >/dev/null 2>&1; then
    openssl version 2>/dev/null | awk '{print $2}'
  fi
}
get_curl_version() {
  if command -v curl >/dev/null 2>&1; then
    curl --version 2>/dev/null | head -n1 | awk '{print $2}'
  fi
}
get_wget_version() {
  if command -v wget >/dev/null 2>&1; then
    wget --version 2>/dev/null | head -n1 | awk '{print $3}'
  fi
}
get_unzip_version() {
  if command -v unzip >/dev/null 2>&1; then
    unzip -v 2>/dev/null | head -n1 | awk '{print $2}'
  fi
}

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
check_exact "awscli" "aws" "$(get_awscli_version)" "${AWSCLI_VERSION}" || true
check_exact "mkcert" "mkcert" "$(get_mkcert_version)" "${MKCERT_VERSION}" || true
check_exact "kustomize" "kustomize" "$(get_kustomize_version)" "${KUSTOMIZE_VERSION}" || true
check_exact "kubeconform" "kubeconform" "$(get_kubeconform_version)" "${KUBECONFORM_VERSION}" || true

AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_PROFILE="${AWS_PROFILE:-default}"

echo
echo "AWS_REGION=${AWS_REGION}"
echo "AWS_PROFILE=${AWS_PROFILE}"

aws sts get-caller-identity --region "${AWS_REGION}" --profile "${AWS_PROFILE}" >/dev/null && echo "aws identity ok"

if kubectl get ns dev >/dev/null 2>&1; then
  if kubectl -n dev get secret ecr-pull >/dev/null 2>&1; then
    ts=$(kubectl -n dev get secret ecr-pull -o jsonpath='{.metadata.annotations.ecr-pull\.bpl/refreshedAtEpoch}' 2>/dev/null || true)
    if [ -n "$ts" ]; then
      now=$(date +%s)
      age=$((now - ts))
      echo "ecr-pull age seconds=${age}"
    else
      echo "ecr-pull missing refreshedAtEpoch annotation"
    fi
  else
    echo "ecr-pull secret not found in dev namespace"
  fi
else
  echo "dev namespace not found"
fi
