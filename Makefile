.PHONY: help test lint format kind-up kind-down dev-context dev-env-init dev-secrets-apply dev-build dev-kind-load dev-apply dev-dd \
	dev-up dev-fg dev-reload dev-rollout dev-rollout-all dev-port dev-port-bg dev-port-stop dev-port-status dev-port-logs dev-reset dev-verify dev dev-status \
	dev-logs dev-psql dev-port-kong-admin dev-tls dev-kong-whitelist dev-kong-user dev-kong-user-remove dev-kong-crds-install \
	dev-hosts-status dev-hosts-apply dev-hosts-remove dev-hosts-status-win dev-hosts-apply-win dev-hosts-remove-win \
	k8s-validate dev-clean dev-nuke kustomize-bin kubeconform-bin doctor bootstrap bootstrap-full first-run

TOOL_VERSIONS_FILE ?= setup/ubuntu-22.04/tool-versions.env
-include $(TOOL_VERSIONS_FILE)
export KUSTOMIZE_VERSION KUBECONFORM_VERSION

ENV_FILE ?= .env
KONG_CRDS_REF ?= v3.3
KIND_CLUSTER_NAME ?= bpl-dev
EXPECTED_KUBE_CONTEXT ?= kind-$(KIND_CLUSTER_NAME)
KIND_NODE_IMAGE ?= kindest/node:v1.34.3
# KIND_WORKERS can be:
# - auto: pick based on CPU/RAM heuristics
# - 0/1/2/...: explicit workers count
# Default: 1 worker (more stable on dev laptops)
KIND_WORKERS ?= 1

IMAGE ?= reliable-message-api:dev

DEV_HTTP_PORT ?= 8080
DEV_HTTPS_PORT ?= 8443
DEV_PORT_FORWARD_ADDR ?= 127.0.0.1
DEV_PORT_FORWARD_DIR ?= /tmp/reliable-message-api-dev-$(KIND_CLUSTER_NAME)
DEV_WAIT_TIMEOUT ?= 300s

BIN_DIR ?= bin

# Prefer repo-local tools installed into ./bin (e.g., via `make bootstrap` / `./setup/ubuntu-22.04/setup.sh bootstrap`).
export PATH := $(BIN_DIR):$(PATH)

# Cross-platform helpers (Windows uses .exe).
EXE ?=
ifeq ($(OS),Windows_NT)
UNAME_S := Windows_NT
EXE := .exe
else
UNAME_S := $(shell uname -s 2>/dev/null || echo unknown)
endif
ifneq (,$(filter MINGW% MSYS% CYGWIN%,$(UNAME_S)))
EXE := .exe
endif

PYTHON ?= python3
ifeq ($(EXE),.exe)
PYTHON := python
endif

KUSTOMIZE_BIN ?= $(BIN_DIR)/kustomize$(EXE)
KUBECONFORM_BIN ?= $(BIN_DIR)/kubeconform$(EXE)

help:
	@echo "Targets:"
	@echo "  make first-run          First time: bootstrap tools + bring up dev environment"
	@echo "  make bootstrap          Install pinned tools into ./bin (fast; no sysctl/apt changes)"
	@echo "  make doctor             Check your local toolchain/environment"
	@echo "  make dev                Full local dev flow (apply + restart + port-forward in background)"
	@echo "  make dev-fg             Same as dev, but keeps port-forward in foreground (Ctrl+C to stop)"
	@echo "  make dev-up             Provision/apply/restart/wait (no port-forward)"
	@echo "  make dev-reload         Fast loop: build+load and restart only the API"
	@echo "  make dev-port-bg        Start/restart port-forward in background and exit"
	@echo "  make dev-port-stop      Stop background port-forward (if running)"
	@echo "  make dev-dd             Apply dev-dd overlay (includes Datadog agent)"
	@echo "  make dev-secrets-apply   Apply dev/app-secrets from $(ENV_FILE)"
	@echo "  make k8s-validate        Validate k8s manifests with kubeconform"
	@echo "  make dev-clean           Clean dev namespace, kind cluster, and build cache"

doctor:
	@./setup/ubuntu-22.04/setup.sh doctor

# Lightweight bootstrap for onboarding: installs pinned binaries into ./bin without changing sysctl
# or running apt maintenance (no sudo required for most machines).
bootstrap:
	@set -e; \
	if [ "$(EXE)" = ".exe" ]; then \
	  echo "Windows host bootstrap via Makefile is not supported for this repo."; \
	  echo "Use the supported Windows workflow:"; \
	  echo "  powershell -ExecutionPolicy Bypass -File setup/windows-11-wsl2-docker-desktop/setup.ps1 install"; \
	  echo "Or run make inside WSL (Ubuntu 22.04)."; \
	  exit 1; \
	else \
	  BOOTSTRAP_INSTALL_MODE=local \
	    BOOTSTRAP_ENFORCE_GLOBAL_BIN=0 \
	    BOOTSTRAP_APT_MAINTENANCE=0 \
	    BOOTSTRAP_TUNE_SYSCTL=0 \
	    BOOTSTRAP_SYSCTL_PERSIST=0 \
	    ./setup/ubuntu-22.04/setup.sh bootstrap; \
	fi

# Full bootstrap (may require sudo and may tune sysctl for kind stability).
bootstrap-full:
	@./setup/ubuntu-22.04/setup.sh bootstrap

first-run:
	@$(MAKE) bootstrap
	@$(MAKE) dev

kind-up:
	@cluster="$(KIND_CLUSTER_NAME)"; \
	ctx="$(EXPECTED_KUBE_CONTEXT)"; \
	image="$(KIND_NODE_IMAGE)"; \
	workers="$(KIND_WORKERS)"; \
	auto_workers() { \
		os=$$(uname -s 2>/dev/null || echo unknown); \
		cpus=2; \
		mem_gb=4; \
		if command -v nproc >/dev/null 2>&1; then cpus=$$(nproc); \
		elif [ "$$os" = "Darwin" ]; then cpus=$$(sysctl -n hw.ncpu 2>/dev/null || echo 2); \
		fi; \
		if [ -r /proc/meminfo ]; then \
			mem_kb=$$(awk '/MemTotal:/ {print $$2}' /proc/meminfo); \
			mem_gb=$$((mem_kb/1024/1024)); \
		elif [ "$$os" = "Darwin" ]; then \
			mem_bytes=$$(sysctl -n hw.memsize 2>/dev/null || echo 4294967296); \
			mem_gb=$$((mem_bytes/1024/1024/1024)); \
		fi; \
		# Conservative defaults. Docker Desktop may allocate less than host RAM, but this avoids the worst cases. \
		# 0 workers: low RAM or low CPU. 1 worker: medium. 2 workers: decent dev machine. \
		if [ "$$mem_gb" -lt 8 ] || [ "$$cpus" -lt 4 ]; then echo 0; \
		elif [ "$$mem_gb" -lt 12 ] || [ "$$cpus" -lt 6 ]; then echo 1; \
		else echo 2; fi; \
	}; \
	if [ "$$workers" = "auto" ] || [ -z "$$workers" ]; then \
		workers=$$(auto_workers); \
		echo "auto-selected kind workers=$$workers (override with KIND_WORKERS=0|1|2)"; \
	fi; \
	make_config() { \
		out="$$1"; \
		w="$$2"; \
		{ \
			echo "kind: Cluster"; \
			echo "apiVersion: kind.x-k8s.io/v1alpha4"; \
			echo "nodes:"; \
			echo "  - role: control-plane"; \
			i=0; \
			while [ "$$i" -lt "$$w" ]; do \
				echo "  - role: worker"; \
				i=$$((i+1)); \
			done; \
		} > "$$out"; \
	}; \
	create_cluster() { \
		w="$$1"; \
		cfg="/tmp/kind-$$cluster-config.yaml"; \
		make_config "$$cfg" "$$w"; \
		echo "kind config: $$cfg (workers=$$w)"; \
		if [ -n "$$image" ]; then \
			echo "using kind node image: $$image"; \
			kind create cluster --name "$$cluster" --image "$$image" --config "$$cfg"; \
		else \
			kind create cluster --name "$$cluster" --config "$$cfg"; \
		fi; \
	}; \
	if kind get clusters 2>/dev/null | grep -qx "$$cluster"; then \
		echo "kind cluster '$$cluster' already exists"; \
	else \
		echo "creating kind cluster '$$cluster'"; \
		if create_cluster "$$workers"; then \
			:; \
		else \
			echo "ERROR: kind create cluster failed (workers=$$workers); exporting logs..."; \
			kind export logs "/tmp/kind-$$cluster-logs" >/dev/null 2>&1 || true; \
			echo "logs: /tmp/kind-$$cluster-logs"; \
			if [ "$$workers" -gt 0 ]; then \
				echo "retrying with single-node cluster (workers=0) for maximum stability..."; \
				kind delete cluster --name "$$cluster" >/dev/null 2>&1 || true; \
				if ! create_cluster 0; then \
					echo "ERROR: kind create cluster failed even with workers=0"; \
					echo "Common causes: low RAM/CPU allocated to Docker, cgroup/iptables incompatibility, or disk pressure."; \
					echo "Try: increase Docker resources and re-run: KIND_WORKERS=0 make kind-up"; \
					exit 1; \
				fi; \
			else \
				exit 1; \
			fi; \
		fi; \
	fi; \
		echo "ensuring kubectl context is '$$ctx'"; \
		kind export kubeconfig --name "$$cluster" >/dev/null 2>&1 || true; \
		kubectl config use-context "$$ctx" >/dev/null; \
		cur_ctx=$$(kubectl config current-context 2>/dev/null || true); \
		if [ "$$cur_ctx" != "$$ctx" ]; then \
			echo "ERROR: failed to switch kubectl context to $$ctx (current=$$cur_ctx)"; \
			exit 1; \
		fi; \
		echo "waiting for nodes/CNI/kube-proxy to be ready..."; \
		kubectl wait --for=condition=Ready node --all --timeout=180s >/dev/null || true; \
		kubectl -n kube-system rollout status ds/kindnet --timeout=180s >/dev/null 2>&1 || true; \
	if ! kubectl -n kube-system rollout status ds/kube-proxy --timeout=180s >/dev/null 2>&1; then \
		echo "ERROR: kube-proxy is not healthy; Service networking will not work."; \
		echo "kube-proxy pods:"; \
		kubectl -n kube-system get pods -l k8s-app=kube-proxy -o wide || true; \
		echo "kube-proxy logs (tail):"; \
		kubectl -n kube-system logs -l k8s-app=kube-proxy --tail=200 || true; \
		echo "Hint: this is commonly caused by too-low file descriptor limits (nofile) for Docker containers."; \
		echo "Fix host Docker ulimits and re-run: make kind-down && KIND_WORKERS=0 make kind-up"; \
		exit 1; \
	fi; \
		echo "installing local-path storage provisioner"; \
		kubectl apply -f k8s/vendor/local-path-storage.v0.0.27.yaml; \
		kubectl -n local-path-storage rollout status deployment/local-path-provisioner; \
		kubectl patch storageclass local-path -p '{"metadata": {"annotations": {"storageclass.kubernetes.io/is-default-class":"true"}}}' >/dev/null; \
		echo "kind cluster is ready"

kind-down:
	@cluster="$(KIND_CLUSTER_NAME)"; \
	if kind get clusters 2>/dev/null | grep -qx "$$cluster"; then \
		echo "deleting kind cluster '$$cluster'"; \
		kind delete cluster --name "$$cluster"; \
	else \
		echo "kind cluster '$$cluster' does not exist"; \
	fi

dev-context:
	@expected="$(EXPECTED_KUBE_CONTEXT)"; \
	cluster="$(KIND_CLUSTER_NAME)"; \
	if ! kubectl config get-contexts -o name 2>/dev/null | grep -qx "$$expected"; then \
		echo "kube context '$$expected' not found; creating kind cluster '$$cluster'"; \
		cfg="/tmp/kind-$$cluster-config.yaml"; \
		{ \
			echo "kind: Cluster"; \
			echo "apiVersion: kind.x-k8s.io/v1alpha4"; \
			echo "nodes:"; \
			echo "  - role: control-plane"; \
		} > "$$cfg"; \
		if kind get clusters 2>/dev/null | grep -qx "$$cluster"; then \
			echo "kind cluster '$$cluster' already exists (context missing, re-exporting kubeconfig)"; \
		else \
			kind create cluster --name "$$cluster" --image "$(KIND_NODE_IMAGE)" --config "$$cfg" || { \
				echo "ERROR: kind create cluster failed; exporting logs..."; \
				kind export logs "/tmp/kind-$$cluster-logs" >/dev/null 2>&1 || true; \
				echo "logs: /tmp/kind-$$cluster-logs"; \
				exit 1; \
			}; \
		fi; \
		kind export kubeconfig --name "$$cluster" >/dev/null 2>&1 || true; \
		if ! kubectl config get-contexts -o name 2>/dev/null | grep -qx "$$expected"; then \
			echo "ERROR: kube context still missing after kind create/export: $$expected"; \
			echo "Available contexts:"; \
			kubectl config get-contexts -o name || true; \
			exit 1; \
		fi; \
	fi; \
	kubectl config use-context "$$expected" >/dev/null; \
	ctx=$$(kubectl config current-context 2>/dev/null || true); \
	if [ "$$ctx" != "$$expected" ]; then \
		echo "ERROR: failed to switch kubectl context to $$expected (current=$$ctx)"; \
		exit 1; \
	fi; \
		echo "Using kube context: $$expected"; \
		if ! kubectl get ns local-path-storage >/dev/null 2>&1; then \
			echo "installing local-path storage provisioner"; \
			kubectl apply -f k8s/vendor/local-path-storage.v0.0.27.yaml; \
			kubectl -n local-path-storage rollout status deployment/local-path-provisioner; \
			kubectl patch storageclass local-path -p '{"metadata": {"annotations": {"storageclass.kubernetes.io/is-default-class":"true"}}}' >/dev/null; \
		fi

dev-env-init:
	@$(PYTHON) scripts/dev_env.py init --env-file "$(ENV_FILE)"

dev-build:
	DOCKER_BUILDKIT=1 docker build -f docker/Dockerfile -t $(IMAGE) --label project=reliable-message-api .

dev-kind-load: dev-context dev-build
	@set -e; \
	cluster="$(KIND_CLUSTER_NAME)"; \
	image="$(IMAGE)"; \
	nodes="$$(kind get nodes --name "$$cluster" 2>/dev/null || true)"; \
	if [ -z "$$nodes" ]; then \
		echo "ERROR: kind cluster '$$cluster' not found (is it running?)"; \
		exit 1; \
	fi; \
	cp_node="$$(printf "%s\n" "$$nodes" | grep -- '-control-plane$$' | head -n 1 || true)"; \
	workers_csv="$$(printf "%s\n" "$$nodes" | grep -v -- '-control-plane$$' | tr '\n' ',' | sed 's/,$$//')"; \
	if [ -n "$$workers_csv" ]; then \
		if [ -n "$$cp_node" ] && kubectl get node "$$cp_node" -o jsonpath='{range .spec.taints[*]}{.key}{"="}{.effect}{"\n"}{end}' 2>/dev/null | grep -Eq 'node-role.kubernetes.io/(control-plane|master)=NoSchedule'; then \
			echo "==> Loading image into kind worker nodes (skip tainted control-plane): $$workers_csv"; \
			kind load docker-image "$$image" --name "$$cluster" --nodes "$$workers_csv"; \
		else \
			echo "==> Control-plane appears schedulable (or taints unknown); loading image into all kind nodes"; \
			kind load docker-image "$$image" --name "$$cluster"; \
		fi; \
	else \
		echo "==> No workers detected; loading image into all kind nodes"; \
		kind load docker-image "$$image" --name "$$cluster"; \
	fi

dev-apply: dev-context kustomize-bin dev-kind-load dev-kong-crds-install
	$(KUSTOMIZE_BIN) build k8s/overlays/dev | kubectl apply -f -

dev-dd: dev-context kustomize-bin dev-kind-load dev-kong-crds-install
	$(KUSTOMIZE_BIN) build k8s/overlays/dev-dd | kubectl apply -f -

dev-reload: dev-kind-load
	@set -e; \
	if ! kubectl -n dev get deployment/api >/dev/null 2>&1; then \
		echo "ERROR: deployment/api not found in namespace dev. Run: make dev-up"; \
		exit 1; \
	fi; \
	echo "==> Restarting API (to pick up the latest local image)..."; \
	kubectl -n dev rollout restart deployment/api >/dev/null; \
	echo "==> Waiting for API rollout..."; \
	kubectl -n dev rollout status deployment/api --timeout=$(DEV_WAIT_TIMEOUT) >/dev/null; \
	echo "==> API rollout OK."

dev-rollout: dev-context
	@set -e; \
	echo "==> Waiting for Postgres to be Ready..."; \
	kubectl -n dev wait --for=condition=Ready pod -l app=postgres --timeout=$(DEV_WAIT_TIMEOUT) >/dev/null; \
	echo "==> Waiting for Kong rollout..."; \
	kubectl -n dev rollout status deployment/kong --timeout=$(DEV_WAIT_TIMEOUT) >/dev/null; \
	echo "==> Waiting for Kong Ingress Controller rollout..."; \
	kubectl -n dev rollout status deployment/kong-ingress --timeout=$(DEV_WAIT_TIMEOUT) >/dev/null; \
	echo "==> Restarting API (to pick up the latest local image/secrets)..."; \
	kubectl -n dev rollout restart deployment/api >/dev/null; \
	echo "==> Waiting for API rollout..."; \
	kubectl -n dev rollout status deployment/api --timeout=$(DEV_WAIT_TIMEOUT) >/dev/null; \
	echo "==> Rollouts OK."

dev-rollout-all: dev-context
	@set -e; \
	echo "==> Waiting for Postgres to be Ready..."; \
	kubectl -n dev wait --for=condition=Ready pod -l app=postgres --timeout=$(DEV_WAIT_TIMEOUT) >/dev/null; \
	echo "==> Restarting Kong + KIC + API (full refresh)..."; \
	kubectl -n dev rollout restart deployment/kong deployment/kong-ingress deployment/api >/dev/null; \
	echo "==> Waiting for Kong rollout..."; \
	kubectl -n dev rollout status deployment/kong --timeout=$(DEV_WAIT_TIMEOUT) >/dev/null; \
	echo "==> Waiting for Kong Ingress Controller rollout..."; \
	kubectl -n dev rollout status deployment/kong-ingress --timeout=$(DEV_WAIT_TIMEOUT) >/dev/null; \
	echo "==> Waiting for API rollout..."; \
	kubectl -n dev rollout status deployment/api --timeout=$(DEV_WAIT_TIMEOUT) >/dev/null; \
	echo "==> Rollouts OK."

dev-port: dev-context
	@echo "==> Waiting for Kong proxy to be ready..."
	@kubectl -n dev wait --for=condition=Ready pod -l app=kong --timeout=$(DEV_WAIT_TIMEOUT) >/dev/null || { \
		echo "ERROR: kong pod not Ready; current status:"; \
		kubectl -n dev get pods -o wide || true; \
		exit 1; \
	}
	@echo "==> Port-forward active at http://$(DEV_PORT_FORWARD_ADDR):$(DEV_HTTP_PORT) and https://$(DEV_PORT_FORWARD_ADDR):$(DEV_HTTPS_PORT) (Ctrl+C to stop)."
	@echo "==> HTTP test (another terminal): curl -H 'Host: api.local.dev' http://$(DEV_PORT_FORWARD_ADDR):$(DEV_HTTP_PORT)/health"
	@echo "==> HTTPS test: curl -sk --resolve api.local.dev:$(DEV_HTTPS_PORT):$(DEV_PORT_FORWARD_ADDR) -H 'Host: api.local.dev' https://api.local.dev:$(DEV_HTTPS_PORT)/health"
	kubectl -n dev port-forward --address $(DEV_PORT_FORWARD_ADDR) svc/kong-proxy $(DEV_HTTP_PORT):80 $(DEV_HTTPS_PORT):443

dev-port-bg: dev-context
	@set -e; \
	mkdir -p "$(DEV_PORT_FORWARD_DIR)"; \
	pid="$(DEV_PORT_FORWARD_DIR)/kong-proxy.pid"; \
	log="$(DEV_PORT_FORWARD_DIR)/kong-proxy.log"; \
	if [ -f "$$pid" ] && kill -0 "$$(cat "$$pid" 2>/dev/null)" 2>/dev/null; then \
		echo "==> Stopping existing kong-proxy port-forward (pid=$$(cat "$$pid"))..."; \
		kill "$$(cat "$$pid")" >/dev/null 2>&1 || true; \
		sleep 1; \
	fi; \
	rm -f "$$pid"; \
	echo "==> Waiting for Kong proxy to be ready..."; \
	kubectl -n dev wait --for=condition=Ready pod -l app=kong --timeout=$(DEV_WAIT_TIMEOUT) >/dev/null; \
	start_pf() { \
		args="$$1"; \
		: >"$$log"; \
		nohup kubectl -n dev port-forward --address $(DEV_PORT_FORWARD_ADDR) svc/kong-proxy $$args >"$$log" 2>&1 & \
		echo $$! >"$$pid"; \
	}; \
	mode="both"; \
	echo "==> Starting kong-proxy port-forward in background: $(DEV_PORT_FORWARD_ADDR):$(DEV_HTTP_PORT)->80, $(DEV_PORT_FORWARD_ADDR):$(DEV_HTTPS_PORT)->443"; \
	start_pf "$(DEV_HTTP_PORT):80 $(DEV_HTTPS_PORT):443"; \
	timeout=60; elapsed=0; \
	while :; do \
		code=$$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: api.local.dev' "http://$(DEV_PORT_FORWARD_ADDR):$(DEV_HTTP_PORT)/health" 2>/dev/null || echo 000); \
		if [ "$$code" = "200" ] || [ "$$code" = "403" ]; then \
			break; \
		fi; \
		if ! kill -0 "$$(cat "$$pid" 2>/dev/null)" 2>/dev/null; then \
			if [ "$$mode" = "both" ] && grep -qi "address already in use" "$$log" && grep -q ":$(DEV_HTTPS_PORT)" "$$log"; then \
				echo "WARN: HTTPS port $(DEV_HTTPS_PORT) is in use; starting HTTP-only port-forward..."; \
				mode="http-only"; \
				start_pf "$(DEV_HTTP_PORT):80"; \
				elapsed=0; \
				continue; \
			fi; \
			echo "ERROR: port-forward exited early. Log (last 50 lines):"; \
			tail -n 50 "$$log" || true; \
			exit 1; \
		fi; \
		if [ $$elapsed -ge $$timeout ]; then \
			echo "ERROR: timeout waiting for port-forward. Log (last 50 lines):"; \
			tail -n 50 "$$log" || true; \
			exit 1; \
		fi; \
		sleep 1; \
		elapsed=$$((elapsed+1)); \
	done; \
	echo "==> Port-forward OK (pid=$$(cat "$$pid"), mode=$$mode)."; \
	echo "==> HTTP:  http://$(DEV_PORT_FORWARD_ADDR):$(DEV_HTTP_PORT)"; \
	if [ "$$mode" = "both" ]; then \
		echo "==> HTTPS: https://api.local.dev:$(DEV_HTTPS_PORT) (use --resolve if needed)"; \
	else \
		echo "==> HTTPS: (disabled)"; \
	fi; \
	echo "==> Stop:  make dev-port-stop"; \
	echo "==> Logs:  make dev-port-logs"

dev-port-stop:
	@set -e; \
	pid="$(DEV_PORT_FORWARD_DIR)/kong-proxy.pid"; \
	if [ ! -f "$$pid" ]; then \
		echo "==> No managed port-forward pid file found ($$pid)."; \
		exit 0; \
	fi; \
	if kill -0 "$$(cat "$$pid" 2>/dev/null)" 2>/dev/null; then \
		echo "==> Stopping kong-proxy port-forward (pid=$$(cat "$$pid"))..."; \
		kill "$$(cat "$$pid")" >/dev/null 2>&1 || true; \
		sleep 1; \
	fi; \
	rm -f "$$pid"; \
	echo "==> Port-forward stopped."

dev-port-status:
	@set -e; \
	pid="$(DEV_PORT_FORWARD_DIR)/kong-proxy.pid"; \
	log="$(DEV_PORT_FORWARD_DIR)/kong-proxy.log"; \
	if [ -f "$$pid" ] && kill -0 "$$(cat "$$pid" 2>/dev/null)" 2>/dev/null; then \
		echo "==> kong-proxy port-forward running (pid=$$(cat "$$pid"))"; \
		echo "==> HTTP:  http://$(DEV_PORT_FORWARD_ADDR):$(DEV_HTTP_PORT)"; \
		echo "==> HTTPS: https://api.local.dev:$(DEV_HTTPS_PORT)"; \
		if [ -f "$$log" ]; then \
			echo "==> Forwarding:"; \
			grep -E "Forwarding from" "$$log" | tail -n 5 || true; \
		fi; \
		exit 0; \
	fi; \
	echo "==> kong-proxy port-forward not running."; \
	if [ -f "$$log" ]; then \
		echo "==> Last log lines:"; \
		tail -n 20 "$$log" || true; \
	fi

dev-port-logs:
	@tail -n 200 -f "$(DEV_PORT_FORWARD_DIR)/kong-proxy.log"

dev-port-kong-admin: dev-context
	kubectl -n dev port-forward svc/kong-admin 8001:8001 8002:8002

dev-hosts-status:
	@./setup/ubuntu-22.04/setup.sh hosts status

dev-hosts-apply:
	@./setup/ubuntu-22.04/setup.sh hosts apply

dev-hosts-remove:
	@./setup/ubuntu-22.04/setup.sh hosts remove

dev-hosts-status-win:
	@powershell.exe -ExecutionPolicy Bypass -File setup/windows-11-wsl2-docker-desktop/setup.ps1 hosts -HostsAction status

dev-hosts-apply-win:
	@powershell.exe -ExecutionPolicy Bypass -File setup/windows-11-wsl2-docker-desktop/setup.ps1 hosts -HostsAction apply

dev-hosts-remove-win:
	@powershell.exe -ExecutionPolicy Bypass -File setup/windows-11-wsl2-docker-desktop/setup.ps1 hosts -HostsAction remove

dev-reset: dev-context
	-$(MAKE) dev-port-stop >/dev/null 2>&1 || true
	kubectl delete ns dev --ignore-not-found=true
	$(MAKE) dev-secrets-apply
	$(MAKE) dev-apply

dev-secrets-apply: dev-context dev-env-init
	@echo "==> Applying Kubernetes Secret dev/app-secrets from $(ENV_FILE) (no values printed)..."
	@if [ ! -f "$(ENV_FILE)" ]; then \
		echo "ERROR: $(ENV_FILE) not found."; \
		echo "Create it (or run: make dev-env-init) and re-run."; \
		exit 1; \
	fi
	@$(PYTHON) scripts/dev_env.py validate --env-file "$(ENV_FILE)" >/dev/null
	@kubectl apply -f k8s/overlays/dev/namespace.yaml >/dev/null
	@kubectl -n dev create secret generic app-secrets \
		--from-env-file="$(ENV_FILE)" \
		--dry-run=client -o yaml | kubectl apply -f - >/dev/null
	@kubectl -n dev annotate secret app-secrets \
		--overwrite \
		app-secrets.bpl/refreshedAtEpoch="$$(date +%s)" \
		app-secrets.bpl/refreshedAt="$$(date -Is)" >/dev/null 2>&1 || true
	@echo "==> app-secrets applied."

dev-tls: dev-context
	@cert_dir="setup/ubuntu-22.04/certs"; \
	if ! command -v mkcert >/dev/null 2>&1; then \
		echo "WARN: mkcert not found; skipping TLS secret. Install mkcert and run: make dev-tls"; \
		exit 0; \
	fi; \
	mkdir -p "$$cert_dir"; \
	mkcert -install >/dev/null; \
	mkcert -cert-file "$$cert_dir/kong-local.crt" -key-file "$$cert_dir/kong-local.key" api.local.dev kong.local.dev >/dev/null; \
	echo "certs written to $$cert_dir"; \
	kubectl -n dev create secret tls kong-local-tls \
		--cert=setup/ubuntu-22.04/certs/kong-local.crt \
		--key=setup/ubuntu-22.04/certs/kong-local.key \
		--dry-run=client -o yaml | kubectl apply -f -

dev-kong-crds-install: dev-context
	@vendor="k8s/vendor/kong-kic-crds.yaml"; \
	if [ -f "$$vendor" ]; then \
		echo "==> Installing Kong CRDs from $$vendor..."; \
		kubectl apply -f "$$vendor"; \
		kubectl wait --for=condition=Established --timeout=120s -f "$$vendor" >/dev/null; \
	else \
		echo "WARN: Kong CRDs vendor file not found ($$vendor); skipping CRD install."; \
		echo "WARN: dev-kong-whitelist will be skipped until Kong CRDs are installed."; \
		exit 0; \
	fi

dev-kong-whitelist: dev-context dev-kong-crds-install
	@if ! kubectl get crd kongplugins.configuration.konghq.com >/dev/null 2>&1; then \
		echo "WARN: Kong CRD kongplugins.configuration.konghq.com not installed; skipping dev-kong-whitelist."; \
		exit 0; \
	fi
	@out_file="k8s/overlays/dev/kong/ip-whitelist.yaml"; \
	mkdir -p "$$(dirname "$$out_file")"; \
	local_ips() { \
		if command -v ip >/dev/null 2>&1; then \
			ip -o -4 addr show | awk '{print $$4}'; \
		elif command -v ifconfig >/dev/null 2>&1; then \
			ifconfig | awk '/inet /{print $$2\"/32\"}'; \
		fi; \
	}; \
	node_ips() { \
		kubectl get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address}{\"/32\\n\"}{end}' 2>/dev/null || true; \
	}; \
	docker_bridge_ips() { \
		if command -v ip >/dev/null 2>&1; then \
			ip -o -4 addr show docker0 2>/dev/null | awk '{print $$4}' || true; \
		fi; \
	}; \
	allow_list=$$(printf "%s\\n" \
		"127.0.0.1/32" \
		"172.16.0.0/12" \
		"192.168.0.0/16" \
		"10.0.0.0/8" \
		$$(docker_bridge_ips) \
		$$(node_ips) \
		$$(local_ips) \
		| sed '/^$$/d' | sort -u); \
	{ \
		echo "apiVersion: configuration.konghq.com/v1"; \
		echo "kind: KongPlugin"; \
		echo "metadata:"; \
		echo "  name: kong-admin-ip-whitelist"; \
		echo "  labels:"; \
		echo "    app: kong"; \
		echo "config:"; \
		echo "  allow:"; \
	} > "$$out_file"; \
	printf "%s\\n" "$$allow_list" | while IFS= read -r cidr; do \
		echo "    - $$cidr" >> "$$out_file"; \
	done; \
	{ \
		echo "plugin: ip-restriction"; \
	} >> "$$out_file"; \
	echo "wrote $$out_file"
	kubectl -n dev apply -f k8s/overlays/dev/kong/ip-whitelist.yaml

dev-kong-user: dev-context dev-env-init
	@set -e; \
	user=$$(hostname | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-'); \
	pass_file=".git/dev-kong-user"; \
	if [ -f "$$pass_file" ]; then \
		pair=$$(cat "$$pass_file"); \
		echo "Using existing Kong RBAC user from $$pass_file (user=$${pair%%:*})"; \
	else \
		if command -v openssl >/dev/null 2>&1; then \
			pass=$$(openssl rand -base64 24 | tr -cd 'a-zA-Z0-9' | head -c 24); \
		else \
			pass=$$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 24); \
		fi; \
		pair="$$user:$$pass"; \
		echo "$$pair" > "$$pass_file"; \
		echo "Generated Kong RBAC user: $$user"; \
		echo "Password: $$pass"; \
		echo "Stored at $$pass_file"; \
	fi; \
	echo "Updating KONG_RBAC_USERS in $(ENV_FILE)..."; \
	$(PYTHON) scripts/dev_env.py kong-user-add --env-file "$(ENV_FILE)" --user "$$user" --pair "$$pair"; \
	$(MAKE) dev-secrets-apply; \
	if kubectl -n dev get deployment/kong >/dev/null 2>&1; then \
		echo "==> Restarting Kong to pick up updated RBAC users..."; \
		kubectl -n dev rollout restart deployment/kong >/dev/null; \
		kubectl -n dev rollout status deployment/kong --timeout=$(DEV_WAIT_TIMEOUT) >/dev/null; \
	else \
		echo "WARN: deployment/kong not found. Run: make dev"; \
	fi

dev-kong-user-remove: dev-context dev-env-init
	@set -e; \
	user=$${USER_NAME:-$$(hostname | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')}; \
	echo "Removing $$user from KONG_RBAC_USERS in $(ENV_FILE)..."; \
	$(PYTHON) scripts/dev_env.py kong-user-remove --env-file "$(ENV_FILE)" --user "$$user"; \
	$(MAKE) dev-secrets-apply; \
	if kubectl -n dev get deployment/kong >/dev/null 2>&1; then \
		echo "==> Restarting Kong to pick up updated RBAC users..."; \
		kubectl -n dev rollout restart deployment/kong >/dev/null; \
		kubectl -n dev rollout status deployment/kong --timeout=$(DEV_WAIT_TIMEOUT) >/dev/null; \
	else \
		echo "WARN: deployment/kong not found. Run: make dev"; \
	fi

kustomize-bin:
	@mkdir -p $(BIN_DIR)
	@if [ ! -f "$(KUSTOMIZE_BIN)" ]; then \
		os="linux"; arch="amd64"; \
		uname_s=$$(uname -s 2>/dev/null || echo ""); \
		uname_m=$$(uname -m 2>/dev/null || echo ""); \
		case "$$uname_s" in \
			Darwin*) os="darwin" ;; \
			Linux*) os="linux" ;; \
			MINGW*|MSYS*|CYGWIN*) os="windows" ;; \
			*) if [ "$(OS)" = "Windows_NT" ]; then os="windows"; fi ;; \
		esac; \
		case "$$uname_m" in \
			x86_64|amd64) arch="amd64" ;; \
			aarch64|arm64) arch="arm64" ;; \
		esac; \
		url="https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v$(KUSTOMIZE_VERSION)/kustomize_v$(KUSTOMIZE_VERSION)_$${os}_$${arch}.tar.gz"; \
		tmp="/tmp/kustomize.$$$$.tar.gz"; \
		echo "downloading kustomize from $$url"; \
		curl -sSL -o "$$tmp" "$$url"; \
		tar -C $(BIN_DIR) -xzf "$$tmp"; \
		rm -f "$$tmp"; \
		if [ "$(EXE)" = ".exe" ] && [ -f "$(BIN_DIR)/kustomize" ] && [ ! -f "$(KUSTOMIZE_BIN)" ]; then \
			mv "$(BIN_DIR)/kustomize" "$(KUSTOMIZE_BIN)"; \
		fi; \
		chmod +x $(KUSTOMIZE_BIN) 2>/dev/null || true; \
	fi

kubeconform-bin:
	@mkdir -p $(BIN_DIR)
	@if [ ! -f "$(KUBECONFORM_BIN)" ]; then \
		os="linux"; arch="amd64"; \
		uname_s=$$(uname -s 2>/dev/null || echo ""); \
		uname_m=$$(uname -m 2>/dev/null || echo ""); \
		case "$$uname_s" in \
			Darwin*) os="darwin" ;; \
			Linux*) os="linux" ;; \
			MINGW*|MSYS*|CYGWIN*) os="windows" ;; \
			*) if [ "$(OS)" = "Windows_NT" ]; then os="windows"; fi ;; \
		esac; \
		case "$$uname_m" in \
			x86_64|amd64) arch="amd64" ;; \
			aarch64|arm64) arch="arm64" ;; \
		esac; \
		archive="kubeconform-$${os}-$${arch}.tar.gz"; \
		url="https://github.com/yannh/kubeconform/releases/download/v$(KUBECONFORM_VERSION)/$$archive"; \
		tmp="/tmp/kubeconform.$$$$.tar.gz"; \
		echo "downloading kubeconform from $$url"; \
		curl -sSL -o "$$tmp" "$$url"; \
		tar -C $(BIN_DIR) -xzf "$$tmp"; \
		rm -f "$$tmp"; \
		if [ "$(EXE)" = ".exe" ] && [ -f "$(BIN_DIR)/kubeconform" ] && [ ! -f "$(KUBECONFORM_BIN)" ]; then \
			mv "$(BIN_DIR)/kubeconform" "$(KUBECONFORM_BIN)"; \
		fi; \
		chmod +x "$(KUBECONFORM_BIN)" 2>/dev/null || true; \
	fi

k8s-validate: kustomize-bin kubeconform-bin
	$(KUSTOMIZE_BIN) build k8s/base | $(KUBECONFORM_BIN) -strict -summary -output text -ignore-missing-schemas
	$(KUSTOMIZE_BIN) build k8s/overlays/dev | $(KUBECONFORM_BIN) -strict -summary -output text -ignore-missing-schemas
	$(KUSTOMIZE_BIN) build k8s/overlays/dev-dd | $(KUBECONFORM_BIN) -strict -summary -output text -ignore-missing-schemas

dev-status: dev-context
	kubectl -n dev get pods,svc

dev-logs: dev-context
	kubectl -n dev logs deploy/api --tail=200 -f

dev-psql: dev-context
	kubectl -n dev exec -it statefulset/postgres -- psql -U postgres -d messages

dev-up:
	$(MAKE) kind-up
	$(MAKE) dev-context
	$(MAKE) dev-secrets-apply
	$(MAKE) dev-tls
	$(MAKE) dev-kong-whitelist
	$(MAKE) dev-apply
	$(MAKE) dev-rollout
	@echo "==> Dev environment ready."
	@echo "==> Port-forward (bg): make dev-port-bg"
	@echo "==> Port-forward (fg): make dev-port"

dev:
	$(MAKE) dev-up
	$(MAKE) dev-port-bg

dev-fg:
	$(MAKE) dev-up
	$(MAKE) dev-port

dev-verify: dev-context
	@set -e; \
	echo "Checking secrets..."; \
	kubectl -n dev get secret app-secrets >/dev/null; \
	kubectl -n dev get secret kong-local-tls >/dev/null; \
	require_api_key=$$(kubectl -n dev get secret app-secrets -o jsonpath='{.data.REQUIRE_API_KEY}' 2>/dev/null | base64 -d 2>/dev/null | tr '[:upper:]' '[:lower:]' || true); \
	if [ -z "$$require_api_key" ]; then require_api_key="false"; fi; \
	api_key=""; \
	if [ "$$require_api_key" = "true" ]; then \
		api_key=$$(kubectl -n dev get secret app-secrets -o jsonpath='{.data.API_KEY}' | base64 -d); \
		if [ -z "$$api_key" ]; then \
			echo "ERROR: REQUIRE_API_KEY=true but API_KEY is empty in dev/app-secrets"; \
			exit 1; \
		fi; \
	fi; \
	echo "Starting port-forwards..."; \
	kubectl -n dev port-forward svc/kong-proxy 18080:80 18443:443 >/tmp/dev-kong-proxy.log 2>&1 & \
	pid_proxy=$$!; \
	kubectl -n dev port-forward svc/kong-admin 18001:8001 18002:8002 >/tmp/dev-kong-admin.log 2>&1 & \
	pid_admin=$$!; \
	trap 'kill $$pid_proxy $$pid_admin >/dev/null 2>&1 || true' EXIT; \
	timeout=60; \
	elapsed=0; \
	until curl -sS --max-time 2 http://localhost:18001/status >/dev/null 2>&1; do \
		if [ $$elapsed -ge $$timeout ]; then \
			echo "timeout waiting for kong admin"; \
			exit 1; \
		fi; \
		sleep 2; \
		elapsed=$$((elapsed+2)); \
	done; \
	timeout=60; \
	elapsed=0; \
	while :; do \
		if [ "$$require_api_key" = "true" ]; then \
			code=$$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' -H "Host: api.local.dev" -H "X-API-Key: $$api_key" http://localhost:18080/health 2>/dev/null || echo 000); \
		else \
			code=$$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' -H "Host: api.local.dev" http://localhost:18080/health 2>/dev/null || echo 000); \
		fi; \
		if [ "$$code" = "200" ]; then \
			break; \
		fi; \
		if [ $$elapsed -ge $$timeout ]; then \
			echo "timeout waiting for kong proxy (http_code=$$code)"; \
			echo "Proxy port-forward log (last 50 lines):"; \
			tail -n 50 /tmp/dev-kong-proxy.log || true; \
			exit 1; \
		fi; \
		sleep 2; \
		elapsed=$$((elapsed+2)); \
	done; \
	echo "Checking Kong RBAC..."; \
	token=$$(kubectl -n dev get secret app-secrets -o jsonpath='{.data.KONG_ADMIN_TOKEN}' | base64 -d); \
	curl -sS --max-time 3 -H "Kong-Admin-Token: $$token" http://localhost:18001/status >/dev/null; \
	echo "Checking Kong routes..."; \
	curl -sS --max-time 5 -H "Kong-Admin-Token: $$token" http://localhost:18001/routes | jq -e '(.data // [])[] | select(((.hosts // []) | index("api.local.dev")) or ((.snis // []) | index("api.local.dev"))) | select((.protocols // []) | index("https"))' >/dev/null || { \
		echo "ERROR: Kong route for api.local.dev with protocol https not found."; \
		echo "Tip: check Ingress annotation konghq.com/protocols and KIC logs."; \
		exit 1; \
	}; \
	echo "Checking Ingress TLS..."; \
	if [ "$$require_api_key" = "true" ]; then \
		code=$$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' --resolve api.local.dev:18443:127.0.0.1 -H "Host: api.local.dev" -H "X-API-Key: $$api_key" https://api.local.dev:18443/health 2>/dev/null || echo 000); \
	else \
		code=$$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' --resolve api.local.dev:18443:127.0.0.1 -H "Host: api.local.dev" https://api.local.dev:18443/health 2>/dev/null || echo 000); \
	fi; \
	if [ "$$code" != "200" ]; then \
		echo "ERROR: expected HTTPS /health to return 200, got $$code"; \
		echo "Proxy port-forward log (last 50 lines):"; \
		tail -n 50 /tmp/dev-kong-proxy.log || true; \
		exit 1; \
	fi; \
		echo "Checking API health via Kong..."; \
		if [ "$$require_api_key" = "true" ]; then \
			curl -sS --max-time 5 -H "Host: api.local.dev" -H "X-API-Key: $$api_key" http://localhost:18080/health | jq -e '.status=="ok"' >/dev/null; \
		else \
			curl -sS --max-time 5 -H "Host: api.local.dev" http://localhost:18080/health | jq -e '.status=="ok"' >/dev/null; \
		fi; \
		echo "dev-verify OK"

dev-clean: dev-context
	@echo "This will delete the dev namespace, kind cluster, and prune build cache."
	-$(MAKE) dev-port-stop >/dev/null 2>&1 || true
	kubectl delete ns dev --ignore-not-found=true
	$(MAKE) kind-down
	docker builder prune -f
	docker image prune -f --filter "label=project=reliable-message-api"

dev-nuke:
	@read -r -p "Type NUKE to continue: " ans; if [ "$$ans" != "NUKE" ]; then exit 1; fi
	docker system prune -af


test:
	pytest -q

lint:
	ruff check .
	mypy app tests

format:
	ruff format .
