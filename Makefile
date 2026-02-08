.PHONY: help test lint format kind-up kind-down dev-context dev-eso-install dev-build dev-apply dev-dd dev-port dev-reset dev-verify \
	dev-secrets-apply dev dev-status dev-logs dev-psql dev-port-kong-admin dev-tls dev-kong-whitelist dev-kong-user dev-kong-user-remove \
	ecr-repo-ensure dev-ecr-login dev-ecr-push dev-ecr-secret-refresh \
	k8s-validate dev-clean dev-nuke kustomize-bin kubeconform-bin

TOOL_VERSIONS_FILE ?= hack/tool-versions.env
-include $(TOOL_VERSIONS_FILE)
export KUSTOMIZE_VERSION KUBECONFORM_VERSION

AWS_REGION ?= us-east-1
AWS_PROFILE ?= default
AWS_SECRET_NAME ?= braiton-platform-labs/dev/reliable-message-api
KIND_CLUSTER_NAME ?= bpl-dev
EXPECTED_KUBE_CONTEXT ?= kind-$(KIND_CLUSTER_NAME)
KIND_NODE_IMAGE ?= kindest/node:v1.34.3
# KIND_WORKERS can be:
# - auto: pick based on CPU/RAM heuristics
# - 0/1/2/...: explicit workers count
# Default: 1 worker (more stable on dev laptops)
KIND_WORKERS ?= 1

ECR_REPO_NAME ?= reliable-message-api
GIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo local)
AWS_ACCOUNT_ID = $(shell aws sts get-caller-identity --query Account --output text --profile $(AWS_PROFILE) --region $(AWS_REGION))
ECR_REGISTRY = $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
ECR_REPO_URI = $(ECR_REGISTRY)/$(ECR_REPO_NAME)

BIN_DIR ?= bin
KUSTOMIZE_BIN ?= $(BIN_DIR)/kustomize
KUBECONFORM_BIN ?= $(BIN_DIR)/kubeconform

help:
	@echo "Targets:"
	@echo "  make dev                Full local dev flow (kind + ESO + ECR + apply + port)"
	@echo "  make dev-dd             Apply dev-dd overlay (includes Datadog agent)"
	@echo "  make dev-secrets-apply   Apply SecretStore/ExternalSecret + awssm-secret"
	@echo "  make k8s-validate        Validate k8s manifests with kubeconform"
	@echo "  make dev-clean           Clean dev namespace, kind cluster, and build cache"

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

dev-build:
	docker build -f docker/Dockerfile -t reliable-message-api:dev --label project=reliable-message-api .


dev-apply: dev-context kustomize-bin dev-ecr-secret-ensure-fresh
	@image_tag=$$(cat .git/dev-last-image 2>/dev/null || echo $(GIT_SHA)); \
	$(KUSTOMIZE_BIN) build k8s/overlays/dev | sed "s|REPLACE_ECR_IMAGE|$(ECR_REPO_URI):dev-$$image_tag|" | kubectl apply -f -

dev-dd: dev-context kustomize-bin dev-ecr-secret-ensure-fresh
	@image_tag=$$(cat .git/dev-last-image 2>/dev/null || echo $(GIT_SHA)); \
	$(KUSTOMIZE_BIN) build k8s/overlays/dev-dd | sed "s|REPLACE_ECR_IMAGE|$(ECR_REPO_URI):dev-$$image_tag|" | kubectl apply -f -

dev-port: dev-context
	kubectl -n dev port-forward svc/kong-proxy 8080:80

dev-port-kong-admin: dev-context
	kubectl -n dev port-forward svc/kong-admin 8001:8001 8002:8002

dev-reset: dev-context
	kubectl delete ns dev --ignore-not-found=true
	$(MAKE) dev-secrets-apply
	$(MAKE) dev-apply

dev-eso-install: dev-context
	@echo "==> Installing External Secrets Operator (CRDs + controller)..."
	@kubectl apply --server-side -k k8s/overlays/dev/external-secrets/install
	@echo "==> Waiting for External Secrets Operator to be ready..."
	@kubectl -n external-secrets rollout status deploy/external-secrets --timeout=180s || { \
		echo "ERROR: External Secrets Operator did not become ready (namespace=external-secrets)."; \
		echo "Troubleshooting:"; \
		echo "  kubectl -n external-secrets get pods -o wide"; \
		echo "  kubectl -n external-secrets logs deploy/external-secrets --tail=200"; \
		exit 1; \
	}
	@echo "==> Waiting for External Secrets webhook/cert-controller to be ready..."
	@kubectl -n external-secrets rollout status deploy/external-secrets-webhook --timeout=180s || { \
		echo "ERROR: External Secrets webhook did not become ready."; \
		echo "Troubleshooting:"; \
		echo "  kubectl -n external-secrets get pods -o wide"; \
		echo "  kubectl -n external-secrets logs deploy/external-secrets-webhook --tail=200"; \
		exit 1; \
	}
	@kubectl -n external-secrets rollout status deploy/external-secrets-cert-controller --timeout=180s || { \
		echo "ERROR: External Secrets cert-controller did not become ready."; \
		echo "Troubleshooting:"; \
		echo "  kubectl -n external-secrets get pods -o wide"; \
		echo "  kubectl -n external-secrets logs deploy/external-secrets-cert-controller --tail=200"; \
		exit 1; \
	}
	@echo "==> Waiting for External Secrets CRDs to be established..."
	@crds="externalsecrets.external-secrets.io secretstores.external-secrets.io clustersecretstores.external-secrets.io"; \
	for crd in $$crds; do \
		if ! kubectl get crd "$$crd" >/dev/null 2>&1; then \
			echo "ERROR: CRD $$crd not found (ESO install incomplete)."; \
			exit 1; \
		fi; \
	done; \
	if ! kubectl wait --for=condition=Established --timeout=180s crd/externalsecrets.external-secrets.io crd/secretstores.external-secrets.io crd/clustersecretstores.external-secrets.io >/dev/null 2>&1; then \
		echo "ERROR: External Secrets CRDs did not become Established within timeout."; \
		echo "Troubleshooting:"; \
		echo "  kubectl get crd externalsecrets.external-secrets.io -o yaml | grep -nE \"conditions|Established\""; \
		exit 1; \
	fi; \
	for i in 1 2 3 4 5 6 7 8 9 10; do \
		if kubectl get --raw /apis/external-secrets.io/v1 >/dev/null 2>&1; then \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "ERROR: external-secrets.io/v1 not reachable after CRDs Established."; \
	echo "Troubleshooting:"; \
	echo "  kubectl get crd externalsecrets.external-secrets.io -o yaml | grep -nE \"conditions|Established\""; \
	echo "  kubectl -n external-secrets get pods -o wide"; \
	exit 1

dev-secrets-apply: dev-context dev-eso-install
	@echo "==> Applying ExternalSecret/SecretStore and AWS auth secret (awssm-secret)..."
	@if [ -z "$(AWS_PROFILE)" ] || [ "$(AWS_PROFILE)" = "default" ]; then \
		echo "ERROR: AWS_PROFILE is not set (or is still 'default')."; \
		echo "Set it to the profile you use to access the target AWS account (e.g. AWS_PROFILE=development)."; \
		exit 1; \
	fi
	@if ! command -v aws >/dev/null 2>&1; then \
		echo "ERROR: aws CLI not found in PATH."; \
		exit 1; \
	fi
	@echo "==> Creating/updating Kubernetes Secret dev/awssm-secret from AWS_PROFILE=$(AWS_PROFILE) (no secret values printed)..."
	@set -e; \
	tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	creds_env="$$(aws configure export-credentials --profile "$(AWS_PROFILE)" --format env-no-export 2>&1)" || { \
		echo "ERROR: failed to export AWS credentials for AWS_PROFILE=$(AWS_PROFILE)."; \
		echo "If using AWS SSO, run: aws sso login --profile $(AWS_PROFILE)"; \
		echo "$$creds_env"; \
		exit 1; \
	}; \
	ak="$$(printf '%s\n' "$$creds_env" | sed -n 's/^AWS_ACCESS_KEY_ID=//p')"; \
	sk="$$(printf '%s\n' "$$creds_env" | sed -n 's/^AWS_SECRET_ACCESS_KEY=//p')"; \
	st="$$(printf '%s\n' "$$creds_env" | sed -n 's/^AWS_SESSION_TOKEN=//p')"; \
	if [ -z "$$ak" ] || [ -z "$$sk" ]; then \
		echo "ERROR: exported credentials are missing required fields (need AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)."; \
		exit 1; \
	fi; \
	printf '%s' "$$ak" > "$$tmp/access-key"; \
	printf '%s' "$$sk" > "$$tmp/secret-access-key"; \
	extra_secret_args=""; \
	if [ -n "$$st" ]; then \
		printf '%s' "$$st" > "$$tmp/session-token"; \
		extra_secret_args="--from-file=session-token=$$tmp/session-token"; \
	fi; \
	kubectl apply -f k8s/overlays/dev/external-secrets/namespace-dev.yaml >/dev/null; \
	kubectl -n dev create secret generic awssm-secret \
		--from-file=access-key="$$tmp/access-key" \
		--from-file=secret-access-key="$$tmp/secret-access-key" \
		$$extra_secret_args \
		--dry-run=client -o yaml | kubectl apply -f - >/dev/null; \
	kubectl -n dev annotate secret awssm-secret \
		--overwrite \
		awssm-secret.bpl/refreshedAtEpoch="$$(date +%s)" \
		awssm-secret.bpl/refreshedAt="$$(date -Is)" >/dev/null 2>&1 || true; \
	echo "==> Validating AWS Secrets Manager access and secret format (no secret values printed)..."; \
	if [ -n "$$st" ]; then export AWS_SESSION_TOKEN="$$st"; else unset AWS_SESSION_TOKEN; fi; \
	err="$$(AWS_ACCESS_KEY_ID="$$ak" AWS_SECRET_ACCESS_KEY="$$sk" AWS_REGION="$(AWS_REGION)" aws secretsmanager describe-secret --secret-id "$(AWS_SECRET_NAME)" 2>&1)" || { \
		echo "ERROR: cannot access Secrets Manager secret '$(AWS_SECRET_NAME)' in region $(AWS_REGION) using AWS_PROFILE=$(AWS_PROFILE)."; \
		echo "$$err"; \
		echo "Troubleshooting:"; \
		echo "  1) Confirm the secret exists in this region/account."; \
		echo "  2) Confirm IAM allows secretsmanager:GetSecretValue and secretsmanager:DescribeSecret for this secret."; \
		exit 1; \
	}; \
	AWS_ACCESS_KEY_ID="$$ak" AWS_SECRET_ACCESS_KEY="$$sk" AWS_REGION="$(AWS_REGION)" aws secretsmanager get-secret-value --secret-id "$(AWS_SECRET_NAME)" --query SecretString --output text 2>/dev/null | \
	python3 -c 'import json,sys; raw=sys.stdin.read().strip(); \
 (raw and raw not in ("None","null")) or (_ for _ in ()).throw(SystemExit("SecretString is empty/null (expected JSON string)")); \
 obj=json.loads(raw); isinstance(obj,dict) or (_ for _ in ()).throw(SystemExit("SecretString JSON must be an object; got %s" % type(obj).__name__)); \
 bad=[k for k,v in obj.items() if not isinstance(v,str)]; (not bad) or (_ for _ in ()).throw(SystemExit("Non-string values found for keys (quote them as strings): "+", ".join(sorted(bad)))); \
 print("OK")'; \
	true
	@echo "==> Applying SecretStore/ExternalSecret (may retry while webhook warms up)..."
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		if kubectl apply -k k8s/overlays/dev/external-secrets; then \
			break; \
		fi; \
		echo "retry $$i/10: waiting for external-secrets webhook to accept requests..."; \
		kubectl -n external-secrets get pods -o wide || true; \
		sleep 3; \
		if [ "$$i" = "10" ]; then \
			echo "ERROR: failed to apply external-secrets resources after retries."; \
			exit 1; \
		fi; \
	done
	@# If exported credentials include a session token (ASIA... STS creds), patch SecretStore to include it.
	@creds_env="$$(aws configure export-credentials --profile "$(AWS_PROFILE)" --format env-no-export 2>/dev/null || true)"; \
	st="$$(printf '%s\n' "$$creds_env" | sed -n 's/^AWS_SESSION_TOKEN=//p')"; \
	if [ -n "$$st" ]; then \
		kubectl -n dev patch secretstore aws-secretsmanager --type=merge -p '{"spec":{"provider":{"aws":{"auth":{"secretRef":{"sessionTokenSecretRef":{"name":"awssm-secret","key":"session-token"}}}}}}}' >/dev/null; \
	else \
		kubectl -n dev patch secretstore aws-secretsmanager --type=json -p '[{"op":"remove","path":"/spec/provider/aws/auth/secretRef/sessionTokenSecretRef"}]' >/dev/null 2>&1 || true; \
	fi
	@echo "==> Waiting for app-secrets to be created by ESO..."
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60; do \
		if kubectl -n dev get secret app-secrets >/dev/null 2>&1; then \
			echo "app-secrets is present."; \
			exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "ERROR: app-secrets was not created after 120s."; \
	echo "Troubleshooting:"; \
	echo "  kubectl -n dev get externalsecret -o wide"; \
	echo "  kubectl -n dev describe externalsecret app-secrets"; \
	echo "  kubectl -n external-secrets get pods -o wide"; \
	echo "  kubectl -n external-secrets logs deploy/external-secrets --tail=200"; \
	exit 1

dev-tls: dev-context
	@cert_dir="hack/certs"; \
	if ! command -v mkcert >/dev/null 2>&1; then \
		echo "ERROR: mkcert not found (required for local TLS)"; \
		echo "Install it and re-run. Ubuntu: apt install mkcert; macOS: brew install mkcert; Windows: choco install mkcert"; \
		exit 1; \
	fi; \
	mkdir -p "$$cert_dir"; \
	mkcert -install >/dev/null; \
	mkcert -cert-file "$$cert_dir/kong-local.crt" -key-file "$$cert_dir/kong-local.key" api.local.dev kong.local.dev >/dev/null; \
	echo "certs written to $$cert_dir"
	kubectl -n dev create secret tls kong-local-tls \
		--cert=hack/certs/kong-local.crt \
		--key=hack/certs/kong-local.key \
		--dry-run=client -o yaml | kubectl apply -f -

dev-kong-whitelist: dev-context
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

dev-kong-user:
	@user=$$(hostname | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-'); \
	pass_file=".git/dev-kong-user"; \
	if [ -f "$$pass_file" ]; then \
		pair=$$(cat "$$pass_file"); \
		secret_json=$$(aws secretsmanager get-secret-value --secret-id $(AWS_SECRET_NAME) --region $(AWS_REGION) --profile $(AWS_PROFILE) --query SecretString --output text); \
		exists=$$(echo "$$secret_json" | jq --arg pair "$$pair" '(.KONG_RBAC_USERS // \"\") | split(\",\") | index($pair)'); \
		if [ "$$exists" != "null" ]; then \
			echo "user/password already present in AWS Secrets Manager: $$pass_file"; \
			exit 0; \
		fi; \
		echo "user/password exists locally but not in AWS; will append"; \
	fi; \
	if command -v openssl >/dev/null 2>&1; then \
		pass=$$(openssl rand -base64 24 | tr -cd 'a-zA-Z0-9' | head -c 24); \
	else \
		pass=$$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 24); \
	fi; \
	echo "$$user:$$pass" > "$$pass_file"; \
	echo "Generated Kong RBAC user: $$user"; \
	echo "Password: $$pass"; \
	echo "Stored at $$pass_file"; \
	echo "Updating AWS Secrets Manager..."; \
	secret_json=$$(aws secretsmanager get-secret-value --secret-id $(AWS_SECRET_NAME) --region $(AWS_REGION) --profile $(AWS_PROFILE) --query SecretString --output text); \
	updated=$$(echo "$$secret_json" | jq --arg user "$$user" --arg pair "$$user:$$pass" '\
		.KONG_RBAC_USERS = ( \
			(.KONG_RBAC_USERS // \"\") \
			| split(\",\") \
			| map(select(length > 0)) \
			| map(select((split(\":\"))[0] != $user)) \
			| . + [$pair] \
			| join(\",\") \
		)'); \
	aws secretsmanager put-secret-value --secret-id $(AWS_SECRET_NAME) --region $(AWS_REGION) --profile $(AWS_PROFILE) --secret-string "$$updated"; \
	echo "Updated KONG_RBAC_USERS in AWS Secrets Manager. Re-run: make dev-secrets-apply"

dev-kong-user-remove:
	@user=$${USER_NAME:-$$(hostname | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')}; \
	echo "Removing $$user from KONG_RBAC_USERS..."; \
	secret_json=$$(aws secretsmanager get-secret-value --secret-id $(AWS_SECRET_NAME) --region $(AWS_REGION) --profile $(AWS_PROFILE) --query SecretString --output text); \
	exists=$$(echo "$$secret_json" | jq --arg user "$$user" '(.KONG_RBAC_USERS // \"\") | split(\",\") | map(select(length > 0)) | map(split(\":\"))[].0 | index($user)'); \
	if [ "$$exists" = "null" ]; then \
		echo "user $$user not found in KONG_RBAC_USERS; aborting"; \
		exit 1; \
	fi; \
	updated=$$(echo "$$secret_json" | jq --arg user "$$user" '\
		.KONG_RBAC_USERS = ( \
			(.KONG_RBAC_USERS // \"\") \
			| split(\",\") \
			| map(select(length > 0)) \
			| map(select((split(\":\"))[0] != $user)) \
			| join(\",\") \
		)'); \
	aws secretsmanager put-secret-value --secret-id $(AWS_SECRET_NAME) --region $(AWS_REGION) --profile $(AWS_PROFILE) --secret-string "$$updated"; \
	echo "Removed $$user. Re-run: make dev-secrets-apply"

ecr-repo-ensure:
	@if aws ecr describe-repositories --repository-names $(ECR_REPO_NAME) --region $(AWS_REGION) --profile $(AWS_PROFILE) >/dev/null 2>&1; then \
		echo "ECR repo exists: $(ECR_REPO_NAME)"; \
	else \
		aws ecr create-repository --repository-name $(ECR_REPO_NAME) --region $(AWS_REGION) --profile $(AWS_PROFILE); \
	fi

dev-ecr-login:
	aws ecr get-login-password --region $(AWS_REGION) --profile $(AWS_PROFILE) | docker login --username AWS --password-stdin $(ECR_REGISTRY)

dev-ecr-push: dev-build ecr-repo-ensure dev-ecr-login
	@current=$$(git rev-parse --short HEAD 2>/dev/null || echo local); \
	last_file=".git/dev-last-image"; \
	last=""; \
	if [ -f "$$last_file" ]; then last=$$(cat "$$last_file"); fi; \
	do_push=0; \
	if [ -z "$$last" ]; then \
		echo "no last image recorded; pushing $$current"; \
		do_push=1; \
	elif [ "$$last" != "$$current" ]; then \
		if [ -n "$$CI" ] || [ -n "$$ECR_FORCE_PUSH" ]; then \
			echo "new commit detected; forced push"; \
			do_push=1; \
		else \
			read -r -p "New commit $$current detected (last $$last). Generate new image? [y/N] " ans; \
			case "$$ans" in [yY]|[yY][eE][sS]) do_push=1 ;; *) do_push=0 ;; esac; \
		fi; \
	else \
		echo "commit unchanged ($$current); skipping push"; \
	fi; \
	if [ "$$do_push" -eq 1 ]; then \
		docker tag reliable-message-api:dev $(ECR_REPO_URI):dev-$$current; \
		docker push $(ECR_REPO_URI):dev-$$current; \
		echo "$$current" > "$$last_file"; \
	else \
		echo "using existing image tag from $$last_file"; \
	fi


dev-ecr-secret-refresh: dev-context
	@if ! kubectl get ns dev >/dev/null 2>&1; then kubectl create ns dev; fi
	kubectl -n dev create secret docker-registry ecr-pull \
		--docker-server=$(ECR_REGISTRY) \
		--docker-username=AWS \
		--docker-password="$$(aws ecr get-login-password --region $(AWS_REGION) --profile $(AWS_PROFILE))" \
		--dry-run=client -o yaml | kubectl apply -f -
	@kubectl -n dev annotate secret ecr-pull \
		ecr-pull.bpl/refreshedAtEpoch="$$(date +%s)" \
		ecr-pull.bpl/refreshedAt="$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		--overwrite >/dev/null

dev-ecr-secret-ensure-fresh: dev-context
	@if ! kubectl get ns dev >/dev/null 2>&1; then kubectl create ns dev; fi
	@max_age=$$((10*60*60)); \
	if ! kubectl -n dev get secret ecr-pull >/dev/null 2>&1; then \
		echo "ecr-pull missing; refreshing"; \
		$(MAKE) dev-ecr-secret-refresh; \
	else \
		ts=$$(kubectl -n dev get secret ecr-pull -o jsonpath='{.metadata.annotations.ecr-pull\\.bpl/refreshedAtEpoch}' 2>/dev/null || true); \
		now=$$(date +%s); \
		if [ -z "$$ts" ]; then \
			echo "ecr-pull timestamp missing; refreshing"; \
			$(MAKE) dev-ecr-secret-refresh; \
		elif [ $$((now - ts)) -gt $$max_age ]; then \
			echo "ecr-pull expired; refreshing"; \
			$(MAKE) dev-ecr-secret-refresh; \
		else \
			echo "ecr-pull fresh"; \
		fi; \
	fi

kustomize-bin:
	@mkdir -p $(BIN_DIR)
	@if [ ! -f "$(KUSTOMIZE_BIN)" ]; then \
		curl -sSL -o /tmp/kustomize.tar.gz https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v$(KUSTOMIZE_VERSION)/kustomize_v$(KUSTOMIZE_VERSION)_linux_amd64.tar.gz; \
		tar -C $(BIN_DIR) -xzf /tmp/kustomize.tar.gz; \
		chmod +x $(KUSTOMIZE_BIN); \
	fi

kubeconform-bin:
	@mkdir -p $(BIN_DIR)
	@if [ ! -f "$(KUBECONFORM_BIN)" ]; then \
		curl -sSL -o /tmp/kubeconform.tar.gz https://github.com/yannh/kubeconform/releases/download/v$(KUBECONFORM_VERSION)/kubeconform-linux-amd64.tar.gz; \
		tar -C $(BIN_DIR) -xzf /tmp/kubeconform.tar.gz kubeconform; \
		chmod +x $(KUBECONFORM_BIN); \
	fi

k8s-validate: kustomize-bin kubeconform-bin
	$(KUSTOMIZE_BIN) build k8s/base | $(KUBECONFORM_BIN) -strict -summary -output text -ignore-missing-schemas
	$(KUSTOMIZE_BIN) build k8s/overlays/dev | $(KUBECONFORM_BIN) -strict -summary -output text -ignore-missing-schemas
	$(KUSTOMIZE_BIN) build k8s/overlays/dev-dd | $(KUBECONFORM_BIN) -strict -summary -output text -ignore-missing-schemas
	$(KUSTOMIZE_BIN) build k8s/overlays/dev/external-secrets | $(KUBECONFORM_BIN) -strict -summary -output text -ignore-missing-schemas
	$(KUSTOMIZE_BIN) build k8s/overlays/dev/external-secrets/install | $(KUBECONFORM_BIN) -strict -summary -output text -ignore-missing-schemas

dev-status: dev-context
	kubectl -n dev get pods,svc

dev-logs: dev-context
	kubectl -n dev logs deploy/api --tail=200 -f

dev-psql: dev-context
	kubectl -n dev exec -it statefulset/postgres -- psql -U postgres -d messages

dev:
	$(MAKE) kind-up
	$(MAKE) dev-context
	$(MAKE) dev-secrets-apply
	$(MAKE) dev-tls
	$(MAKE) dev-kong-whitelist
	$(MAKE) dev-ecr-push
	$(MAKE) dev-ecr-secret-refresh
	$(MAKE) dev-apply
	$(MAKE) dev-port

dev-verify: dev-context
	@set -e; \
	echo "Checking secrets..."; \
	kubectl -n dev get secret app-secrets >/dev/null; \
	kubectl -n dev get secret kong-local-tls >/dev/null; \
	kubectl -n dev get secret ecr-pull >/dev/null; \
	echo "Starting port-forwards..."; \
	kubectl -n dev port-forward svc/kong-proxy 8080:80 >/tmp/dev-kong-proxy.log 2>&1 & \
	pid_proxy=$$!; \
	kubectl -n dev port-forward svc/kong-admin 8001:8001 8002:8002 >/tmp/dev-kong-admin.log 2>&1 & \
	pid_admin=$$!; \
	trap 'kill $$pid_proxy $$pid_admin >/dev/null 2>&1 || true' EXIT; \
	timeout=60; \
	elapsed=0; \
	until curl -sS http://localhost:8001/status >/dev/null 2>&1; do \
		if [ $$elapsed -ge $$timeout ]; then \
			echo "timeout waiting for kong admin"; \
			exit 1; \
		fi; \
		sleep 2; \
		elapsed=$$((elapsed+2)); \
	done; \
	timeout=60; \
	elapsed=0; \
	until curl -sS -H "Host: api.local.dev" http://localhost:8080/health >/dev/null 2>&1; do \
		if [ $$elapsed -ge $$timeout ]; then \
			echo "timeout waiting for kong proxy"; \
			exit 1; \
		fi; \
		sleep 2; \
		elapsed=$$((elapsed+2)); \
	done; \
	echo "Checking Kong RBAC..."; \
	token=$$(aws secretsmanager get-secret-value --secret-id $(AWS_SECRET_NAME) --region $(AWS_REGION) --profile $(AWS_PROFILE) --query SecretString --output text | jq -r '.KONG_ADMIN_TOKEN'); \
	curl -sS -H "Kong-Admin-Token: $$token" http://localhost:8001/status >/dev/null; \
	echo "Checking Kong routes..."; \
	curl -sS -H "Kong-Admin-Token: $$token" http://localhost:8001/routes | jq -e '.data[] | select(.name==\"api\")' >/dev/null; \
	echo "Checking Ingress TLS..."; \
	curl -skI https://api.local.dev/health | head -n 1 | grep -q "200"; \
	echo "Checking API health via Kong..."; \
	curl -sS -H "Host: api.local.dev" http://localhost:8080/health | jq -e '.status==\"ok\"' >/dev/null; \
	echo "dev-verify OK"

dev-clean: dev-context
	@echo "This will delete the dev namespace, kind cluster, and prune build cache."
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
