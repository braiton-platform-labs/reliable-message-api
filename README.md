# Reliable Message API

Production-minded Message API built with FastAPI + PostgreSQL.

It focuses on the stuff that makes APIs boring (in a good way):
- Validation with human-friendly errors
- Dedupe via normalization (DB-level uniqueness)
- Idempotency via `Idempotency-Key`
- Operational endpoints: `/health`, `/ready`, `/metrics`, `/stats`
- Optional Datadog instrumentation (and a `dev-dd` overlay)

## Quickstart (Local dev with kind)

Prereqs:
- `docker` (daemon running)
- `kubectl`, `kind`, `jq`
- Optional: `mkcert` for local TLS (otherwise disable SSL verification in Postman)

Windows 11 (WSL2 + Docker Desktop):
- Prerequisite: virtualization enabled in BIOS/UEFI (Intel VT-x / AMD-V). Without this, WSL2/Docker/kind will not work.
- You must have WSL2 + an Ubuntu distro installed, and Docker Desktop installed and running (WSL integration enabled).
- The repo includes scripts to install/validate this setup:
  - One-shot setup (run PowerShell as Administrator; may require reboot):
    `powershell -ExecutionPolicy Bypass -File setup\\windows-11-wsl2-docker-desktop\\setup.ps1 install`
  - WSL Ubuntu toolchain bootstrap (installs `make`, `python3`, etc via apt, then installs pinned repo tools into `./bin`):
    `powershell -ExecutionPolicy Bypass -File .\\scripts\\wsl_bootstrap.ps1`
  - Hosts file management (for Postman/Browser on Windows):
    `powershell -ExecutionPolicy Bypass -File setup\\windows-11-wsl2-docker-desktop\\setup.ps1 hosts -HostsAction apply`
  - Optional (faster installs): if `setup\\windows-11-wsl2-docker-desktop\\Docker Desktop Installer.zip` exists, the scripts will use it instead of downloading Docker Desktop.
- The Makefile uses a POSIX shell; the canonical workflow is running `make ...` from inside WSL (Ubuntu 22.04).

TL;DR (Windows 11 + WSL2 + Docker Desktop): run these 3 commands in order on a fresh clone:
```powershell
# 1) Bootstrap WSL Ubuntu deps (make/python3/etc) + pinned repo tools into ./bin (kubectl/kind/jq/kustomize/...)
powershell -ExecutionPolicy Bypass -File .\scripts\wsl_bootstrap.ps1

# 2) Bring up the full dev stack (kind + Postgres + Kong + API + port-forward). May prompt for UAC to edit Windows hosts.
powershell -ExecutionPolicy Bypass -File .\scripts\dev_kind.ps1 up

# 3) Quick health check (Kong routes are host-based)
curl -H "Host: api.local.dev" http://localhost:8080/health
```

Recommended (best experience, especially if you test with Postman on Windows):
```powershell
powershell -ExecutionPolicy Bypass -File .\\scripts\\dev_kind.ps1 up
```
This will:
- Ensure the Windows hosts entries exist (`api.local.dev`, `kong.local.dev`) so Postman can hit the correct virtual hosts.
- Invoke the WSL dev flow (`make bootstrap` + `make dev` + verification) using the repo scripts.

Lens (Kubernetes IDE) on Windows:
- Export the kind kubeconfig to a Windows file and import it in Lens:
  `powershell -ExecutionPolicy Bypass -File .\\scripts\\lens_kind.ps1 -Cluster bpl-dev`

Run:
```bash
make dev
```

First time setup (recommended):
```bash
make bootstrap
make dev
```

Or as a single command:
```bash
make first-run
```

Tip: run multiple clusters by overriding the default name:
```bash
KIND_CLUSTER_NAME=my-dev make dev
```

Recommended local DNS (so you don't need to manually set `Host:` headers):
```bash
make dev-hosts-apply
```

This adds `api.local.dev` and `kong.local.dev` to `/etc/hosts` (idempotent, with a backup).

Remove later:
```bash
make dev-hosts-remove
```

Windows hosts file (run as Administrator):
```bash
make dev-hosts-apply-win
```

Remove later:
```bash
make dev-hosts-remove-win
```

If you run `make dev` inside WSL2 but use Postman/Browser on Windows, you still need the Windows hosts file entry.

Verify (Kong routes are host-based, so `Host: api.local.dev` matters):
```bash
curl -H 'Host: api.local.dev' http://localhost:8080/health
curl -sk --resolve api.local.dev:8443:127.0.0.1 https://api.local.dev:8443/health
```

URLs (via the managed Kong proxy port-forward):
- API (HTTP): `http://api.local.dev:8080` (or `http://localhost:8080` with `Host: api.local.dev`)
- API (HTTPS): `https://api.local.dev:8443`
- Kong Manager (HTTPS): `https://kong.local.dev:8443`
- Kong Admin API (port-forward): `make dev-port-kong-admin` then `http://localhost:8001`

Fast dev loop (after the first `make dev`):
- Code change only: `make dev-reload`
- Kong/KIC config change (or `KONG_*` env changes): `make dev-rollout-all`

Port-forward control:
- Background mode (default): `make dev` (or `make dev-port-bg`)
- Foreground: `make dev-fg` (or `make dev-port`)
- Stop: `make dev-port-stop`
- Status/logs: `make dev-port-status`, `make dev-port-logs`

What `make dev` does (high level):
- Provision kind cluster/context (if missing)
- Generate/apply `dev/app-secrets` from `.env`
- Apply manifests (Postgres, Kong, API)
- Build + load the local API image into kind
- Restart the API deployment to pick up the new image
- Start a managed background port-forward

Optional tool check:
```bash
./setup/ubuntu-22.04/setup.sh doctor
```

## Common commands

| Goal | Command |
| --- | --- |
| First time setup (tools + dev) | `make first-run` |
| Install pinned tools into `./bin` | `make bootstrap` |
| Check your local environment | `make doctor` |
| Start everything (kind + secrets + apply + port-forward) | `make dev` |
| Fast loop after code changes (build+load+restart API) | `make dev-reload` |
| Update `dev/app-secrets` after editing `.env` | `make dev-secrets-apply && make dev-rollout` |
| Restart only the API | `make dev-rollout` |
| Restart Kong + KIC + API | `make dev-rollout-all` |
| See pods/services | `make dev-status` |
| Tail API logs | `make dev-logs` |
| Connect to Postgres (psql) | `make dev-psql` |
| Stop background port-forward | `make dev-port-stop` |
| Clean dev namespace + kind cluster + build cache | `make dev-clean` |

See all available targets:
```bash
make help
```

## Postman (Business Rules)

This repo includes a Postman collection that validates the business rules (validation, dedupe, idempotency) and operational endpoints.

Setup:
1. Import `postman/reliable-message-api.business-rules.postman_collection.json`
2. Import `postman/reliable-message-api.local.postman_environment.json`
3. Select the environment `Reliable Message API - Local`

API key:
- If `REQUIRE_API_KEY=true`, set the environment variable `apiKey` to match `API_KEY` from your `.env` / `dev/app-secrets`.
- Keep Authorization as `No Auth` (the requests already send `X-API-Key: {{apiKey}}`).

Get the current key from the cluster:
```bash
kubectl -n dev get secret app-secrets -o jsonpath='{.data.API_KEY}' | base64 -d; echo
```

HTTPS note:
- If HTTPS fails in Postman, disable SSL verification (Settings -> General) or trust the mkcert root CA.

## Local dev secrets via `.env`

This repo uses a local `.env` file (gitignored) to populate the Kubernetes Secret `dev/app-secrets`.

Create `.env` (only if missing):
```bash
make dev-env-init
```

Apply/update `dev/app-secrets` from `.env`:
```bash
make dev-secrets-apply
```

(`.env.example` is available as a reference.)

After changing `.env` values:
- If it only affects the API: run `make dev-rollout` (restarts the API to pick up updated env vars).
- If it affects Kong/KIC: run `make dev-rollout-all`.

Required keys (dev overlay):
`DATABASE_URL`, `REQUIRE_API_KEY`, `API_KEY`, `METRICS_ENABLED`, `STATS_ENABLED`, `IDEMPOTENCY_TTL_HOURS`, `DD_SERVICE`, `DD_ENV`, `DD_VERSION`, `DD_AGENT_HOST`, `DD_TRACE_AGENT_URL`, `DD_API_KEY` (can be empty unless using `dev-dd`), `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `KONG_PG_PASSWORD`, `KONG_ADMIN_GUI_USER`, `KONG_ADMIN_GUI_PASSWORD`, `KONG_ADMIN_TOKEN`, `KONG_ADMIN_GUI_SESSION_CONF`, `KONG_RBAC_USERS`.

## Kong/KIC validation (dev)

```bash
kubectl get crd | grep konghq.com
kubectl auth can-i list customresourcedefinitions.apiextensions.k8s.io \
  --as=system:serviceaccount:dev:kong-ingress
kubectl -n dev logs deploy/kong-ingress --tail=200
```

## Local dependency bootstrap
To install pinned versions (for maximum stability) on Ubuntu 22.04 / WSL:

`./setup/ubuntu-22.04/setup.sh bootstrap`

Versions are pinned in `setup/ubuntu-22.04/tool-versions.env` and can be adjusted as needed.

## Windows 11 (WSL2 + Docker Desktop)
One-shot (Windows) to prepare and validate the environment (run PowerShell as Administrator):

`powershell -ExecutionPolicy Bypass -File setup\\windows-11-wsl2-docker-desktop\\setup.ps1 install`

After WSL2 + Docker Desktop are ready and the repo is cloned, bring up the project:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\wsl_bootstrap.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\dev_kind.ps1 up
curl -H "Host: api.local.dev" http://localhost:8080/health
```

Unattended provisioning (strict: exits if a reboot is pending; creates Linux user `devuser` and installs Docker Desktop silently):

`powershell -ExecutionPolicy Bypass -File setup\\windows-11-wsl2-docker-desktop\\provision.ps1`

Cleanup/offboarding (unattended: removes Docker Desktop + data, unregisters Ubuntu 22.04 and Docker distros; optionally disables WSL features):

`powershell -ExecutionPolicy Bypass -File setup\\windows-11-wsl2-docker-desktop\\unprovision.ps1`

Status:

`powershell -ExecutionPolicy Bypass -File setup\\windows-11-wsl2-docker-desktop\\setup.ps1 status`

Hosts (Windows, Administrator):

`powershell -ExecutionPolicy Bypass -File setup\\windows-11-wsl2-docker-desktop\\setup.ps1 hosts -HostsAction apply`

Uninstall (keeps OS dependencies):

`powershell -ExecutionPolicy Bypass -File setup\\windows-11-wsl2-docker-desktop\\setup.ps1 uninstall`

Uninstall and attempt to remove OS dependencies (dangerous):

`powershell -ExecutionPolicy Bypass -File setup\\windows-11-wsl2-docker-desktop\\setup.ps1 uninstall -Purge -PurgeAll`

## Kubernetes Manifests
- `k8s/base`: API Deployment + Service.
- `k8s/overlays/dev`: dev namespace + Postgres StatefulSet + PVC.
- `k8s/overlays/dev-dd`: same as dev, plus Datadog agent Deployment/Service.
Kong (gateway) for local dev is included in the dev overlays and proxies requests to the API.
Kong runs with Postgres (same instance as the app, using the `kong` database) to enable plugins and UI.

## Kong access (local)

Kong Manager:
- Via Ingress through Kong proxy: `https://kong.local.dev:8443` (recommended)

Kong Admin API (port-forward):
```bash
make dev-port-kong-admin
```

Auth:
- Kong Manager uses RBAC + basic-auth.
- Credentials come from `app-secrets` (`KONG_ADMIN_GUI_USER`, `KONG_ADMIN_GUI_PASSWORD`).
- Admin API is protected with `KONG_ADMIN_TOKEN` (also in `app-secrets`).

Admin whitelist:
`make dev-kong-whitelist` generates a KongPlugin with an IP allowlist (localhost, Docker bridge, node IPs, and your machine IPs).

RBAC user per dev:
`make dev-kong-user` generates a user based on your machine name + a secure password, stored in `.git/dev-kong-user`.
It also appends the user to `KONG_RBAC_USERS` in `.env` and re-applies `dev/app-secrets`.

Remove user:
`USER_NAME=devname make dev-kong-user-remove`

## Automatic migrations
Migrations run before the app container starts using an initContainer that executes `scripts/run_migrations.py`.
The Alembic online migration path uses a PostgreSQL advisory lock to avoid concurrent migration races.
Lock ID can be configured via `MIGRATION_LOCK_ID` (default `424242`).

## Idempotency TTL cleanup
A daily CronJob (`idempotency-cleanup`) runs `scripts/cleanup_idempotency.py` with `envFrom: app-secrets`.
This keeps the `idempotency_keys` table bounded via `IDEMPOTENCY_TTL_HOURS`.

Run manually:
`kubectl -n dev create job --from=cronjob/idempotency-cleanup manual-cleanup`

## Local image flow
The API image is built locally and loaded into the kind nodes.

- Build: `make dev-build`
- Load into kind: `make dev-kind-load`
- Apply manifests: `make dev-apply` (requires `make dev-secrets-apply` first)
- Fast loop (build+load+restart API): `make dev-reload`

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| POST | /messages | Create a message |
| GET | /messages | Read all messages |
| GET | /messages/{id} | Read message by ID |
| DELETE | /messages/{id} | Delete message by ID |
| POST | /messages/reset | Delete all messages |
| GET | /health | Liveness |
| GET | /ready | Readiness (DB check) |
| GET | /metrics | Prometheus metrics |
| GET | /stats | JSON stats (requests/messages + DB counts) |

## Validation Rules
- Message length: min 5, max 200
- Must not be empty
- Must contain at least 1 alphanumeric character
- Must not duplicate an existing stored message (dedupe)

## Dedupe + Normalization
Messages are stored as `message_raw` and `message_normalized`.
Normalization is: Unicode NFKC, strip, lowercase, collapse internal whitespace.
A UNIQUE constraint on `message_normalized` enforces dedupe at the DB level.

## Idempotency
`Idempotency-Key` is supported on `POST /messages`.
If a key is reused, the original response is replayed. If reused with a different request body, returns 409.

TTL cleanup is performed by `scripts/cleanup_idempotency.py` (e.g., daily CronJob in Kubernetes).

## Auth (Optional)
If `REQUIRE_API_KEY=true`, the API requires header `X-API-Key` matching `API_KEY` for all endpoints except `/health` and `/ready`. Otherwise, open access.

Note: `/health` and `/ready` are always unauthenticated to support Kubernetes probes.

## Observability
- Datadog APM auto-instrumentation via `ddtrace.auto`
- JSON logs with log-trace correlation (dd.trace_id / dd.span_id)
- Prometheus metrics at `/metrics`
- DogStatsD metrics sent when `DD_AGENT_HOST` is configured

Optional local Datadog agent overlay:
`make dev-dd`
Requires `DD_API_KEY` (and usually `DD_AGENT_HOST=datadog-agent`, `DD_TRACE_AGENT_URL=http://datadog-agent:8126`) in `.env`.

Custom metrics:
- `messages.created`
- `messages.duplicate`
- `messages.invalid`
- `http.requests.by_route`
- `request.latency`

## Stats endpoint (JSON)
Quick, human-friendly stats at `/stats` (best-effort).

Example:

```bash
curl -s -H 'Host: api.local.dev' http://localhost:8080/stats | jq .
```

Returns (example):
- `db.messages_stored`: total stored messages
- `db.idempotency_keys_stored`: total stored idempotency keys
- `requests.total`, `requests.by_method`, `requests.by_path`, `requests.responses_by_status`
- `messages.created`, `messages.duplicate`, `messages.invalid`

## Local Examples

```bash
curl -s -X POST http://localhost:8080/messages \
  -H 'Host: api.local.dev' \
  -H 'Content-Type: application/json' \
  -d '{"message":"Hello world"}'
```

```bash
curl -s -H 'Host: api.local.dev' http://localhost:8080/messages
```

```bash
curl -s -X POST http://localhost:8080/messages \
  -H 'Host: api.local.dev' \
  -H 'Idempotency-Key: abc-123' \
  -H 'Content-Type: application/json' \
  -d '{"message":"Idempotent payload"}'
```

## Migrations

```bash
alembic upgrade head
```

## Tests

```bash
make test
```

## Development

```bash
make lint
make format
```

## Pre-commit

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

## K8s Validation

```bash
make k8s-validate
```

## Troubleshooting

- Postman returns 403:
Set `apiKey` in the Postman environment to match `API_KEY` (or set `REQUIRE_API_KEY=false` in `.env` and re-run `make dev`).
- `docker: permission denied` (Linux):
Your user likely can't talk to `/var/run/docker.sock`. Add yourself to the `docker` group or use Docker Desktop.
- HTTP works, HTTPS fails:
Install `mkcert` and re-run `make dev-tls`, or disable SSL verification in Postman.
- You changed Kong/KIC config and routes look stale:
Run `make dev-rollout-all` to restart Kong + KIC + API.

## Design Notes
- Dedupe uses normalized message with DB-level uniqueness.
- Idempotency stored in DB for safe replay across restarts.
- Request ID middleware for traceability.
- Readiness probes DB connectivity.

## Next Steps (EKS/Kong/Argo CD)
1. Run `scripts/cleanup_idempotency.py` as a Kubernetes CronJob.
2. Configure Kong for auth and rate limiting, leaving API key enforcement as defense-in-depth.
3. Use Argo CD to manage deployments and rollouts across environments.
