# Reliable Message API

Production-minded Message API built with FastAPI + PostgreSQL, featuring strong validation, dedupe, idempotency, and Datadog-first observability.

**Local dev with kind (recommended)**
Prereqs: `docker`, `kubectl`, `kind`, `jq`.
Windows 11: run the dev commands from Git Bash (recommended) or WSL2. The `Makefile` uses a POSIX shell (it won't work in plain PowerShell `cmd` semantics).
Secrets: local `.env` (gitignored). Generate one with: `make dev-env-init`.

1. `make dev`

`make dev` finishes and leaves a managed background port-forward running.
- Stop it: `make dev-port-stop`
- Foreground mode: `make dev-fg`
By default it restarts only the API (faster dev loop). If you changed Kong settings (`KONG_*`) run: `make dev-rollout-all`.

API will be available at `http://localhost:8080` (HTTP) and `https://api.local.dev:8443` (HTTPS).

DNS local (recommended, optional):
`make dev-hosts-apply`
This adds `api.local.dev` and `kong.local.dev` to `/etc/hosts` (idempotent, with a backup).
Remove later with: `make dev-hosts-remove`.

Windows 11 DNS:
`make dev-hosts-apply-win` (run as Administrator) updates the Windows hosts file.
Remove with: `make dev-hosts-remove-win`.
If you run `make dev` inside WSL2 but use Postman/Browser on Windows, you still need the Windows hosts file entry.

Postman (business rules):
- Import `postman/reliable-message-api.business-rules.postman_collection.json`
- Import `postman/reliable-message-api.local.postman_environment.json`
- If `REQUIRE_API_KEY=true`, set `apiKey` in the environment to match your `.env` / `dev/app-secrets`.
- If HTTPS fails in Postman, disable SSL verification (Settings -> General) or trust the mkcert root CA.

Optional Datadog agent overlay:
`make dev-dd`
Requires `DD_API_KEY` (and usually `DD_AGENT_HOST=datadog-agent`, `DD_TRACE_AGENT_URL=http://datadog-agent:8126`) in `.env`.

Optional tool check:
`./hack/doctor.sh`

Kong Admin/Manager (local):
`make dev-port-kong-admin`

TLS local (mkcert):
`make dev-tls`

RBAC user per dev:
`make dev-kong-user`
This generates a user based on your machine name and a secure password, saved locally in `.git/dev-kong-user`.
It also appends the user to `KONG_RBAC_USERS` in `.env` and re-applies `dev/app-secrets`.

Remove user:
`USER_NAME=devname make dev-kong-user-remove`

Ingress (prod-like):
Add hosts:
`127.0.0.1 api.local.dev kong.local.dev`
Then access:
- API: `http://api.local.dev` (via Kong Ingress)
- Kong Manager: `http://kong.local.dev`

Auth:
- Kong Manager uses RBAC + basic-auth.
- Credentials come from `app-secrets` (`KONG_ADMIN_GUI_USER`, `KONG_ADMIN_GUI_PASSWORD`).
- Admin API is protected with `KONG_ADMIN_TOKEN` (also in `app-secrets`).

Admin whitelist:
`make dev-kong-whitelist` generates a KongPlugin with IP allowlist (localhost, Docker bridge, node IPs, and your machine IPs).

Tip: when using `make dev-port`, include `Host: api.local.dev` to match the Ingress route:
`curl -H 'Host: api.local.dev' http://localhost:8080/health`

## Kong/KIC validation (dev)

```bash
kubectl get crd | grep konghq.com
kubectl auth can-i list customresourcedefinitions.apiextensions.k8s.io \
  --as=system:serviceaccount:dev:kong-ingress
kubectl -n dev logs deploy/kong-ingress --tail=200
```

## Bootstrap de dependências locais
Para instalar versões fixas (máximo de estabilidade possível):

Linux/macOS:
`./hack/bootstrap.sh`

Windows (PowerShell):
`powershell -ExecutionPolicy Bypass -File .\\hack\\bootstrap.ps1`

Versões ficam em `hack/tool-versions.env` e podem ser ajustadas conforme necessário.

## Kubernetes Manifests
- `k8s/base`: API Deployment + Service.
- `k8s/overlays/dev`: dev namespace + Postgres StatefulSet + PVC.
- `k8s/overlays/dev-dd`: same as dev, plus Datadog agent Deployment/Service.
Kong (gateway) for local dev is included in the dev overlays and proxies requests to the API.
Kong runs with Postgres (same instance as the app, using the `kong` database) to enable plugins and UI.

## Local dev secrets via `.env`
This repo uses a local `.env` file (gitignored) to populate the Kubernetes Secret `dev/app-secrets`.

Steps:
1. Generate a `.env` if you don't have one yet:
   `make dev-env-init`
   (`.env.example` is available as a reference.)
2. Apply/update `dev/app-secrets` from `.env`:
   `make dev-secrets-apply`

Required keys (dev overlay):
`DATABASE_URL`, `REQUIRE_API_KEY`, `API_KEY`, `METRICS_ENABLED`, `STATS_ENABLED`, `IDEMPOTENCY_TTL_HOURS`, `DD_SERVICE`, `DD_ENV`, `DD_VERSION`, `DD_AGENT_HOST`, `DD_TRACE_AGENT_URL`, `DD_API_KEY` (can be empty unless using `dev-dd`), `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `KONG_PG_PASSWORD`, `KONG_ADMIN_GUI_USER`, `KONG_ADMIN_GUI_PASSWORD`, `KONG_ADMIN_TOKEN`, `KONG_ADMIN_GUI_SESSION_CONF`, `KONG_RBAC_USERS`.

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
  -H 'Content-Type: application/json' \
  -d '{"message":"Hello world"}'
```

```bash
curl -s http://localhost:8080/messages
```

```bash
curl -s -X POST http://localhost:8080/messages \
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

## Design Notes
- Dedupe uses normalized message with DB-level uniqueness.
- Idempotency stored in DB for safe replay across restarts.
- Request ID middleware for traceability.
- Readiness probes DB connectivity.

## Next Steps (EKS/Kong/Argo CD)
1. Run `scripts/cleanup_idempotency.py` as a Kubernetes CronJob.
2. Configure Kong for auth and rate limiting, leaving API key enforcement as defense-in-depth.
3. Use Argo CD to manage deployments and rollouts across environments.
