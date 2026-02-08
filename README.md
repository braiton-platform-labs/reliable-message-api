# Reliable Message API

Production-minded Message API built with FastAPI + PostgreSQL, featuring strong validation, dedupe, idempotency, and Datadog-first observability.

**Local dev with kind (recommended)**
Prereqs: `docker`, `kubectl`, `kind`, `aws`, `jq`.
Required env: `AWS_PROFILE` and `AWS_REGION` (default `us-east-1`).
This project uses AWS Secrets Manager + External Secrets (no `.env` support).

1. `AWS_PROFILE=your-profile AWS_REGION=us-east-1 make dev`

API will be available at `http://localhost:8080`.

Optional Datadog agent overlay:
`make dev-dd`

Optional tool check:
`./hack/doctor.sh`

Kong Admin/Manager (local):
`make dev-port-kong-admin`

TLS local (mkcert):
`make dev-tls`

RBAC user per dev:
`make dev-kong-user`
This generates a user based on your machine name and a secure password, saved locally in `.git/dev-kong-user`.
It also appends the user to `KONG_RBAC_USERS` in AWS Secrets Manager automatically.
Then re-run: `make dev-secrets-apply`

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
- `k8s/overlays/dev/external-secrets`: SecretStore + ExternalSecret for AWS Secrets Manager.
- `k8s/overlays/dev/external-secrets/install`: ESO CRDs + controller (pinned version).
Kong (gateway) for local dev is included in the dev overlays and proxies requests to the API.
Kong runs with Postgres (same instance as the app, using the `kong` database) to enable plugins and UI.

## Local dev secrets via AWS Secrets Manager + ESO
Prereqs:
- AWS CLI configured (`aws configure` or `AWS_PROFILE` set)
- `AWS_REGION` set (default `us-east-1`)
- IAM policy with least privilege:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:*:secret:braiton-platform-labs/dev/reliable-message-api*"
    }
  ]
}
```

Steps:
1. Create or update the secret manually in AWS Secrets Manager:
   - Secret name: `braiton-platform-labs/dev/reliable-message-api`
   - Secret type: plain text JSON
   - Required keys: `DATABASE_URL`, `REQUIRE_API_KEY`, `API_KEY`, `METRICS_ENABLED`, `STATS_ENABLED`, `IDEMPOTENCY_TTL_HOURS`, `DD_SERVICE`, `DD_ENV`, `DD_VERSION`, `DD_TRACE_AGENT_URL`, `DD_AGENT_HOST`, `POSTGRES_PASSWORD`, `KONG_PG_PASSWORD`, `KONG_ADMIN_GUI_USER`, `KONG_ADMIN_GUI_PASSWORD`, `KONG_ADMIN_TOKEN`, `KONG_RBAC_USERS`.
2. Install External Secrets Operator (CRDs + controller, pinned):
   `kubectl apply --server-side -k k8s/overlays/dev/external-secrets/install`
3. Ensure your AWS profile is logged in (SSO/AssumeRole):
   - Example: `aws sso login --profile $AWS_PROFILE`
4. Apply SecretStore + ExternalSecret (also creates/updates `dev/awssm-secret` from `AWS_PROFILE` automatically):
   `make dev-secrets-apply`
5. Validate:
   `kubectl -n dev get secret app-secrets`

## Automatic migrations
Migrations run before the app container starts using an initContainer that executes `scripts/run_migrations.py`.
The Alembic online migration path uses a PostgreSQL advisory lock to avoid concurrent migration races.
Lock ID can be configured via `MIGRATION_LOCK_ID` (default `424242`).

## Idempotency TTL cleanup
A daily CronJob (`idempotency-cleanup`) runs `scripts/cleanup_idempotency.py` with `envFrom: app-secrets`.
This keeps the `idempotency_keys` table bounded via `IDEMPOTENCY_TTL_HOURS`.

Run manually:
`kubectl -n dev create job --from=cronjob/idempotency-cleanup manual-cleanup`

## ECR Image Flow
The API Deployment pulls from ECR and uses the `ecr-pull` imagePullSecret.

- Ensure repo/login/push:
  `make dev-ecr-push`
- Refresh imagePullSecret (token expires):
  `make dev-ecr-secret-refresh`

The `make dev` target runs both of these steps automatically.

`dev-apply` and `dev-dd` also run `dev-ecr-secret-ensure-fresh` to refresh the token if it's older than 10 hours.

Image generation prompt:
- When a new commit is detected, `make dev-ecr-push` asks whether to build/push a new image.
- The last pushed commit is stored locally in `.git/dev-last-image` (not committed).
- To force a push without prompt: `ECR_FORCE_PUSH=true make dev-ecr-push` (CI can set `CI=true`).

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
| GET | /stats | JSON counters |

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
If `REQUIRE_API_KEY=true`, the API requires header `X-API-Key` matching `API_KEY`. Otherwise, open access.

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
