# syntax=docker/dockerfile:1.7

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

FROM base AS deps

# Keep build tooling out of the runtime image. We only copy the venv to the final stage.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Cache dependency installs based on pyproject only (code changes won't invalidate this layer).
COPY pyproject.toml /tmp/pyproject.toml
RUN --mount=type=cache,target=/root/.cache/pip \
    python - <<'PY'
import pathlib
import tomllib

data = tomllib.loads(pathlib.Path("/tmp/pyproject.toml").read_text())
deps = data["project"]["dependencies"]
pathlib.Path("/tmp/requirements.txt").write_text("\n".join(deps) + "\n")
PY

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip setuptools wheel \
    && pip install -r /tmp/requirements.txt

FROM base AS runtime

COPY --from=deps /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY alembic.ini /app/alembic.ini
COPY app /app/app
COPY scripts /app/scripts

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
