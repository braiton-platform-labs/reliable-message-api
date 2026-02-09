#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import secrets
import string
import sys


REQUIRED_KEYS: tuple[str, ...] = (
    "DATABASE_URL",
    "REQUIRE_API_KEY",
    "API_KEY",
    "METRICS_ENABLED",
    "STATS_ENABLED",
    "IDEMPOTENCY_TTL_HOURS",
    "DD_SERVICE",
    "DD_ENV",
    "DD_VERSION",
    "DD_AGENT_HOST",
    "DD_TRACE_AGENT_URL",
    "DD_API_KEY",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "POSTGRES_DB",
    "KONG_PG_PASSWORD",
    "KONG_ADMIN_GUI_USER",
    "KONG_ADMIN_GUI_PASSWORD",
    "KONG_ADMIN_TOKEN",
    "KONG_ADMIN_GUI_SESSION_CONF",
    "KONG_RBAC_USERS",
)


def _rand_alnum(n: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _read_lines(path: pathlib.Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def _write_lines(path: pathlib.Path, lines: list[str]) -> None:
    # Always end with newline for POSIX-y tooling.
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _get_key(lines: list[str], key: str) -> str | None:
    prefix = f"{key}="
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix) :]
    return None


def _upsert_key(lines: list[str], key: str, value: str) -> list[str]:
    prefix = f"{key}="
    out: list[str] = []
    replaced = False
    for line in lines:
        if line.startswith(prefix):
            out.append(prefix + value)
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(prefix + value)
    return out


def cmd_init(env_file: pathlib.Path) -> int:
    if env_file.exists():
        print(f"{env_file} already exists")
        return 0

    pg_user = "postgres"
    pg_password = _rand_alnum(24)
    pg_db = "messages"

    kong_admin_token = _rand_alnum(32)
    kong_gui_user = "admin"
    kong_gui_password = _rand_alnum(24)
    kong_session_conf = json.dumps(
        {"secret": _rand_alnum(32), "storage": "kong", "cookie_secure": False},
        separators=(",", ":"),
    )

    lines = [
        f"POSTGRES_USER={pg_user}",
        f"POSTGRES_PASSWORD={pg_password}",
        f"POSTGRES_DB={pg_db}",
        f"KONG_PG_PASSWORD={pg_password}",
        f"DATABASE_URL=postgresql+psycopg2://{pg_user}:{pg_password}@postgres:5432/{pg_db}",
        "REQUIRE_API_KEY=false",
        f"API_KEY={_rand_alnum(32)}",
        "METRICS_ENABLED=true",
        "STATS_ENABLED=true",
        "IDEMPOTENCY_TTL_HOURS=24",
        "DD_SERVICE=reliable-message-api",
        "DD_ENV=local",
        "DD_VERSION=0.1.0",
        "DD_AGENT_HOST=",
        "DD_TRACE_AGENT_URL=",
        "DD_API_KEY=",
        f"KONG_ADMIN_GUI_USER={kong_gui_user}",
        f"KONG_ADMIN_GUI_PASSWORD={kong_gui_password}",
        f"KONG_ADMIN_TOKEN={kong_admin_token}",
        f"KONG_ADMIN_GUI_SESSION_CONF={kong_session_conf}",
        "KONG_RBAC_USERS=",
    ]

    _write_lines(env_file, lines)
    print(f"Wrote {env_file}")
    return 0


def cmd_kong_user_add(env_file: pathlib.Path, user: str, pair: str) -> int:
    lines = _read_lines(env_file)
    if not lines:
        raise SystemExit(f"{env_file} not found (run: make dev-env-init)")

    current = _get_key(lines, "KONG_RBAC_USERS") or ""
    entries = [e for e in current.split(",") if e]
    entries = [e for e in entries if e.split(":", 1)[0] != user]
    entries.append(pair)
    lines = _upsert_key(lines, "KONG_RBAC_USERS", ",".join(entries))
    _write_lines(env_file, lines)
    print(f"Updated KONG_RBAC_USERS in {env_file}")
    return 0


def cmd_kong_user_remove(env_file: pathlib.Path, user: str) -> int:
    lines = _read_lines(env_file)
    if not lines:
        raise SystemExit(f"{env_file} not found")

    current = _get_key(lines, "KONG_RBAC_USERS")
    if current is None:
        raise SystemExit("KONG_RBAC_USERS not found in env file")

    entries = [e for e in current.split(",") if e]
    new_entries: list[str] = []
    removed = False
    for e in entries:
        if e.split(":", 1)[0] == user:
            removed = True
            continue
        new_entries.append(e)

    if not removed:
        raise SystemExit(f"user {user} not found in KONG_RBAC_USERS")

    lines = _upsert_key(lines, "KONG_RBAC_USERS", ",".join(new_entries))
    _write_lines(env_file, lines)
    print(f"Removed {user} from KONG_RBAC_USERS in {env_file}")
    return 0


def cmd_validate(env_file: pathlib.Path) -> int:
    lines = _read_lines(env_file)
    if not lines:
        print(f"{env_file} not found (run: make dev-env-init)", file=sys.stderr)
        return 1

    missing = [k for k in REQUIRED_KEYS if _get_key(lines, k) is None]
    if missing:
        print("Missing required keys in env file:", file=sys.stderr)
        for k in missing:
            print(f"- {k}", file=sys.stderr)
        return 1

    print("OK")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Local dev env helpers for reliable-message-api")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp_init = sub.add_parser("init", help="Create the env file (if missing) with local dev defaults")
    sp_init.add_argument("--env-file", required=True)

    sp_add = sub.add_parser("kong-user-add", help="Add/replace a Kong RBAC user in KONG_RBAC_USERS")
    sp_add.add_argument("--env-file", required=True)
    sp_add.add_argument("--user", required=True)
    sp_add.add_argument("--pair", required=True, help="Format: user:password")

    sp_rm = sub.add_parser("kong-user-remove", help="Remove a Kong RBAC user from KONG_RBAC_USERS")
    sp_rm.add_argument("--env-file", required=True)
    sp_rm.add_argument("--user", required=True)

    sp_validate = sub.add_parser("validate", help="Validate required keys exist in the env file")
    sp_validate.add_argument("--env-file", required=True)

    args = p.parse_args()
    env_file = pathlib.Path(args.env_file)

    if args.cmd == "init":
        return cmd_init(env_file)
    if args.cmd == "kong-user-add":
        return cmd_kong_user_add(env_file, user=args.user, pair=args.pair)
    if args.cmd == "kong-user-remove":
        return cmd_kong_user_remove(env_file, user=args.user)
    if args.cmd == "validate":
        return cmd_validate(env_file)

    raise SystemExit("unknown command")


if __name__ == "__main__":
    raise SystemExit(main())
