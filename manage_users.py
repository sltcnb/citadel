#!/usr/bin/env python3
"""
Citadel — User Management CLI
==============================

Manage local users stored in Redis. Registration is disabled in the UI;
this script is the only way to create or delete accounts.

Usage
-----
  python manage_users.py create <username> [--role admin|analyst] [--password <pwd>]
  python manage_users.py delete <username>
  python manage_users.py list
  python manage_users.py reset-password <username> [--password <pwd>]
  python manage_users.py change-role <username> <role>
  python manage_users.py info <username>

Roles
-----
  analyst  — default; full read/write access to cases, timeline, modules
  admin    — same as analyst + can view all system info (future: user mgmt via API)

Configuration
-------------
  By default connects to Redis at redis://localhost:6379/0.
  Override via:
    REDIS_URL environment variable   e.g. REDIS_URL=redis://myserver:6379/0
    --redis   command-line flag       e.g. --redis redis://myserver:6379/0

Examples
--------
  # Create the first admin account
  python manage_users.py create admin --role admin

  # Create an analyst account with a specific password
  python manage_users.py create alice --role analyst --password s3cr3t!

  # List all users
  python manage_users.py list

  # Reset password interactively
  python manage_users.py reset-password alice

  # Change role
  python manage_users.py change-role alice admin
"""
from __future__ import annotations

import argparse
import getpass
import os
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

# ── Inline minimal deps so this script works without the full venv ────────────
try:
    import redis as redis_lib
except ImportError:
    sys.exit("Missing dependency: pip install redis")

try:
    import bcrypt as _bcrypt_lib
except ImportError:
    sys.exit("Missing dependency: pip install bcrypt")


def _hash_password(password: str) -> str:
    return _bcrypt_lib.hashpw(password.encode("utf-8"), _bcrypt_lib.gensalt()).decode("utf-8")

_USERS_SET = "fo:users"
_USER_KEY  = "fo:user:{username}"

VALID_ROLES = ("admin", "analyst")

# ── Colours ───────────────────────────────────────────────────────────────────

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_CYAN   = "\033[36m"
_GRAY   = "\033[90m"


def _ok(msg: str)   -> None: print(f"{_GREEN}✓{_RESET} {msg}")
def _warn(msg: str) -> None: print(f"{_YELLOW}⚠{_RESET}  {msg}")
def _err(msg: str)  -> None: print(f"{_RED}✗{_RESET} {msg}", file=sys.stderr)
def _info(msg: str) -> None: print(f"{_CYAN}·{_RESET} {msg}")


# ── kubectl port-forward auto-tunnel ─────────────────────────────────────────

def _free_port() -> int:
    """Return an available local TCP port."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _kubectl_find_redis(namespace: str) -> str | None:
    """Return the first pod name whose name starts with 'redis'."""
    try:
        out = subprocess.check_output(
            ["kubectl", "get", "pods", "-n", namespace,
             "--no-headers", "-o", "custom-columns=NAME:.metadata.name"],
            text=True, stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            name = line.strip()
            if name.lower().startswith("redis"):
                return name
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None


def _start_port_forward(namespace: str, local_port: int) -> subprocess.Popen | None:
    """
    Try to start 'kubectl port-forward' to the Redis pod.
    Returns the Popen handle on success, None if kubectl/pod not found.
    """
    pod = _kubectl_find_redis(namespace)
    if not pod:
        return None

    _info(f"Auto port-forward: kubectl → pod/{pod}  6379 → localhost:{local_port}")
    proc = subprocess.Popen(
        ["kubectl", "port-forward", f"pod/{pod}",
         f"{local_port}:6379", "-n", namespace],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait up to 3 s for the port to open
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", local_port), timeout=0.2):
                return proc
        except OSError:
            time.sleep(0.1)

    proc.terminate()
    return None


def _auto_redis_url(explicit_url: str, namespace: str) -> tuple[str, "subprocess.Popen | None"]:
    """
    If the default Redis URL is unreachable, attempt a kubectl port-forward.
    Returns (url_to_use, popen_or_None).
    """
    # Check if the user supplied a non-default URL or env var
    default_url = "redis://localhost:6379/0"
    if explicit_url != default_url:
        return explicit_url, None

    # Probe current URL first
    host, port = "localhost", 6379
    try:
        with socket.create_connection((host, port), timeout=1):
            return explicit_url, None   # already reachable
    except OSError:
        pass

    # Not reachable — try kubectl port-forward
    local_port = _free_port()
    proc = _start_port_forward(namespace, local_port)
    if proc:
        return f"redis://localhost:{local_port}/0", proc

    return explicit_url, None   # fall through; _connect will give a nice error


# ── Redis helpers ─────────────────────────────────────────────────────────────

def _connect(redis_url: str) -> redis_lib.Redis:
    try:
        r = redis_lib.Redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=3)
        r.ping()
        return r
    except Exception as exc:
        _err(f"Cannot connect to Redis at {redis_url}: {exc}")
        _info("Tip: set REDIS_URL or pass --redis <url>")
        sys.exit(1)


def _get_user(r: redis_lib.Redis, username: str) -> dict | None:
    data = r.hgetall(_USER_KEY.format(username=username))
    return data or None


def _public(user: dict) -> dict:
    return {k: v for k, v in user.items() if k != "hashed_password"}


# ── Password input helper ─────────────────────────────────────────────────────

def _read_password(prompt: str = "Password") -> str:
    while True:
        pw = getpass.getpass(f"{prompt}: ")
        if len(pw) < 8:
            _warn("Password must be at least 8 characters. Try again.")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if pw != confirm:
            _warn("Passwords do not match. Try again.")
            continue
        return pw


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_create(r: redis_lib.Redis, args: argparse.Namespace) -> None:
    username = args.username
    role     = args.role

    if _get_user(r, username):
        _err(f"User '{username}' already exists. Use reset-password to change credentials.")
        sys.exit(1)

    password = args.password or _read_password()

    user = {
        "username":        username,
        "hashed_password": _hash_password(password),
        "role":            role,
        "created_at":      datetime.now(timezone.utc).isoformat(),
    }
    r.hset(_USER_KEY.format(username=username), mapping=user)
    r.sadd(_USERS_SET, username)

    _ok(f"Created user '{_BOLD}{username}{_RESET}' with role '{role}'")
    if role == "admin":
        _info("Admin users have full access to all platform features.")


def cmd_delete(r: redis_lib.Redis, args: argparse.Namespace) -> None:
    username = args.username

    if not _get_user(r, username):
        _err(f"User '{username}' does not exist.")
        sys.exit(1)

    confirm = input(f"Delete user '{username}'? This cannot be undone. [y/N] ").strip().lower()
    if confirm != "y":
        _info("Cancelled.")
        return

    r.delete(_USER_KEY.format(username=username))
    r.srem(_USERS_SET, username)
    _ok(f"Deleted user '{username}'")


def cmd_list(r: redis_lib.Redis, _args: argparse.Namespace) -> None:
    usernames = sorted(r.smembers(_USERS_SET))
    if not usernames:
        _info("No users found. Create the first admin with:")
        _info("  python manage_users.py create admin --role admin")
        return

    print(f"\n{'USERNAME':<20} {'ROLE':<12} {'CREATED AT'}")
    print("─" * 55)
    for u in usernames:
        user = r.hgetall(_USER_KEY.format(username=u))
        if not user:
            continue
        created = user.get("created_at", "unknown")[:19].replace("T", " ")
        role    = user.get("role", "analyst")
        colour  = _CYAN if role == "admin" else _RESET
        print(f"{colour}{u:<20}{_RESET} {role:<12} {_GRAY}{created}{_RESET}")
    print()


def cmd_reset_password(r: redis_lib.Redis, args: argparse.Namespace) -> None:
    username = args.username

    if not _get_user(r, username):
        _err(f"User '{username}' does not exist.")
        sys.exit(1)

    password = args.password or _read_password(f"New password for '{username}'")
    r.hset(_USER_KEY.format(username=username), "hashed_password", _hash_password(password))
    _ok(f"Password updated for '{username}'")


def cmd_change_role(r: redis_lib.Redis, args: argparse.Namespace) -> None:
    username = args.username
    new_role = args.role

    if not _get_user(r, username):
        _err(f"User '{username}' does not exist.")
        sys.exit(1)

    r.hset(_USER_KEY.format(username=username), "role", new_role)
    _ok(f"Role for '{username}' changed to '{new_role}'")


def cmd_info(r: redis_lib.Redis, args: argparse.Namespace) -> None:
    username = args.username
    user = _get_user(r, username)

    if not user:
        _err(f"User '{username}' does not exist.")
        sys.exit(1)

    print()
    for k, v in _public(user).items():
        print(f"  {_BOLD}{k:<16}{_RESET} {v}")
    print()


# ── Argument parser ───────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="manage_users.py",
        description="Citadel user management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--redis",
        default=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        metavar="URL",
        help="Redis URL (default: REDIS_URL env or redis://localhost:6379/0)",
    )
    p.add_argument(
        "--namespace", "-n",
        default=os.getenv("K8S_NAMESPACE", "forensics-operator-dev"),
        metavar="NS",
        help="Kubernetes namespace for auto port-forward (default: forensics-operator-dev)",
    )

    sub = p.add_subparsers(dest="command", required=True)

    # create
    c = sub.add_parser("create", help="Create a new user")
    c.add_argument("username")
    c.add_argument("--role", choices=VALID_ROLES, default="analyst",
                   help="User role (default: analyst)")
    c.add_argument("--password", default=None, help="Password (prompted if omitted)")

    # delete
    d = sub.add_parser("delete", help="Delete a user")
    d.add_argument("username")

    # list
    sub.add_parser("list", help="List all users")

    # reset-password
    rp = sub.add_parser("reset-password", help="Reset a user's password")
    rp.add_argument("username")
    rp.add_argument("--password", default=None, help="New password (prompted if omitted)")

    # change-role
    cr = sub.add_parser("change-role", help="Change a user's role")
    cr.add_argument("username")
    cr.add_argument("role", choices=VALID_ROLES)

    # info
    i = sub.add_parser("info", help="Show detailed info about a user")
    i.add_argument("username")

    return p


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    redis_url, pf_proc = _auto_redis_url(args.redis, args.namespace)

    try:
        r = _connect(redis_url)
        commands = {
            "create":         cmd_create,
            "delete":         cmd_delete,
            "list":           cmd_list,
            "reset-password": cmd_reset_password,
            "change-role":    cmd_change_role,
            "info":           cmd_info,
        }
        commands[args.command](r, args)
    finally:
        if pf_proc is not None:
            pf_proc.terminate()
            _info("Port-forward closed.")


if __name__ == "__main__":
    main()
