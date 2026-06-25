"""Shared backend state for the thin MCP server and the CLI.

The thin MCP server (``thin_server.py``) spawns a persistent ``idalib-pool``
backend and records its HTTP endpoint here.  The CLI (``cli.py``) reads this
file as a fallback to discover the backend endpoint and auth token when they
are not provided explicitly via flags or environment variables.

This module is intentionally free of any ``idapro`` / ``ida_mcp`` imports so it
can be loaded by the thin server and the CLI without pulling in idalib.

State file layout (``<state_dir>/backend.json``)::

    {
      "version": 1,
      "backend": {
        "endpoint": "http://127.0.0.1:8765",
        "transport": "http",
        "host": "127.0.0.1",
        "port": 8765,
        "pid": 12345,
        "auth_token": null,
        "owner_pid": 9876,
        "started_at": 1700000000.0,
        "max_instances": 1
      },
      "cli": {"command": "ida-cli", "module": "ida_pro_mcp.cli", "python": "..."},
      "default_session_id": "ab12cd34",
      "sessions": ["ab12cd34"],
      "updated_at": 1700000123.0
    }
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

STATE_VERSION = 1
STATE_FILENAME = "backend.json"
BACKEND_LOG_FILENAME = "backend.log"

ENV_STATE_DIR = "IDA_MCP_STATE_DIR"
ENV_ENDPOINT = "IDA_MCP_ENDPOINT"
ENV_SESSION = "IDA_MCP_SESSION"
ENV_AUTH_TOKEN = "IDA_MCP_AUTH_TOKEN"


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

def state_dir() -> Path:
    """Resolve the directory used for the shared backend state file.

    Priority:
      1. ``IDA_MCP_STATE_DIR`` environment variable.
      2. win32: ``%LOCALAPPDATA%\\ida-mcp`` (falls back to home if unset).
      3. posix: ``~/.ida-mcp``.
    """
    override = os.environ.get(ENV_STATE_DIR)
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base else Path.home()
        return root / "ida-mcp"
    return Path.home() / ".ida-mcp"


def state_file() -> Path:
    return state_dir() / STATE_FILENAME


def backend_log_file() -> Path:
    return state_dir() / BACKEND_LOG_FILENAME


def ensure_state_dir() -> Path:
    d = state_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


# --------------------------------------------------------------------------
# Read / write
# --------------------------------------------------------------------------

def read_state() -> Optional[dict]:
    """Read and parse the backend state file. Returns None if missing/invalid."""
    path = state_file()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def write_state(data: dict) -> Path:
    """Atomically write the backend state file."""
    ensure_state_dir()
    data = dict(data)
    data["version"] = STATE_VERSION
    data["updated_at"] = time.time()
    path = state_file()
    # Write to a temp file in the same dir, then replace (atomic on Windows/posix).
    fd, tmp = tempfile.mkstemp(prefix=".backend-", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def clear_state() -> None:
    """Remove the backend state file if it exists."""
    try:
        os.unlink(state_file())
    except (FileNotFoundError, OSError):
        pass


def update_state(**changes: Any) -> dict:
    """Merge ``changes`` into the existing state (creating it if absent)."""
    data = read_state() or {"version": STATE_VERSION}
    data.update(changes)
    write_state(data)
    return data


# --------------------------------------------------------------------------
# Resolution helpers (CLI uses these)
# --------------------------------------------------------------------------

def resolve_endpoint(explicit: Optional[str] = None) -> Optional[str]:
    """Resolve the backend endpoint URL.

    Priority: explicit flag > IDA_MCP_ENDPOINT env > backend.json.
    """
    if explicit:
        return explicit
    env = os.environ.get(ENV_ENDPOINT)
    if env:
        return env
    data = read_state()
    if data:
        backend = data.get("backend") or {}
        endpoint = backend.get("endpoint")
        if endpoint:
            return endpoint
    return None


def resolve_auth_token(explicit: Optional[str] = None) -> Optional[str]:
    """Resolve the bearer token.

    Priority: explicit flag > IDA_MCP_AUTH_TOKEN env > backend.json.
    """
    if explicit:
        return explicit
    env = os.environ.get(ENV_AUTH_TOKEN)
    if env:
        return env
    data = read_state()
    if data:
        backend = data.get("backend") or {}
        token = backend.get("auth_token")
        if token:
            return token
    return None


def resolve_session(explicit: Optional[str] = None) -> Optional[str]:
    """Resolve the session id.

    Priority: explicit flag > IDA_MCP_SESSION env. The backend.json
    ``default_session_id`` is intentionally NOT used to force a session — the
    backend's own default is authoritative — but it is exposed via
    :func:`default_session` for display/hints.
    """
    if explicit:
        return explicit
    env = os.environ.get(ENV_SESSION)
    if env:
        return env
    return None


def default_session() -> Optional[str]:
    """Return the backend.json default_session_id (for hints/display only)."""
    data = read_state()
    if data:
        sid = data.get("default_session_id")
        if isinstance(sid, str) and sid:
            return sid
    return None


# --------------------------------------------------------------------------
# CLI invocation prefix
# --------------------------------------------------------------------------

def cli_invocation_prefix() -> list[str]:
    """Return the argv prefix to invoke the CLI.

    Prefers the installed ``ida-cli`` console script if it is on PATH;
    otherwise falls back to ``<python> -m ida_pro_mcp.cli``.
    """
    found = shutil.which("ida-cli")
    if found:
        return [found]
    # Prefer the recorded python (from backend.json), else current interpreter.
    data = read_state()
    py = None
    if data:
        cli = data.get("cli") or {}
        py = cli.get("python")
    if not py or not os.path.exists(py):
        py = sys.executable
    return [py, "-m", "ida_pro_mcp.cli"]


def cli_command_string(session_id: Optional[str] = None) -> str:
    """Human-readable CLI command prefix string for messages/hints."""
    prefix = cli_invocation_prefix()
    parts = list(prefix)
    if session_id:
        parts += ["--session", session_id]
    return " ".join(_quote(p) for p in parts)


def _quote(part: str) -> str:
    if part and not any(c.isspace() for c in part):
        return part
    return f'"{part}"'


def cli_info() -> dict:
    """Describe how to invoke the CLI (used by use_help / open_session)."""
    found = shutil.which("ida-cli")
    return {
        "command": "ida-cli",
        "module": "ida_pro_mcp.cli",
        "python": sys.executable,
        "on_path": bool(found),
        "resolved_path": found,
        "invocation": cli_command_string(),
    }


def skills_dir() -> Optional[str]:
    """Absolute path to the bundled IDAPython skills/reference directory.

    Bundled inside the package at ``ida_pro_mcp/skills``. Returns None if it
    cannot be located (e.g. a stripped install).
    """
    candidate = Path(__file__).resolve().parent / "skills" / "idapython"
    if candidate.is_dir():
        return str(candidate)
    return None

