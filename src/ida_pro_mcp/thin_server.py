"""Thin MCP server — the single public MCP entry point.

Exposes only three tools:

  * ``open_session``  — open a binary in the persistent backend, return a
                        ``session_id`` plus the exact CLI command to use.
  * ``close_session`` — tear a session down.
  * ``use_help``      — point the agent at the ``ida-cli`` binary and tell it
                        to run ``-h`` to discover the full reverse-engineering
                        toolset (kept out of the MCP surface to minimise the
                        tool count).

All heavy reverse-engineering tools live in the CLI (``cli.py``), which talks
to the SAME persistent backend over HTTP.  This module spawns that backend
(an ``idalib-pool`` subprocess) on startup unless ``--endpoint`` points at an
already-running one.

This module does NOT import ``idapro`` / ``ida_mcp``; it loads ``McpServer``
from the vendored zeromcp package by file path (same trick as
``idalib_pool_server.py``).
"""

from __future__ import annotations

import argparse
import atexit
import importlib.util
import logging
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Annotated, Optional

from ida_pro_mcp import backend_state
from ida_pro_mcp.mcp_client import McpClient, McpClientError, structured_content

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Load McpServer without triggering ida_mcp.__init__ (which imports idapro)
# --------------------------------------------------------------------------

def _import_zeromcp_module(name: str, subpath: str):
    zeromcp_dir = os.path.join(os.path.dirname(__file__), "ida_mcp", "zeromcp")
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(zeromcp_dir, subpath)
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_import_zeromcp_module("ida_pro_mcp.ida_mcp.zeromcp.jsonrpc", "jsonrpc.py")
_mcp_mod = _import_zeromcp_module("ida_pro_mcp.ida_mcp.zeromcp.mcp", "mcp.py")
McpServer = _mcp_mod.McpServer


# --------------------------------------------------------------------------
# Backend lifecycle
# --------------------------------------------------------------------------

class Backend:
    """Owns (optionally) a spawned idalib-pool subprocess + an MCP client."""

    def __init__(
        self,
        endpoint: str,
        auth_token: Optional[str],
        process: Optional[subprocess.Popen],
        owns_process: bool,
    ):
        self.endpoint = endpoint
        self.auth_token = auth_token
        self.process = process
        self.owns_process = owns_process
        self.client = McpClient(endpoint, auth_token=auth_token)

    def stop(self) -> None:
        """Tear down the backend cleanly, then terminate its process tree.

        IMPORTANT — IDB safety: the backend (idalib-pool) spawns idalib_server
        grandchildren, each holding an open IDB. Hard-killing the tree (esp. on
        Windows where there is no real SIGTERM) would skip ``close_database()``
        and leave .i64 files unsaved / lock-stale.

        So we ALWAYS do an application-level graceful shutdown FIRST:
        enumerate sessions and ``idalib_close`` each one, which makes the owning
        idalib child run ``idapro.close_database()`` (saves the IDB). Only after
        every database is closed do we terminate the process tree — by then the
        children hold no open IDB, so killing them is safe.

          * POSIX: SIGTERM (the pool proxy's own cleanup is a harmless backup).
          * Windows: ``taskkill /T /F`` (databases are already closed).
        """
        if not self.owns_process or self.process is None:
            return
        proc = self.process
        self.process = None
        if proc.poll() is not None:
            return

        # 1. Close every session so each .i64 is saved and released.
        self._graceful_close_all_sessions()

        # 2. Terminate the (now IDB-free) backend process tree.
        logger.info("Stopping backend (pid=%s)...", proc.pid)
        if sys.platform == "win32":
            self._kill_tree_windows(proc)
            return

        try:
            proc.terminate()
        except (ProcessLookupError, OSError):
            return
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            logger.warning("Backend did not exit in 30s; killing")
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass

    def _graceful_close_all_sessions(self) -> None:
        """Close all backend sessions over MCP so each IDB is saved/closed.

        Best-effort and time-bounded: any failure is logged and shutdown
        continues, since the process is being torn down regardless.
        """
        try:
            closer = McpClient(
                self.endpoint, auth_token=self.auth_token, timeout=60.0
            )
            closer.initialize()
            payload = structured_content(closer.tools_call("idalib_list", {}))
            sessions = (
                payload.get("sessions", []) if isinstance(payload, dict) else []
            )
            if not sessions:
                return
            logger.info(
                "Gracefully closing %d session(s) (saving IDBs)...", len(sessions)
            )
            for sess in sessions:
                sid = sess.get("session_id") if isinstance(sess, dict) else None
                if not sid:
                    continue
                try:
                    logger.info("Closing session %s and saving its IDB...", sid)
                    closer.tools_call("idalib_close", {"session_id": sid})
                except (McpClientError, OSError) as e:
                    logger.warning("Failed to close session %s cleanly: %s", sid, e)
        except (McpClientError, TimeoutError, OSError) as e:
            logger.warning(
                "Graceful session shutdown skipped (backend unreachable?): %s", e
            )

    @staticmethod
    def _kill_tree_windows(proc: subprocess.Popen) -> None:
        """Kill the proxy and all its descendants on Windows.

        Only called AFTER :meth:`_graceful_close_all_sessions`, so no child
        holds an open IDB at this point — the hard kill cannot corrupt a .i64.
        """
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as e:
            logger.warning("taskkill failed (%s); falling back to kill()", e)
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            pass


def _find_free_tcp_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def _spawn_backend(args: argparse.Namespace) -> Backend:
    """Spawn an ``idalib-pool`` HTTP backend and wait for it to be ready."""
    host = args.backend_host
    port = args.port or _find_free_tcp_port(host)
    endpoint = f"http://{host}:{port}"

    cmd = [
        sys.executable,
        "-m",
        "ida_pro_mcp.idalib_pool_server",
        "--transport",
        endpoint,
        "--max-instances",
        str(args.max_instances),
    ]
    if args.ida_dir:
        cmd += ["--ida-dir", args.ida_dir]
    if args.auth_token:
        cmd += ["--auth-token", args.auth_token]
    if args.unsafe:
        cmd.append("--unsafe")
    if args.verbose:
        cmd.append("--verbose")

    backend_state.ensure_state_dir()
    log_path = backend_state.backend_log_file()
    logger.info("Spawning backend: %s", " ".join(cmd))
    logger.info("Backend log: %s", log_path)
    log_fh = open(log_path, "ab")
    proc = subprocess.Popen(
        cmd,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
    )

    backend = Backend(
        endpoint=endpoint,
        auth_token=args.auth_token,
        process=proc,
        owns_process=True,
    )

    # Wait for readiness; surface backend log tail on failure.
    try:
        backend.client.wait_ready(timeout=args.startup_timeout)
    except (TimeoutError, McpClientError) as e:
        if proc.poll() is not None:
            tail = _read_log_tail(log_path)
            backend.stop()
            raise RuntimeError(
                f"Backend exited during startup (code {proc.returncode}).\n"
                f"--- backend log tail ---\n{tail}"
            ) from e
        backend.stop()
        raise RuntimeError(f"Backend failed to become ready: {e}") from e

    logger.info("Backend ready at %s", endpoint)
    return backend


def _connect_existing(endpoint: str, auth_token: Optional[str], timeout: float) -> Backend:
    backend = Backend(
        endpoint=endpoint,
        auth_token=auth_token,
        process=None,
        owns_process=False,
    )
    backend.client.wait_ready(timeout=timeout)
    logger.info("Connected to existing backend at %s", endpoint)
    return backend


def _read_log_tail(path: Path, limit: int = 4000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()[-limit:]
    except OSError:
        return ""


# --------------------------------------------------------------------------
# State file maintenance
# --------------------------------------------------------------------------

def _write_backend_state(backend: Backend, args: argparse.Namespace) -> None:
    parsed_port = backend.client.port
    backend_state.update_state(
        backend={
            "endpoint": backend.endpoint,
            "transport": "http",
            "host": backend.client.host,
            "port": parsed_port,
            "pid": backend.process.pid if backend.process else None,
            "auth_token": backend.auth_token,
            "owner_pid": os.getpid(),
            "started_at": time.time(),
            "max_instances": args.max_instances,
            "owns_process": backend.owns_process,
        },
        cli=backend_state.cli_info(),
        default_session_id=None,
        sessions=[],
    )


def _record_open(session_id: str) -> None:
    data = backend_state.read_state() or {}
    sessions = list(data.get("sessions") or [])
    if session_id not in sessions:
        sessions.append(session_id)
    backend_state.update_state(default_session_id=session_id, sessions=sessions)


def _record_close(session_id: str) -> None:
    data = backend_state.read_state() or {}
    sessions = [s for s in (data.get("sessions") or []) if s != session_id]
    default = data.get("default_session_id")
    if default == session_id:
        default = sessions[-1] if sessions else None
    backend_state.update_state(default_session_id=default, sessions=sessions)


# --------------------------------------------------------------------------
# The three tools
# --------------------------------------------------------------------------

def _register_tools(mcp, backend: Backend) -> None:
    client = backend.client

    @mcp.tool
    def open_session(
        input_path: Annotated[str, "Path to the binary file to analyze"],
        run_auto_analysis: Annotated[
            bool, "Run automatic analysis on the binary"
        ] = True,
        session_id: Annotated[
            Optional[str], "Custom session ID (auto-generated if omitted)"
        ] = None,
    ) -> dict:
        """Open a binary in the backend and return a session_id + CLI command.

        After opening, use the `ida-cli` command-line tool (see `use_help`) to
        run the full reverse-engineering toolset against this session.
        """
        arguments: dict = {
            "input_path": input_path,
            "run_auto_analysis": run_auto_analysis,
        }
        if session_id:
            arguments["session_id"] = session_id
        try:
            result = client.tools_call("idalib_open", arguments)
        except McpClientError as e:
            return {"error": f"Backend call failed: {e}"}

        payload = structured_content(result)
        if isinstance(payload, dict) and payload.get("error"):
            return {"error": payload["error"]}

        sid = None
        binary = None
        if isinstance(payload, dict):
            session = payload.get("session") or {}
            if isinstance(session, dict):
                sid = session.get("session_id")
                binary = session.get("binary_path") or session.get("input_path")
        if not sid:
            return {
                "error": "Backend did not return a session_id",
                "raw": payload,
            }

        _record_open(sid)
        return {
            "session_id": sid,
            "backend_endpoint": backend.endpoint,
            "cli_command": (
                f"{backend_state.cli_command_string(sid)} <subcommand> [args]"
            ),
            "cli_help": (
                "Run `ida-cli --help` to list all subcommands; "
                "`ida-cli <subcommand> -h` for per-command usage."
            ),
            "binary": os.path.basename(binary) if binary else None,
            "message": (
                "Session created. Use the ida-cli command above for detailed "
                "analysis (decompile, xrefs, types, rename, etc.)."
            ),
        }

    @mcp.tool
    def close_session(
        session_id: Annotated[str, "Session ID to close"],
    ) -> dict:
        """Close an analysis session and free its backend resources."""
        try:
            result = client.tools_call("idalib_close", {"session_id": session_id})
        except McpClientError as e:
            return {"error": f"Backend call failed: {e}"}
        payload = structured_content(result)
        _record_close(session_id)
        if isinstance(payload, dict):
            return payload
        return {"result": payload}

    @mcp.tool
    def use_help() -> dict:
        """Explain how to use the ida-cli tool for detailed RE operations.

        The full reverse-engineering toolset (decompile, disassemble, xrefs,
        rename, type recovery, memory read/patch, debugger, etc.) is exposed
        through the `ida-cli` command-line tool, NOT through MCP. Discover the
        commands by running its `--help`.
        """
        info = backend_state.cli_info()
        return {
            "cli_invocation": info["invocation"],
            "cli_on_path": info["on_path"],
            "discover_usage": "Run `ida-cli --help` (or `-h`) to list every subcommand.",
            "per_command_usage": (
                "Run `ida-cli <subcommand> -h` to see the arguments for a "
                "specific tool (e.g. `ida-cli decompile -h`)."
            ),
            "session_hint": (
                "Pass `--session <id>` (from open_session) to target a specific "
                "session; otherwise the backend default session is used."
            ),
            "endpoint_hint": (
                "The CLI auto-discovers the backend endpoint from the shared "
                "state file; override with `--endpoint http://host:port`."
            ),
            "management_subcommands": (
                "Session management beyond open/close is in the CLI: "
                "list, current, switch, save, health, warmup, unbind."
            ),
            "skills_doc": (
                f"Static IDAPython API reference is bundled at "
                f"{backend_state.skills_dir() or 'skills/idapython/'} "
                "(informational; not required to use the CLI)."
            ),
        }


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Thin MCP server exposing open_session/close_session/use_help. "
            "Spawns and shares a persistent idalib-pool backend with ida-cli."
        )
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    parser.add_argument(
        "--max-instances",
        type=int,
        default=1,
        help="Max idalib backend instances (0 = unlimited, default: 1)",
    )
    parser.add_argument(
        "--backend-host",
        type=str,
        default="127.0.0.1",
        help="Loopback host for the backend (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="Backend TCP port (default: 0 = pick a free port)",
    )
    parser.add_argument(
        "--ida-dir",
        type=str,
        default=None,
        help="IDA installation directory passed to the backend.",
    )
    parser.add_argument(
        "--auth-token",
        type=str,
        default=os.environ.get(backend_state.ENV_AUTH_TOKEN),
        help="Bearer token for backend HTTP (or set IDA_MCP_AUTH_TOKEN).",
    )
    parser.add_argument(
        "--unsafe",
        action="store_true",
        help="Enable unsafe tools in the backend (DANGEROUS).",
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        default=None,
        help=(
            "Connect to an already-running idalib-pool backend at this URL "
            "instead of spawning one. The thin server will NOT own its lifecycle."
        ),
    )
    parser.add_argument(
        "--keep-backend",
        action="store_true",
        help="Do not stop the spawned backend when the thin server exits.",
    )
    parser.add_argument(
        "--startup-timeout",
        type=float,
        default=120.0,
        help="Seconds to wait for the backend to become ready (default: 120).",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    if args.endpoint:
        auth = backend_state.resolve_auth_token(args.auth_token)
        backend = _connect_existing(args.endpoint, auth, args.startup_timeout)
    else:
        backend = _spawn_backend(args)

    _write_backend_state(backend, args)

    # Lifecycle: stop backend on exit unless told to keep it.
    def _shutdown() -> None:
        if not args.keep_backend:
            backend.stop()
            backend_state.clear_state()

    atexit.register(_shutdown)

    def _signal_handler(signum, frame):
        logger.info("Received signal %s; shutting down.", signum)
        _shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    mcp = McpServer("ida-pro-mcp-thin")
    if args.auth_token:
        # Note: this guards the THIN server's own HTTP transport if it were
        # served over HTTP. In stdio mode it has no effect, but we keep it for
        # symmetry.
        mcp.auth_token = args.auth_token

    _register_tools(mcp, backend)

    logger.info(
        "Thin MCP ready (stdio). Backend=%s, tools=open_session/close_session/use_help",
        backend.endpoint,
    )
    try:
        mcp.stdio()
    finally:
        _shutdown()


if __name__ == "__main__":
    main()
