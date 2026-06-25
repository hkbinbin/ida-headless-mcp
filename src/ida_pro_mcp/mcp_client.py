"""Minimal MCP JSON-RPC-over-HTTP client (stdlib only).

Used by both the thin MCP server (``thin_server.py``) and the CLI (``cli.py``)
to talk to the persistent ``idalib-pool`` backend over loopback HTTP.

Deliberately free of ``idapro`` / ``ida_mcp`` imports and third-party deps.
Only loopback TCP is supported (win32 has no AF_UNIX; the backend's
``--transport`` is always an ``http://host:port`` URL).
"""

from __future__ import annotations

import http.client
import json
import socket
import time
from typing import Any, Optional
from urllib.parse import urlparse

PROTOCOL_VERSION = "2025-06-18"
CLIENT_NAME = "ida-mcp-thin-client"
CLIENT_VERSION = "1.0.0"


class McpClientError(RuntimeError):
    """Transport or protocol-level error talking to the backend."""


class McpClient:
    """Tiny synchronous MCP client over Streamable HTTP (``POST /mcp``)."""

    def __init__(
        self,
        endpoint: str,
        auth_token: Optional[str] = None,
        timeout: float = 300.0,
    ):
        parsed = urlparse(endpoint)
        if parsed.scheme not in ("http", ""):
            raise McpClientError(
                f"Unsupported endpoint scheme {parsed.scheme!r}; only http:// is supported"
            )
        if not parsed.hostname or not parsed.port:
            raise McpClientError(f"Invalid endpoint URL: {endpoint!r}")
        self.endpoint = endpoint
        self.host = parsed.hostname
        self.port = parsed.port
        self.path = parsed.path or "/mcp"
        if self.path == "/":
            self.path = "/mcp"
        self.auth_token = auth_token
        self.timeout = timeout
        self._next_id = 0
        self._initialized = False
        self._mcp_session_id: Optional[str] = None

    # -- low level ---------------------------------------------------------

    def _alloc_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        if self._mcp_session_id:
            headers["Mcp-Session-Id"] = self._mcp_session_id
        return headers

    def _post(self, payload: dict) -> Optional[dict]:
        """POST a JSON-RPC payload; return parsed JSON response or None (202)."""
        body = json.dumps(payload).encode("utf-8")
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            conn.request("POST", self.path, body=body, headers=self._headers())
            resp = conn.getresponse()
            raw = resp.read()
            # Capture session id handed back on initialize.
            sid = resp.getheader("Mcp-Session-Id")
            if sid:
                self._mcp_session_id = sid
            if resp.status == 202:
                return None
            if resp.status >= 400:
                text = raw.decode("utf-8", errors="replace").strip()
                raise McpClientError(
                    f"Backend HTTP {resp.status} {resp.reason}: {text}"
                )
            if not raw:
                return None
            try:
                return json.loads(raw)
            except json.JSONDecodeError as e:
                raise McpClientError(f"Invalid JSON from backend: {e}") from e
        except (ConnectionRefusedError, OSError) as e:
            raise McpClientError(
                f"Cannot reach backend at {self.endpoint}: {e}"
            ) from e
        finally:
            conn.close()

    def _request(self, method: str, params: Optional[dict] = None) -> Any:
        """Send a JSON-RPC request and return its ``result`` (raises on error)."""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self._alloc_id(),
        }
        resp = self._post(payload)
        if resp is None:
            raise McpClientError(f"No response for method {method!r}")
        if "error" in resp and resp["error"]:
            err = resp["error"]
            raise McpClientError(
                f"JSON-RPC error {err.get('code')}: {err.get('message')}"
            )
        return resp.get("result")

    def _notify(self, method: str, params: Optional[dict] = None) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        payload = {"jsonrpc": "2.0", "method": method}
        if params:
            payload["params"] = params
        self._post(payload)

    # -- MCP protocol ------------------------------------------------------

    def initialize(self) -> dict:
        result = self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
            },
        )
        self._notify("notifications/initialized")
        self._initialized = True
        return result or {}

    def ensure_initialized(self) -> None:
        if not self._initialized:
            self.initialize()

    def tools_list(self) -> list[dict]:
        self.ensure_initialized()
        result = self._request("tools/list")
        if isinstance(result, dict):
            return list(result.get("tools", []))
        return []

    def tools_call(self, name: str, arguments: Optional[dict] = None) -> dict:
        """Call a tool; return the MCP result object.

        The returned dict typically has ``content``, ``structuredContent`` and
        ``isError`` keys.
        """
        self.ensure_initialized()
        result = self._request(
            "tools/call", {"name": name, "arguments": arguments or {}}
        )
        if not isinstance(result, dict):
            return {"structuredContent": result, "isError": False}
        return result

    # -- readiness ---------------------------------------------------------

    def ping_tcp(self) -> bool:
        """Return True if the TCP port accepts a connection right now."""
        try:
            with socket.create_connection((self.host, self.port), timeout=1):
                return True
        except (ConnectionRefusedError, OSError):
            return False

    def wait_ready(self, timeout: float = 120.0, poll_interval: float = 0.3) -> None:
        """Block until the backend answers an ``initialize`` handshake.

        Raises :class:`McpClientError` / :class:`TimeoutError` on failure.
        """
        deadline = time.monotonic() + timeout
        last_err: Optional[Exception] = None
        while time.monotonic() < deadline:
            if self.ping_tcp():
                try:
                    self.initialize()
                    return
                except McpClientError as e:
                    last_err = e
            time.sleep(poll_interval)
        msg = f"Backend at {self.endpoint} did not become ready within {timeout}s"
        if last_err is not None:
            msg = f"{msg} (last error: {last_err})"
        raise TimeoutError(msg)


def structured_content(result: dict) -> Any:
    """Extract the useful payload from an MCP tools/call result."""
    if not isinstance(result, dict):
        return result
    if "structuredContent" in result and result["structuredContent"] is not None:
        return result["structuredContent"]
    content = result.get("content")
    if isinstance(content, list) and content:
        first = content[0]
        if isinstance(first, dict) and "text" in first:
            text = first["text"]
            try:
                return json.loads(text)
            except (json.JSONDecodeError, TypeError):
                return text
    return result
