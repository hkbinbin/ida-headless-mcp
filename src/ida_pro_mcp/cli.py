"""ida-cli — full reverse-engineering command-line surface.

This CLI is a thin client over the persistent ``idalib-pool`` backend that the
thin MCP server (``thin_server.py``) spawns. It does NOT implement any IDA
logic itself; instead it:

  1. Connects to the backend and calls ``tools/list``.
  2. DYNAMICALLY generates an argparse subcommand for every tool the backend
     exposes (decompile, disasm, xrefs, rename, types, ... ~60 tools), mapping
     each tool's JSON ``inputSchema`` to argparse arguments.
  3. On invocation, issues ``tools/call`` with the assembled arguments (plus
     the selected ``session_id``) and prints the result.

Session management beyond open/close (which stay in the MCP) is folded in:
``list``, ``current``, ``switch``, ``save``, ``health``, ``warmup``, ``unbind``
(the ``idalib_`` prefix is stripped).

No ``idapro`` / ``ida_mcp`` imports — pure stdlib + the local mcp_client.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Optional

from ida_pro_mcp import backend_state
from ida_pro_mcp.mcp_client import McpClient, McpClientError, structured_content


# Sentinel for "argument not supplied by the user" so we never forward nulls.
class _Unset:
    def __repr__(self) -> str:
        return "<unset>"


UNSET = _Unset()

# Tools that stay on the MCP surface only — not exposed as CLI subcommands.
MCP_ONLY_TOOLS = {"idalib_open", "idalib_close"}

# Management tools whose ``idalib_`` prefix is stripped for the subcommand name.
MANAGEMENT_PREFIX = "idalib_"


# --------------------------------------------------------------------------
# Schema → argparse
# --------------------------------------------------------------------------

def _schema_type(prop: dict) -> str:
    """Classify a JSON-schema property into a handling category."""
    if "anyOf" in prop or "oneOf" in prop or "allOf" in prop:
        return "union"
    t = prop.get("type")
    if t in ("integer", "number", "string", "boolean", "array", "object"):
        return t
    return "union"  # unknown / missing → treat as JSON-passthrough


def _add_argument_for_prop(
    sub: argparse.ArgumentParser,
    name: str,
    prop: dict,
    required: bool,
) -> dict:
    """Add a single ``--<name>`` argument; return per-arg conversion metadata."""
    kind = _schema_type(prop)
    help_text = prop.get("description", "") or ""
    flag = f"--{name.replace('_', '-')}"
    dest = name
    meta = {"name": name, "kind": kind}

    if kind == "boolean":
        # --flag / --no-flag, only present if user passes it.
        sub.add_argument(
            flag,
            dest=dest,
            action=argparse.BooleanOptionalAction,
            default=UNSET,
            required=required,
            help=help_text,
        )
        return meta

    if kind == "integer":
        sub.add_argument(
            flag, dest=dest, type=int, default=UNSET, required=required, help=help_text
        )
        return meta

    if kind == "number":
        sub.add_argument(
            flag, dest=dest, type=float, default=UNSET, required=required, help=help_text
        )
        return meta

    if kind in ("array", "object"):
        hint = "JSON array" if kind == "array" else "JSON object"
        extra = f" ({hint}, e.g. pass a JSON string)"
        sub.add_argument(
            flag,
            dest=dest,
            type=str,
            default=UNSET,
            required=required,
            help=(help_text + extra).strip(),
        )
        return meta

    # string and union/unknown → string passthrough.
    if kind == "union":
        help_text = (
            help_text
            + " (accepts a value or a JSON literal; for string values that "
            "look like a number/bool, wrap in quotes e.g. '\"123\"')"
        ).strip()
    sub.add_argument(
        flag, dest=dest, type=str, default=UNSET, required=required, help=help_text
    )
    return meta


def _coerce_value(meta: dict, raw: Any) -> Any:
    """Convert a parsed argparse value into the JSON argument to send."""
    kind = meta["kind"]
    if kind in ("integer", "number", "boolean"):
        return raw
    if kind in ("array", "object"):
        # These genuinely expect a structured value — parse the JSON string.
        if isinstance(raw, str):
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw  # pass through as string
        return raw
    if kind == "union":
        # Union types (e.g. ``list[str] | str``) accept either a JSON container
        # OR a plain scalar string. Only parse when the value LOOKS like a JSON
        # container/quoted-literal — otherwise keep it as a string so that
        # address-like scalars ("4521", "401000") and names ("main") are NOT
        # silently coerced into int/bool/float.
        if isinstance(raw, str):
            stripped = raw.lstrip()
            if stripped[:1] in ("[", "{", '"'):
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return raw
            return raw  # plain scalar string — send as-is
        return raw
    return raw  # string


def _subcommand_name(tool_name: str) -> Optional[str]:
    """Map a backend tool name to a CLI subcommand name (or None to skip)."""
    if tool_name in MCP_ONLY_TOOLS:
        return None
    if tool_name.startswith(MANAGEMENT_PREFIX):
        return tool_name[len(MANAGEMENT_PREFIX):]
    return tool_name


def _build_subparsers(
    subparsers, tools: list[dict], passthrough: argparse.ArgumentParser
) -> dict[str, dict]:
    """Create a subparser per tool. Returns name → command spec."""
    commands: dict[str, dict] = {}
    for tool in tools:
        tool_name = tool.get("name", "")
        sub_name = _subcommand_name(tool_name)
        if not sub_name:
            continue
        description = tool.get("description", "") or f"Call {tool_name}"
        # argparse help shows the first line; keep it short.
        short = description.strip().splitlines()[0] if description.strip() else sub_name
        sub = subparsers.add_parser(
            sub_name,
            help=short,
            description=description,
            parents=[passthrough],
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        schema = tool.get("inputSchema") or {}
        props = schema.get("properties") or {}
        required = set(schema.get("required") or [])
        arg_meta: dict[str, dict] = {}
        for prop_name, prop in props.items():
            # session_id is provided globally via --session; never per-command.
            if prop_name == "session_id":
                continue
            meta = _add_argument_for_prop(
                sub, prop_name, prop, required=prop_name in required
            )
            arg_meta[prop_name] = meta
        commands[sub_name] = {"tool_name": tool_name, "arg_meta": arg_meta}
    return commands


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def _print_pretty(payload: Any) -> None:
    if isinstance(payload, (dict, list)):
        _print_json(payload)
    else:
        print(payload)


def _maybe_warn_truncation(payload: Any) -> None:
    if not isinstance(payload, dict):
        return
    if not payload.get("_output_truncated"):
        return
    total = payload.get("_total_chars")
    out_id = payload.get("_output_id")
    msg = [
        "",
        "[!] Output was truncated by the backend (>50000 chars).",
    ]
    if total is not None:
        msg.append(f"    Full size: {total} chars. Output id: {out_id}.")
    msg.append(
        "    Tip: narrow the query (filters/pagination/specific address) to "
        "get a complete result."
    )
    msg.append(
        "    Note: the _download_url is generally NOT reachable in the "
        "pool/idalib backend setup; do not rely on curling it."
    )
    print("\n".join(msg), file=sys.stderr)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def _global_parser() -> argparse.ArgumentParser:
    """Top-level global options (real defaults)."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--endpoint", type=str, default=None,
                        help="Backend MCP endpoint URL (overrides state file/env).")
    parser.add_argument("--session", type=str, default=None,
                        help="Session ID to target (from open_session).")
    parser.add_argument("--auth-token", type=str, default=None,
                        help="Bearer token for backend HTTP.")
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="Print the raw JSON result.")
    parser.add_argument("--timeout", type=float, default=300.0,
                        help="Per-request timeout in seconds (default: 300).")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose diagnostics on stderr.")
    return parser


def _passthrough_parser() -> argparse.ArgumentParser:
    """Per-subcommand copy of the post-connection global options.

    Uses ``default=SUPPRESS`` so these only land in the namespace when the user
    actually passes them AFTER the subcommand, leaving the top-level values
    intact otherwise. This lets ``ida-cli decompile --address X --json`` work
    as well as ``ida-cli --json decompile --address X``. Connection-level
    options (endpoint/auth/timeout) are intentionally NOT repeated here — they
    must precede the subcommand because the client is built before subcommand
    parsing.
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--session", type=str, default=argparse.SUPPRESS,
                        help="Session ID to target (from open_session).")
    parser.add_argument("--json", action="store_true", dest="json_out",
                        default=argparse.SUPPRESS,
                        help="Print the raw JSON result.")
    parser.add_argument("--verbose", "-v", action="store_true",
                        default=argparse.SUPPRESS,
                        help="Verbose diagnostics on stderr.")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Phase 1: parse global options (ignore subcommand for now).
    pre = _global_parser()
    pre_args, _ = pre.parse_known_args(argv)

    endpoint = backend_state.resolve_endpoint(pre_args.endpoint)
    if not endpoint:
        print(
            "Error: no backend endpoint found.\n"
            "  Start the thin MCP server first (it spawns the backend), or pass\n"
            "  --endpoint http://host:port (or set IDA_MCP_ENDPOINT).",
            file=sys.stderr,
        )
        return 2

    auth = backend_state.resolve_auth_token(pre_args.auth_token)
    session = backend_state.resolve_session(pre_args.session)

    client = McpClient(endpoint, auth_token=auth, timeout=pre_args.timeout)

    # Phase 2: discover tools from the backend.
    try:
        client.initialize()
        tools = client.tools_list()
    except (McpClientError, TimeoutError) as e:
        print(f"Error: cannot reach backend at {endpoint}: {e}", file=sys.stderr)
        print(
            "  Is the thin MCP server running? Try --endpoint or check that the "
            "backend is up.",
            file=sys.stderr,
        )
        return 2

    # Phase 3: build the full parser with dynamic subcommands.
    parser = argparse.ArgumentParser(
        prog="ida-cli",
        parents=[_global_parser()],
        description=(
            "Reverse-engineering CLI over a shared idalib backend. "
            f"Connected to {endpoint}. Tools discovered: {len(tools)}."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", metavar="<subcommand>")
    commands = _build_subparsers(subparsers, tools, _passthrough_parser())

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    # Global flags may appear before OR after the subcommand; the post-command
    # passthrough (SUPPRESS defaults) only sets attrs when actually given.
    json_out = getattr(args, "json_out", False) or pre_args.json_out
    verbose = getattr(args, "verbose", False) or pre_args.verbose
    session = backend_state.resolve_session(
        getattr(args, "session", None) or pre_args.session
    )

    spec = commands.get(args.command)
    if spec is None:
        print(f"Error: unknown subcommand {args.command!r}", file=sys.stderr)
        return 2

    # Phase 4: assemble arguments from supplied (non-UNSET) values.
    arguments: dict[str, Any] = {}
    for prop_name, meta in spec["arg_meta"].items():
        raw = getattr(args, prop_name, UNSET)
        if raw is UNSET:
            continue
        arguments[prop_name] = _coerce_value(meta, raw)

    # Inject session_id when targeting a specific session.
    if session:
        arguments["session_id"] = session

    if verbose:
        print(
            f"[ida-cli] {args.command} -> tool {spec['tool_name']} "
            f"args={json.dumps(arguments, default=str)} session={session}",
            file=sys.stderr,
        )

    # Phase 5: call and print.
    try:
        result = client.tools_call(spec["tool_name"], arguments)
    except McpClientError as e:
        print(f"Error: backend call failed: {e}", file=sys.stderr)
        return 1

    payload = structured_content(result)

    if result.get("isError"):
        # Surface error text on stderr; still print payload for context.
        content = result.get("content") or []
        text = ""
        if content and isinstance(content[0], dict):
            text = content[0].get("text", "")
        print(f"Error: {text or payload}", file=sys.stderr)
        return 1

    if json_out:
        _print_json(payload)
    else:
        _print_pretty(payload)
    _maybe_warn_truncation(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
