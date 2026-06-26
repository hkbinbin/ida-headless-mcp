# IDA Pro MCP `__VERSION__`

Headless IDA Pro reverse-engineering over MCP, with a **thin MCP surface** (only
3 tools) plus a full-power **`ida-cli`** command line. Both share one persistent
idalib backend, so analysis sessions stay warm.

---

## 1. Prerequisites

- **Python 3.11+**
- **IDA Pro 8.3+** (9.0+ recommended) with **idalib** — IDA Free is *not* supported

### Point idalib at your IDA installation

Headless mode loads IDA's native `idalib`, so it must know where IDA lives.
Pick one (checked in this order):

1. **`--ida-dir` flag** — `ida-mcp --ida-dir "C:/Program Files/IDA Professional 9.3"`
2. **`IDADIR` env var** — set it to the IDA install dir (the folder containing
   `idalib.dll` / `libidalib.so` / `libidalib.dylib`):
   ```sh
   setx IDADIR "C:\Program Files\IDA Professional 9.3"   # Windows
   export IDADIR="/opt/ida-9.3"                            # Linux/macOS
   ```
3. **Activate once** (recommended) — run with the same Python env you installed into:
   ```sh
   python "<IDA install dir>/idalib/python/py-activate-idalib.py"
   ```

Verify: `python -c "import idapro; print('idalib OK')"`

## 2. Install

Install the wheel attached to this release:

```sh
pip install https://github.com/hkbinbin/ida-headless-mcp/releases/download/__TAG__/ida_pro_mcp-__VERSION__-py3-none-any.whl
```

Or download `ida_pro_mcp-__VERSION__-py3-none-any.whl` below and:

```sh
pip install ida_pro_mcp-__VERSION__-py3-none-any.whl
```

This installs two console commands: **`ida-mcp`** (the thin MCP server) and
**`ida-cli`** (the full reverse-engineering CLI).

## 3. Add the MCP server to your client

The MCP server is `ida-mcp` and speaks **stdio**. It exposes only three tools:
`open_session`, `close_session`, `use_help`.

**Claude Code / Claude Desktop / Codebuddy (`mcp.json`):**

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "ida-mcp"
    }
  }
}
```

If `ida-mcp` isn't on PATH, use the absolute path to the console script (e.g.
`.../Scripts/ida-mcp.exe` on Windows or `.../bin/ida-mcp`), or invoke the module:

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "python",
      "args": ["-m", "ida_pro_mcp.thin_server"]
    }
  }
}
```

Optional flags: `--ida-dir "<IDA install dir>"`, `--max-instances N`,
`--auth-token <token>`, `--endpoint <url>` (attach to an existing backend),
`--keep-backend` (leave the backend running after the MCP exits).

On startup `ida-mcp` spawns a persistent backend and writes its endpoint to a
shared state file (`%LOCALAPPDATA%\ida-mcp\backend.json` on Windows,
`~/.ida-mcp/backend.json` otherwise). On shutdown it **closes every session and
saves the `.i64` databases** before tearing the backend down.

## 4. The 3 MCP tools

| Tool | What it does |
|------|--------------|
| `open_session(input_path, run_auto_analysis?, session_id?)` | Open a binary; returns a `session_id` and the exact `ida-cli` command to run against it |
| `close_session(session_id)` | Close a session and free its backend resources (IDB is saved) |
| `use_help()` | Points you at `ida-cli` and tells you to run `ida-cli --help` for the full toolset |

Typical agent flow: call `open_session("/path/to/binary")` → get a `session_id`
→ run `ida-cli` commands → `close_session(session_id)`.

## 5. `ida-cli` — the full toolset

All ~60+ reverse-engineering tools (decompile, disassemble, xrefs, rename, type
recovery, memory read/patch, search, survey, debugger, …) live in **`ida-cli`**.
Subcommands are generated dynamically from the backend, so they always match the
installed tools.

```sh
# List every subcommand
ida-cli --help

# Arguments for one command
ida-cli decompile -h

# Run a tool against a session (id from open_session)
ida-cli --session <id> survey_binary          # start here for triage
ida-cli --session <id> decompile --addr 0x401000
ida-cli --session <id> xrefs_to --addresses '["0x401000"]'
ida-cli --session <id> rename --batch '{"func":[{"addr":"0x401000","name":"main_real"}]}'

# Session management (idalib_ prefix dropped): list / current / switch / save / health / warmup / unbind
ida-cli list
ida-cli --json list        # raw JSON output
```

**Notes**

- Global flags (`--session`, `--json`, `--verbose`) may come before or after the
  subcommand; `--endpoint` / `--auth-token` / `--timeout` must come first.
- The CLI auto-discovers the backend endpoint from the shared state file written
  by `ida-mcp`; override with `--endpoint http://host:port`.
- Endpoint/session/auth resolution: flag > env (`IDA_MCP_ENDPOINT`,
  `IDA_MCP_SESSION`, `IDA_MCP_AUTH_TOKEN`) > state file.
- Address args expect hex (e.g. `0x401000`); array/object args take a JSON string.
- Commands on the **same session run serially**; different sessions run in parallel.

---

<!-- The auto-generated changelog (commits / PRs) is appended below. -->
