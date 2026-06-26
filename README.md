# IDA Pro MCP

[中文版](README_zh.md) | English

MCP Server for IDA Pro reverse engineering. Fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) with multi-binary pool proxy and infrastructure improvements.

## What's different from upstream?

This fork adds:

- **`idalib-pool`** — a proxy server that manages a pool of idalib instances for concurrent multi-binary analysis
- **Unix domain socket or loopback TCP** backend transport for idalib server instances
- **`execute_sync` deadlock fix** for headless idalib mode
- **Bearer token authentication** (`--auth-token` / `IDA_MCP_AUTH_TOKEN`)
- **stdio / HTTP / SSE transport** for the pool proxy

For the original IDA Pro MCP plugin (GUI mode, tool documentation, prompt engineering, etc.), see the upstream: [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).

## Three ways to run

| Mode | Command | Use case |
|------|---------|----------|
| **Thin MCP + CLI** | `ida-mcp` + `ida-cli` | **Recommended.** Minimal MCP surface, full power via CLI |
| **GUI plugin** | `ida-pro-mcp` | Connecting to IDA Pro with GUI open |
| **Headless single** | `idalib-mcp [binary]` | Analyzing one binary without GUI |
| **Headless pool** | `idalib-pool [binary]` | Analyzing multiple binaries concurrently |

## Thin MCP + CLI (recommended)

Exposing ~60 reverse-engineering tools directly over MCP bloats the tool list
and slows down agents. This mode keeps the **MCP surface tiny (3 tools)** while
moving the full toolset into a command-line tool (`ida-cli`). Both share the
**same persistent backend**, so sessions and IDBs stay warm — no per-command
cold start.

```
   MCP client (agent)                       you / agent shell
        │ stdio                                   │
        ▼                                         ▼
┌──────────────────┐                       ┌──────────────┐
│  ida-mcp (thin)  │                       │   ida-cli    │
│ open_session     │                       │ decompile…   │
│ close_session    │                       │ xrefs_to…    │
│ use_help         │                       │ rename…      │
└────────┬─────────┘   loopback HTTP/JSON-RPC   └──────┬───────┘
         └───────────────┐         ┌───────────────────┘
                         ▼         ▼
                  ┌──────────────────────┐
                  │  idalib-pool backend │  (spawned by ida-mcp)
                  │  routes by session   │
                  └──────────┬───────────┘
                             ▼
                        idalib (IDA)
```

### The 3 MCP tools

| Tool | Description |
|------|-------------|
| `open_session(input_path, run_auto_analysis?, session_id?)` | Open a binary in the backend; returns a `session_id` and the exact `ida-cli` command to run |
| `close_session(session_id)` | Close a session and free its backend resources |
| `use_help()` | Tells the agent where `ida-cli` is and to run `ida-cli --help` to discover every command |

### How it works

1. Start the thin MCP server. It **spawns an `idalib-pool` backend** on a free
   loopback port and records the endpoint in a shared state file
   (`%LOCALAPPDATA%\ida-mcp\backend.json` on Windows, `~/.ida-mcp/backend.json`
   otherwise).
2. The agent calls `open_session("/path/to/binary")` → gets back a `session_id`
   plus a ready-to-run `ida-cli` command.
3. All heavy analysis is run through `ida-cli`, which **auto-discovers** the
   backend endpoint from that state file and **dynamically generates** a
   subcommand for every backend tool (no hand-written command list).

### MCP client configuration (thin)

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "ida-mcp"
    }
  }
}
```

From source with uv:
```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/ida-pro-mcp", "ida-mcp", "--ida-dir", "C:/Program Files/IDA Professional 9.3"]
    }
  }
}
```

`ida-mcp` flags: `--max-instances N` (default 1), `--port`, `--backend-host`,
`--ida-dir`, `--auth-token`, `--unsafe`, `--endpoint URL` (attach to an
already-running backend instead of spawning one), `--keep-backend` (leave the
backend running after the thin server exits).

### Using `ida-cli`

```sh
# List every available subcommand (dynamically generated from the backend)
ida-cli --help

# Per-command arguments
ida-cli decompile -h

# Run a tool against a session (id comes from open_session)
ida-cli --session ab12cd34 decompile --address 0x401000
ida-cli --session ab12cd34 xrefs_to --address 0x401000
ida-cli --session ab12cd34 rename --renames '[{"address":"0x401000","name":"main"}]'

# Global flags can come before OR after the subcommand
ida-cli --session ab12cd34 list
ida-cli list --json                      # raw JSON output

# Session management (idalib_ prefix stripped): list/current/switch/save/health/warmup/unbind
ida-cli list
ida-cli switch --session crypto-01
ida-cli save
```

Resolution order:

- **endpoint**: `--endpoint` > `IDA_MCP_ENDPOINT` > state file. If none is
  found, start `ida-mcp` first (or pass `--endpoint`).
- **session**: `--session` > `IDA_MCP_SESSION` > backend default session.
- **auth token**: `--auth-token` > `IDA_MCP_AUTH_TOKEN` > state file.

Argument typing is derived from each tool's JSON schema:

- integers/floats/strings map to plain values;
- booleans become `--flag` / `--no-flag`;
- arrays/objects accept a **JSON string** (e.g. `--renames '[{...}]'`).

Notes:

- Commands on the **same session run serially** (the backend instance is
  single-threaded for IDA-API safety); different sessions can run in parallel.
- If a result is very large the backend **truncates** it and `ida-cli` prints a
  warning — narrow the query (filters/pagination/specific address) to get a
  complete result.

> `idalib-pool` / `idalib-mcp` are still available and are now reused as the
> internal backend for this mode. You can keep using them directly if you
> prefer exposing all tools over MCP.

## idalib-pool: Multi-Binary Analysis

The pool proxy manages multiple idalib instances behind a single MCP endpoint. Each instance holds one active IDB — no in-process switching overhead.

```
MCP Client
    │
    ▼  stdio / HTTP :8750
┌───────────────────────────┐
│  idalib-pool (proxy)       │
│  routes by session_id      │
└───┬───────────┬────────────┘
    │           │
 unix/tcp    unix/tcp
    ▼           ▼
┌─────────┐ ┌─────────┐
│ idalib#0 │ │ idalib#1 │
│ httpd    │ │ libcrypto│
└─────────┘ └─────────┘
```

### Key features

- **1 instance = 1 session**: no IDB switching, no thrashing
- **Optional `session_id`** on every IDA tool: omit for default session, specify for explicit routing. Parallel calls to different sessions are safe.
- **`idalib_switch`** only changes the default session pointer — zero IDB cost
- **LRU eviction** when pool is full (`--max-instances N`)
- **Unlimited mode** (`--max-instances 0`): fresh instance per open, destroy on close
- **Path dedup**: re-opening the same binary returns the existing session

### Usage

```sh
# stdio (default, for MCP clients like Claude Desktop)
idalib-pool

# stdio with initial binary
idalib-pool /path/to/binary

# HTTP/SSE mode
idalib-pool --transport http://127.0.0.1:8750

# Multi-instance pool
idalib-pool --max-instances 3

# Force TCP backend instances, useful on Windows
idalib-pool --instance-transport tcp --max-instances 3

# With authentication
idalib-pool --auth-token mysecret
# or: IDA_MCP_AUTH_TOKEN=mysecret idalib-pool
```

### Workflow example

```
idalib_open("/firmware/httpd")        → session "httpd-01" (default)
idalib_open("/firmware/libcrypto.so") → session "crypto-01"

# Explicit routing — parallel safe
decompile("main", session_id="httpd-01")
decompile("SSL_connect", session_id="crypto-01")

# Or switch default and omit session_id
idalib_switch("crypto-01")
decompile("SSL_connect")  → routes to crypto-01
```

## Prerequisites

- [Python](https://www.python.org/downloads/) **3.11+**
- [IDA Pro](https://hex-rays.com/ida-pro) **8.3+** (9.0+ recommended) with [idalib](https://docs.hex-rays.com/user-guide/idalib) — **IDA Free is not supported**

## Configure idalib (point it at your IDA installation)

Headless mode loads IDA's `idalib` native library, so it must know where IDA is
installed. There are **three ways** to tell it — pick whichever fits; they are
checked in this priority order:

1. **`--ida-dir` flag** (highest priority) — pass it to `ida-mcp` (or the
   backend). Good for per-client config:
   ```sh
   ida-mcp --ida-dir "C:/Program Files/IDA Professional 9.3"
   ```
2. **`IDADIR` environment variable** — set it to your IDA installation directory
   (the folder that contains `idalib.dll` / `libidalib.so` / `libidalib.dylib`):
   ```sh
   # Windows (PowerShell)
   setx IDADIR "C:\Program Files\IDA Professional 9.3"
   # Windows (current cmd session only)
   set IDADIR=C:\Program Files\IDA Professional 9.3
   # macOS / Linux (bash/zsh)
   export IDADIR="/Applications/IDA Professional 9.3.app/Contents/MacOS"   # macOS
   export IDADIR="/opt/ida-9.3"                                            # Linux
   ```
3. **idalib activation config** (recommended, set once) — run Hex-Rays'
   activation script so `import idapro` resolves automatically, no env var
   needed afterward:
   ```sh
   # Run with the SAME Python environment you installed this package into:
   python "<IDA install dir>/idalib/python/py-activate-idalib.py"
   ```
   This writes the IDA install path into
   `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json` (Windows) or
   `~/.idapro/ida-config.json` (macOS/Linux), which the tool reads on startup.

Verify it works:
```sh
python -c "import idapro; print('idalib OK:', idapro.__file__)"
```

> The directory must contain the idalib shared library (`idalib.dll` on Windows,
> `libidalib.so` on Linux, `libidalib.dylib` on macOS). Pointing `IDADIR` at the
> wrong folder is the most common cause of "failed to load idalib" errors.

## Installation

Install the latest release wheel directly from the GitHub Releases page (built
automatically by CI):

```sh
pip install https://github.com/hkbinbin/ida-headless-mcp/releases/latest/download/ida_pro_mcp-2.1.0-py3-none-any.whl
```

Or download the `.whl` / `.tar.gz` asset from the
[Releases page](https://github.com/hkbinbin/ida-headless-mcp/releases) and install it:

```sh
pip install ida_pro_mcp-2.1.0-py3-none-any.whl
```

Or from source:
```sh
git clone https://github.com/hkbinbin/ida-headless-mcp
cd ida-headless-mcp
uv run ida-mcp
```

### Cutting a release (maintainers)

Releases are produced by the `release` GitHub Action — you only need to push a
`v*` tag:

```sh
git tag -a v2.0.1 -m "v2.0.1"
git push origin v2.0.1
```

CI then runs `uv build` and attaches the wheel + sdist to a GitHub Release for
that tag (the release is created automatically). You can also run it manually
from the **Actions → release** tab.

## Docker Deployment

> **Note:** Due to IDA Pro licensing restrictions, we do not provide the IDA Pro base image. You need to build an `ida-pro:latest` Docker image yourself that contains a licensed IDA Pro (with idalib) installation.

### Build

```bash
docker build -t ida-mcp .
```

### Run

```bash
docker run -p 8745:8745 -v /path/to/binaries:/data ida-mcp
```

Mount the binaries to analyze into the `/data` directory. The MCP service listens on `0.0.0.0:8745` by default.

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TRANSPORT` | `http://0.0.0.0:8745` | Transport URL |
| `MAX_INSTANCES` | `10` | Max concurrent idalib instances |

### Connect from Claude Code

```bash
claude mcp add --transport http --scope user ida-pro-mcp http://<host>:8745/mcp
```

## MCP Client Configuration

The recommended MCP server is the thin **`ida-mcp`** (stdio), which exposes only
`open_session` / `close_session` / `use_help`. See the
[Thin MCP + CLI](#thin-mcp--cli-recommended) section for the full picture.

**Claude Code / Claude Desktop / Codebuddy (stdio, recommended):**
```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "ida-mcp"
    }
  }
}
```

**With an explicit IDA directory** (use this if you did NOT set `IDADIR` /
activate idalib — see [Configure idalib](#configure-idalib-point-it-at-your-ida-installation)):
```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "ida-mcp",
      "args": ["--ida-dir", "C:/Program Files/IDA Professional 9.3"]
    }
  }
}
```

**If `ida-mcp` is not on PATH** (point at the console script or run the module):
```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "python",
      "args": ["-m", "ida_pro_mcp.thin_server", "--ida-dir", "C:/Program Files/IDA Professional 9.3"]
    }
  }
}
```

**From source with uv:**
```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/ida-headless-mcp", "ida-mcp", "--ida-dir", "C:/Program Files/IDA Professional 9.3"]
    }
  }
}
```

<details>
<summary>Legacy: exposing all tools directly over MCP (idalib-pool)</summary>

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "idalib-pool",
      "args": ["--ida-dir", "C:/Program Files/IDA Professional 9.3"]
    }
  }
}
```

Or HTTP/SSE mode: `{ "url": "http://127.0.0.1:8750/mcp" }` (start
`idalib-pool --transport http://127.0.0.1:8750` separately).
</details>

## Session Management Tools

| Tool | Description |
|------|-------------|
| `idalib_open(path, session_id?)` | Open a binary, auto-assign to an instance |
| `idalib_close(session_id)` | Close a session (saves IDB) |
| `idalib_switch(session_id)` | Set the default session (no IDB cost) |
| `idalib_list()` | List all sessions |
| `idalib_current()` | Get the default session info |
| `idalib_save(path?)` | Save the active IDB |

## IDA Tools

66 tools from upstream ida-pro-mcp, all with optional `session_id` routing. See the [upstream documentation](https://github.com/mrexodia/ida-pro-mcp) for details:

- Decompilation & disassembly (`decompile`, `disasm`)
- Cross-references & call graphs (`xrefs_to`, `callees`, `callgraph`)
- Function & global listing (`list_funcs`, `list_globals`, `imports`)
- Memory operations (`get_bytes`, `get_int`, `get_string`, `patch`)
- Type operations (`declare_type`, `set_type`, `infer_types`, `read_struct`)
- Rename & comment (`rename`, `set_comments`)
- Pattern search (`find`, `find_bytes`, `find_regex`)
- Binary survey (`survey_binary` — start here for triage)
- Python execution (`py_eval`)

## Acknowledgments

Fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) by [@mrexodia](https://github.com/mrexodia). Multi-binary pool proxy developed with [@WinMin](https://github.com/WinMin).
