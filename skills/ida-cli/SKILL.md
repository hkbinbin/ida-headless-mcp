---
name: ida-cli
description: Drive headless IDA Pro reverse engineering from the command line via `ida-cli` (the thin-MCP + CLI architecture of ida-headless-mcp). Use when an agent or user needs to decompile, disassemble, list functions/strings/imports, follow cross-references, rename, retype, patch, search, or run py_eval against one or many binaries through a shared persistent idalib backend. Covers the open_session → ida-cli workflow, global flags, JSON argument passing, session management, and the ~60 dynamically generated subcommands.
---

# ida-cli — headless IDA reverse engineering from the shell

`ida-cli` is a thin client over a **persistent `idalib-pool` backend**. It does
no IDA work itself: it connects to the backend, calls `tools/list`, and
**dynamically generates one subcommand per backend tool** (~60: decompile,
disasm, xrefs, rename, types, search, …). Sessions and IDBs stay warm across
commands — no per-command cold start.

```
MCP client (agent) --stdio--> ida-mcp (thin, 3 tools) --spawns--> idalib-pool backend --> idalib (IDA)
                                                                        ^
you / agent shell  -----------------  ida-cli (full toolset)  ---------/   (loopback HTTP/JSON-RPC)
```

## The golden workflow

The MCP surface is intentionally tiny — only 3 tools. **Everything heavy goes
through `ida-cli`.**

1. **Start the thin server** (usually wired into your MCP client config):
   ```sh
   ida-mcp                                         # spawns the backend, writes a state file
   ida-mcp --ida-dir "C:/Program Files/IDA Professional 9.3"   # if IDADIR not set
   ```
2. **Open a binary** via the MCP tool `open_session(input_path)`. It returns a
   `session_id` AND the exact `ida-cli` command to run. From a shell you can
   also attach to an already-running backend (see "Endpoint resolution").
3. **Analyze through `ida-cli`** — it auto-discovers the backend endpoint from
   the state file and routes by `--session`.
4. Close with the MCP tool `close_session(session_id)` when done.

> The state file lives at `%LOCALAPPDATA%\ida-mcp\backend.json` (Windows) or
> `~/.ida-mcp/backend.json` (otherwise). `ida-cli` reads it automatically.

## Discover everything

The subcommand list is generated live from the connected backend — when unsure,
ask the tool, don't guess:

```sh
ida-cli --help                 # list every subcommand (dynamic)
ida-cli decompile -h           # per-command arguments + descriptions
ida-cli xrefs_to -h
```

## Global flags

Global flags may appear **before OR after** the subcommand (connection-level
ones — `--endpoint`, `--auth-token`, `--timeout` — must come *before* it).

| Flag | Purpose |
|------|---------|
| `--session ID` | Target session (from `open_session`). Also `IDA_MCP_SESSION`. |
| `--endpoint URL` | Backend MCP endpoint. Overrides state file/env. |
| `--auth-token TOK` | Bearer token for the backend. Also `IDA_MCP_AUTH_TOKEN`. |
| `--json` | Print the raw JSON result (machine-readable). |
| `--timeout SECS` | Per-request timeout (default 300). |
| `--verbose` / `-v` | Diagnostics on stderr. |

### Endpoint / session / auth resolution order

- **endpoint**: `--endpoint` > `IDA_MCP_ENDPOINT` > state file. If none found,
  start `ida-mcp` first (or pass `--endpoint http://host:port`).
- **session**: `--session` > `IDA_MCP_SESSION` > backend default session.
- **auth token**: `--auth-token` > `IDA_MCP_AUTH_TOKEN` > state file.

## Command examples by task

### 0. Triage first
`survey_binary` is the recommended starting point for any unknown target.
```sh
ida-cli --session ab12cd34 survey_binary
```

### 1. Resolve a name to an address (do this before address-taking tools!)
Address-taking tools (`decompile`, `xrefs_to`, …) require **numeric** addresses.
Symbol names are NOT accepted — resolve first:
```sh
ida-cli --session ab12cd34 lookup_funcs --queries '["main","encrypt"]'
```

### 2. Decompile / disassemble
```sh
ida-cli --session ab12cd34 decompile --addr 0x401000
ida-cli --session ab12cd34 disasm --addr 0x401000
```

### 3. List functions / globals / imports / strings
```sh
ida-cli --session ab12cd34 list_funcs
ida-cli --session ab12cd34 list_globals
ida-cli --session ab12cd34 imports
```

### 4. Cross-references & call graph
```sh
ida-cli --session ab12cd34 xrefs_to --addrs 0x401000
ida-cli --session ab12cd34 xrefs_to --addrs '["0x401000","0x401abc"]'   # batch (JSON array)
ida-cli --session ab12cd34 callees   --addr  0x401000
ida-cli --session ab12cd34 callgraph --addr  0x401000
```

### 5. Memory: read & patch
```sh
ida-cli --session ab12cd34 get_bytes  --addr 0x402000 --size 64
ida-cli --session ab12cd34 get_int    --addr 0x402000
ida-cli --session ab12cd34 get_string --addr 0x403010
ida-cli --session ab12cd34 patch      --addr 0x401005 --bytes '"9090"'
```

### 6. Rename & comment
```sh
ida-cli --session ab12cd34 rename --batch '{"func":[{"addr":"0x401000","name":"main"}]}'
ida-cli --session ab12cd34 set_comments --batch '[{"addr":"0x401010","comment":"loop start"}]'
```

### 7. Types
```sh
ida-cli --session ab12cd34 declare_type --decl 'struct Foo { int a; char b; };'
ida-cli --session ab12cd34 set_type     --addr 0x401000 --type 'int (*)(char *, int)'
ida-cli --session ab12cd34 infer_types  --addrs '["0x401000"]'
ida-cli --session ab12cd34 read_struct  --addr 0x402000 --type Foo
```

### 8. Pattern search
```sh
ida-cli --session ab12cd34 find       --query "AES"
ida-cli --session ab12cd34 find_bytes --pattern "48 8B ?? ??"
ida-cli --session ab12cd34 find_regex --pattern "https?://[a-z]+"
```

### 9. Run Python in the IDA context
```sh
ida-cli --session ab12cd34 py_eval --code 'print(hex(ida_ida.inf_get_min_ea()))'
```

### 10. Session management (the `idalib_` prefix is stripped)
```sh
ida-cli list                       # all sessions
ida-cli current                    # default session info
ida-cli switch  --session crypto-01
ida-cli save                       # persist the active IDB
ida-cli health
ida-cli warmup
ida-cli unbind
```

## Argument typing (derived from each tool's JSON schema)

| Schema type | How to pass it |
|-------------|----------------|
| integer / number / string | plain value: `--addr 0x401000`, `--size 64` |
| boolean | `--flag` to enable, `--no-flag` to disable |
| array / object | a **JSON string**: `--batch '{"func":[{...}]}'`, `--addrs '["0x401000"]'` |
| union (e.g. `list[str] \| str`) | a scalar OR a JSON literal; quote numeric-looking strings: `'"123"'` |

`--json` makes the output raw JSON — pipe it into `jq` or parse it
programmatically.

## Critical gotchas

1. **Addresses must be numeric** — hex with `0x` prefix (`0x401000`) or plain
   decimal. Names are rejected by address-taking tools; resolve with
   `lookup_funcs` first.
2. **Same-session commands run serially** (the idalib instance is
   single-threaded for IDA-API safety). Different sessions run in parallel —
   open one session per binary for concurrency.
3. **Large results are truncated** by the backend (>50000 chars) and `ida-cli`
   prints a warning on stderr. Narrow the query (filters / pagination /
   specific address) to get a complete result. The `_download_url` is generally
   NOT reachable in the pool/idalib setup — don't rely on curling it.
4. **No endpoint?** `ida-cli` errors out. Start `ida-mcp` first (it spawns the
   backend and writes the state file) or pass `--endpoint`.
5. **idalib must be configured** — point it at your IDA install via `--ida-dir`,
   the `IDADIR` env var, or Hex-Rays' `py-activate-idalib.py`. Wrong path ⇒
   "failed to load idalib".

## Multi-binary example

```sh
# open two binaries through MCP -> two sessions (httpd-01, crypto-01)
ida-cli --session httpd-01  decompile --addr 0x401000     # parallel-safe
ida-cli --session crypto-01 lookup_funcs --queries '["SSL_connect"]'
ida-cli --session crypto-01 decompile --addr 0x0040A2C0
ida-cli switch --session crypto-01      # change default; later cmds can omit --session
ida-cli current
```

## Tool catalog (subcommands)

~60 tools, all routed by `--session`. Highlights (run `ida-cli --help` for the
authoritative live list):

- **Triage**: `survey_binary`
- **Decompile / disasm**: `decompile`, `disasm`
- **Listing**: `list_funcs`, `list_globals`, `imports`, `lookup_funcs`
- **Xrefs / graphs**: `xrefs_to`, `callees`, `callgraph`
- **Memory**: `get_bytes`, `get_int`, `get_string`, `patch`
- **Types**: `declare_type`, `set_type`, `infer_types`, `read_struct`
- **Modify**: `rename`, `set_comments`
- **Search**: `find`, `find_bytes`, `find_regex`
- **Python**: `py_eval`
- **Sessions**: `list`, `current`, `switch`, `save`, `health`, `warmup`, `unbind`

For IDAPython scripting inside `py_eval`, see the companion **`idapython`**
skill (modern `ida_*` modules, iterators, ctree, type system).
