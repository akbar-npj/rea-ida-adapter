# rea-ida-adapter

A small, stdlib-only Python 3 MCP adapter that bridges **REA's "IDA provider"** to a
running **`ida-free-mcp`** IDA plugin.

REA's *attached* mode expects the upstream MCP server to speak the **ida-pro-mcp
v1.4 "legacy attached" tool profile** — a fixed set of 10 tools with specific JSON
result shapes that REA validates with zod (a shape mismatch hard-fails the request).
`ida-free-mcp` exposes a *different* (modern) tool set over **Streamable HTTP MCP**.
This adapter sits in between:

```
REA  --stdio JSON-RPC-->  adapter.py  --HTTP MCP-->  ida-free-mcp (IDA plugin)
       (legacy 1.4 profile)              (modern profile)
```

It advertises exactly the 10 legacy tool names, translates each call into one or more
`ida-free-mcp` tool calls, and reshapes the results into the exact legacy schemas.

## Files

| File | Purpose |
| --- | --- |
| `adapter.py` | The adapter (executable, `#!/usr/bin/env python3`). |
| `README.md` | This document. |
| `.gitignore` | Ignore local scratch files. |

No third-party packages are required. Run it with `python3 adapter.py`; it reads/writes
newline-delimited JSON-RPC 2.0 on stdin/stdout and logs to **stderr only**.

## Registering with REA

Point `REA_IDA_MCP_CONFIG` at a JSON file shaped like:

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "type": "stdio",
      "command": "python3",
      "args": ["/home/shaanair/Projects/ida-mcp/rea-ida-adapter/adapter.py"],
      "mode": "attached"
    }
  }
}
```

REA spawns the adapter over stdio, calls `initialize` / `tools/list`, checks that the
legacy tool set is present, and then drives the tools below.

### Upstream discovery

On the first tool call the adapter connects to `ida-free-mcp` at `POST /mcp`:

1. `IDA_MCP_URL` (env) — full URL or base; `/mcp` is appended if missing.
2. `IDA_MCP_PORT` (env) — `http://127.0.0.1:<port>/mcp`.
3. `~/.ida-mcp/instances/*.json` — each file records `{port, pid, idb_path}`; ports are
   tried newest-file-first (handles the plugin's auto-increment when 13337 is busy).
4. `http://127.0.0.1:13337/mcp` — the default.

It performs an MCP `initialize` + `notifications/initialized` handshake against the
first reachable candidate and pins it. Responses are accepted as either plain JSON or
SSE-framed (`text/event-stream` with `data: {...}` lines).

## Tool mapping

| REA tool (legacy 1.4) | args | `ida-free-mcp` source | result translation |
| --- | --- | --- | --- |
| `get_metadata` | `{}` | resource `ida://idb/metadata` | passthrough `{path, module, sha256, base, ...}`; `base` normalized to `0x…` |
| `list_functions` | `{offset, count}` | `list_funcs` `{queries:{offset,count}}` | `[{data,next_offset}]` → `{data:[{address,name,size}], next_offset}` |
| `get_function_by_name` | `{name}` | `lookup_funcs` `{queries:[name]}` | `[{query,fn,error}]` → `{address,name,size}` |
| `get_function_by_address` | `{address}` | `lookup_funcs` `{queries:[addr]}` | `[{query,fn,error}]` → `{address,name,size}` |
| `list_strings` | `{offset, count}` | `find_regex` `{pattern:"(?s).*", limit, offset}` | `{matches:[{addr,string}]}` → `{data:[{address,string,length}], next_offset}`; `length` synthesized |
| `disassemble_function` | `{start_address}` | `disasm` `{addr, max_instructions:50000}` | `asm.lines` **string** → parsed into `[{address,instruction}]`; `name`/`start_ea`/`return_type`/`arguments` passed through |
| `decompile_function` | `{address}` | `decompile` `{addr}` | `{ok,pseudocode}` → pseudocode **string**, or `null` when `ok=false` |
| `get_xrefs_to` | `{address}` | `xrefs_to` `{addrs:[addr], limit:1000}` | `[{xrefs:[{addr,type,fn}]}]` → `[{address,type,function}]` |
| `get_callers` | `{function_address}` | `xrefs_to` (derived) | keep `type=="code"` xrefs, dedupe by containing function, drop self-references → `[{address,name,size}]` |
| `get_callees` | `{function_address}` | `callees` `{addrs:[addr], limit:500}` | `[{callees:[{addr,name,type}]}]` → `[{address,name,type}]` |

All addresses are normalized to lowercase `0x…`; `size` is always a string.

## Known limitations

- **`list_strings`** — `ida-free-mcp` has no string-list tool. This adapter enumerates
  string literals via `find_regex` with `(?s).*`, falling back to `[\s\S]*` if the
  C++ `std::regex` ECMAScript engine rejects the inline `(?s)` flag. Only items IDA has
  flagged as string literals (`is_strlit`) are returned; `length` is the Python
  character count of the decoded string (not the on-disk byte length). Empty strings
  are not returned by the upstream tool.
- **`get_callers`** — `ida-free-mcp` has no callers tool. Callers are *derived* from
  `xrefs_to`: only `code` cross-references whose containing function differs from the
  target are reported. This can miss callers reached through data/indirect references
  and can, in principle, include non-call code references (e.g. a tail jump) that IDA
  classifies as `code`. It is a best-effort approximation, not a proven call-edge set.
- **`get_metadata.sha256`** — passed straight through from IDA. If IDA cannot produce
  the input SHA-256 (e.g. the `.i64` has no input hash), the upstream returns
  `"unavailable"`, which REA rejects (it requires 64 hex chars). Open the original
  input binary in IDA so the hash is recorded.
- **`disassemble_function`** — the upstream caps a single call at 50 000 instructions;
  larger functions are silently truncated. Basic-block/CFG data is not requested.
- **`decompile_function`** — on IDA Free the upstream uses GUI-based decompilation
  (F5 + widget scraping); it returns `null` (never an error) when no pseudocode widget
  can be found for the function.
- **Startup** — the adapter starts even when `ida-free-mcp` is down; the first tool
  call returns a clear MCP tool error, which REA surfaces rather than crashing.

## Verifying without IDA

```sh
python3 -c "import ast; ast.parse(open('adapter.py').read())"

printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | python3 adapter.py
```

`tools/list` does not touch `ida-free-mcp` and returns all 10 legacy tool names.
