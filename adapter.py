#!/usr/bin/env python3
"""REA <-> ida-free-mcp adapter.

Bridges REA's "IDA provider" (which speaks the ida-pro-mcp v1.4 *legacy attached*
tool profile over stdio) to a running `ida-free-mcp` IDA plugin that exposes a
different tool set over Streamable HTTP MCP.

The adapter is a stdio MCP server: newline-delimited JSON-RPC 2.0 on stdin/stdout.
All diagnostics go to stderr; stdout is reserved for the JSON-RPC channel.

Standard library only.
"""

import glob
import json
import os
import re
import sys
import urllib.error
import urllib.request

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "rea-ida-adapter"
SERVER_VERSION = "1"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13337
UPSTREAM_PROTOCOL_VERSION = "2025-06-18"
HTTP_TIMEOUT = 120.0

LOG_PREFIX = "[rea-ida-adapter]"


def log(message):
    sys.stderr.write("%s %s\n" % (LOG_PREFIX, message))
    sys.stderr.flush()


class UpstreamError(Exception):
    """Raised when ida-free-mcp is unreachable or returns an unusable result."""


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------

def to_int(value):
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if not s:
        raise ValueError("empty address")
    try:
        return int(s, 16)  # accepts "0x.." and bare hex
    except ValueError:
        return int(s, 10)


def hex_addr(value):
    return "0x%x" % to_int(value)


# ---------------------------------------------------------------------------
# Upstream (ida-free-mcp) Streamable HTTP MCP client
# ---------------------------------------------------------------------------

class Upstream:
    def __init__(self):
        self._url = None
        self._rid = 0

    # -- discovery ---------------------------------------------------------

    def _candidate_urls(self):
        env_url = os.environ.get("IDA_MCP_URL")
        env_port = os.environ.get("IDA_MCP_PORT")
        urls = []
        if env_url:
            urls.append(self._normalize_url(env_url))
        elif env_port:
            urls.append("http://%s:%s/mcp" % (DEFAULT_HOST, env_port))
        else:
            for port in self._instance_ports():
                urls.append("http://%s:%d/mcp" % (DEFAULT_HOST, port))
            urls.append("http://%s:%d/mcp" % (DEFAULT_HOST, DEFAULT_PORT))
        seen = set()
        ordered = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                ordered.append(url)
        return ordered

    @staticmethod
    def _normalize_url(url):
        url = url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        url = url.rstrip("/")
        if url.endswith("/mcp"):
            return url
        return url + "/mcp"

    @staticmethod
    def _instance_ports():
        """Read ~/.ida-mcp/instances/*.json (port, pid, idb_path), newest first."""
        home = os.environ.get("HOME")
        if not home:
            return []
        paths = glob.glob(os.path.join(home, ".ida-mcp", "instances", "*.json"))
        try:
            paths.sort(key=os.path.getmtime, reverse=True)
        except OSError:
            pass
        ports = []
        for path in paths:
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    info = json.load(handle)
            except (OSError, ValueError):
                continue
            port = info.get("port")
            if isinstance(port, int) and 0 < port <= 65535:
                ports.append(port)
        return ports

    # -- transport ---------------------------------------------------------

    def _post(self, payload, url):
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json, text/event-stream")
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
                status = response.status
                content_type = response.headers.get("Content-Type", "")
                text = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise UpstreamError("HTTP %s from %s: %s" % (exc.code, url, detail[:400]))
        except (urllib.error.URLError, OSError) as exc:
            raise UpstreamError("cannot reach ida-free-mcp at %s: %s" % (url, exc))

        if status == 202 or not text.strip():
            return None
        if "text/event-stream" in content_type or text.lstrip().startswith("event:"):
            return self._parse_sse(text)
        try:
            return json.loads(text)
        except ValueError:
            raise UpstreamError("invalid JSON from %s: %s" % (url, text[:400]))

    @staticmethod
    def _parse_sse(text):
        message = None
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            chunk = line[len("data:"):].strip()
            if not chunk or chunk == "{}":
                continue
            try:
                message = json.loads(chunk)
            except ValueError:
                continue
        return message

    def _next_id(self):
        self._rid += 1
        return self._rid

    def _rpc(self, url, method, params):
        payload = {"jsonrpc": "2.0", "id": self._next_id(), "method": method}
        if params is not None:
            payload["params"] = params
        message = self._post(payload, url)
        if not isinstance(message, dict):
            raise UpstreamError("empty response for %s" % method)
        error = message.get("error")
        if error:
            raise UpstreamError("ida-free-mcp %s error: %s" % (method, error.get("message", error)))
        return message.get("result")

    def _notify(self, url, method, params):
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._post(payload, url)

    # -- session -----------------------------------------------------------

    def _connect(self):
        if self._url is not None:
            return self._url
        errors = []
        for url in self._candidate_urls():
            try:
                self._initialize(url)
            except UpstreamError as exc:
                errors.append("%s (%s)" % (url, exc))
                continue
            self._url = url
            log("connected to ida-free-mcp at %s" % url)
            return url
        detail = "; ".join(errors) if errors else "no candidate URL"
        raise UpstreamError("ida-free-mcp is not reachable. Tried: " + detail)

    def _initialize(self, url):
        result = self._rpc(url, "initialize", {
            "protocolVersion": UPSTREAM_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })
        if not isinstance(result, dict):
            raise UpstreamError("initialize returned no result")
        self._notify(url, "notifications/initialized", {})

    # -- high level --------------------------------------------------------

    def call_tool(self, name, arguments):
        url = self._connect()
        result = self._rpc(url, "tools/call", {"name": name, "arguments": arguments})
        return self._decode_tool_result(name, result)

    @staticmethod
    def _decode_tool_result(name, result):
        if not isinstance(result, dict):
            raise UpstreamError("ida-free-mcp %s returned a malformed result" % name)
        if result.get("isError") is True:
            raise UpstreamError("ida-free-mcp %s failed: %s" % (name, _text_of(result)))
        # The text block always carries the full pretty-printed result
        # (structuredContent is downgraded to a preview when output is truncated).
        text = _text_of(result)
        if text:
            try:
                return json.loads(text)
            except ValueError:
                pass
        if result.get("structuredContent") is not None:
            value = result["structuredContent"]
            if isinstance(value, dict) and list(value.keys()) == ["result"]:
                return value["result"]
            return value
        return text or None

    def read_resource(self, uri):
        url = self._connect()
        result = self._rpc(url, "resources/read", {"uri": uri})
        contents = (result or {}).get("contents") or []
        if not contents:
            raise UpstreamError("ida-free-mcp returned no contents for %s" % uri)
        first = contents[0]
        if isinstance(first, dict) and isinstance(first.get("text"), str):
            try:
                return json.loads(first["text"])
            except ValueError:
                return first["text"]
        return first


def _text_of(result):
    blocks = result.get("content") or []
    parts = []
    for block in blocks:
        if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
            parts.append(block["text"])
    return "\n".join(parts)


UPSTREAM = Upstream()


# ---------------------------------------------------------------------------
# Tool implementations (ida-free-mcp -> REA legacy shapes)
# ---------------------------------------------------------------------------

def _function_obj(fn):
    address = hex_addr(fn.get("addr", fn.get("address")))
    name = fn.get("name") or ""
    if not name:
        # IDA can return an empty name for unnamed items; REA requires a non-empty
        # name, so synthesize the conventional IDA placeholder.
        name = "sub_" + address[2:]
    return {
        "address": address,
        "name": name,
        "size": str(fn.get("size", "0")),
    }


def _lookup(query):
    result = UPSTREAM.call_tool("lookup_funcs", {"queries": [query]})
    if not isinstance(result, list) or not result:
        raise UpstreamError("lookup_funcs returned no result for %s" % query)
    item = result[0]
    fn = item.get("fn") if isinstance(item, dict) else None
    if not isinstance(fn, dict):
        error = item.get("error") if isinstance(item, dict) else None
        raise UpstreamError("no function for %s: %s" % (query, error or "not found"))
    return _function_obj(fn)


def tool_get_metadata(_args):
    metadata = UPSTREAM.read_resource("ida://idb/metadata")
    if not isinstance(metadata, dict):
        raise UpstreamError("unexpected metadata payload from ida-free-mcp")
    out = dict(metadata)
    out["base"] = hex_addr(metadata.get("base", 0))
    return out


def tool_list_functions(args):
    offset = int(args.get("offset", 0))
    count = int(args.get("count", 100))
    result = UPSTREAM.call_tool("list_funcs", {"queries": {"offset": offset, "count": count}})
    page = result[0] if isinstance(result, list) and result else result
    data = page.get("data") if isinstance(page, dict) else None
    return {
        "data": [_function_obj(item) for item in (data or [])],
        "next_offset": page.get("next_offset") if isinstance(page, dict) else None,
    }


def tool_get_function_by_name(args):
    return _lookup(args["name"])


def tool_get_function_by_address(args):
    return _lookup(hex_addr(args["address"]))


def tool_list_strings(args):
    offset = int(args.get("offset", 0))
    count = int(args.get("count", 100))
    last_error = None
    for pattern in ("(?s).*", "[\\s\\S]*"):
        result = UPSTREAM.call_tool("find_regex", {"pattern": pattern, "limit": count, "offset": offset})
        if isinstance(result, dict) and not result.get("error"):
            data = []
            for match in result.get("matches") or []:
                value = match.get("string", "")
                data.append({
                    "address": hex_addr(match.get("addr", match.get("address"))),
                    "string": value,
                    "length": len(value),
                })
            cursor = result.get("cursor") or {}
            next_offset = cursor.get("next") if isinstance(cursor, dict) and "next" in cursor else None
            return {"data": data, "next_offset": next_offset}
        last_error = result.get("error") if isinstance(result, dict) else "malformed find_regex result"
    raise UpstreamError("string enumeration failed: %s" % last_error)


_ASM_LINE = re.compile(r"^([0-9a-fA-F]+)\s+(.*)$")


def _parse_asm_lines(text):
    lines = []
    if not isinstance(text, str):
        return lines
    for index, raw in enumerate(text.split("\n")):
        if index == 0:
            continue  # header line: "name (segment @ 0x..):"
        line = raw.rstrip("\r")
        if not line.strip():
            continue
        match = _ASM_LINE.match(line)
        if not match:
            continue
        lines.append({"address": "0x" + match.group(1).lower(), "instruction": match.group(2)})
    return lines


def tool_disassemble_function(args):
    start = hex_addr(args["start_address"])
    result = UPSTREAM.call_tool("disasm", {
        "addr": start,
        "max_instructions": 50000,
        "include_total": False,
    })
    asm = result.get("asm") if isinstance(result, dict) else None
    if not isinstance(asm, dict):
        error = result.get("error") if isinstance(result, dict) else "missing assembly"
        raise UpstreamError("disasm failed: %s" % error)
    out = {
        "name": asm.get("name", ""),
        "start_ea": hex_addr(asm.get("start_ea", start)),
        "lines": _parse_asm_lines(asm.get("lines", "")),
    }
    if asm.get("return_type") is not None:
        out["return_type"] = asm["return_type"]
    if asm.get("arguments") is not None:
        out["arguments"] = asm["arguments"]
    return out


def tool_decompile_function(args):
    address = hex_addr(args["address"])
    result = UPSTREAM.call_tool("decompile", {"addr": address})
    if isinstance(result, dict) and result.get("ok") and isinstance(result.get("pseudocode"), str):
        return result["pseudocode"]
    return None


def _first_xrefs(result):
    page = result[0] if isinstance(result, list) and result else result
    if isinstance(page, dict) and page.get("xrefs") is not None:
        return page["xrefs"]
    return []


def tool_get_xrefs_to(args):
    address = hex_addr(args["address"])
    result = UPSTREAM.call_tool("xrefs_to", {"addrs": [address], "limit": 1000})
    out = []
    for xref in _first_xrefs(result):
        fn = xref.get("fn")
        out.append({
            "address": hex_addr(xref.get("addr", xref.get("address"))),
            "type": xref.get("type", "unknown"),
            "function": _function_obj(fn) if isinstance(fn, dict) else None,
        })
    return out


def tool_get_callers(args):
    address = hex_addr(args["function_address"])
    result = UPSTREAM.call_tool("xrefs_to", {"addrs": [address], "limit": 1000})
    seen = set()
    out = []
    for xref in _first_xrefs(result):
        if xref.get("type") != "code":
            continue
        fn = xref.get("fn")
        if not isinstance(fn, dict):
            continue
        fn_address = hex_addr(fn.get("addr", fn.get("address")))
        if fn_address == address or fn_address in seen:
            continue
        seen.add(fn_address)
        out.append(_function_obj(fn))
    return out


def _first_callees(result):
    page = result[0] if isinstance(result, list) and result else result
    if isinstance(page, dict) and page.get("callees") is not None:
        return page["callees"]
    return []


def tool_get_callees(args):
    address = hex_addr(args["function_address"])
    result = UPSTREAM.call_tool("callees", {"addrs": [address], "limit": 500})
    out = []
    for callee in _first_callees(result):
        address = hex_addr(callee.get("addr", callee.get("address")))
        name = callee.get("name") or ""
        if not name:
            name = "sub_" + address[2:]
        out.append({
            "address": address,
            "name": name,
            "type": callee.get("type", "internal"),
        })
    return out


# ---------------------------------------------------------------------------
# MCP tool catalog
# ---------------------------------------------------------------------------

_OBJECT = {"type": "object"}


def _schema(properties, required=None):
    schema = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


TOOLS = [
    {
        "name": "get_metadata",
        "description": "Return identity metadata for the loaded input (path, module, sha256, image base).",
        "inputSchema": _schema({}),
    },
    {
        "name": "list_functions",
        "description": "List functions with offset/count pagination.",
        "inputSchema": _schema({
            "offset": {"type": "integer"},
            "count": {"type": "integer"},
        }, ["offset", "count"]),
    },
    {
        "name": "get_function_by_name",
        "description": "Resolve a single function by name.",
        "inputSchema": _schema({"name": {"type": "string"}}, ["name"]),
    },
    {
        "name": "get_function_by_address",
        "description": "Resolve a single function by address.",
        "inputSchema": _schema({"address": {"type": "string"}}, ["address"]),
    },
    {
        "name": "list_strings",
        "description": "List string literals with offset/count pagination.",
        "inputSchema": _schema({
            "offset": {"type": "integer"},
            "count": {"type": "integer"},
        }, ["offset", "count"]),
    },
    {
        "name": "disassemble_function",
        "description": "Disassemble a function to instruction lines.",
        "inputSchema": _schema({"start_address": {"type": "string"}}, ["start_address"]),
    },
    {
        "name": "decompile_function",
        "description": "Decompile a function to pseudocode (string or null).",
        "inputSchema": _schema({"address": {"type": "string"}}, ["address"]),
    },
    {
        "name": "get_xrefs_to",
        "description": "Return cross-references to an address.",
        "inputSchema": _schema({"address": {"type": "string"}}, ["address"]),
    },
    {
        "name": "get_callers",
        "description": "Return functions that call the given function.",
        "inputSchema": _schema({"function_address": {"type": "string"}}, ["function_address"]),
    },
    {
        "name": "get_callees",
        "description": "Return functions called by the given function.",
        "inputSchema": _schema({"function_address": {"type": "string"}}, ["function_address"]),
    },
]

HANDLERS = {
    "get_metadata": tool_get_metadata,
    "list_functions": tool_list_functions,
    "get_function_by_name": tool_get_function_by_name,
    "get_function_by_address": tool_get_function_by_address,
    "list_strings": tool_list_strings,
    "disassemble_function": tool_disassemble_function,
    "decompile_function": tool_decompile_function,
    "get_xrefs_to": tool_get_xrefs_to,
    "get_callers": tool_get_callers,
    "get_callees": tool_get_callees,
}


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 dispatch
# ---------------------------------------------------------------------------

def _result(request_id, result):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id, code, message):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _tool_result(value):
    return {"content": [{"type": "text", "text": json.dumps(value)}], "isError": False}


def _tool_error(message):
    return {"content": [{"type": "text", "text": message}], "isError": True}


def handle(request):
    method = request.get("method")
    request_id = request.get("id")
    is_notification = "id" not in request
    params = request.get("params") or {}

    if method == "initialize":
        protocol_version = params.get("protocolVersion") or PROTOCOL_VERSION
        return _result(request_id, {
            "protocolVersion": protocol_version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })

    if method in ("notifications/initialized", "notifications/cancelled", "notifications/roots/list_changed"):
        return None

    if method == "ping":
        return _result(request_id, {})

    if method == "tools/list":
        return _result(request_id, {"tools": TOOLS})

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        handler = HANDLERS.get(name)
        if handler is None:
            return _result(request_id, _tool_error("unknown tool: %s" % name))
        try:
            value = handler(arguments)
        except UpstreamError as exc:
            log("tool %s failed: %s" % (name, exc))
            return _result(request_id, _tool_error(str(exc)))
        except Exception as exc:  # noqa: BLE001 - surface any handler bug to REA
            log("tool %s crashed: %r" % (name, exc))
            return _result(request_id, _tool_error("adapter error in %s: %s" % (name, exc)))
        return _result(request_id, _tool_result(value))

    if method == "resources/list":
        return _result(request_id, {"resources": []})
    if method == "prompts/list":
        return _result(request_id, {"prompts": []})
    if method == "logging/setLevel":
        return _result(request_id, {})

    if is_notification:
        return None
    return _error(request_id, -32601, "method not found: %s" % method)


def main():
    log("adapter started (pid=%d); stdout is the JSON-RPC channel" % os.getpid())
    while True:
        try:
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            break
        if line == "":
            break  # EOF: parent (REA) closed the pipe
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError as exc:
            sys.stdout.write(json.dumps(_error(None, -32700, "parse error: %s" % exc)) + "\n")
            sys.stdout.flush()
            continue
        if not isinstance(request, dict):
            sys.stdout.write(json.dumps(_error(None, -32600, "invalid request")) + "\n")
            sys.stdout.flush()
            continue
        try:
            response = handle(request)
        except Exception as exc:  # noqa: BLE001
            response = _error(request.get("id"), -32603, "internal error: %s" % exc)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    log("adapter exiting")


if __name__ == "__main__":
    main()
