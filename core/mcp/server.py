"""A tiny MCP server framework (stdio, newline-delimited JSON-RPC 2.0).

Register tools with the :meth:`MCPServer.tool` decorator, then ``run_stdio()``.
Handles ``initialize``, ``notifications/initialized``, ``tools/list``,
``tools/call`` and ``ping``. A tool handler receives the call ``arguments`` dict
and returns a string or JSON-serializable value (wrapped as MCP text content).
Raise :class:`ToolError` for a clean tool-level failure.

stdout is reserved strictly for protocol frames; the server redirects
``sys.stdout`` to ``sys.stderr`` for the lifetime of the loop so any stray
``print`` from a wrapped module cannot corrupt the JSON-RPC stream.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from . import protocol as P


class ToolError(Exception):
    """Raised by a tool handler to signal a clean, reportable failure."""


@dataclass
class _Tool:
    name: str
    description: str
    input_schema: dict
    handler: Callable[[dict], Any]


@dataclass
class MCPServer:
    name: str
    version: str = "1.0.0"
    _tools: Dict[str, _Tool] = field(default_factory=dict)

    def tool(self, name: str, description: str = "",
             input_schema: Optional[dict] = None):
        """Decorator: register ``fn(arguments: dict) -> str|json`` as a tool."""
        schema = input_schema or {"type": "object", "properties": {}}

        def deco(fn: Callable[[dict], Any]) -> Callable[[dict], Any]:
            self._tools[name] = _Tool(name, description or fn.__doc__ or "",
                                      schema, fn)
            return fn
        return deco

    # --- request dispatch (transport-independent, unit-testable) ----------

    def handle(self, msg: dict) -> Optional[dict]:
        """Process one request/notification; return a response dict or None."""
        if not isinstance(msg, dict):
            # a bare `null`/array/string is a valid JSON line but not a request;
            # never let it crash the loop.
            return P.error(None, P.INVALID_REQUEST, "request must be a JSON object")
        if msg.get("jsonrpc") != "2.0":
            return P.error(msg.get("id"), P.INVALID_REQUEST, "not jsonrpc 2.0")
        method = msg.get("method")
        msg_id = msg.get("id")
        # a request with id absent OR null is a notification (JSON-RPC 2.0).
        is_notification = "id" not in msg or msg_id is None

        if method == "initialize":
            res = {
                "protocolVersion": P.PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": self.name, "version": self.version},
            }
            return P.result(msg_id, res)
        if method in ("notifications/initialized", "initialized"):
            return None                                   # notification, no reply
        if method == "ping":
            return P.result(msg_id, {})
        if method == "tools/list":
            tools = [{"name": t.name, "description": t.description,
                      "inputSchema": t.input_schema} for t in self._tools.values()]
            return P.result(msg_id, {"tools": tools})
        if method == "tools/call":
            return self._call_tool(msg_id, msg.get("params") or {})

        if is_notification:
            return None
        return P.error(msg_id, P.METHOD_NOT_FOUND, f"unknown method: {method}")

    def _call_tool(self, msg_id, params: dict) -> dict:
        name = params.get("name")
        args = params.get("arguments") or {}
        tool = self._tools.get(name)
        if tool is None:
            # a missing tool is a reportable tool error, not a protocol crash
            return P.result(msg_id, {"isError": True,
                                     "content": [{"type": "text",
                                                  "text": f"unknown tool: {name}"}]})
        try:
            out = tool.handler(args if isinstance(args, dict) else {})
        except ToolError as exc:
            return P.result(msg_id, {"isError": True,
                                     "content": [{"type": "text", "text": str(exc)}]})
        except Exception as exc:   # noqa: BLE001 — surface as a tool error, never crash
            return P.result(msg_id, {"isError": True,
                                     "content": [{"type": "text",
                                                  "text": f"{type(exc).__name__}: {exc}"}]})
        if isinstance(out, str):
            text = out
        else:
            try:
                text = json.dumps(out, default=str, allow_nan=False)
            except (ValueError, TypeError) as exc:
                return P.result(msg_id, {"isError": True,
                                         "content": [{"type": "text",
                                                      "text": f"tool output not serializable: {exc}"}]})
        return P.result(msg_id, {"content": [{"type": "text", "text": text}]})

    # --- stdio loop --------------------------------------------------------

    def run_stdio(self, stdin=None, stdout=None) -> None:
        real_out = stdout or sys.stdout
        stream_in = stdin or sys.stdin
        # Protect the protocol stream from stray prints in wrapped code.
        saved_stdout = sys.stdout
        sys.stdout = sys.stderr
        try:
            for line in stream_in:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = P.decode(line)
                except ValueError:
                    real_out.write(P.encode(P.error(None, P.PARSE_ERROR, "parse error")))
                    real_out.flush()
                    continue
                resp = self.handle(msg)
                if resp is not None:
                    real_out.write(P.encode(resp))
                    real_out.flush()
        finally:
            sys.stdout = saved_stdout
