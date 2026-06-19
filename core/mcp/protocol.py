"""JSON-RPC 2.0 message helpers for MCP over stdio (newline-delimited).

Each message is a single line of compact JSON terminated by ``\\n``. This module
is transport-agnostic: it only builds/parses message dicts.
"""
from __future__ import annotations

import json
from typing import Any, Optional

PROTOCOL_VERSION = "2024-11-05"

# JSON-RPC error codes used here.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def request(msg_id: int, method: str, params: Optional[dict] = None) -> dict:
    m = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        m["params"] = params
    return m


def notification(method: str, params: Optional[dict] = None) -> dict:
    m = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        m["params"] = params
    return m


def result(msg_id: Any, value: Any) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": value}


def error(msg_id: Any, code: int, message: str, data: Any = None) -> dict:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": msg_id, "error": err}


def encode(msg: dict) -> str:
    """Serialize a message to a single newline-terminated line.

    ``allow_nan=False`` so NaN/Infinity raise rather than emit invalid JSON that
    would corrupt the wire; ``default=str`` keeps odd-but-finite values resilient.
    """
    return json.dumps(msg, separators=(",", ":"), default=str,
                      allow_nan=False) + "\n"


def decode(line: str) -> dict:
    """Parse one line into a message dict (raises ValueError on bad JSON)."""
    return json.loads(line)
