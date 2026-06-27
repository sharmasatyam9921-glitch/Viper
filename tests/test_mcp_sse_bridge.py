"""SSE/HTTP MCP connector (e.g. an external Burp Suite MCP) via a stdio bridge."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.mcp.config import load_servers, register_sse_bridge  # noqa: E402


def test_register_builds_bridge_command_with_auth(tmp_path):
    p = tmp_path / "mcp.json"
    cmd = register_sse_bridge("burp", "http://127.0.0.1:9876/", token="TOK123", path=p)
    assert cmd[:4] == ["npx", "-y", "mcp-remote", "http://127.0.0.1:9876/"]
    saved = load_servers(p)["burp"]["command"]
    assert "--header" in saved
    assert any("Authorization: Bearer TOK123" in a for a in saved)


def test_register_without_token_has_no_header(tmp_path):
    p = tmp_path / "mcp.json"
    register_sse_bridge("plain", "http://x/", path=p)
    assert "--header" not in load_servers(p)["plain"]["command"]


def test_custom_header_not_prefixed_with_bearer(tmp_path):
    p = tmp_path / "mcp.json"
    register_sse_bridge("svc", "http://x/", token="K", header="X-Api-Key", path=p)
    saved = load_servers(p)["svc"]["command"]
    assert any(a == "X-Api-Key: K" for a in saved)        # raw token, no "Bearer"


def test_consumed_as_a_normal_stdio_server(tmp_path):
    # the bridge is registered as an ordinary command entry, so the existing
    # stdio MCP client + gate-filter path consume it with no special-casing.
    p = tmp_path / "mcp.json"
    register_sse_bridge("burp", "http://127.0.0.1:9876/", token="t", path=p)
    entry = load_servers(p)["burp"]
    assert isinstance(entry.get("command"), list) and entry["command"][0] == "npx"
