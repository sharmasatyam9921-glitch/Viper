"""Operator-configured external MCP servers.

VIPER ships its own MCP servers (mitre/cve); this lets an operator register
EXTERNAL ones — e.g. an offensive-tool MCP server exposing a large tool arsenal —
so VIPER can call those tools and run their output through its validation gate.

Stored in a gitignored, operator-local ``config/mcp_servers.json`` (it can carry
local paths / env / API keys, so it is never committed). Shape::

    {
      "arsenal": {"command": ["python", "-m", "some_mcp_server"], "cwd": "/opt/x",
                  "env": {"API_KEY": "..."}},
      "scanner": ["node", "server.js"]          # bare command list is also accepted
    }
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = _ROOT / "config" / "mcp_servers.json"


def load_servers(path: Optional[Path] = None) -> Dict[str, dict]:
    """Return {name: {"command": [...], "cwd"?, "env"?}} from the config file."""
    p = Path(path) if path else CONFIG_PATH
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out: Dict[str, dict] = {}
    if not isinstance(data, dict):
        return {}
    for name, spec in data.items():
        if isinstance(spec, list) and spec:
            out[name] = {"command": [str(x) for x in spec]}
        elif isinstance(spec, dict) and spec.get("command"):
            entry = {"command": [str(x) for x in spec["command"]]}
            if spec.get("cwd"):
                entry["cwd"] = str(spec["cwd"])
            if isinstance(spec.get("env"), dict):
                entry["env"] = {str(k): str(v) for k, v in spec["env"].items()}
            out[name] = entry
    return out


def save_servers(servers: Dict[str, dict], path: Optional[Path] = None) -> None:
    p = Path(path) if path else CONFIG_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(servers, indent=2), encoding="utf-8")


def add_server(name: str, command, *, cwd: Optional[str] = None,
               env: Optional[dict] = None, path: Optional[Path] = None) -> None:
    servers = load_servers(path)
    entry = {"command": [str(x) for x in command]}
    if cwd:
        entry["cwd"] = cwd
    if env:
        entry["env"] = {str(k): str(v) for k, v in env.items()}
    servers[name] = entry
    save_servers(servers, path)


def register_sse_bridge(name: str, url: str, *, token: Optional[str] = None,
                        header: str = "Authorization",
                        bridge=("npx", "-y", "mcp-remote"),
                        path: Optional[Path] = None) -> list:
    """Register an SSE/HTTP MCP server (e.g. an external Burp Suite MCP) for VIPER's
    stdio-only client by spawning a stdio<->SSE bridge (mcp-remote). VIPER runs the
    bridge as a subprocess; the bridge speaks SSE to `url`. `token`, when given, is
    forwarded as an auth header so the bridge authenticates to the server. The
    config is operator-local + gitignored, so the token in the command is fine.
    This does NOT build a Burp integration — it wires VIPER to an already-running
    external MCP server. Returns the registered command."""
    cmd = list(bridge) + [str(url)]
    if token:
        value = f"Bearer {token}" if header.lower() == "authorization" else token
        cmd += ["--header", f"{header}: {value}"]
    add_server(name, cmd, path=path)
    return cmd


def remove_server(name: str, path: Optional[Path] = None) -> bool:
    servers = load_servers(path)
    if name in servers:
        del servers[name]
        save_servers(servers, path)
        return True
    return False
