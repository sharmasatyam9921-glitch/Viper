"""Registry of configured MCP servers — connect lazily, aggregate, route calls.

This is what surfaces MCP tools to the rest of VIPER (a wave/worker can list the
available MCP tools and call one). Ships with VIPER's own offline servers
pre-configured; add external servers with :meth:`MCPRegistry.add_server`.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Dict, List, Optional

from core.mcp_client import MCPClient, MCPError

logger = logging.getLogger("viper.mcp.registry")

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def default_servers() -> Dict[str, List[str]]:
    """VIPER's own servers, launched with the current interpreter."""
    py = sys.executable or "python"
    return {
        "mitre": [py, "-m", "core.mcp.servers.mitre_mcp"],
        "cve": [py, "-m", "core.mcp.servers.cve_mcp"],
    }


class MCPRegistry:
    def __init__(self, servers: Optional[Dict[str, List[str]]] = None,
                 *, cwd: Optional[str] = None, timeout: float = 20.0):
        self._servers: Dict[str, List[str]] = dict(
            servers if servers is not None else default_servers())
        self._cwd = cwd or _ROOT
        self._timeout = timeout
        self._clients: Dict[str, MCPClient] = {}
        self._failed: set = set()        # servers that already failed to start

    def add_server(self, name: str, command: List[str]) -> None:
        self._servers[name] = list(command)

    @property
    def server_names(self) -> List[str]:
        return list(self._servers)

    def client(self, name: str) -> MCPClient:
        if name not in self._servers:
            raise KeyError(f"no such MCP server: {name}")
        c = self._clients.get(name)
        if c is None:
            if name in self._failed:
                # don't re-spawn a server we already know won't start
                raise MCPError(f"MCP server {name!r} previously failed to start")
            try:
                c = MCPClient(self._servers[name], cwd=self._cwd,
                              timeout=self._timeout).start()
            except Exception:
                self._failed.add(name)
                raise
            self._clients[name] = c
        return c

    def tools(self, name: Optional[str] = None) -> List[dict]:
        """Aggregate tools across servers, each tagged with its server name.

        A server that fails to start is skipped (logged), not fatal.
        """
        out: List[dict] = []
        for sname in ([name] if name else self._servers):
            try:
                for t in self.client(sname).list_tools():
                    out.append({**t, "server": sname})
            except Exception as exc:   # noqa: BLE001
                logger.warning("MCP server %s unavailable: %s", sname, exc)
        return out

    def call(self, server: str, tool: str, arguments: Optional[dict] = None) -> dict:
        return self.client(server).call_tool(tool, arguments or {})

    def close_all(self) -> None:
        for name, c in list(self._clients.items()):
            try:
                c.close()
            except Exception as exc:   # noqa: BLE001 — one bad close can't strand the rest
                logger.warning("error closing MCP client %s: %s", name, exc)
        self._clients.clear()

    def __enter__(self) -> "MCPRegistry":
        return self

    def __exit__(self, *exc) -> None:
        self.close_all()
