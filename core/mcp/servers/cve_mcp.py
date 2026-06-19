"""MCP server exposing VIPER's CVE lookup (NVD / Vulners).

Wraps ``recon.cve_lookup`` as MCP tools. ``cve_build_cpe`` is offline/deterministic;
``cve_lookup`` queries NVD (returns an empty list when offline or unconfigured).

    python -m core.mcp.servers.cve_mcp
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.mcp.server import MCPServer, ToolError  # noqa: E402


def build() -> MCPServer:
    from recon import cve_lookup

    srv = MCPServer(name="viper-cve", version="1.0.0")

    @srv.tool("cve_build_cpe",
              "Build a CPE 2.3 string for a technology/version (offline).",
              {"type": "object",
               "properties": {"tech": {"type": "string"},
                              "version": {"type": "string"}},
               "required": ["tech"]})
    def _cpe(args):
        cpe = cve_lookup.build_cpe(str(args.get("tech", "")),
                                   args.get("version") or None)
        if not cpe:
            raise ToolError(f"could not build CPE for {args.get('tech')!r}")
        return {"cpe": cpe}

    @srv.tool("cve_lookup",
              "Look up CVEs for a technology/CPE via NVD (network; [] offline).",
              {"type": "object",
               "properties": {"query": {"type": "string"},
                              "version": {"type": "string"}},
               "required": ["query"]})
    def _lookup(args):
        cves = cve_lookup.lookup_cves(str(args.get("query", "")),
                                      args.get("version") or None)
        return {"count": len(cves or []), "cves": cves or []}

    return srv


if __name__ == "__main__":
    build().run_stdio()
