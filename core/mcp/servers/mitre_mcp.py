"""MCP server exposing VIPER's vendored OFFLINE MITRE database.

Wraps ``recon.mitre_offline`` (CWE/CAPEC/ATT&CK, ~969 CWE + 615 CAPEC, no
network) as MCP tools. Deterministic and dependency-free — ideal as a reference
server and for offline enrichment inside a hunt.

    python -m core.mcp.servers.mitre_mcp
"""
from __future__ import annotations

import os
import sys

# Allow `python -m core.mcp.servers.mitre_mcp` from anywhere by ensuring the repo
# root (which holds the `recon` and `core` packages) is importable.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.mcp.server import MCPServer  # noqa: E402


def build() -> MCPServer:
    from recon import mitre_offline as mo

    srv = MCPServer(name="viper-mitre", version="1.0.0")

    @srv.tool("mitre_stats", "Offline MITRE database statistics (entry counts).")
    def _stats(_args):
        return mo.database_stats()

    @srv.tool("mitre_enrich_cve",
              "Enrich a CVE id with CWE/CAPEC/ATT&CK from the offline DB.",
              {"type": "object",
               "properties": {"cve_id": {"type": "string"}},
               "required": ["cve_id"]})
    def _enrich(args):
        return mo.enrich_cve(str(args.get("cve_id", "")))

    @srv.tool("mitre_capec_for_cwe",
              "List CAPEC attack patterns related to a CWE id.",
              {"type": "object",
               "properties": {"cwe_id": {"type": "string"}},
               "required": ["cwe_id"]})
    def _capec(args):
        return mo.get_capec_for_cwe(str(args.get("cwe_id", "")))

    @srv.tool("mitre_attack_for_capec",
              "List ATT&CK technique ids for a CAPEC id.",
              {"type": "object",
               "properties": {"capec_id": {"type": "string"}},
               "required": ["capec_id"]})
    def _attack(args):
        return mo.get_attack_techniques(str(args.get("capec_id", "")))

    return srv


if __name__ == "__main__":
    build().run_stdio()
