"""VIPER's own MCP servers — each wraps an existing module as MCP tools.

Run any of them directly, e.g.::

    python -m core.mcp.servers.mitre_mcp     # offline MITRE enrichment (no network)
    python -m core.mcp.servers.cve_mcp       # CVE lookup (NVD/Vulners)
"""
