"""Minimal, dependency-free Model Context Protocol (MCP) support.

VIPER speaks MCP over stdio using newline-delimited JSON-RPC 2.0 — no third-party
package required. This lets VIPER both CONSUME external MCP servers (via
``core.mcp_client``) and SHIP its own servers that wrap existing modules
(``core.mcp.servers``), so capabilities like CVE lookup or offline MITRE
enrichment are reachable as standard MCP tools.

Namespaced under ``core.mcp`` so it never shadows the official ``mcp`` package.
"""
from __future__ import annotations

from .server import MCPServer, ToolError   # noqa: F401
