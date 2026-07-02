"""Preset MCP plan for an external Burp Suite MCP (e.g. a Burp-Pro MCP extension).

Auto-invokes the high-value Burp tools mid-hunt through VIPER's standard mcp_plan
path: the access-control (BOLA/IDOR/privesc) sweep, Burp Collaborator OOB polling,
and the scanner's existing issues. Every result is gate-filtered exactly like any
`mcp:*` source — capped confidence, re-confirmed by VIPER's own gate, and (per the
gate) an external finding can NEVER use the two-identity trust short-circuit — so
Burp's breadth arrives without Burp's false positives.

Arguments are best-effort defaults for a common Burp MCP schema; the operator can
override any entry via --mcp-plan. This module builds the plan only — it makes no
network calls and requires no Burp at import time.
"""
from __future__ import annotations

from typing import List, Optional

# The high-value Burp tools, in the order they run.
ACCESS_CONTROL_TOOL = "access_control_sweep"   # IDOR / privesc across identities
COLLABORATOR_TOOL = "collaborator_poll"        # OOB DNS/HTTP/SMTP interactions
SCANNER_ISSUES_TOOL = "scanner_get_all_issues"  # Burp scanner's existing findings


def burp_hunt_plan(target: str, *, server: str = "burp",
                   identities: Optional[list] = None,
                   access_control: bool = True, collaborator: bool = True,
                   scanner_issues: bool = True) -> List[dict]:
    """Build an mcp_plan (list of {server, tool, arguments, url}) that a hunt runs
    against the external Burp MCP. `identities` (two+ authenticated sessions the
    OPERATOR configured — VIPER never creates accounts) enables the true cross-user
    access-control sweep; without them the sweep still runs anon/self checks."""
    plan: List[dict] = []
    if access_control:
        args: dict = {"url": target}
        if identities:
            args["identities"] = identities        # operator-supplied sessions
        plan.append({"server": server, "tool": ACCESS_CONTROL_TOOL,
                     "arguments": args, "url": target})
    if scanner_issues:
        plan.append({"server": server, "tool": SCANNER_ISSUES_TOOL,
                     "arguments": {"severity": "low"}, "url": target})
    if collaborator:
        plan.append({"server": server, "tool": COLLABORATOR_TOOL,
                     "arguments": {}, "url": target})
    return plan


def merge_plan(base: Optional[list], extra: Optional[list]) -> Optional[list]:
    """Merge an existing --mcp-plan with the Burp preset (preset appended)."""
    out = list(base) if base else []
    out.extend(extra or [])
    return out or None
