"""Burp MCP preset: builds a valid gate-filtered mcp_plan the hunt can consume."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.mcp.burp_preset import (  # noqa: E402
    ACCESS_CONTROL_TOOL, COLLABORATOR_TOOL, SCANNER_ISSUES_TOOL,
    burp_hunt_plan, merge_plan,
)
from core.mcp_tool_bridge import collect_mcp_findings  # noqa: E402

_TARGET = "http://target.example"


def _valid_entry(e: dict) -> bool:
    return (isinstance(e, dict) and isinstance(e.get("server"), str)
            and isinstance(e.get("tool"), str)
            and isinstance(e.get("arguments"), dict)
            and isinstance(e.get("url"), str))


def test_plan_entries_are_valid_and_cover_the_three_tools():
    plan = burp_hunt_plan(_TARGET)
    assert plan and all(_valid_entry(e) for e in plan)
    tools = {e["tool"] for e in plan}
    assert tools == {ACCESS_CONTROL_TOOL, SCANNER_ISSUES_TOOL, COLLABORATOR_TOOL}
    assert all(e["server"] == "burp" and e["url"] == _TARGET for e in plan)


def test_identities_arm_the_access_control_sweep():
    ids = [{"name": "A", "headers": {"Cookie": "a=1"}},
           {"name": "B", "headers": {"Cookie": "b=2"}}]
    plan = burp_hunt_plan(_TARGET, identities=ids)
    ac = next(e for e in plan if e["tool"] == ACCESS_CONTROL_TOOL)
    assert ac["arguments"]["identities"] == ids
    # without identities the sweep still runs, just no identities key
    ac2 = next(e for e in burp_hunt_plan(_TARGET) if e["tool"] == ACCESS_CONTROL_TOOL)
    assert "identities" not in ac2["arguments"]


def test_toggles_and_custom_server():
    plan = burp_hunt_plan(_TARGET, server="burp2", collaborator=False,
                          scanner_issues=False)
    assert [e["tool"] for e in plan] == [ACCESS_CONTROL_TOOL]
    assert plan[0]["server"] == "burp2"


def test_merge_appends_preset_after_existing_plan():
    base = [{"server": "x", "tool": "t", "arguments": {}, "url": _TARGET}]
    merged = merge_plan(base, burp_hunt_plan(_TARGET))
    assert merged[0]["tool"] == "t"                 # existing kept first
    assert {e["tool"] for e in merged[1:]} == {
        ACCESS_CONTROL_TOOL, SCANNER_ISSUES_TOOL, COLLABORATOR_TOOL}
    assert merge_plan(None, None) is None
    assert merge_plan(None, []) is None


class _FakeRegistry:
    """Mimics MCPRegistry.call: returns a Burp-style issue array as {text,...}."""

    def __init__(self):
        self.calls = []

    def call(self, server, tool, arguments):
        self.calls.append((server, tool, arguments))
        if tool == ACCESS_CONTROL_TOOL:
            issues = [{"vuln_type": "idor", "severity": "high",
                       "confidence": 0.95,  # Burp is "sure" — gate must still cap it
                       "url": _TARGET + "/api/orders/7", "title": "IDOR on order id"}]
        elif tool == SCANNER_ISSUES_TOOL:
            issues = [{"type": "xss", "severity": "medium",
                       "url": _TARGET + "/search", "title": "Reflected XSS"}]
        else:  # collaborator poll: no interactions this run
            issues = []
        return {"text": json.dumps(issues), "is_error": False, "raw": {}}


def test_plan_runs_through_the_gate_bridge_as_capped_external_leads():
    reg = _FakeRegistry()
    plan = burp_hunt_plan(_TARGET)
    findings = asyncio.run(collect_mcp_findings(reg, plan, default_url=_TARGET))
    # both non-empty tools produced a finding; collaborator (empty) produced none
    assert len(findings) == 2
    assert {c[1] for c in reg.calls} == {
        ACCESS_CONTROL_TOOL, SCANNER_ISSUES_TOOL, COLLABORATOR_TOOL}
    for f in findings:
        assert f["source"].startswith("mcp:burp:")     # provenance stamped
        assert f["confidence"] <= 0.5                   # external cap enforced
        assert f["needs_manual_verification"] is True   # never trusted raw
