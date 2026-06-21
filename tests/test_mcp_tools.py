"""Consume an external MCP tool -> normalize -> VIPER's gate filters the output."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.mcp.config import add_server, load_servers, remove_server  # noqa: E402
from core.mcp.registry import MCPRegistry  # noqa: E402
from core.mcp_tool_bridge import call_to_findings, normalize_tool_result  # noqa: E402
from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402

_ROOT = str(Path(__file__).resolve().parents[1])


# --- config round-trip -----------------------------------------------------

def test_config_round_trip(tmp_path):
    cfg = tmp_path / "mcp_servers.json"
    add_server("arsenal", ["python", "-m", "x"], cwd="/opt/x", path=cfg)
    add_server("scanner", ["node", "s.js"], path=cfg)
    loaded = load_servers(cfg)
    assert loaded["arsenal"]["command"] == ["python", "-m", "x"]
    assert loaded["arsenal"]["cwd"] == "/opt/x"
    assert loaded["scanner"]["command"] == ["node", "s.js"]
    assert remove_server("scanner", path=cfg) and "scanner" not in load_servers(cfg)


def test_load_servers_tolerates_missing_and_bad(tmp_path):
    assert load_servers(tmp_path / "nope.json") == {}
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    assert load_servers(tmp_path / "bad.json") == {}


# --- normalization ---------------------------------------------------------

def test_normalize_findings_array_caps_confidence():
    res = {"is_error": False, "text":
           '{"findings":[{"vuln_type":"sqli:id","url":"http://t/x?id=1",'
           '"parameter":"id","severity":"high","confidence":0.99}]}'}
    out = normalize_tool_result("arsenal", "scan", res)
    assert len(out) == 1
    f = out[0]
    assert f["vuln_type"] == "sqli:id" and f["confidence"] == 0.5    # capped
    assert f["source"] == "mcp:arsenal:scan" and f["needs_manual_verification"]


def test_normalize_ignores_errors_and_unstructured():
    assert normalize_tool_result("a", "t", {"is_error": True, "text": "x"}) == []
    assert normalize_tool_result("a", "t", {"is_error": False, "text": "just prose"}) == []
    assert normalize_tool_result("a", "t", {}) == []


# --- end-to-end: external tool -> gate filters -----------------------------

def _scan_server_cmd():
    # an MCP server whose "scan" tool reports TWO issues: a real SQLi and a bogus
    # XSS. VIPER's gate should confirm only the one its own probe reproduces.
    code = "\n".join([
        "import sys",
        "sys.path.insert(0, %r)" % _ROOT,
        "from core.mcp.server import MCPServer",
        "s = MCPServer('scanner')",
        "def scan(a):",
        "    return {'findings': [",
        "      {'vuln_type':'sqli:id','url':'http://t/x?id=1','parameter':'id','severity':'high','confidence':0.95},",
        "      {'vuln_type':'xss_text:q','url':'http://t/s?q=1','parameter':'q','severity':'high','confidence':0.95}]}",
        "s.tool('scan','run a scan')(scan)",
        "s.run_stdio()",
    ])
    return [sys.executable, "-c", code]


async def _gate_fetch(method, url, *, headers=None, timeout=10.0):
    from urllib.parse import urlsplit, parse_qs
    q = parse_qs(urlsplit(url).query)
    val = next((v[0] for v in q.values() if v), "")
    # confirm SQLi (unbalanced quote -> 500 DB error); XSS stays inert (no markup)
    if val.count("'") % 2 == 1:
        return HttpResp(500, {}, "You have an error in your SQL syntax near", url)
    return HttpResp(200, {}, "ok", url)


def test_external_scanner_output_is_filtered_by_the_gate():
    reg = MCPRegistry(servers={"scanner": _scan_server_cmd()}, cwd=_ROOT, timeout=30)
    try:
        candidates = call_to_findings(reg, "scanner", "scan")
    finally:
        reg.close_all()
    # the external tool reported two issues, both as leads (capped)
    assert len(candidates) == 2 and all(c["confidence"] <= 0.5 for c in candidates)
    assert all(c["source"] == "mcp:scanner:scan" for c in candidates)

    # VIPER's gate independently re-tests them: only the real SQLi is submittable
    validated = asyncio.run(validate_findings(candidates, fetch=_gate_fetch))
    sub = [f for f in validated if f["submittable"]]
    assert len(sub) == 1 and sub[0]["vuln_type"] == "sqli:id"
    leads = [f for f in validated if not f["submittable"]]
    assert any(f["vuln_type"] == "xss_text:q" for f in leads)   # bogus XSS filtered out


def test_registry_from_config_merges_external(tmp_path):
    cfg = tmp_path / "mcp_servers.json"
    add_server("arsenal", [sys.executable, "-c", "pass"], path=cfg)
    reg = MCPRegistry.from_config(config_path=cfg, cwd=_ROOT)
    try:
        assert "arsenal" in reg.server_names          # external merged in
        assert "mitre" in reg.server_names            # defaults still present
    finally:
        reg.close_all()
