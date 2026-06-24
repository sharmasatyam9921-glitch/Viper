"""Dashboard operator API — the bug-bounty control-panel backend functions."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dashboard import operator_api as op  # noqa: E402


def test_scorecard_shape_and_zero_fp():
    sc = op.get_scorecard()
    assert "error" not in sc
    assert sc["overall"]["fp"] == 0 and sc["overall"]["precision"] == 1.0
    assert all("precision" in c and "fp" in c for c in sc["classes"])


def test_classes_flags():
    cl = op.get_classes()
    assert cl["count"] > 0
    xss = [c for c in cl["classes"] if c["technique"] == "xss_probe"]
    assert xss and isinstance(xss[0]["gate_confirmed"], bool)


def test_scope_show_when_absent_is_graceful(tmp_path, monkeypatch):
    monkeypatch.setattr(op, "_ROOT", tmp_path)        # no scopes/ dir
    s = op.get_scope()
    assert s["loaded"] is False and "hint" in s


def test_coverage_and_paths_accept_explicit_findings():
    cov = op.get_coverage(findings=[{"type": "subdomain", "url": "https://a.t/"}])
    assert "gaps" in cov and any(g["kind"] == "unswept_host" for g in cov["gaps"])
    paths = op.get_attack_paths(findings=[{"vuln_type": "rce", "submittable": True,
                                           "url": "http://t/x", "title": "rce"}])
    assert paths["paths"] and paths["paths"][0]["goal"] == "rce"


def test_verify_requires_findings_and_runs_gate():
    assert op.verify_findings({})["ok"] is False                  # no findings
    r = op.verify_findings({"findings": [{"vuln_type": "xss", "url": "http://127.0.0.1:1/",
                                          "parameter": "q"}]})
    assert r["ok"] and r["total"] == 1 and r["submittable"] == 0  # unreachable -> lead


def test_modes_and_compliance():
    m = op.get_modes()
    ids = {x["id"] for x in m["modes"]}
    assert ids == {"bugbounty", "pentest", "ctf"}
    assert m["platforms"]["hackerone"]["auto_pull"] is True
    assert m["platforms"]["bugcrowd"]["auto_pull"] is True       # now wired
    assert m["platforms"]["yeswehack"]["auto_pull"] is False     # not yet
    fw = {f["id"] for f in op.get_compliance()["frameworks"]}
    assert {"owasp", "pci_dss", "nist", "hipaa", "soc2"} <= fw
    # the pentest mode runs the full kill-chain
    assert next(x for x in m["modes"] if x["id"] == "pentest")["go"] is True


def test_scope_pull_bugcrowd_without_token_is_graceful(monkeypatch):
    monkeypatch.delenv("BUGCROWD_API_TOKEN", raising=False)
    r = op.scope_pull({"handle": "demo", "platform": "bugcrowd"})
    assert r["ok"] is False and "BUGCROWD_API_TOKEN" in r["error"]


def test_scope_pull_unsupported_platform_is_graceful():
    r = op.scope_pull({"handle": "demo", "platform": "synack"})
    assert r["ok"] is False and "isn't wired yet" in r["error"]


def test_compliance_report_maps_and_filters():
    finds = [{"vuln_type": "xss", "cwe": "CWE-79", "url": "http://t/x"}]
    rep = op.compliance_report({"findings": finds})
    assert rep["ok"] and rep["finding_count"] == 1
    ids = {f["id"] for f in rep["frameworks"]}
    assert {"owasp", "pci_dss", "nist", "hipaa"} <= ids          # CWE-79 mapping
    # framework filter narrows the result
    only = op.compliance_report({"findings": finds, "frameworks": ["owasp"]})
    assert {f["id"] for f in only["frameworks"]} == {"owasp"}
    assert only["frameworks"][0]["controls"]                     # has a control ref


def test_scope_pull_without_creds_is_graceful(monkeypatch):
    monkeypatch.delenv("HACKERONE_API_USERNAME", raising=False)
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    monkeypatch.setattr(op, "_ROOT", Path("/nonexistent-root-xyz"))  # no creds file
    r = op.scope_pull({"handle": "demo"})
    assert r["ok"] is False and "token" in r["error"].lower()


def test_scope_import_csv(tmp_path, monkeypatch):
    monkeypatch.setattr(op, "_ROOT", tmp_path)
    csv = tmp_path / "s.csv"
    csv.write_text("identifier,asset_type,instruction,eligible_for_bounty,"
                   "eligible_for_submission,max_severity\n"
                   "*.demo.test,WILDCARD,,true,true,critical\n", encoding="utf-8")
    r = op.scope_import({"path": str(csv)})
    assert r["ok"] and r["in_scope"] == 1
    assert (tmp_path / "scopes" / "current_scope.json").exists()
