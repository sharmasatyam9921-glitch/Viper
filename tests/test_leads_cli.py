"""`viper.py leads` groups non-submittable findings by gate-failure reason."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.ops_cli import (  # noqa: E402
    _lead_reason_bucket, _load_findings_for_leads, run_leads_cli,
)


def _write(tmp_path, findings):
    p = tmp_path / "f.json"
    p.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return str(p)


def test_reason_bucket_collapses_url_and_number_specifics():
    a = _lead_reason_bucket("redirect target https://t/a?x=1 absent under control (conf 0.2)")
    b = _lead_reason_bucket("redirect target https://t/b?y=9 absent under control (conf 0.7)")
    assert a == b and "<url>" in a


def test_unvalidated_reason_gets_a_bucket():
    assert _lead_reason_bucket("") == "not gate-evaluated"
    assert _lead_reason_bucket(None) == "not gate-evaluated"


def test_loader_accepts_envelope_and_bare_list(tmp_path):
    env = tmp_path / "env.json"
    env.write_text(json.dumps({"findings": [{"a": 1}]}), encoding="utf-8")
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps([{"b": 2}]), encoding="utf-8")
    assert _load_findings_for_leads(str(env)) == [{"a": 1}]
    assert _load_findings_for_leads(str(bare)) == [{"b": 2}]
    assert _load_findings_for_leads(str(tmp_path / "missing.json")) == []


def test_leads_grouped_and_counted(tmp_path, capsys):
    findings = [
        {"vuln_type": "cors_origin_reflect", "url": "http://t/a", "submittable": False,
         "validation_reason": "arbitrary origin not reflected (no real CORS bug)",
         "validation_confidence": 0.2},
        {"vuln_type": "cors_origin_reflect", "url": "http://t/b", "submittable": False,
         "validation_reason": "arbitrary origin not reflected (no real CORS bug)",
         "validation_confidence": 0.2},
        {"vuln_type": "idor:user", "url": "http://t/u/5", "submittable": False,
         "validation_reason": "single-session IDOR candidate - supply two sessions"},
        {"vuln_type": "xss_text:q", "url": "http://t/s", "submittable": True,
         "validation_reason": "live markup"},
    ]
    rc = run_leads_cli([_write(tmp_path, findings)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "4 finding(s): 1 submittable, 3 lead(s)" in out
    assert "[  2]" in out                       # the two CORS leads grouped
    assert "single-session IDOR" in out
    assert "http://t/s" not in out              # the submittable one is not a lead


def test_no_findings_is_graceful(tmp_path, capsys):
    rc = run_leads_cli([str(tmp_path / "missing.json")])
    assert rc == 0 and "no findings" in capsys.readouterr().out


def test_all_submittable_reports_no_leads(tmp_path, capsys):
    rc = run_leads_cli([_write(tmp_path, [{"vuln_type": "xss", "submittable": True}])])
    assert rc == 0 and "no leads" in capsys.readouterr().out
