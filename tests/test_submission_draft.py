"""Submission-draft generator for gate-confirmed findings."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.submission_draft import _DEFAULT, _meta, build_submission, write_drafts  # noqa: E402


def test_confirmed_classes_have_accurate_cvss_not_the_generic_default():
    # Every gate-confirmable class must map to a real CWE/CVSS, never the CWE-Other
    # fallback — a submission draft with the wrong severity is worse than none.
    expected = {
        "ssrf:url": "CWE-918", "nosql_injection:login": "CWE-943",
        "jwt:weak_key": "CWE-347", "jwt:alg_confusion": "CWE-347",
        "graphql_introspection:/graphql": "CWE-200", "graphql_ide:/graphql": "CWE-200",
        "xxe:file_read": "CWE-611", "crlf_header_injection": "CWE-93",
        "secrets:sourcemap": "CWE-798", "open_redirect:next": "CWE-601",
    }
    for vt, cwe in expected.items():
        meta = _meta(vt)
        assert meta is not _DEFAULT, f"{vt} fell through to the generic default"
        assert meta[0] == cwe, f"{vt} -> {meta[0]} (expected {cwe})"
        assert meta[2].startswith("AV:")           # a real CVSS 3.1 vector


def test_ssrf_draft_renders_accurate_vector():
    md = build_submission({"vuln_type": "ssrf:url", "url": "http://t/f?url=x",
                           "submittable": True, "severity": "high"}, "http://t")
    assert "CWE-918" in md and "CVSS:3.1/AV:N" in md and "CWE-Other" not in md


def test_sqli_draft_has_required_sections():
    f = {"vuln_type": "sqli:q", "url": "http://t/s?q=1", "parameter": "q",
         "evidence": "DB error under quote", "validation_reason": "DB error under ' and \"",
         "validation_confidence": 0.75}
    md = build_submission(f, "http://t")
    for section in ("# SQL Injection", "CVSS 3.1", "CWE-89",
                    "## Steps to Reproduce", "## Impact", "## Remediation",
                    "validation gate"):
        assert section in md, section
    assert "Critical" in md  # 9.8 -> critical


def test_bola_draft_two_account_repro():
    f = {"vuln_type": "idor:bola:/api/orders/1", "url": "http://t/api/orders/1",
         "submittable": True, "evidence": "B read A's marker"}
    md = build_submission(f)
    assert "CWE-639" in md
    assert "user A" in md and "user B" in md  # two-account reproduction


def test_xss_draft_severity_and_cwe():
    md = build_submission({"vuln_type": "xss_text:q", "url": "http://t/s?q=x",
                           "parameter": "q"})
    assert "CWE-79" in md and "Medium" in md  # 6.1 -> medium


def test_write_drafts_only_submittable(tmp_path):
    findings = [
        {"vuln_type": "sqli:q", "url": "http://t/s?q=1", "parameter": "q",
         "submittable": True},
        {"vuln_type": "clickjacking", "url": "http://t/", "submittable": False},
    ]
    paths = write_drafts(findings, tmp_path, target="http://t")
    assert len(paths) == 1                       # only the submittable one
    assert paths[0].exists()
    assert "sqli" in paths[0].name
    assert "SQL Injection" in paths[0].read_text(encoding="utf-8")


def test_unknown_class_uses_default_meta():
    md = build_submission({"vuln_type": "weird_thing", "url": "http://t/x"})
    assert "CWE-Other" in md and "## Remediation" in md  # never crashes
