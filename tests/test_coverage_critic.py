"""Completeness critic — coverage-gap reflection."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.coverage_critic import CANON_CLASSES, critique, gaps_to_targets  # noqa: E402


def test_unswept_host_gap():
    findings = [
        {"type": "subdomain", "url": "https://admin.t.com/"},
        {"vuln_type": "xss", "url": "https://www.t.com/q?s=1"},   # www probed, admin not
    ]
    gaps = critique(findings)
    kinds = {(g.kind, g.detail) for g in gaps}
    assert ("unswept_host", "https://admin.t.com") in kinds


def test_probed_host_not_flagged():
    findings = [
        {"type": "subdomain", "url": "https://admin.t.com/"},
        {"vuln_type": "sqli", "url": "https://admin.t.com/login?u=1"},   # admin WAS probed
    ]
    assert not any(g.kind == "unswept_host" for g in critique(findings))


def test_untested_param_endpoint_gap():
    findings = [
        {"type": "endpoint", "url": "https://t.com/api?id=1"},          # no finding on it
        {"type": "endpoint", "url": "https://t.com/safe?q=2"},
        {"vuln_type": "sqli", "url": "https://t.com/safe?q=2"},          # this one was hit
    ]
    gaps = critique(findings)
    untested = {g.detail for g in gaps if g.kind == "untested_params"}
    assert "https://t.com/api?id=1" in untested
    assert "https://t.com/safe?q=2" not in untested


def test_class_not_run_only_when_ran_known():
    findings = [{"vuln_type": "sqli", "url": "https://t.com/x?a=1"}]
    # no ran_techniques -> we don't guess about classes
    assert not any(g.kind == "class_not_run" for g in critique(findings))
    # told ssrf+sqli ran -> every other canon class is flagged
    gaps = critique(findings, ran_techniques={"sqli", "ssrf"})
    not_run = {g.detail for g in gaps if g.kind == "class_not_run"}
    assert "xxe" in not_run and "sqli" not in not_run and "ssrf" not in not_run
    assert not_run == (CANON_CLASSES - {"sqli", "ssrf"})


def test_gaps_to_targets_extracts_urls():
    findings = [{"type": "subdomain", "url": "https://admin.t.com/"},
                {"type": "endpoint", "url": "https://t.com/api?id=1"}]
    targets = gaps_to_targets(critique(findings))
    assert "https://admin.t.com" in targets and "https://t.com/api?id=1" in targets


def test_empty_input_no_gaps():
    assert critique([]) == []
