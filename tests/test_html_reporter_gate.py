"""The HTML report surfaces the validation gate's submittable vs lead split."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.html_reporter import _build_findings  # noqa: E402


def _findings():
    return [
        {"vuln_type": "clickjacking", "severity": "low", "url": "http://t/",
         "submittable": False, "validation_reason": "no independent re-test"},
        {"vuln_type": "sqli:q", "severity": "high", "url": "http://t/s?q=1",
         "submittable": True, "validation_confidence": 0.75,
         "validation_reason": "DB error under ' and \" breakers, not benign"},
    ]


def test_submittable_badge_and_count():
    html = _build_findings(_findings())
    assert "SUBMITTABLE" in html
    assert "1 SUBMITTABLE" in html          # header count
    assert "lead(s) need manual review" in html


def test_submittable_sorted_first():
    html = _build_findings(_findings())
    assert html.index("sqli:q") < html.index("clickjacking")


def test_gate_verdict_row_present():
    html = _build_findings(_findings())
    assert "Validation gate" in html
    assert "PASS" in html and "LEAD" in html


def test_no_submittable_no_count_banner():
    html = _build_findings([
        {"vuln_type": "cors_wildcard", "severity": "medium", "url": "http://t/",
         "submittable": False}])
    assert "SUBMITTABLE" not in html  # no green banner when nothing passed
    assert "lead (manual review)" in html
