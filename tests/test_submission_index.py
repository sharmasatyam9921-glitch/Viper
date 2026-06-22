"""write_drafts also emits a prioritized INDEX.md triage page."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.submission_draft import write_drafts  # noqa: E402


def test_write_drafts_creates_prioritized_index(tmp_path):
    findings = [
        {"vuln_type": "clickjacking", "severity": "low", "submittable": True,
         "validation_confidence": 0.5, "url": "http://t/"},
        {"vuln_type": "sqli:id", "severity": "critical", "submittable": True,
         "validation_confidence": 0.9, "url": "http://t/x?id=1", "parameter": "id"},
        {"vuln_type": "xss:q", "severity": "medium", "submittable": False},  # lead
    ]
    paths = write_drafts(findings, tmp_path, target="http://t/")
    assert len(paths) == 2                              # only submittable drafted
    idx = (tmp_path / "INDEX.md").read_text(encoding="utf-8")
    assert "Submission index" in idx and "2 submittable" in idx
    # priority-sorted: critical SQLi above low clickjacking
    assert idx.index("sqli:id") < idx.index("clickjacking")
    assert "xss:q" not in idx                           # the lead is excluded
    # links to the per-finding drafts
    assert any(p.name in idx for p in paths)


def test_no_index_when_nothing_submittable(tmp_path):
    write_drafts([{"vuln_type": "xss:q", "submittable": False}], tmp_path)
    assert not (tmp_path / "INDEX.md").exists()
