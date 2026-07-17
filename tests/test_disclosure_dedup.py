"""Public-disclosure dedup: a finding matching the program's already-disclosed issues is
TAGGED likely_duplicate (never dropped) and sorted below novel findings. Read-only/offline,
no gate impact."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.disclosure_dedup import DisclosureCache  # noqa: E402
from core.prioritization import priority_score      # noqa: E402


def test_matches_by_exact_and_loose_signature():
    cache = DisclosureCache([
        {"vuln_type": "xss", "url": "https://app.example/search", "parameter": "q",
         "title": "H1 #123 reflected XSS in search"},
        {"class": "idor", "url": "https://app.example/api/users/1"},   # `class` alias, no param
    ])
    # exact (class|host|path|param)
    assert cache.match({"vuln_type": "xss:q", "url": "https://app.example/search?q=x",
                        "parameter": "q"})
    # loose (class|host|path) — a disclosure named the endpoint, not the exact param
    assert cache.match({"vuln_type": "idor", "url": "https://app.example/api/users/1"})
    # object-id normalization: /api/users/2 collapses to the same {id} path -> match
    assert cache.match({"vuln_type": "idor", "url": "https://app.example/api/users/2"})


def test_non_matching_finding_not_flagged():
    cache = DisclosureCache([{"vuln_type": "xss", "url": "https://app.example/search"}])
    # different class, different host, different path -> no match
    assert cache.match({"vuln_type": "sqli", "url": "https://app.example/search"}) is None
    assert cache.match({"vuln_type": "xss", "url": "https://other.example/search"}) is None
    assert cache.match({"vuln_type": "xss", "url": "https://app.example/login"}) is None


def test_annotate_tags_and_counts():
    cache = DisclosureCache([{"vuln_type": "cors", "url": "https://app.example/api"}])
    fs = [
        {"vuln_type": "cors", "url": "https://app.example/api", "submittable": True},
        {"vuln_type": "sqli", "url": "https://app.example/x", "submittable": True},
    ]
    assert cache.annotate(fs) == 1
    assert fs[0].get("likely_duplicate") is True and "public disclosure" in fs[0]["duplicate_reason"]
    assert not fs[1].get("likely_duplicate")


def test_likely_duplicate_sorts_below_novel_finding():
    novel = {"vuln_type": "cors", "url": "https://app.example/a", "severity": "high",
             "submittable": True, "validation_confidence": 0.85}
    dup = {**novel, "url": "https://app.example/b", "likely_duplicate": True}
    assert priority_score(novel) > priority_score(dup)


def test_missing_or_empty_cache_is_noop(tmp_path):
    assert DisclosureCache.from_file(tmp_path / "nope.json").size == 0
    assert DisclosureCache([]).annotate([{"vuln_type": "xss", "url": "http://x/y"}]) == 0


def test_from_file_roundtrip(tmp_path):
    p = tmp_path / "disc.json"
    p.write_text(json.dumps({"disclosures": [
        {"vuln_type": "open_redirect", "url": "https://app.example/go", "parameter": "next",
         "title": "known open redirect"}]}), encoding="utf-8")
    cache = DisclosureCache.from_file(p)
    assert cache.size == 1
    assert cache.match({"vuln_type": "open_redirect", "url": "https://app.example/go?next=x",
                        "parameter": "next"}) == "known open redirect"
