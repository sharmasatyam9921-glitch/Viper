"""The gate holds precision 1.00 across confidence thresholds AND benign response
perturbations — not just at the default snapshot."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.gate_mutations import (  # noqa: E402
    CONF_GRID, PERTURBATIONS, find_leaks, format_report,
)
from core.gate_benchmark import BENCHMARK, HttpResp  # noqa: E402


def test_no_safe_responder_leaks_across_thresholds_and_perturbations():
    leaks = find_leaks()
    assert leaks == [], format_report(leaks)


def test_grid_actually_spans_below_and_above_default():
    assert min(CONF_GRID) < 0.5 < max(CONF_GRID)
    assert "identity" in PERTURBATIONS and len(PERTURBATIONS) >= 2


def test_harness_would_catch_a_planted_leak():
    # Sanity: a deliberately-leaky SAFE scenario (a responder that reproduces a real
    # open redirect but is mislabeled 'safe') MUST be reported — proving the harness
    # can fail, not just pass.
    from core.gate_benchmark import Scenario

    def _leaky(m, url, h):
        from urllib.parse import urlsplit, parse_qs
        v = next((x[0] for x in parse_qs(urlsplit(url).query).values() if x), "")
        return HttpResp(302, {"location": v}, "", url)   # parameter-driven redirect

    planted = Scenario("open_redirect", "safe", "planted leak",
                       {"vuln_type": "open_redirect:next",
                        "url": "http://t/r?next=x", "parameter": "next"}, _leaky)
    leaks = find_leaks([planted])
    assert leaks, "harness failed to catch a planted safe->submittable leak"


def test_all_benchmark_safes_are_covered():
    # Every safe scenario is exercised (guards against silently skipping classes).
    n_safe = sum(1 for s in BENCHMARK if s.label == "safe")
    assert n_safe >= 30
