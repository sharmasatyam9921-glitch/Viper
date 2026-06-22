"""XBOW benchmark runner — config parsing, tag->class, dual scoring (no Docker)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.xbow_runner import (  # noqa: E402
    BenchmarkSpec,
    load_config,
    run_benchmark,
    score_findings,
    summarize,
)


def _write_bench(tmp_path, tags, win="flag"):
    bd = tmp_path / "XBEN-001"
    (bd / "benchmark").mkdir(parents=True)
    (bd / "benchmark" / "benchmark-config.json").write_text(json.dumps({
        "name": "Reflected XSS in search", "level": 1, "win_condition": win,
        "tags": tags, "canaries": ["CANARY123"]}), encoding="utf-8")
    return str(bd)


def test_load_config_and_expected_classes(tmp_path):
    spec = load_config(_write_bench(tmp_path, ["reflected-xss", "client-side"]))
    assert spec.name == "Reflected XSS in search" and spec.level == 1
    assert spec.expected_classes == {"xss"}            # unknown tag dropped


def test_tag_mapping_covers_core_classes(tmp_path):
    spec = load_config(_write_bench(tmp_path, ["sql-injection", "idor", "path-traversal"]))
    assert spec.expected_classes == {"sqli", "idor", "lfi"}


def test_score_detection_on_class_match():
    spec = BenchmarkSpec("t", 1, "flag", ["sql-injection"])
    confirmed = [{"vuln_type": "sqli:error", "evidence": "DB error"}]
    r = score_findings(spec, confirmed)
    assert r.detected and r.matched_classes == {"sqli"} and not r.flag_captured


def test_score_no_detection_on_class_mismatch():
    spec = BenchmarkSpec("t", 1, "flag", ["xss"])
    r = score_findings(spec, [{"vuln_type": "sqli", "evidence": "x"}])
    assert not r.detected and r.matched_classes == set()


def test_flag_capture_separate_from_detection():
    spec = BenchmarkSpec("t", 1, "flag", ["lfi"])
    confirmed = [{"vuln_type": "lfi", "evidence": "read /etc/passwd FLAG{abc123}"}]
    r = score_findings(spec, confirmed, flag="FLAG{abc123}")
    assert r.detected and r.flag_captured


def test_run_benchmark_without_docker_uses_injected_hunt(tmp_path):
    # bring_up=False skips Docker entirely; hunt_fn supplies findings
    bd = _write_bench(tmp_path, ["reflected-xss"])
    seen = {}

    def hunt(url, classes):
        seen["classes"] = classes                       # runner passes scoped classes
        return [{"vuln_type": "xss", "evidence": "reflected"}]
    r = run_benchmark(bd, hunt, bring_up=False)
    assert r.detected and r.matched_classes == {"xss"}
    assert seen["classes"] == {"xss"}                   # scoped to the benchmark's tags


def test_summarize_counts(tmp_path):
    spec = BenchmarkSpec("a", 1, "flag", ["xss"])
    results = [score_findings(spec, [{"vuln_type": "xss", "evidence": "x"}]),
               score_findings(spec, [{"vuln_type": "sqli", "evidence": "y"}])]
    out = summarize(results)
    assert "detected (vuln confirmed):  1/2" in out
