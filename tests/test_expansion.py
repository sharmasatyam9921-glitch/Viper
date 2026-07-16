"""Finding-driven targeted expansion (the 'mythos-like' next-probe brain)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.expansion import expand, plan_expansions  # noqa: E402


def test_ssrf_escalates_to_ssrf_pivot():
    t = expand({"vuln_type": "ssrf:confirmed", "url": "http://t/fetch?u=1", "severity": "high"})
    assert t and t.techniques == ["ssrf"] and not t.new_host


def test_lfi_reaches_for_config():
    t = expand({"vuln_type": "lfi", "url": "http://t/p?f=x"})
    assert t and t.techniques == ["lfi"]


def test_open_redirect_chases_oauth_and_host_header():
    t = expand({"vuln_type": "open_redirect", "url": "http://t/r?to=x"})
    assert t and t.techniques == ["open_redirect", "host_header"]


def test_discovered_endpoint_gets_broad_probe():
    t = expand({"type": "endpoint", "url": "http://t/api/v1/users?id=1"})
    assert t and "sqli" in t.techniques and "xss" in t.techniques


def test_new_subdomain_triggers_full_sweep_on_origin():
    t = expand({"type": "subdomain", "url": "https://admin.t.com/login?next=/"})
    assert t and t.new_host
    assert t.target == "https://admin.t.com"          # stripped to origin


def test_terminal_secret_is_not_auto_chained():
    assert expand({"vuln_type": "secret:aws", "url": "http://t/.env"}) is None
    assert expand({"vuln_type": "subdomain_takeover", "url": "http://t/"}) is None


def test_non_http_and_urlless_and_fp_yield_nothing():
    assert expand({"vuln_type": "ssrf", "url": "ftp://t/x"}) is None
    assert expand({"vuln_type": "ssrf"}) is None
    assert expand({"vuln_type": "ssrf", "url": "http://t/", "false_positive": True}) is None
    assert expand({"vuln_type": "technology", "url": "http://t/"}) is None   # empty techs


def test_plan_expansions_dedupes_by_target_and_techniques():
    findings = [
        {"vuln_type": "lfi", "url": "http://t/p?f=1"},
        {"vuln_type": "lfi", "url": "http://t/p?f=1"},      # dup -> dropped
        {"vuln_type": "sqli", "url": "http://t/p?f=1"},     # same url, diff tech -> kept
    ]
    tasks = plan_expansions(findings)
    assert len(tasks) == 2


def test_plan_expansions_respects_max_tasks():
    findings = [{"vuln_type": "lfi", "url": f"http://t/{i}?f=1"} for i in range(50)]
    assert len(plan_expansions(findings, max_tasks=5)) == 5


# ── #7(b) soft-signal pivots ─────────────────────────────────────────────────
def test_filtered_reflection_pivots_to_sibling_injection_classes():
    # A param reflected as text (tags filtered) is a proven-hot injection point:
    # re-fire SIBLING classes on that exact URL, not xss again (which would dedup).
    t = expand({"vuln_type": "xss_text:q", "type": "xss_reflection",
                "url": "http://t/s?q=x"})
    assert t is not None
    assert t.target == "http://t/s?q=x"
    assert set(t.techniques) == {"ssti", "sqli", "lfi", "command_injection"}
    assert "xss" not in t.techniques        # not the class that produced the soft signal


def test_xss_tag_and_blind_sqli_pivot():
    assert set(expand({"vuln_type": "xss_tag:q", "url": "http://t/s?q=x"}).techniques) \
        == {"ssti", "sqli"}
    assert expand({"vuln_type": "sqli_blind:id", "url": "http://t/a?id=1"}).techniques == ["sqli"]


def test_confirmed_classes_unaffected():
    # A confirmed reflected XSS is not a soft signal — behavior unchanged (no pivot).
    assert expand({"vuln_type": "xss:q", "url": "http://t/s?q=x"}) is None
