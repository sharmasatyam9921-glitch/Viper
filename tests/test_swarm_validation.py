"""Tests for the independent validation gate."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_validation import (  # noqa: E402
    FetchHTTP,
    partition,
    validate_findings,
    validator_key,
)


class _FakeValidator:
    """Records what it was asked to validate and returns scripted verdicts."""
    def __init__(self, verdicts):
        # verdicts: dict keyed by normalized vuln_type -> (ok, conf, reason)
        self.verdicts = verdicts
        self.seen = []

    async def validate(self, finding, target_url):
        self.seen.append((finding.get("vuln_type"), target_url))
        return self.verdicts.get(finding.get("vuln_type"), (False, 0.0, "no verdict"))


def test_vuln_type_normalization():
    assert validator_key("rce:cmdi:id") == "cmdi"
    assert validator_key("xss_text:q") == "xss"
    assert validator_key("idor:bola:/x") == "idor_enum"
    assert validator_key("cors_wildcard") == "cors"
    assert validator_key("auth_bypass:sqli_login") == "sqli"
    assert validator_key("something_unknown") == "generic"


def test_validated_finding_is_submittable():
    findings = [{"vuln_type": "rce:cmdi:id", "url": "http://t/x?id=1"}]
    v = _FakeValidator({"cmdi": (True, 0.9, "confirmed by timing")})
    out = asyncio.run(validate_findings(findings, validator=v, min_confidence=0.5))
    assert out[0]["validated"] is True
    assert out[0]["submittable"] is True
    assert out[0]["validation_confidence"] == 0.9
    # original finding object is not mutated
    assert "validated" not in findings[0]


def test_low_confidence_is_lead_not_submittable():
    findings = [{"vuln_type": "xss_text:q", "url": "http://t/s?q=1"}]
    v = _FakeValidator({"xss": (True, 0.3, "weak reflection")})
    out = asyncio.run(validate_findings(findings, validator=v, min_confidence=0.5))
    assert out[0]["validated"] is True
    assert out[0]["submittable"] is False   # confidence below threshold


def test_unconfirmed_finding_fails_closed():
    findings = [{"vuln_type": "sqli:id", "url": "http://t/x?id=1"}]
    v = _FakeValidator({"sqli": (False, 0.0, "could not reproduce")})
    out = asyncio.run(validate_findings(findings, validator=v))
    assert out[0]["validated"] is False
    assert out[0]["submittable"] is False


def test_validator_exception_fails_closed():
    class _Boom:
        async def validate(self, finding, target_url):
            raise RuntimeError("network down")
    findings = [{"vuln_type": "ssrf:url", "url": "http://t/x"}]
    out = asyncio.run(validate_findings(findings, validator=_Boom()))
    assert out[0]["validated"] is False and out[0]["submittable"] is False
    assert "validation error" in out[0]["validation_reason"]


def test_partition_splits_submittable_and_leads():
    findings = [
        {"vuln_type": "rce:cmdi:id", "url": "http://t/a"},
        {"vuln_type": "xss_text:q", "url": "http://t/b"},
    ]
    v = _FakeValidator({"cmdi": (True, 0.9, "ok"), "xss": (True, 0.2, "weak")})
    out = asyncio.run(validate_findings(findings, validator=v))
    sub, leads = partition(out)
    assert len(sub) == 1 and sub[0]["vuln_type"] == "rce:cmdi:id"
    assert len(leads) == 1 and leads[0]["vuln_type"] == "xss_text:q"


from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def _fetch_returning(responder):
    async def fake(method, url, *, headers=None, timeout=10.0, **kw):
        return responder(method, url, headers or {})
    return fake


def _injected(url):
    from urllib.parse import urlsplit, parse_qs
    q = parse_qs(urlsplit(url).query)
    for v in q.values():
        if v:
            return v[0]
    return ""


def _run1(finding, responder):
    out = asyncio.run(validate_findings([finding], fetch=_fetch_returning(responder)))
    return out[0]


# --- injection-class orthogonal re-tests ---

def test_xss_live_markup_submittable():
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "text/html"},
                        f"<h1>Results for {_injected(url)}</h1>", url)
    f = _run1({"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}, resp)
    assert f["submittable"]


def test_xss_escaped_reflection_is_lead():
    import html
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "text/html"},
                        f"<h1>Results for {html.escape(_injected(url))}</h1>", url)
    f = _run1({"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}, resp)
    assert not f["submittable"]  # correctly-escaped reflection (round-3 FP) stays a lead


def test_sqli_error_under_both_quotes_submittable():
    def resp(m, url, h):
        v = _injected(url)
        if "'" in v or '"' in v:
            return HttpResp(500, {}, "You have an error in your SQL syntax near", url)
        return HttpResp(200, {}, "ok", url)
    f = _run1({"vuln_type": "sqli:id", "url": "http://t/x?id=1", "parameter": "id"}, resp)
    assert f["submittable"]


def test_sqli_corpus_search_is_lead():
    def resp(m, url, h):
        v = _injected(url)
        if v == "1'":  # only this query surfaces a post mentioning the error
            return HttpResp(200, {}, "post: 'error in your SQL syntax' help", url)
        return HttpResp(200, {}, "other posts", url)
    f = _run1({"vuln_type": "sqli:q", "url": "http://t/s?q=1", "parameter": "q"}, resp)
    assert not f["submittable"]  # round-3 corpus-search FP rejected


def test_ssti_fresh_eval_submittable():
    import re as _re2
    def resp(m, url, h):
        v = _injected(url)
        mm = _re2.search(r"(\d+)\*(\d+)", v)
        return HttpResp(200, {}, f"Result: {int(mm.group(1))*int(mm.group(2))}" if mm
                        else f"Result: {v}", url)
    f = _run1({"vuln_type": "ssti", "url": "http://t/x?n=1", "parameter": "n"}, resp)
    assert f["submittable"]


def test_lfi_passwd_under_traversal_submittable():
    def resp(m, url, h):
        v = _injected(url)
        if "etc/passwd" in v and "../" in v:
            return HttpResp(200, {}, "root:x:0:0:root:/root:/bin/bash", url)
        return HttpResp(200, {}, "no such doc", url)
    f = _run1({"vuln_type": "lfi:file", "parameter": "file",
               "url": "http://t/x?file=../../../../etc/passwd"}, resp)
    assert f["submittable"]


def test_lfi_doc_echo_is_lead():
    def resp(m, url, h):
        return HttpResp(200, {}, "root:x:0:0: (from a tutorial)", url)  # leaks for everything
    f = _run1({"vuln_type": "lfi:file", "parameter": "file",
               "url": "http://t/x?file=../../../../etc/passwd"}, resp)
    assert not f["submittable"]  # benign control also leaks -> doc echo


def test_bola_finding_trusted_submittable():
    def resp(m, url, h):
        return HttpResp(200, {}, "x", url)
    f = _run1({"vuln_type": "idor:bola:/api/orders/1", "url": "http://t/api/orders/1"}, resp)
    assert f["submittable"] and f["validation_confidence"] >= 0.8


def test_secrets_shape_specific_submittable():
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "application/javascript"},
                        'var k="AKIAIOSFODNN7EXAMPLE";', url)
    f = _run1({"vuln_type": "secret:aws", "url": "http://t/main.js"}, resp)
    assert f["submittable"]


def test_secrets_generic_match_is_lead():
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "text/html"},
                        "<html>password reset instructions</html>", url)
    f = _run1({"vuln_type": "secret:generic", "url": "http://t/page"}, resp)
    assert not f["submittable"]  # no shape-specific credential -> lead


def test_access_control_anon_sensitive_submittable():
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "application/json"},
                        '[{"id":1,"email":"alice@corp.example","role":"admin"}]', url)
    f = _run1({"vuln_type": "access_control:missing_authorization",
               "url": "http://t/api/Users"}, resp)
    assert f["submittable"]


def test_access_control_forbidden_is_lead():
    def resp(m, url, h):
        return HttpResp(403, {}, "Forbidden", url)
    f = _run1({"vuln_type": "access_control:missing_authorization",
               "url": "http://t/api/Users"}, resp)
    assert not f["submittable"]  # 403 anonymously -> access control works


def test_cmdi_not_reproduced_is_lead():
    # cmdi re-test re-runs the hardened worker against the finding URL (its own
    # fetch, not this fake). An unreachable / non-injectable target won't
    # reproduce -> lead. (Fast: fetches to a bogus host fail immediately.)
    def resp(m, url, h):
        return HttpResp(200, {}, "x", url)
    f = _run1({"vuln_type": "rce:cmdi:id",
               "url": "http://127.0.0.1:9/x?id=1", "parameter": "id"}, resp)
    assert not f["submittable"]


def test_cors_reflecting_arbitrary_origin_is_submittable():
    def resp(method, url, headers):
        return HttpResp(200, {"access-control-allow-origin": headers.get("Origin", ""),
                              "access-control-allow-credentials": "true"}, "{}", url)
    out = asyncio.run(validate_findings(
        [{"vuln_type": "cors_origin_reflect", "url": "http://t/api"}],
        fetch=_fetch_returning(resp)))
    assert out[0]["validated"] and out[0]["submittable"]
    assert out[0]["validation_confidence"] >= 0.9  # credentials=true


def test_cors_not_reflecting_probe_origin_is_lead():
    def resp(method, url, headers):
        return HttpResp(200, {"access-control-allow-origin": "https://trusted.example"}, "{}", url)
    out = asyncio.run(validate_findings(
        [{"vuln_type": "cors_wildcard", "url": "http://t/api"}],
        fetch=_fetch_returning(resp)))
    assert not out[0]["submittable"]


def test_env_exposed_reconfirmed_submittable():
    def resp(method, url, headers):
        return HttpResp(200, {"content-type": "text/plain"},
                        "DB_PASSWORD=s3cret\nAPI_KEY=abc123xyz\n", url)
    out = asyncio.run(validate_findings(
        [{"vuln_type": "env_exposed:/.env", "url": "http://t/.env"}],
        fetch=_fetch_returning(resp)))
    assert out[0]["validated"] and out[0]["submittable"]


def test_env_html_page_is_lead_not_submittable():
    def resp(method, url, headers):
        return HttpResp(200, {"content-type": "text/html"}, "<html>KEY=val here</html>", url)
    out = asyncio.run(validate_findings(
        [{"vuln_type": "env_exposed", "url": "http://t/.env"}],
        fetch=_fetch_returning(resp)))
    assert not out[0]["submittable"]


def test_directory_listing_reconfirmed_submittable():
    def resp(method, url, headers):
        return HttpResp(200, {}, "<html><h1>Index of /ftp</h1><a href='x'>x</a></html>", url)
    out = asyncio.run(validate_findings(
        [{"vuln_type": "information_disclosure:listing:/ftp", "url": "http://t/ftp"}],
        fetch=_fetch_returning(resp)))
    assert out[0]["validated"] and out[0]["submittable"]


def test_injection_class_unconfirmed_stays_lead():
    # An sqli finding whose differential re-test never errors -> not confirmed -> lead.
    def resp(method, url, headers):
        return HttpResp(200, {}, "ordinary content, no DB error", url)
    out = asyncio.run(validate_findings(
        [{"vuln_type": "sqli:id", "url": "http://t/x?id=1", "parameter": "id"}],
        fetch=_fetch_returning(resp)))
    assert not out[0]["submittable"]


def test_fetchhttp_returns_status0_stub_on_network_failure(monkeypatch):
    from core.swarm_workers.vuln import _http

    async def dead_fetch(*a, **k):
        return None
    monkeypatch.setattr(_http, "fetch", dead_fetch)
    resp = asyncio.run(FetchHTTP().get("http://unreachable/"))
    assert resp.status == 0 and resp.body == ""
