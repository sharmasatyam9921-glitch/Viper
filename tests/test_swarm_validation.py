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


def test_injection_class_stays_lead():
    def resp(method, url, headers):
        return HttpResp(200, {}, "x", url)
    out = asyncio.run(validate_findings(
        [{"vuln_type": "sqli:id", "url": "http://t/x?id=1"}],
        fetch=_fetch_returning(resp)))
    assert not out[0]["submittable"]
    assert "manual review" in out[0]["validation_reason"]


def test_fetchhttp_returns_status0_stub_on_network_failure(monkeypatch):
    from core.swarm_workers.vuln import _http

    async def dead_fetch(*a, **k):
        return None
    monkeypatch.setattr(_http, "fetch", dead_fetch)
    resp = asyncio.run(FetchHTTP().get("http://unreachable/"))
    assert resp.status == 0 and resp.body == ""
