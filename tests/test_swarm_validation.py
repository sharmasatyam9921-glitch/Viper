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

_AKIA = "AKIA2E0K8Z9QXVB7N3RT"   # AKIA + 16, no EXAMPLE/placeholder
_PWHASH = '[{"id":1,"email":"a@b.co","passwordHash":"$2b$10$abcdefghijklmno"}]'


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
    assert not f["submittable"]


def test_xss_textarea_context_is_lead():
    # GATE-FP regression: raw reflection INSIDE a <textarea> is inert (RCDATA).
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "text/html"},
                        f"<form><textarea>{_injected(url)}</textarea></form>", url)
    f = _run1({"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}, resp)
    assert not f["submittable"]


def test_xss_json_under_text_html_is_lead():
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "text/html"},
                        '{"q":"' + _injected(url) + '"}', url)
    f = _run1({"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}, resp)
    assert not f["submittable"]  # JSON body -> data, not markup


def _sqli_real(m, url, h):
    # genuine DB: an UNBALANCED quote breaks the query (5xx + error); a balanced
    # '' and the benign value do not.
    v = _injected(url)
    if v.count("'") % 2 == 1 or v.count('"') % 2 == 1:
        return HttpResp(500, {}, "You have an error in your SQL syntax near", url)
    return HttpResp(200, {}, "ok", url)


def test_sqli_unbalanced_quote_500_submittable():
    f = _run1({"vuln_type": "sqli:id", "url": "http://t/x?id=1", "parameter": "id"},
              _sqli_real)
    assert f["submittable"]


def test_sqli_waf_block_is_lead():
    # GATE-FP regression: a WAF 403-blocks any quote and its page mentions SQL.
    def resp(m, url, h):
        if "'" in _injected(url) or '"' in _injected(url):
            return HttpResp(403, {}, "Request blocked by Web Application Firewall: "
                            "incorrect syntax near the submitted token", url)
        return HttpResp(200, {}, "ok", url)
    f = _run1({"vuln_type": "sqli:id", "url": "http://t/x?id=1", "parameter": "id"}, resp)
    assert not f["submittable"]


def test_sqli_corpus_search_is_lead():
    def resp(m, url, h):
        v = _injected(url)
        if v == "1'":  # 200 page echoing a post about SQL syntax (no 5xx)
            return HttpResp(200, {}, "post: 'error in your SQL syntax' help", url)
        return HttpResp(200, {}, "other posts", url)
    f = _run1({"vuln_type": "sqli:q", "url": "http://t/s?q=1", "parameter": "q"}, resp)
    assert not f["submittable"]


def _ssti_engine(m, url, h):
    import re as _re2
    v = _injected(url)
    mm = _re2.search(r"\$\{(\d+)\*(\d+)\}", v)   # ONLY evaluate inside ${...}
    if mm:
        return HttpResp(200, {}, f"Result: {int(mm.group(1))*int(mm.group(2))}", url)
    return HttpResp(200, {}, f"Result: {v}", url)


def test_ssti_template_engine_submittable():
    f = _run1({"vuln_type": "ssti", "url": "http://t/x?n=1", "parameter": "n"}, _ssti_engine)
    assert f["submittable"]


def test_ssti_calculator_is_lead():
    # GATE-FP regression: a calculator evaluates BARE arithmetic too -> not SSTI.
    import re as _re2
    def resp(m, url, h):
        v = _injected(url)
        mm = _re2.search(r"(\d+)\*(\d+)", v)   # evaluates with OR without ${}
        return HttpResp(200, {}, f"Result: {int(mm.group(1))*int(mm.group(2))}" if mm
                        else f"Result: {v}", url)
    f = _run1({"vuln_type": "ssti", "url": "http://t/order?qty=1", "parameter": "qty"}, resp)
    assert not f["submittable"]


def test_lfi_multi_account_passwd_submittable():
    def resp(m, url, h):
        v = _injected(url)
        if "etc/passwd" in v and "../" in v:
            return HttpResp(200, {}, "root:x:0:0:root:/root:/bin/bash\n"
                            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n", url)
        return HttpResp(200, {}, "no such doc", url)
    f = _run1({"vuln_type": "lfi:file", "parameter": "file",
               "url": "http://t/x?file=../../../../etc/passwd"}, resp)
    assert f["submittable"]


def test_lfi_single_quoted_line_is_lead():
    # GATE-FP regression: a doc/search quoting only the canonical root line.
    def resp(m, url, h):
        return HttpResp(200, {}, "The file starts with root:x:0:0:root:/root (one line).", url)
    f = _run1({"vuln_type": "lfi:file", "parameter": "file",
               "url": "http://t/x?file=../../../../etc/passwd"}, resp)
    assert not f["submittable"]


def test_bola_finding_trusted_submittable():
    def resp(m, url, h):
        return HttpResp(200, {}, "x", url)
    f = _run1({"vuln_type": "idor:bola:/api/orders/1", "url": "http://t/api/orders/1"}, resp)
    assert f["submittable"] and f["validation_confidence"] >= 0.8


def test_secrets_live_credential_submittable():
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "application/javascript"},
                        f'var k="{_AKIA}";', url)
    f = _run1({"vuln_type": "secret:aws", "url": "http://t/main.js"}, resp)
    assert f["submittable"]


def test_secrets_placeholder_is_lead():
    # GATE-FP regression: the AWS canonical EXAMPLE key is not a live secret.
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "application/javascript"},
                        'var k="AKIAIOSFODNN7EXAMPLE";', url)
    f = _run1({"vuln_type": "secret:aws", "url": "http://t/main.js"}, resp)
    assert not f["submittable"]


def test_secrets_generic_match_is_lead():
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "text/html"},
                        "<html>password reset instructions</html>", url)
    f = _run1({"vuln_type": "secret:generic", "url": "http://t/page"}, resp)
    assert not f["submittable"]


def test_access_control_strong_sensitive_submittable():
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "application/json"}, _PWHASH, url)
    f = _run1({"vuln_type": "access_control:missing_authorization",
               "url": "http://t/api/Users"}, resp)
    assert f["submittable"]


def test_access_control_public_email_is_lead():
    # GATE-FP regression: a public profile returning an email is not broken auth.
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "application/json"},
                        '{"name":"Acme Co","email":"contact@acme.example"}', url)
    f = _run1({"vuln_type": "access_control:missing_authorization",
               "url": "http://t/api/public-profile"}, resp)
    assert not f["submittable"]


def test_access_control_forbidden_is_lead():
    def resp(m, url, h):
        return HttpResp(403, {}, "Forbidden", url)
    f = _run1({"vuln_type": "access_control:missing_authorization",
               "url": "http://t/api/Users"}, resp)
    assert not f["submittable"]


def test_sqli_dsl_parser_is_lead():
    # GATE-FP regression: a query-DSL parser 500s on an unbalanced quote with a
    # generic "near ...: syntax error" (NOT a DB error).
    def resp(m, url, h):
        v = _injected(url)
        if v.count("'") % 2 == 1:
            return HttpResp(500, {}, "ParseException: near \"'\": syntax error", url)
        return HttpResp(200, {}, "ok", url)
    f = _run1({"vuln_type": "sqli:q", "url": "http://t/search?q=docs", "parameter": "q"}, resp)
    assert not f["submittable"]


def test_access_control_publishable_key_is_lead():
    # GATE-FP regression: a public SPA config serving a Stripe PUBLISHABLE key.
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "application/json"},
                        '{"api_key":"pk_live_51ABCdefGHIjklMNOpqr"}', url)
    f = _run1({"vuln_type": "access_control:missing_authorization",
               "url": "http://t/config.json"}, resp)
    assert not f["submittable"]


def test_secrets_changelog_is_lead():
    # GATE-FP regression: a credential-shaped string in a CHANGELOG (rotated/sample).
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "text/plain"},
                        f"v1.2: rotated key {_AKIA}", url)
    f = _run1({"vuln_type": "secret:aws", "url": "http://t/CHANGELOG.txt"}, resp)
    assert not f["submittable"]


def test_lfi_html_docs_is_lead():
    # GATE-FP regression: a man-page search returning a passwd tutorial as HTML.
    def resp(m, url, h):
        v = _injected(url)
        if "etc/passwd" in v:
            return HttpResp(200, {"content-type": "text/html"},
                            "<html>root:x:0:0:root:/root:/bin/bash\n"
                            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</html>", url)
        return HttpResp(200, {"content-type": "text/html"}, "<html>no match</html>", url)
    f = _run1({"vuln_type": "lfi:file", "parameter": "file",
               "url": "http://t/x?file=../../../../etc/passwd"}, resp)
    assert not f["submittable"]


def test_cors_static_asset_is_lead():
    # GATE-FP regression: a CDN reflecting Origin + credentials on a .css asset.
    def resp(m, url, h):
        return HttpResp(200, {"content-type": "text/css",
                              "access-control-allow-origin": h.get("Origin", ""),
                              "access-control-allow-credentials": "true"}, "body{}", url)
    out = asyncio.run(validate_findings(
        [{"vuln_type": "cors_origin_reflect", "url": "http://t/brand.css"}],
        fetch=_fetch_returning(resp)))
    assert not out[0]["submittable"]


_A_MARKER = "alice@victim.io"


def _bola_cfg():
    return {"owner_headers": {"Cookie": "s=alice"}, "owner_markers": [_A_MARKER],
            "attacker_headers": {"Cookie": "s=bob"}}


def test_single_session_idor_without_two_sessions_is_lead():
    def resp(m, url, h):
        return HttpResp(200, {}, "{}", url)
    f = _run1({"vuln_type": "idor:user", "url": "http://t/api/users/5"}, resp)
    assert not f["submittable"]
    assert "two sessions" in f["validation_reason"]


def test_single_session_idor_escalates_to_bola_submittable():
    def resp(m, url, h):
        ck = (h or {}).get("Cookie", "")
        if "s=alice" in ck or "s=bob" in ck:          # both authed see A's object
            return HttpResp(200, {}, '{"owner":"%s"}' % _A_MARKER, url)
        return HttpResp(401, {}, "", url)             # anon control -> not public
    out = asyncio.run(validate_findings(
        [{"vuln_type": "idor:user", "url": "http://t/api/users/5"}],
        fetch=_fetch_returning(resp), bola_config=_bola_cfg()))
    assert out[0]["submittable"] and out[0]["validation_confidence"] >= 0.9
    assert "two-account BOLA" in out[0]["validation_reason"]


def test_single_session_idor_proper_authz_stays_lead():
    def resp(m, url, h):
        ck = (h or {}).get("Cookie", "")
        if "s=alice" in ck:
            return HttpResp(200, {}, '{"owner":"%s"}' % _A_MARKER, url)
        return HttpResp(403, {}, "", url)             # B forbidden -> no cross-user read
    out = asyncio.run(validate_findings(
        [{"vuln_type": "idor:user", "url": "http://t/api/users/5"}],
        fetch=_fetch_returning(resp), bola_config=_bola_cfg()))
    assert not out[0]["submittable"]


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
    assert out[0]["validation_confidence"] >= 0.8  # reflected origin + credentials


def test_cors_reflect_without_credentials_is_lead():
    # GATE-FP regression: a public read-only API reflects Origin but no credentials.
    def resp(method, url, headers):
        return HttpResp(200, {"access-control-allow-origin": headers.get("Origin", "")},
                        '{"price":1}', url)
    out = asyncio.run(validate_findings(
        [{"vuln_type": "cors_origin_reflect", "url": "http://t/ticker"}],
        fetch=_fetch_returning(resp)))
    assert not out[0]["submittable"]


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
                        f"DB_PASSWORD=s3cret\nAWS_KEY={_AKIA}\n", url)
    out = asyncio.run(validate_findings(
        [{"vuln_type": "env_exposed:/.env", "url": "http://t/.env"}],
        fetch=_fetch_returning(resp)))
    assert out[0]["validated"] and out[0]["submittable"]


def test_env_example_is_lead():
    # GATE-FP regression: a committed .env.example with placeholders is not a leak.
    def resp(method, url, headers):
        return HttpResp(200, {"content-type": "text/plain"},
                        "DB_PASSWORD=changeme\nAWS_KEY=YOUR_KEY_HERE\n", url)
    out = asyncio.run(validate_findings(
        [{"vuln_type": "env_exposed:/.env.example", "url": "http://t/.env.example"}],
        fetch=_fetch_returning(resp)))
    assert not out[0]["submittable"]


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


def test_dir_listing_prose_is_lead():
    # GATE-FP regression: a normal page mentioning "index of" with many links, but
    # not a real autoindex.
    def resp(method, url, headers):
        links = "".join(f'<a href="/p{i}">page {i}</a>' for i in range(12))
        return HttpResp(200, {}, f"<html><h2>Our index of services</h2>{links}</html>", url)
    out = asyncio.run(validate_findings(
        [{"vuln_type": "information_disclosure:listing:/x", "url": "http://t/services"}],
        fetch=_fetch_returning(resp)))
    assert not out[0]["submittable"]


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
