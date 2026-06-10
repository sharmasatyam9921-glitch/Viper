"""Tests for the 9 vuln-phase swarm workers.

Each worker tested with mocked HTTP so the suite runs offline.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # auto-imports recon + vuln packages  # noqa: F401,E402
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner, list_workers  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def _agent(target: str, *, technique: str, timeout: float = 5.0,
           payload=None) -> SwarmAgent:
    return SwarmAgent(
        agent_id="test_agent",
        objective=f"{technique} on {target}",
        target=target,
        technique=technique,
        payload=payload or {},
        timeout_s=timeout,
    )


def _mock_fetch(responses_by_url: dict):
    """Build a fake fetch that returns canned responses by URL.
    `responses_by_url` maps URL substrings → HttpResp (or callable)."""
    async def fake(method, url, **kw):
        for key, resp in responses_by_url.items():
            if key in url:
                if callable(resp):
                    return resp(method, url, **kw)
                return resp
        return None  # default: no response
    return fake


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestVulnRegistry:
    def test_all_nine_vuln_workers_registered(self):
        names = set(list_workers("vuln"))
        expected = {"sqli_probe", "xss_probe", "cors", "nuclei", "idor",
                    "jwt", "secrets", "graphql", "bola"}
        missing = expected - names
        assert not missing, f"missing vuln workers: {missing}"


# ---------------------------------------------------------------------------
# sqli_probe
# ---------------------------------------------------------------------------


class TestSqliProbe:
    def test_detects_sql_error_banner(self):
        body = "Warning: You have an error in your SQL syntax near 'X'"
        resp = HttpResp(200, {}, body, "http://t/?id=1'")

        async def go():
            with patch("core.swarm_workers.vuln.sqli_probe.fetch",
                       side_effect=_mock_fetch({"id=1%27": resp, "id=1'": resp})):
                runner = get_worker_runner("vuln", "sqli_probe")
                return await runner(_agent("http://t/?id=5", technique="sqli_probe"))

        result = asyncio.run(go())
        sqlis = [r for r in result if r["type"] == "sqli"]
        assert len(sqlis) >= 1
        assert sqlis[0]["severity"] == "high"
        assert sqlis[0]["cwe"] == "CWE-89"

    def test_boolean_blind_length_divergence(self):
        # Same URL, same status, but very different body lengths.
        # url-encoded `1 AND 1=1` → `1+AND+1%3D1` — match on the unique tail
        true_resp = HttpResp(200, {}, "X" * 1000, "http://t/?id=true")
        false_resp = HttpResp(200, {}, "X" * 100, "http://t/?id=false")

        async def fake(method, url, **kw):
            if "1%3D1" in url:
                return true_resp
            if "1%3D2" in url:
                return false_resp
            # Error-mode probe (?id=1%27)
            return HttpResp(200, {}, "harmless", url)

        async def go():
            with patch("core.swarm_workers.vuln.sqli_probe.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "sqli_probe")
                return await runner(_agent("http://t/?id=5", technique="sqli_probe"))

        result = asyncio.run(go())
        blinds = [r for r in result if "blind" in r["vuln_type"]]
        assert blinds

    def test_no_findings_on_clean_response(self):
        clean = HttpResp(200, {}, "<html>welcome</html>", "http://t/")

        async def go():
            with patch("core.swarm_workers.vuln.sqli_probe.fetch",
                       return_value=clean):
                runner = get_worker_runner("vuln", "sqli_probe")
                return await runner(_agent("http://t/?id=5", technique="sqli_probe"))

        assert asyncio.run(go()) == []

    def test_no_url_returns_empty(self):
        async def go():
            runner = get_worker_runner("vuln", "sqli_probe")
            return await runner(_agent("", technique="sqli_probe"))

        assert asyncio.run(go()) == []


# ---------------------------------------------------------------------------
# xss_probe
# ---------------------------------------------------------------------------


class TestXssProbe:
    def test_full_payload_reflection_high(self):
        # Build a response containing our payload pattern verbatim
        async def fake(method, url, **kw):
            # Extract the q= value and echo the full payload back
            import urllib.parse
            qs = urllib.parse.urlsplit(url).query
            params = urllib.parse.parse_qs(qs)
            payload = params.get("q", [""])[0]
            return HttpResp(200, {}, f"<html>{payload}</html>", url)

        async def go():
            with patch("core.swarm_workers.vuln.xss_probe.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "xss_probe")
                return await runner(_agent("http://t/?q=hi", technique="xss_probe"))

        result = asyncio.run(go())
        high = [r for r in result if r["severity"] == "high"]
        assert high, "expected at least one high-severity reflected XSS"
        assert high[0]["cwe"] == "CWE-79"

    def test_only_text_reflection_low(self):
        # Echo only the marker, NOT the full payload
        async def fake(method, url, **kw):
            import urllib.parse, re
            qs = urllib.parse.urlsplit(url).query
            params = urllib.parse.parse_qs(qs)
            v = params.get("q", [""])[0]
            # Extract the marker (vXXXXXXXXz) from the payload
            m = re.search(r"v[a-f0-9]{8}z", v)
            text = m.group(0) if m else ""
            return HttpResp(200, {}, f"<p>you said {text}</p>", url)

        async def go():
            with patch("core.swarm_workers.vuln.xss_probe.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "xss_probe")
                return await runner(_agent("http://t/?q=hi", technique="xss_probe"))

        result = asyncio.run(go())
        assert result
        # Marker-only reflection → severity low
        assert any(r["severity"] == "low" for r in result)

    def test_no_reflection_returns_empty(self):
        clean = HttpResp(200, {}, "<html>no echo</html>", "http://t/")

        async def go():
            with patch("core.swarm_workers.vuln.xss_probe.fetch",
                       return_value=clean):
                runner = get_worker_runner("vuln", "xss_probe")
                return await runner(_agent("http://t/?q=hi", technique="xss_probe"))

        assert asyncio.run(go()) == []


# ---------------------------------------------------------------------------
# cors
# ---------------------------------------------------------------------------


class TestCors:
    def test_wildcard_with_credentials_high(self):
        resp = HttpResp(
            200,
            {"access-control-allow-origin": "*",
             "access-control-allow-credentials": "true"},
            "", "http://t/",
        )

        async def go():
            with patch("core.swarm_workers.vuln.cors.fetch", return_value=resp):
                runner = get_worker_runner("vuln", "cors")
                return await runner(_agent("http://t/", technique="cors"))

        result = asyncio.run(go())
        assert result
        assert any(r["severity"] == "high" for r in result)
        assert any("CWE-942" == r.get("cwe") for r in result)

    def test_origin_reflected(self):
        async def fake(method, url, **kw):
            origin = (kw.get("headers") or {}).get("Origin", "")
            if origin.startswith("https://evil-"):
                return HttpResp(
                    200,
                    {"access-control-allow-origin": origin,
                     "access-control-allow-credentials": "true"},
                    "", url,
                )
            return HttpResp(200, {"access-control-allow-origin": "null"}, "", url)

        async def go():
            with patch("core.swarm_workers.vuln.cors.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "cors")
                return await runner(_agent("http://t/", technique="cors"))

        result = asyncio.run(go())
        types = {r["vuln_type"] for r in result}
        assert "cors_origin_reflect" in types
        assert "cors_null_origin" in types  # null origin path also fires

    def test_no_cors_headers_returns_empty(self):
        resp = HttpResp(200, {}, "", "http://t/")

        async def go():
            with patch("core.swarm_workers.vuln.cors.fetch", return_value=resp):
                runner = get_worker_runner("vuln", "cors")
                return await runner(_agent("http://t/", technique="cors"))

        assert asyncio.run(go()) == []


# ---------------------------------------------------------------------------
# idor
# ---------------------------------------------------------------------------


class TestIdor:
    def test_numeric_id_distinct_bodies_flags_candidate(self):
        async def fake(method, url, **kw):
            if "id=5" in url:
                return HttpResp(200, {}, "user 5 secret", url)
            if "id=6" in url:
                return HttpResp(200, {}, "different user 6", url)
            return None

        async def go():
            with patch("core.swarm_workers.vuln.idor.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "idor")
                return await runner(_agent("http://t/u?id=5", technique="idor"))

        result = asyncio.run(go())
        assert result
        assert result[0]["cwe"] == "CWE-639"
        assert result[0]["confidence"] >= 0.5

    def test_identical_bodies_no_flag(self):
        same = HttpResp(200, {}, "generic 404 page", "http://t/")

        async def go():
            with patch("core.swarm_workers.vuln.idor.fetch", return_value=same):
                runner = get_worker_runner("vuln", "idor")
                return await runner(_agent("http://t/?id=5", technique="idor"))

        assert asyncio.run(go()) == []

    def test_no_id_param_returns_empty(self):
        # /search?q=hello has no ID-shaped param
        async def go():
            runner = get_worker_runner("vuln", "idor")
            return await runner(_agent("http://t/search?q=hi", technique="idor"))

        assert asyncio.run(go()) == []


# ---------------------------------------------------------------------------
# jwt
# ---------------------------------------------------------------------------


class TestJwt:
    def test_weak_hmac_key_cracked(self):
        # Pre-built JWT signed with HS256 and key="secret"
        # Header: {"alg":"HS256","typ":"JWT"}
        # Payload: {"user":"x"}
        import base64
        import hashlib
        import hmac
        import json as _json
        h = _json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":"))
        p = _json.dumps({"user": "x"}, separators=(",", ":"))

        def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

        token = (
            b64u(h.encode()) + "." + b64u(p.encode()) + "."
            + b64u(hmac.new(b"secret",
                            (b64u(h.encode()) + "." + b64u(p.encode())).encode(),
                            hashlib.sha256).digest())
        )
        # Token contains all three parts; the regex requires eyJ prefix on
        # header AND payload — which it has.

        resp = HttpResp(
            200,
            {"set-cookie": f"session={token}"},
            "", "http://t/",
        )

        async def go():
            with patch("core.swarm_workers.vuln.jwt.fetch", return_value=resp):
                runner = get_worker_runner("vuln", "jwt")
                return await runner(_agent("http://t/", technique="jwt"))

        result = asyncio.run(go())
        cracked = [r for r in result if r["type"] == "jwt_weak_key"]
        assert cracked, "expected cracked weak-key finding"
        assert cracked[0]["severity"] == "critical"

    def test_no_jwt_in_response_returns_only_empty(self):
        resp = HttpResp(200, {}, "no tokens here", "http://t/")

        async def go():
            with patch("core.swarm_workers.vuln.jwt.fetch", return_value=resp):
                runner = get_worker_runner("vuln", "jwt")
                return await runner(_agent("http://t/", technique="jwt"))

        assert asyncio.run(go()) == []


# ---------------------------------------------------------------------------
# secrets
# ---------------------------------------------------------------------------


class TestSecrets:
    def test_aws_key_in_body_detected(self):
        body = "config: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE other"
        resp = HttpResp(200, {}, body, "http://t/")

        async def go():
            with patch("core.swarm_workers.vuln.secrets.fetch", return_value=resp):
                runner = get_worker_runner("vuln", "secrets")
                return await runner(_agent("http://t/", technique="secrets"))

        result = asyncio.run(go())
        assert any(r["vuln_type"] == "secret:aws_access_key" for r in result)
        # Severity is high or above
        leaks = [r for r in result if r["type"] == "secret_leak"]
        assert leaks
        assert leaks[0]["severity"] in ("high", "critical")

    def test_env_file_exposure_flagged(self):
        async def fake(method, url, **kw):
            if url.endswith("/.env"):
                return HttpResp(
                    200, {}, "API_KEY=fake_key_1234567890abcd\nDB_PASS=hello",
                    url,
                )
            return HttpResp(200, {}, "clean", url)

        async def go():
            with patch("core.swarm_workers.vuln.secrets.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "secrets")
                return await runner(_agent("http://t/", technique="secrets"))

        result = asyncio.run(go())
        env_findings = [r for r in result if r["type"] == "env_exposed"]
        assert env_findings
        assert env_findings[0]["severity"] == "high"

    def test_git_head_exposed(self):
        async def fake(method, url, **kw):
            if url.endswith("/.git/HEAD"):
                return HttpResp(200, {}, "ref: refs/heads/main\n", url)
            return HttpResp(200, {}, "clean", url)

        async def go():
            with patch("core.swarm_workers.vuln.secrets.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "secrets")
                return await runner(_agent("http://t/", technique="secrets"))

        result = asyncio.run(go())
        git = [r for r in result if r["type"] == "git_exposed"]
        assert git

    def test_juiceshop_ftp_directory_listing(self):
        # /ftp returns an HTML index linking downloadable files → info disclosure.
        async def fake(method, url, **kw):
            if url.endswith("/ftp"):
                return HttpResp(
                    200, {},
                    '<html><body><a href="acquisitions.md">acquisitions.md</a>'
                    '<a href="coupons_2013.md.bak">coupons</a></body></html>',
                    url,
                )
            if url.endswith("/ftp/acquisitions.md"):
                return HttpResp(200, {}, "# Acquisition of ...confidential...", url)
            return None  # everything else: no response, no findings

        async def go():
            with patch("core.swarm_workers.vuln.secrets.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "secrets")
                return await runner(_agent("http://t/", technique="secrets"))

        result = asyncio.run(go())
        listing = [r for r in result if r["type"] == "directory_listing"]
        doc = [r for r in result if r["type"] == "sensitive_file_exposed"]
        assert listing, "expected a directory_listing finding for /ftp"
        assert doc, "expected a confidential-doc finding for /ftp/acquisitions.md"
        # Labels must be scorer-matchable to the info_disclosure class.
        assert all("information_disclosure" in r["vuln_type"]
                   for r in listing + doc)
        assert listing[0]["severity"] == "high"

    def test_juiceshop_encryptionkeys_listing(self):
        async def fake(method, url, **kw):
            if url.endswith("/encryptionkeys"):
                return HttpResp(
                    200, {},
                    '<a href="jwt.pub">jwt.pub</a><a href="premium.key">premium</a>',
                    url,
                )
            return None

        async def go():
            with patch("core.swarm_workers.vuln.secrets.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "secrets")
                return await runner(_agent("http://t/", technique="secrets"))

        result = asyncio.run(go())
        listing = [r for r in result if r["type"] == "directory_listing"]
        assert listing
        assert "/encryptionkeys" in listing[0]["url"]

    def test_exposure_paths_are_root_relative(self):
        # Worker dispatched against a sub-path asset must still test /ftp at the
        # site ORIGIN, not append it to the asset path (/styles.css/ftp).
        seen = []

        async def fake(method, url, **kw):
            seen.append(url)
            if url == "http://t/ftp":
                return HttpResp(200, {}, '<a href="acquisitions.md">x</a>', url)
            return None

        async def go():
            with patch("core.swarm_workers.vuln.secrets.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "secrets")
                return await runner(_agent("http://t/styles.css", technique="secrets"))

        result = asyncio.run(go())
        assert "http://t/ftp" in seen
        assert "http://t/styles.css/ftp" not in seen
        assert any(r["type"] == "directory_listing" for r in result)

    def test_no_false_positive_on_plain_200(self):
        # A 200 that is NOT a listing must not produce an exposure finding.
        async def fake(method, url, **kw):
            if url.endswith("/ftp") or url.endswith("/encryptionkeys"):
                return HttpResp(200, {}, "<html><body>Not Found page</body></html>", url)
            return None

        async def go():
            with patch("core.swarm_workers.vuln.secrets.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "secrets")
                return await runner(_agent("http://t/", technique="secrets"))

        result = asyncio.run(go())
        assert not [r for r in result if r["type"] in
                    ("directory_listing", "sensitive_file_exposed")]


# ---------------------------------------------------------------------------
# graphql
# ---------------------------------------------------------------------------


class TestGraphQL:
    def test_introspection_enabled_flagged(self):
        async def fake(method, url, **kw):
            if method == "POST" and "/graphql" in url:
                return HttpResp(
                    200, {},
                    '{"data":{"__schema":{"types":[{"name":"Query"},{"name":"Mutation"}]}}}',
                    url,
                )
            return None

        async def go():
            with patch("core.swarm_workers.vuln.graphql.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "graphql")
                return await runner(_agent("http://t/", technique="graphql"))

        result = asyncio.run(go())
        intro = [r for r in result if r["type"] == "graphql_introspection"]
        assert intro
        assert intro[0]["severity"] == "medium"
        assert intro[0]["schema_type_count"] == 2

    def test_graphiql_ide_detected(self):
        async def fake(method, url, **kw):
            if method == "GET" and "/graphql" in url:
                return HttpResp(200, {}, "<html>GraphiQL</html>", url)
            return None

        async def go():
            with patch("core.swarm_workers.vuln.graphql.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "graphql")
                return await runner(_agent("http://t/", technique="graphql"))

        result = asyncio.run(go())
        ide = [r for r in result if r["type"] == "graphql_ide_exposed"]
        assert ide

    def test_no_graphql_endpoint_returns_empty(self):
        async def go():
            with patch("core.swarm_workers.vuln.graphql.fetch", return_value=None):
                runner = get_worker_runner("vuln", "graphql")
                return await runner(_agent("http://t/", technique="graphql"))

        assert asyncio.run(go()) == []


# ---------------------------------------------------------------------------
# bola
# ---------------------------------------------------------------------------


class TestBola:
    def test_finds_api_endpoint_candidate(self):
        baseline = (
            '<html><a href="/api/users/123">user</a>'
            '<script>fetch("/api/users/456")</script></html>'
        )
        baseline_resp = HttpResp(200, {}, baseline, "http://t/")

        async def fake(method, url, **kw):
            if url == "http://t/" or url == "http://t":
                return baseline_resp
            if "/users/123" in url:
                return HttpResp(200, {}, "user 123 data", url)
            if "/users/124" in url:
                return HttpResp(200, {}, "other user 124 data", url)
            return None

        async def go():
            with patch("core.swarm_workers.vuln.bola.fetch", side_effect=fake):
                runner = get_worker_runner("vuln", "bola")
                return await runner(_agent("http://t/", technique="bola"))

        result = asyncio.run(go())
        assert result
        assert result[0]["type"] == "bola_candidate"
        assert result[0]["cwe"] == "CWE-639"

    def test_no_api_urls_in_baseline_returns_empty(self):
        clean = HttpResp(200, {}, "<html>no api here</html>", "http://t/")

        async def go():
            with patch("core.swarm_workers.vuln.bola.fetch", return_value=clean):
                runner = get_worker_runner("vuln", "bola")
                return await runner(_agent("http://t/", technique="bola"))

        assert asyncio.run(go()) == []


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------


class TestNuclei:
    def test_subprocess_path_when_no_module(self):
        # Force scanners.nuclei_scanner.NucleiScanner to fail, then
        # also force shutil.which("nuclei") to return None → returns []
        async def go():
            with patch.dict(sys.modules, {"scanners.nuclei_scanner": None}):
                with patch("shutil.which", return_value=None):
                    runner = get_worker_runner("vuln", "nuclei")
                    return await runner(_agent("http://t/", technique="nuclei"))

        assert asyncio.run(go()) == []

    def test_no_target_returns_empty(self):
        async def go():
            runner = get_worker_runner("vuln", "nuclei")
            return await runner(_agent("", technique="nuclei"))

        assert asyncio.run(go()) == []


# ---------------------------------------------------------------------------
# Common contract: all workers handle empty input + network failure
# ---------------------------------------------------------------------------


class TestWorkerContract:
    @pytest.mark.parametrize("technique", [
        "sqli_probe", "xss_probe", "cors", "idor", "jwt",
        "secrets", "graphql", "bola", "nuclei",
    ])
    def test_workers_never_raise_on_network_failure(self, technique):
        async def go():
            runner = get_worker_runner("vuln", technique)
            # Workers all go through `_http.fetch` → `_fetch_sync` →
            # urllib.OpenerDirector.open. Patching `_fetch_sync` is the
            # cleanest single-point intercept that covers every worker
            # regardless of how it imported `fetch`.
            with patch("core.swarm_workers.vuln._http._fetch_sync",
                       return_value=None):
                with patch("shutil.which", return_value=None):
                    return await runner(_agent("http://t/", technique=technique))

        result = asyncio.run(go())
        assert isinstance(result, list)
