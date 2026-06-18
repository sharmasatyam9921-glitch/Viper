"""False-positive regression for the `vuln/secrets` swarm worker.

Audit scenario: a catch-all SPA (React/Vue/Angular client-side routing, or a
CDN-fronted app) returns its normal index.html with HTTP 200 for ANY unmatched
route, including `/.env`. The pre-fix worker gated the high-severity
`env_exposed` finding on `r.ok and r.body` plus a bare `"=" in r.body` test —
which ANY HTML body satisfies (`lang="en"`, `charset="utf-8"`, any attr=value).
So the SPA index tripped a high-severity .env-exposed finding even though no
secret is exposed.

Test (a) reproduces that FP (must FAIL pre-fix). Test (b) pins the genuine
true-positive: a real dotenv body served as text/plain still fires.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402  (registers vuln workers)
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def _agent(target: str) -> SwarmAgent:
    return SwarmAgent(
        agent_id="t",
        objective="secrets on " + target,
        target=target,
        technique="secrets",
        payload={},
        timeout_s=10.0,
    )


# The catch-all SPA index served for EVERY path, including /.env. Has plenty of
# `attr=value` so the old bare `"=" in body` test fired; declared text/html so
# the content-type guard recognizes it. No secret of any kind is present.
_SPA_INDEX = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    '<title>My App</title></head><body><div id="root"></div>'
    '<script src="/static/js/main.abc123.js"></script></body></html>'
)


def _run(target: str, fake):
    async def go():
        with patch("core.swarm_workers.vuln.secrets.fetch", side_effect=fake):
            runner = get_worker_runner("vuln", "secrets")
            return await runner(_agent(target))

    return asyncio.run(go())


def test_spa_catchall_env_not_flagged():
    """A catch-all SPA that returns index.html for /.env must NOT be flagged.

    Pre-fix this FAILS: the SPA index body trips `env_exposed:/.env` (high).
    """
    async def fake(method, url, **kw):
        # Catch-all: same 200 text/html SPA index for absolutely every path,
        # including /.env, /.git/HEAD, /.aws/credentials, etc.
        return HttpResp(200, {"content-type": "text/html; charset=utf-8"},
                        _SPA_INDEX, url)

    result = _run("http://t/", fake)
    offenders = [r for r in result if r["type"] in
                 ("env_exposed", "secret_leak", "git_exposed",
                  "actuator_exposed")]
    assert offenders == [], (
        "catch-all SPA index must not produce any exposure/secret finding, got: "
        + repr(offenders)
    )


def test_real_dotenv_still_flagged():
    """A genuinely exposed .env (text/plain, KEY=value lines) STILL fires.

    Guards against over-correcting the FP fix into a false negative.
    """
    dotenv_body = (
        "# production env\n"
        "API_KEY=sk_realvalue_9f8c3a21bd\n"
        "DB_PASSWORD=Sup3rSecretPw!\n"
        "DEBUG=false\n"
    )

    async def fake(method, url, **kw):
        if url.endswith("/.env"):
            return HttpResp(200, {"content-type": "text/plain"}, dotenv_body, url)
        # Everything else: an honest 404 so nothing else fires.
        return HttpResp(404, {"content-type": "text/html"}, "Not Found", url)

    result = _run("http://t/", fake)
    env = [r for r in result if r["type"] == "env_exposed"]
    assert env, "a real text/plain dotenv with KEY=value lines must be flagged"
    assert env[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# Round-2 audit: Google AIza... browser keys (Maps JS / Firebase web config /
# reCAPTCHA) are PUBLIC by design — embedded in client-side JS, visible to every
# visitor, secured by HTTP-referrer/app restrictions in Google Cloud Console,
# NOT by secrecy. A minified JS bundle served as application/javascript that
# contains such a key is not a "leaked secret". The round-1 HTML gate does not
# cover this (the body is JS, not HTML), so the worker still emits a spurious
# secret:google_api_key finding. Same gap applies to low-severity jwt_token
# (public OIDC sample/config tokens in JS bundles).
# ---------------------------------------------------------------------------

# Canonical Google browser API key shape: AIza + 35 url-safe chars = 39 total.
_GMAPS_KEY = "AIzaSyB1cD3fGh4Jk5Lm6No7Pq8Rs9Tu0Vw4uA0"
# A public (non-sensitive) OIDC/JWT-shaped value as a JS bundles often inline.
_PUBLIC_JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
    "abcdefghijklmnopqrstuvwxyz0123456789ABCD"
)

# A realistic minified browser bundle, served as application/javascript.
_JS_BUNDLE = (
    '(function(){var cfg={apiKey:"' + _GMAPS_KEY + '",'
    'authDomain:"shop.firebaseapp.com",projectId:"shop"};'
    'var t="' + _PUBLIC_JWT + '";'
    'window.__APP__=cfg;})();'
)


def test_google_key_in_js_bundle_not_flagged():
    """A Google AIza browser key in a JS bundle (application/javascript) is
    public-by-design and must NOT be flagged as a leaked secret.

    Pre-fix this FAILS: the worker emits secret:google_api_key (medium).
    """
    asset = "http://shop.example.com/assets/index-4f3a.js"

    async def fake(method, url, **kw):
        if url == asset:
            return HttpResp(
                200, {"content-type": "application/javascript; charset=utf-8"},
                _JS_BUNDLE, url)
        # Honest 404s for every origin-relative exposure path.
        return HttpResp(404, {"content-type": "text/html"}, "Not Found", url)

    result = _run(asset, fake)
    offenders = [r for r in result if r.get("vuln_type") in
                 ("secret:google_api_key", "secret:jwt_token")]
    assert offenders == [], (
        "Google browser key / public JWT in a JS bundle is public-by-design and "
        "must not be flagged as a leaked secret, got: " + repr(offenders)
    )


def test_google_key_by_js_extension_not_flagged():
    """Even when content-type is generic, a .js URL marks a public client-side
    asset — the AIza key must be suppressed by extension alone.
    """
    asset = "http://shop.example.com/static/main.mjs"

    async def fake(method, url, **kw):
        if url == asset:
            # Mislabeled content-type (octet-stream) — extension must still gate.
            return HttpResp(
                200, {"content-type": "application/octet-stream"},
                _JS_BUNDLE, url)
        return HttpResp(404, {"content-type": "text/html"}, "Not Found", url)

    result = _run(asset, fake)
    offenders = [r for r in result if r.get("vuln_type") in
                 ("secret:google_api_key", "secret:jwt_token")]
    assert offenders == [], (
        "AIza key on a .mjs asset must be suppressed by URL extension, got: "
        + repr(offenders)
    )


def test_google_key_on_server_side_json_still_flagged():
    """A Google AIza key in a genuinely server-side surface (JSON config dump,
    NOT a JS asset) is still a real leak and MUST fire — guards against
    over-correcting the public-asset gate into a false negative.
    """
    config_url = "http://api.example.com/config"
    config_body = (
        '{"env":"prod","mapsKey":"' + _GMAPS_KEY + '",'
        '"debug":false,"region":"us-east-1"}'
    )

    async def fake(method, url, **kw):
        if url == config_url:
            return HttpResp(200, {"content-type": "application/json"},
                            config_body, url)
        return HttpResp(404, {"content-type": "text/html"}, "Not Found", url)

    result = _run(config_url, fake)
    google = [r for r in result if r.get("vuln_type") == "secret:google_api_key"]
    assert google, (
        "an AIza key in a server-side application/json config dump is a real "
        "leak and must still be flagged"
    )


def test_high_confidence_secret_in_js_still_flagged():
    """Shape-specific, never-public secrets (AKIA/ghp_/sk_live_/PEM) in a JS
    bundle STILL fire unconditionally — the public-asset gate must NOT swallow
    them.
    """
    asset = "http://shop.example.com/assets/leaky.js"
    leaky = (
        'var c={k:"AKIAIOSFODNN7EXAMPLE",'
        't:"ghp_' + "a" * 36 + '"};'
    )

    async def fake(method, url, **kw):
        if url == asset:
            return HttpResp(
                200, {"content-type": "application/javascript"}, leaky, url)
        return HttpResp(404, {"content-type": "text/html"}, "Not Found", url)

    result = _run(asset, fake)
    vt = {r.get("vuln_type") for r in result}
    assert "secret:aws_access_key" in vt, "AKIA key in JS must still fire"
    assert "secret:github_pat" in vt, "ghp_ PAT in JS must still fire"
