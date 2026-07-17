"""Enhancement: XSS is confirmed by a real headless-browser EXECUTION oracle when
Playwright is available — if the payload's JS actually runs (window[marker] set), it's
confirmed (reflected OR DOM-sourced). Without a browser the gate falls back to the
read-only reflection differential, so precision never depends on a browser. Execution of
a random per-finding marker is unforgeable → never a false positive."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.browser import viper_browser  # noqa: E402
from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def _run(finding, fetch=None):
    return asyncio.run(validate_findings([finding], default_target="http://app.test/",
                                         fetch=fetch))


def test_confirmed_when_payload_executes_in_browser():
    f = {"type": "xss", "vuln_type": "xss:q", "url": "http://app.test/s?q=x",
         "parameter": "q", "severity": "medium"}

    async def probe(url, param=None, *, marker, **kw):
        return True   # the browser executed the payload and set window[marker]

    with patch.object(viper_browser, "available", lambda: True), \
         patch.object(viper_browser, "probe_dom_xss", probe):
        out = _run(f)
    assert out[0]["submittable"] is True
    assert "EXECUTED" in out[0]["validation_reason"]


def test_dom_only_finding_confirms_without_a_param():
    # A DOM-source XSS (payload in location.hash) has no query param — the oracle still
    # confirms it, where the reflection differential would have bailed on "no parameter".
    f = {"type": "dom_xss", "vuln_type": "dom_xss", "url": "http://app.test/app",
         "severity": "medium"}

    async def probe(url, param=None, *, marker, **kw):
        assert param is None
        return True

    with patch.object(viper_browser, "available", lambda: True), \
         patch.object(viper_browser, "probe_dom_xss", probe):
        out = _run(f)
    assert out[0]["submittable"] is True


def test_falls_back_to_reflection_differential_when_no_execution():
    # Browser present but payload did NOT execute -> fall through to the read-only
    # reflection differential, which here sees an html-escaped reflection -> lead.
    f = {"type": "xss", "vuln_type": "xss:q", "url": "http://app.test/s?q=x",
         "parameter": "q", "severity": "medium"}

    async def probe(url, param=None, *, marker, **kw):
        return False

    async def fetch(method, url, timeout=10, **kw):
        # reflection differential re-fetches; return an ESCAPED reflection (secure)
        return HttpResp(200, {"content-type": "text/html"},
                        "<h1>Results for &lt;vgx&gt;</h1>", url)

    with patch.object(viper_browser, "available", lambda: True), \
         patch.object(viper_browser, "probe_dom_xss", probe):
        out = _run(f, fetch=fetch)
    assert not out[0]["submittable"]


def test_no_browser_uses_reflection_path_and_confirms_live_markup():
    # No Playwright: the reflection differential runs unchanged and confirms LIVE markup.
    f = {"type": "xss", "vuln_type": "xss:q", "url": "http://app.test/s?q=x",
         "parameter": "q", "severity": "medium"}

    async def fetch(method, url, timeout=10, **kw):
        from urllib.parse import parse_qs, unquote, urlsplit
        v = next((x[0] for x in parse_qs(urlsplit(url).query).values() if x), "")
        return HttpResp(200, {"content-type": "text/html"},
                        f"<h1>Results for {unquote(v)}</h1>", url)   # reflected LIVE

    with patch.object(viper_browser, "available", lambda: False):
        out = _run(f, fetch=fetch)
    assert out[0]["submittable"] is True
    assert "LIVE element" in out[0]["validation_reason"]


def test_oracle_error_falls_back_not_crash():
    f = {"type": "xss", "vuln_type": "xss:q", "url": "http://app.test/s?q=x",
         "parameter": "q", "severity": "medium"}

    async def probe(url, param=None, *, marker, **kw):
        raise RuntimeError("browser crashed")

    async def fetch(method, url, timeout=10, **kw):
        return HttpResp(200, {"content-type": "text/html"}, "<h1>no reflection</h1>", url)

    with patch.object(viper_browser, "available", lambda: True), \
         patch.object(viper_browser, "probe_dom_xss", probe):
        out = _run(f, fetch=fetch)   # must not raise
    assert not out[0]["submittable"]
