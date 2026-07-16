"""Enhancement: client-side prototype pollution becomes gate-CONFIRMED via a real
headless-browser DOM oracle when Playwright is available; without a browser it stays a
manual-review LEAD (so gate precision never depends on a browser being installed). The
oracle observation (a random marker landing on Object.prototype) is unforgeable, so a
confirmation is never a false positive."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.browser import viper_browser  # noqa: E402
from core.swarm_validation import validate_findings  # noqa: E402


def _finding():
    return {"type": "prototype_pollution", "vuln_type": "prototype_pollution:client",
            "url": "http://app.test/x", "severity": "medium"}


def _run():
    return asyncio.run(validate_findings([_finding()], default_target="http://app.test/"))


def test_confirmed_when_oracle_observes_pollution():
    async def probe(url, marker, **kw):
        return True   # the browser saw the marker land on Object.prototype

    with patch.object(viper_browser, "available", lambda: True), \
         patch.object(viper_browser, "probe_proto_pollution", probe):
        out = _run()
    assert out[0]["submittable"] is True
    assert "prototype pollution CONFIRMED" in out[0]["validation_reason"]


def test_lead_when_oracle_sees_no_pollution():
    async def probe(url, marker, **kw):
        return False

    with patch.object(viper_browser, "available", lambda: True), \
         patch.object(viper_browser, "probe_proto_pollution", probe):
        out = _run()
    assert not out[0]["submittable"]
    assert "did not observe" in out[0]["validation_reason"]


def test_lead_when_browser_unavailable():
    # No Playwright (the default in CI) -> stays a lead, exactly as before.
    with patch.object(viper_browser, "available", lambda: False):
        out = _run()
    assert not out[0]["submittable"]
    assert "Playwright not installed" in out[0]["validation_reason"]


def test_lead_when_oracle_errors():
    async def probe(url, marker, **kw):
        raise RuntimeError("browser crashed")

    with patch.object(viper_browser, "available", lambda: True), \
         patch.object(viper_browser, "probe_proto_pollution", probe):
        out = _run()
    assert not out[0]["submittable"]   # an oracle error must never confirm


def test_probe_returns_none_without_playwright():
    # The probe itself is a no-op when Playwright is absent (available()==False in CI).
    if not viper_browser.available():
        r = asyncio.run(viper_browser.probe_proto_pollution("http://x/", "vpMARKER"))
        assert r is None
