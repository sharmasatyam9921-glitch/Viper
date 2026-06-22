"""Clickjacking is now gate-confirmed (framable HTML, header-checked)."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def _fetch(headers, body="<html>x</html>", status=200):
    async def fake(method, url, *, timeout=10.0, **kw):
        return HttpResp(status, headers, body, url)
    return fake


_F = {"vuln_type": "clickjacking_frameable", "url": "http://t/"}


def test_framable_html_is_confirmed():
    out = asyncio.run(validate_findings([_F], fetch=_fetch({"content-type": "text/html"})))
    assert out[0]["submittable"] and out[0]["validation_confidence"] == 0.6


def test_x_frame_options_present_is_lead():
    out = asyncio.run(validate_findings(
        [_F], fetch=_fetch({"content-type": "text/html", "x-frame-options": "DENY"})))
    assert not out[0]["submittable"]


def test_csp_frame_ancestors_present_is_lead():
    out = asyncio.run(validate_findings([_F], fetch=_fetch(
        {"content-type": "text/html", "content-security-policy": "frame-ancestors 'self'"})))
    assert not out[0]["submittable"]


def test_non_html_is_lead():
    out = asyncio.run(validate_findings(
        [_F], fetch=_fetch({"content-type": "application/json"})))
    assert not out[0]["submittable"]
