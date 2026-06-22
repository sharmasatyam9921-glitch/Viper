"""Subdomain takeover worker + independent gate re-check (fingerprint-based)."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402
from core.swarm_workers.vuln.subdomain_takeover import (  # noqa: E402
    match_fingerprint,
    run as st_run,
)


class _Agent:
    def __init__(self, t):
        self.target = t
        self.timeout_s = 8.0
        self.payload = {}


def _fetch(body, status=200):
    async def fake(method, url, *, headers=None, timeout=10.0, **kw):
        return HttpResp(status, {}, body, url)
    return fake


def test_match_fingerprint_is_service_specific():
    assert match_fingerprint("There isn't a GitHub Pages site here") == "GitHub Pages"
    assert match_fingerprint("NoSuchBucket") == "AWS S3"
    assert match_fingerprint("Fastly error: unknown domain") == "Fastly"
    assert match_fingerprint("404 Not Found") is None        # generic -> no match
    assert match_fingerprint("welcome to my blog") is None


def test_worker_flags_unclaimed_service(monkeypatch):
    from core.swarm_workers.vuln import subdomain_takeover as mod
    monkeypatch.setattr(mod, "fetch",
                        _fetch("<h1>There isn't a GitHub Pages site here.</h1>", 404))
    out = asyncio.run(st_run(_Agent("http://sub.t/")))
    assert len(out) == 1
    assert out[0]["vuln_type"] == "subdomain_takeover:github_pages"
    assert out[0]["severity"] == "high"


def test_worker_no_finding_on_normal_page(monkeypatch):
    from core.swarm_workers.vuln import subdomain_takeover as mod
    monkeypatch.setattr(mod, "fetch", _fetch("<h1>Welcome</h1>", 200))
    assert asyncio.run(st_run(_Agent("http://sub.t/"))) == []


def test_gate_confirms_takeover_fingerprint():
    f = {"vuln_type": "subdomain_takeover:aws_s3", "url": "http://sub.t/"}
    out = asyncio.run(validate_findings(
        [f], fetch=_fetch("NoSuchBucket\nThe specified bucket does not exist", 404)))
    assert out[0]["submittable"] and out[0]["validation_confidence"] == 0.85


def test_gate_rejects_when_fingerprint_gone():
    f = {"vuln_type": "subdomain_takeover:aws_s3", "url": "http://sub.t/"}
    out = asyncio.run(validate_findings([f], fetch=_fetch("the bucket is now claimed, hello", 200)))
    assert not out[0]["submittable"]


def test_200_page_with_fingerprint_is_not_takeover(monkeypatch):
    # a doc/blog/parked page (2xx) that merely quotes the phrase is NOT a takeover
    from core.swarm_workers.vuln import subdomain_takeover as mod
    monkeypatch.setattr(mod, "fetch",
                        _fetch("Our guide explains the 'NoSuchBucket' S3 error", 200))
    assert asyncio.run(st_run(_Agent("http://sub.t/"))) == []
    # and the gate rejects a 200 even with the fingerprint
    f = {"vuln_type": "subdomain_takeover:aws_s3", "url": "http://sub.t/"}
    out = asyncio.run(validate_findings([f], fetch=_fetch("NoSuchBucket", 200)))
    assert not out[0]["submittable"]
