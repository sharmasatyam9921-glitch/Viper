"""Enhancement: subdomain-takeover fingerprint corpus expanded ~12 -> ~50 providers via
data/takeover_fingerprints.json. Pure RECALL on an already-confirmed class — the gate
recheck is unchanged, and each fingerprint is provider-specific so a benign 404 matches
none (precision 1.00 preserved)."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers.vuln import subdomain_takeover as sdt  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def test_corpus_expanded_from_builtins():
    # The external corpus should meaningfully expand the ~12 built-ins.
    assert len(sdt.FINGERPRINTS) >= 40
    services = {s for s, _ in sdt.FINGERPRINTS}
    for s in ("Vercel", "UserVoice", "Kinsta", "Cargo Collective", "Ngrok"):
        assert s in services, f"expanded corpus missing {s}"


def test_new_provider_fingerprints_match():
    cases = {
        "The deployment could not be found. DEPLOYMENT_NOT_FOUND": "Vercel",
        "This UserVoice subdomain is currently available!": "UserVoice",
        "No Site For Domain": "Kinsta",
        "Tunnel foo.ngrok.io not found": "Ngrok",
    }
    for body, svc in cases.items():
        assert sdt.match_fingerprint(body) == svc


def test_benign_404_pages_match_no_fingerprint():
    # The whole precision guarantee: a normal custom-404 must not match any provider.
    for body in (
        "<h1>404 Page Not Found</h1><p>The page you requested was not found.</p>",
        "<html><body>Not found</body></html>",
        "Repository not found",           # deliberately excluded generic phrase
        "Sorry, this page could not be located on our servers.",
    ):
        assert sdt.match_fingerprint(body) is None, body


def _agent(t):
    return SwarmAgent(agent_id="t", objective="x", target=t, technique="subdomain_takeover",
                      payload={}, timeout_s=6.0)


def test_worker_flags_new_provider_and_not_benign():
    async def vercel(method, url, timeout=10, **kw):
        return HttpResp(404, {}, '{"error":{"code":"DEPLOYMENT_NOT_FOUND"}}', url)

    async def benign(method, url, timeout=10, **kw):
        return HttpResp(404, {}, "<h1>404 Not Found</h1>", url)

    with patch.object(sdt, "fetch", vercel):
        out = asyncio.run(sdt.run(_agent("http://gone.example.test/")))
        assert any(f["type"] == "subdomain_takeover" for f in out)
    with patch.object(sdt, "fetch", benign):
        assert asyncio.run(sdt.run(_agent("http://ok.example.test/"))) == []
