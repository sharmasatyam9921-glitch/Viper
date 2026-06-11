import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401  (registers workers)
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner, list_workers
from core.swarm_workers.vuln._http import HttpResp


def _agent(target="http://t/?url=x", timeout=5.0):
    return SwarmAgent(
        agent_id="t", objective="x", target=target,
        technique="ssrf", payload={}, timeout_s=timeout,
    )


def _run(fake, target="http://t/?url=x"):
    async def go():
        with patch("core.swarm_workers.vuln.ssrf.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "ssrf")(_agent(target))
    return asyncio.run(go())


# --- registration -----------------------------------------------------------
def test_registered():
    assert "ssrf" in list_workers("vuln")


# --- true positive ----------------------------------------------------------
def test_metadata_reflected_is_flagged():
    """Internal payload returns IMDS markers the benign baseline lacks."""
    async def fake(method, url, **kw):
        if "example.com" in url:
            return HttpResp(200, {}, "Example Domain — nothing here", url)
        if "169.254.169.254" in url:
            return HttpResp(
                200, {},
                "ami-id\ninstance-id\niam/security-credentials/role",
                url,
            )
        return HttpResp(200, {}, "ok", url)

    findings = _run(fake)
    assert len(findings) == 1
    f = findings[0]
    assert "ssrf" in f["vuln_type"]
    assert f["cwe"] == "CWE-918"
    assert f["parameter"] == "url"
    assert f["payload"] == "http://169.254.169.254/latest/meta-data/"
    assert 0.0 <= f["confidence"] <= 1.0


# --- false-positive guard: benign baseline already has the markers ----------
def test_marker_in_baseline_not_flagged():
    """If the benign fetch ALSO returns the markers, it's page content, not SSRF."""
    async def fake(method, url, **kw):
        # Every fetched page mentions instance-id — including the benign one.
        return HttpResp(200, {}, "docs about instance-id and ami-id", url)

    assert _run(fake) == []


# --- false-positive guard: normal app, no markers anywhere ------------------
def test_no_markers_not_flagged():
    async def fake(method, url, **kw):
        return HttpResp(200, {}, "<html>normal page</html>", url)

    assert _run(fake) == []


# --- non-url params are skipped (no candidate → still safe) -----------------
def test_only_url_like_params_probed():
    """A non-url query param shouldn't be probed; defaults kick in but stay clean."""
    seen = []

    async def fake(method, url, **kw):
        seen.append(url)
        return HttpResp(200, {}, "clean", url)

    findings = _run(fake, target="http://t/?q=hello")
    assert findings == []
    # The non-url 'q' param must not be an injection point.
    assert not any("q=http" in u for u in seen)


# --- network failure tolerated ----------------------------------------------
def test_fetch_none_no_crash():
    async def fake(method, url, **kw):
        return None

    assert _run(fake) == []
