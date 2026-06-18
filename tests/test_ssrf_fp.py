"""Regression tests for the SSRF worker false positive.

Audit scenario: a benign endpoint that merely REFLECTS the submitted `url`
parameter value back in its response body (an open-redirect validator, a
search page, an "invalid URL" error page) without ever fetching it. Because
the AWS-IMDS payload http://169.254.169.254/latest/meta-data/ literally
contains the string "169.254.169.254", which used to be one of the metadata
markers, the reflected payload produced a marker that the benign
http://example.com/ baseline lacked -> false-positive SSRF finding.

The fix: markers must be SERVICE-EMITTED content only (never a substring of
the payload we send), and the reflected payload is stripped from the body
before marker matching so pure reflection can never trip any marker.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401  (registers workers)
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner
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


def _echoed_value(url: str) -> str:
    """Return the value the endpoint received for the `url` param (what it reflects)."""
    from urllib.parse import parse_qs, urlsplit
    qs = parse_qs(urlsplit(url).query)
    return qs.get("url", [""])[0]


# --- (a) FALSE POSITIVE: pure reflection of the payload, no fetch -------------
def test_reflected_payload_false_positive_not_flagged():
    """Benign endpoint reflects the submitted url value (open-redirect validator
    / search page) but NEVER fetches it. Must NOT be reported as SSRF."""
    async def fake(method, url, **kw):
        echoed = _echoed_value(url)
        # 400 JSON error echoing the rejected URL (open-redirect validator).
        body = (
            '{"message":"The supplied url \'' + echoed + "' is not an "
            'allowed redirect target."}'
        )
        return HttpResp(400, {"content-type": "application/json"}, body, url)

    assert _run(fake) == []


# --- (b) TRUE POSITIVE: server actually fetches IMDS and reflects it ----------
def test_metadata_fetched_true_positive_still_fires():
    """Server proxies the internal URL and returns the IMDS service's OWN
    output (instance-id / IAM creds) that the benign baseline never contains.
    This is genuine SSRF and MUST still fire."""
    async def fake(method, url, **kw):
        echoed = _echoed_value(url)
        if "example.com" in url:
            # benign remote fetch — stable baseline, no metadata
            return HttpResp(200, {}, "Example Domain", url)
        if "169.254.169.254" in url:
            # genuine SSRF: the IMDS service emitted these, NOT a reflection of
            # the payload. The payload string is absent from this body.
            return HttpResp(
                200, {},
                "instance-id: i-0abc123\n"
                "iam/security-credentials/admin\n"
                "AccessKeyId: AKIAEXAMPLE",
                url,
            )
        # other internal payloads just echo (reflection, not a fetch)
        return HttpResp(200, {}, f"fetched {echoed}", url)

    findings = _run(fake)
    assert len(findings) == 1
    f = findings[0]
    assert "ssrf" in f["vuln_type"]
    assert f["cwe"] == "CWE-918"
    assert f["parameter"] == "url"
    assert f["payload"] == "http://169.254.169.254/latest/meta-data/"
