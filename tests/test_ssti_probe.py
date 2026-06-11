"""Tests for the SSTI (server-side template injection) vuln worker."""

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401  (registers workers)
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner, list_workers
from core.swarm_workers.vuln._http import HttpResp


def _agent(target="http://t", timeout=5.0):
    return SwarmAgent(
        agent_id="t",
        objective="x",
        target=target,
        technique="ssti_probe",
        payload={},
        timeout_s=timeout,
    )


def _run(fake, target="http://t"):
    async def go():
        with patch(
            "core.swarm_workers.vuln.ssti_probe.fetch", side_effect=fake
        ):
            return await get_worker_runner("vuln", "ssti_probe")(_agent(target))

    return asyncio.run(go())


def test_registered():
    assert "ssti_probe" in list_workers("vuln")


def test_true_positive_evaluated_marker():
    """Live payload (operator intact) reflects 49; control (7x7) does not."""

    async def fake(method, url, **kw):
        # The control payload mutates the operator -> contains "7x7".
        if "7x7" in url:
            return HttpResp(200, {}, "Result: 7x7 echoed back", url)
        # The live payload preserves "7*7"; engine evaluates it to 49.
        if "7%2A7" in url or "7*7" in url:
            return HttpResp(200, {}, "Result: 49", url)
        return HttpResp(200, {}, "nothing here", url)

    findings = _run(fake)
    assert findings, "expected an SSTI finding"
    f = findings[0]
    assert "ssti" in f["vuln_type"]
    assert f["cwe"] == "CWE-1336"
    assert f["severity"] == "critical"
    assert "parameter" in f and "payload" in f
    assert 0.0 < f["confidence"] <= 1.0


def test_fp_guard_marker_already_present():
    """Page always contains '49' (e.g. a price) -> no finding.

    Because the control response ALSO carries '49', the worker must suppress
    the marker and not flag.
    """

    async def fake(method, url, **kw):
        # Every response carries the literal marker, evaluated or not.
        return HttpResp(200, {}, "Total price: $49.00", url)

    findings = _run(fake)
    assert findings == [], "must not flag pages that already contain '49'"


def test_fp_guard_benign_reflection():
    """Payload reflected verbatim but never evaluated -> no finding."""

    async def fake(method, url, **kw):
        # Reflect whatever was injected without evaluating it. Neither the
        # control nor the live response yields the bare evaluated marker "49".
        return HttpResp(200, {}, "you searched for something", url)

    findings = _run(fake)
    assert findings == []


def test_error_signature_medium():
    """A template-engine error (only under live payload) -> medium finding."""

    async def fake(method, url, **kw):
        if "7x7" in url:  # control -> clean
            return HttpResp(200, {}, "ok", url)
        # Live payload -> engine throws a recognizable error.
        return HttpResp(500, {}, "jinja2.exceptions.TemplateSyntaxError: bad", url)

    findings = _run(fake)
    assert findings, "expected an error-signature SSTI finding"
    f = findings[0]
    assert f["vuln_type"] == "ssti_error"
    assert f["severity"] == "medium"
    assert f["cwe"] == "CWE-1336"


def test_network_error_no_crash():
    """fetch returning None must not raise and yields no findings."""

    async def fake(method, url, **kw):
        return None

    assert _run(fake) == []


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-v"]))
