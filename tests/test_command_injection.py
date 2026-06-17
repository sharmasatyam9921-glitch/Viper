import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner, list_workers
from core.swarm_workers.vuln._http import HttpResp


def _agent(target="http://t/run?cmd=ls", timeout=12.0):
    return SwarmAgent(
        agent_id="t", objective="x", target=target,
        technique="command_injection", payload={}, timeout_s=timeout,
    )


def _run(fake, agent=None):
    async def go():
        with patch(
            "core.swarm_workers.vuln.command_injection.fetch", side_effect=fake
        ):
            return await get_worker_runner("vuln", "command_injection")(
                agent or _agent()
            )
    return asyncio.run(go())


def _resp(body="ok", status=200):
    return HttpResp(status=status, headers={}, body=body, final_url="http://t/")


def test_registered():
    assert "command_injection" in list_workers("vuln")


def test_marker_reflection_true_positive():
    """Injected echo payload surfaces the unique marker -> finding."""
    async def fake(method, url, **kw):
        # The control value (no shell metachars) never reflects the marker;
        # any URL carrying an `echo CMDI...` payload echoes the marker back.
        if "echo+CMDI" in url or "echo%20CMDI" in url or "echo CMDI" in url:
            # Pull the marker out of the encoded payload and reflect it.
            import re
            m = re.search(r"CMDI[0-9a-f]{8}", urllib_unquote(url))
            marker = m.group(0) if m else "CMDIdeadbeef"
            return _resp(body=f"output: {marker}\n")
        return _resp(body="output: viperctl\n")

    def urllib_unquote(u):
        from urllib.parse import unquote
        return unquote(u)

    findings = _run(fake)
    assert len(findings) == 1
    f = findings[0]
    assert "rce" in f["vuln_type"]
    assert f["vuln_type"].startswith("rce:cmdi:")
    assert f["cwe"] == "CWE-78"
    assert f["severity"] == "critical"
    assert f["parameter"] == "cmd"


def test_benign_response_no_finding():
    """A target that never reflects the marker and never delays -> no finding."""
    async def fake(method, url, **kw):
        # Static body, same fast timing for every request.
        return _resp(body="<html>welcome, viperctl</html>")

    findings = _run(fake)
    assert findings == []


def test_marker_already_reflected_is_suppressed():
    """If the control itself surfaces a CMDI-looking marker, no false positive."""
    async def fake(method, url, **kw):
        # Body always contains a CMDI token regardless of injection -> the
        # control check sees the marker and the param is skipped.
        return _resp(body="echo of CMDIaaaaaaaa always present")

    findings = _run(fake)
    assert findings == []


import re as _re
from urllib.parse import unquote_plus as _unquote_plus


def _injected_sleep_seconds(url: str) -> float:
    """Parse the `sleep N` duration out of an injected URL (0.0 if none)."""
    m = _re.search(r"sleep\s+([\d.]+)", _unquote_plus(url))
    return float(m.group(1)) if m else 0.0


# Scaled-down constants so the tests run fast but still exercise the real
# paired-control differential. Ratios mirror production (SHORT=0.3, LONG=0.7,
# ABS_TOL=0.08, DELTA_HI=0.35, SCALE_TOL=0.12). The detector now differences each
# sleep probe against a benign control taken immediately before it, so the fakes
# model latency as (base + injected_sleep) for sleep probes and base for controls.
def _patch_fast_timing():
    return [
        patch("core.swarm_workers.vuln.command_injection._SLEEP_SHORT", 0.3),
        patch("core.swarm_workers.vuln.command_injection._SLEEP_LONG", 0.7),
        patch("core.swarm_workers.vuln.command_injection._ABS_TOL", 0.08),
        patch("core.swarm_workers.vuln.command_injection._DELTA_HI", 0.35),
        patch("core.swarm_workers.vuln.command_injection._SCALE_TOL", 0.12),
        patch("core.swarm_workers.vuln.command_injection._BLIND_HEADROOM", 2.0),
    ]


def _run_fast(fake, agent=None):
    async def go():
        patches = _patch_fast_timing() + [
            patch("core.swarm_workers.vuln.command_injection.fetch", side_effect=fake)
        ]
        for p in patches:
            p.start()
        try:
            return await get_worker_runner("vuln", "command_injection")(agent or _agent())
        finally:
            for p in patches:
                p.stop()
    return asyncio.run(go())


_BASE = 0.02  # simulated base latency for the fakes


def test_time_based_blind_fallback_scaling_true_positive():
    """A server that actually sleeps the injected duration: each sleep probe adds
    ~N over its adjacent control and the deltas scale -> blind finding."""
    async def fake(method, url, **kw):
        n = _injected_sleep_seconds(url)
        await asyncio.sleep(_BASE + n)  # control(n=0) -> base; sleep probe -> base+N
        return _resp(body="done")

    findings = _run_fast(fake)
    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_type"].startswith("rce:cmdi:")
    assert f["cwe"] == "CWE-78"
    assert f["confidence"] < 0.9  # blind is lower-confidence than reflection
    assert "sleep" in f["payload"]


def test_time_based_uniform_slow_not_flagged():
    """A uniformly slow / laggy server (every request ~constant, sleep ignored).
    The control taken moments before is just as slow -> delta ~0 -> not flagged."""
    async def fake(method, url, **kw):
        await asyncio.sleep(0.5)  # constant, regardless of the injected command
        return _resp(body="done")

    findings = _run_fast(fake)
    assert findings == [], f"uniformly-slow latency wrongly flagged as RCE: {findings}"


def test_time_based_monotonic_degradation_not_flagged():
    """Regression (HIGH-sev FP found by adversarial review): a server whose latency
    GROWS over time (GC pressure / memory leak under scan load), ignoring the
    command. Each successive probe is slower, which defeated a floor+scaling+repeat
    check. The paired control (taken moments before each probe) cancels the drift:
    delta ~= one request-gap, far below the commanded sleep -> not flagged."""
    calls = {"n": 0}

    async def fake(method, url, **kw):
        calls["n"] += 1
        await asyncio.sleep(0.04 * calls["n"])  # each request slower than the last
        return _resp(body="done")

    findings = _run_fast(fake)
    assert findings == [], f"monotonic latency drift wrongly flagged as RCE: {findings}"


def test_time_based_probe_spike_not_flagged():
    """A sleep probe that spikes FAR beyond the commanded duration is a latency
    spike, not a sleep — the upper bound (delta <= N + _DELTA_HI) rejects it."""
    async def fake(method, url, **kw):
        n = _injected_sleep_seconds(url)
        await asyncio.sleep(_BASE + (n + 1.0 if n else 0.0))  # +1.0s over commanded
        return _resp(body="done")

    findings = _run_fast(fake)
    assert findings == [], f"over-long spike wrongly flagged as RCE: {findings}"


def test_time_based_subsleep_not_flagged():
    """Responses come back FASTER than commanded (server never actually slept):
    delta < N -> rejected by the lower bound of the paired differential."""
    async def fake(method, url, **kw):
        n = _injected_sleep_seconds(url)
        await asyncio.sleep(_BASE + n * 0.4)  # only 40% of the commanded sleep
        return _resp(body="done")

    findings = _run_fast(fake)
    assert findings == [], f"sub-sleep latency wrongly flagged as RCE: {findings}"


def test_time_based_reproduction_guard():
    """First short+long pair passes, but the reproduction (repeat long) probe
    collapses — a coincidental spike that won't repeat must not flag."""
    long_seen = {"n": 0}

    async def fake(method, url, **kw):
        n = _injected_sleep_seconds(url)
        if abs(n - 0.7) < 1e-6:                 # a LONG sleep probe
            long_seen["n"] += 1
            if long_seen["n"] >= 2:             # reproduction probe: collapses to base
                await asyncio.sleep(_BASE)
            else:
                await asyncio.sleep(_BASE + 0.7)
        elif n:                                  # SHORT sleep probe
            await asyncio.sleep(_BASE + n)
        else:                                    # control
            await asyncio.sleep(_BASE)
        return _resp(body="done")

    findings = _run_fast(fake)
    assert findings == [], f"non-reproducing spike wrongly flagged as RCE: {findings}"


def test_time_based_slow_base_true_positive():
    """Regression (FN found by adversarial review): a genuinely vulnerable server
    with a SLOW base page (was missed by the old noise-floor skip gate). The
    paired control absorbs the base, so the sleep delta is still ~N -> flagged."""
    async def fake(method, url, **kw):
        n = _injected_sleep_seconds(url)
        await asyncio.sleep(0.5 + n)  # slow 0.5s base on EVERY request + real sleep
        return _resp(body="done")

    findings = _run_fast(fake)
    assert len(findings) == 1, "slow-base vulnerable server should still be flagged"
    assert findings[0]["vuln_type"].startswith("rce:cmdi:")


def test_reflected_payload_is_not_command_injection():
    """Regression (found live on www.newegg.com): an app that reflects the query
    string into a canonical / og:url <meta> tag echoes the WHOLE payload —
    including the unique marker — back into the body. That is reflection, NOT
    execution, and must NOT be flagged as a critical RCE."""
    from urllib.parse import urlsplit, parse_qs, quote_plus

    async def fake(method, url, **kw):
        # Reflect every param value, URL-encoded, into an og:url meta tag — the
        # exact ASP.NET/IIS behaviour that produced the false positive.
        q = parse_qs(urlsplit(url).query)
        reflected = "".join(
            f'<meta property="og:url" content="http://t/?p={quote_plus(v[0])}" />'
            for v in q.values()
        )
        return HttpResp(status=200, headers={}, body="<html>" + reflected + "</html>",
                        final_url="http://t/")

    findings = _run(fake)
    assert findings == [], f"reflected payload wrongly flagged as RCE: {findings}"


if __name__ == "__main__":
    test_registered()
    test_marker_reflection_true_positive()
    test_benign_response_no_finding()
    test_marker_already_reflected_is_suppressed()
    test_time_based_blind_fallback_scaling_true_positive()
    test_time_based_uniform_slow_not_flagged()
    test_time_based_monotonic_degradation_not_flagged()
    test_time_based_probe_spike_not_flagged()
    test_time_based_subsleep_not_flagged()
    test_time_based_reproduction_guard()
    test_time_based_slow_base_true_positive()
    test_reflected_payload_is_not_command_injection()
    print("ok")
