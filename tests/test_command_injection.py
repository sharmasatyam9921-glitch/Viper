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


# Scaled-down sleep constants so the tests run fast but still exercise the real
# floor + scaling + reproduction logic. Ratios mirror production
# (SHORT=0.3, LONG=0.7, ABS_TOL=0.08 -> floors 0.22/0.62, SCALE_TOL=0.12).
def _patch_fast_timing():
    return [
        patch("core.swarm_workers.vuln.command_injection._SLEEP_SHORT", 0.3),
        patch("core.swarm_workers.vuln.command_injection._SLEEP_LONG", 0.7),
        patch("core.swarm_workers.vuln.command_injection._ABS_TOL", 0.08),
        patch("core.swarm_workers.vuln.command_injection._SCALE_TOL", 0.12),
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


def test_time_based_blind_fallback_scaling_true_positive():
    """A server that actually sleeps the injected duration -> the delay SCALES
    (sleep 0.3 -> ~0.3s, sleep 0.7 -> ~0.7s) -> blind finding."""
    async def fake(method, url, **kw):
        n = _injected_sleep_seconds(url)
        if n:
            await asyncio.sleep(n)  # real shell would sleep the commanded time
        return _resp(body="done")

    findings = _run_fast(fake)
    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_type"].startswith("rce:cmdi:")
    assert f["cwe"] == "CWE-78"
    assert f["confidence"] < 0.9  # blind is lower-confidence than reflection
    assert "sleep" in f["payload"]
    assert "scaled" in f["evidence"]


def test_time_based_load_spike_not_flagged():
    """Regression (found live on Juice Shop under benchmark load): a NON-vulnerable
    target whose latency spikes ~uniformly regardless of the sleep duration must
    NOT be flagged. The delay does not scale with the command, so it is noise."""
    async def fake(method, url, **kw):
        n = _injected_sleep_seconds(url)
        # Every sleep probe spikes to ~0.8s irrespective of N (3s vs 7s) — exactly
        # the load-latency signature. Old single-threshold logic flagged this.
        if n:
            await asyncio.sleep(0.8)
        return _resp(body="done")

    findings = _run_fast(fake)
    assert findings == [], f"non-scaling latency wrongly flagged as RCE: {findings}"


def test_time_based_single_spike_not_flagged():
    """One isolated spike on the SHORT probe, with the LONG probe fast, must not
    flag — the long probe must also wait ~its full duration."""
    state = {"short_seen": False}

    async def fake(method, url, **kw):
        n = _injected_sleep_seconds(url)
        if n and not state["short_seen"]:
            state["short_seen"] = True
            await asyncio.sleep(0.9)  # lone spike on the first (short) probe
        # long probe (and everything after) returns fast
        return _resp(body="done")

    findings = _run_fast(fake)
    assert findings == [], f"lone latency spike wrongly flagged as RCE: {findings}"


def test_time_based_subsleep_not_flagged():
    """Regression (the survivor under benchmark load): responses come back FASTER
    than the commanded sleep (sleep 3 -> 2.1s, sleep 7 -> 5.0s) — load rose
    between probes so the delta scaled, but the server never actually slept. The
    absolute floor (a real `sleep N` can't return faster than N) must reject it."""
    async def fake(method, url, **kw):
        n = _injected_sleep_seconds(url)
        if n:
            await asyncio.sleep(n * 0.5)  # always returns in HALF the commanded time
        return _resp(body="done")

    findings = _run_fast(fake)
    assert findings == [], f"sub-sleep latency wrongly flagged as RCE: {findings}"


def test_time_based_reproduction_guard():
    """Floors and scaling pass on the first pair, but the confirmation (repeat
    long) probe is fast — a coincidental spike that won't repeat must not flag."""
    long_seen = {"n": 0}

    async def fake(method, url, **kw):
        n = _injected_sleep_seconds(url)
        if abs(n - 0.7) < 1e-6:           # a LONG probe
            long_seen["n"] += 1
            if long_seen["n"] >= 2:       # the reproduction probe: collapses
                return _resp(body="done")
            await asyncio.sleep(0.7)
        elif n:                            # the SHORT probe
            await asyncio.sleep(0.3)
        return _resp(body="done")

    findings = _run_fast(fake)
    assert findings == [], f"non-reproducing spike wrongly flagged as RCE: {findings}"


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
    test_time_based_load_spike_not_flagged()
    test_time_based_single_spike_not_flagged()
    test_time_based_subsleep_not_flagged()
    test_time_based_reproduction_guard()
    test_reflected_payload_is_not_command_injection()
    print("ok")
