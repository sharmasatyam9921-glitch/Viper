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


def _trailing_number(url: str) -> float:
    """The last number embedded ANYWHERE in the injected value (no `sleep` needed).
    Models a number-parsing endpoint (?limit/?count/?page) whose latency tracks an
    integer in the query — including the bare-number control 'viperctl6'."""
    m = _re.findall(r"[\d.]+", _unquote_plus(url))
    return float(m[-1]) if m else 0.0


# Virtual-clock harness: instead of REAL sleeps (which made median-of-N tests take
# minutes), each test supplies a latency_fn(url, state)->seconds. A fake fetch
# advances a virtual clock by that latency, and command_injection._clock is patched
# to read it — so the worker measures the exact simulated time with ZERO real
# sleeping, and asyncio's own clock is untouched. Tests run at PRODUCTION constants
# (SHORT=2, LONG=6, _SLEEP_SAMPLES=3), exercising the real thresholds, instantly.
class _VClock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t


def _run_vclock(latency_fn, agent=None):
    clock = _VClock()
    state = {}

    async def fake(method, url, **kw):
        clock.t += max(0.0, latency_fn(url, state))  # advance virtual time
        return _resp(body="done")

    async def go():
        patches = [
            patch("core.swarm_workers.vuln.command_injection._clock", clock.now),
            patch("core.swarm_workers.vuln.command_injection.fetch", side_effect=fake),
        ]
        for p in patches:
            p.start()
        try:
            return await get_worker_runner("vuln", "command_injection")(agent or _agent())
        finally:
            for p in patches:
                p.stop()
    return asyncio.run(go())


_BASE = 0.02  # simulated base latency


def test_time_based_blind_fallback_scaling_true_positive():
    """A server that actually sleeps the injected duration: each sleep probe adds
    ~N over its adjacent control and the deltas scale -> blind finding."""
    findings = _run_vclock(lambda url, st: _BASE + _injected_sleep_seconds(url))
    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_type"].startswith("rce:cmdi:")
    assert f["cwe"] == "CWE-78"
    assert f["confidence"] < 0.9  # blind is lower-confidence than reflection
    assert "sleep" in f["payload"]


def test_time_based_uniform_slow_not_flagged():
    """A uniformly slow / laggy server (every request ~constant, sleep ignored).
    The control taken moments before is just as slow -> delta ~0 -> not flagged."""
    findings = _run_vclock(lambda url, st: 5.0)  # constant, command ignored
    assert findings == [], f"uniformly-slow latency wrongly flagged as RCE: {findings}"


def test_time_based_monotonic_degradation_not_flagged():
    """Regression (HIGH-sev FP found by adversarial review): a server whose latency
    GROWS with each request (GC pressure / memory leak under scan load), ignoring
    the command. The paired control (taken moments before each probe) cancels the
    drift: delta ~= one request-gap, far below the commanded sleep -> not flagged."""
    def lat(url, st):
        st["n"] = st.get("n", 0) + 1
        return 0.5 * st["n"]  # each request slower than the last
    findings = _run_vclock(lat)
    assert findings == [], f"monotonic latency drift wrongly flagged as RCE: {findings}"


def test_time_based_probe_spike_not_flagged():
    """A sleep probe that spikes FAR beyond the commanded duration is a latency
    spike, not a sleep — the short upper bound (delta <= N + _DELTA_HI) rejects it."""
    findings = _run_vclock(
        lambda url, st: _BASE + (_injected_sleep_seconds(url) + 5.0
                                 if _injected_sleep_seconds(url) else 0.0))
    assert findings == [], f"over-long spike wrongly flagged as RCE: {findings}"


def test_time_based_subsleep_not_flagged():
    """Responses come back FASTER than commanded (server never actually slept):
    delta < N -> rejected by the lower bound of the paired differential."""
    findings = _run_vclock(lambda url, st: _BASE + _injected_sleep_seconds(url) * 0.4)
    assert findings == [], f"sub-sleep latency wrongly flagged as RCE: {findings}"


def test_time_based_inconsistent_long_not_flagged():
    """The long delay must be CONSISTENT: if a MAJORITY of the long samples
    collapse (so the median is low), it is noise, not a `sleep` — no finding."""
    def lat(url, st):
        n = _injected_sleep_seconds(url)
        if abs(n - 6.0) < 1e-6:                 # a LONG sleep probe
            st["lng"] = st.get("lng", 0) + 1
            return _BASE if st["lng"] >= 2 else _BASE + 6.0  # 2 of 3 collapse
        return _BASE + n                         # short probe / control
    findings = _run_vclock(lat)
    assert findings == [], f"inconsistent long delay wrongly flagged: {findings}"


def test_time_based_jitter_median_recovers_true_positive():
    """Regression (FN found by adversarial review): a GENUINELY vulnerable server
    with request-to-request jitter — one long sample comes up short. The median of
    several samples recovers the true sleep, so the real injection is still flagged
    (the old single-sample + reproduction check missed it)."""
    def lat(url, st):
        n = _injected_sleep_seconds(url)
        if abs(n - 6.0) < 1e-6:                 # LONG probe: first draw jittery-short
            st["lng"] = st.get("lng", 0) + 1
            return _BASE + (3.5 if st["lng"] == 1 else 6.0)
        return _BASE + n
    findings = _run_vclock(lat)
    assert len(findings) == 1, "median should recover a real sleep through jitter"


def test_time_based_numeric_latency_not_flagged():
    """Regression (FP found by adversarial review): a non-executing endpoint whose
    latency scales with a NUMBER parsed from the query (?limit/?count/?page). The
    probes embed 2 then 6, so the delta scales — but the bare-number control
    'viperctl6' (no shell metacharacter) reproduces the delay, proving the latency
    tracks the number, not shell execution. Must NOT be flagged."""
    # latency follows ANY trailing number (incl. the bare-number control) — no shell
    findings = _run_vclock(lambda url, st: _BASE + _trailing_number(url))
    assert findings == [], f"number-driven latency wrongly flagged as RCE: {findings}"


def test_time_based_slow_base_true_positive():
    """Regression (FN found by adversarial review): a genuinely vulnerable server
    with a SLOW base page. The paired control absorbs the base, so the sleep delta
    is still ~N -> flagged."""
    findings = _run_vclock(lambda url, st: 3.0 + _injected_sleep_seconds(url))
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


def test_whitespace_collapse_sanitizer_not_flagged():
    """Regression (gate-FP): a sanitizer that strips shell metacharacters AND
    collapses whitespace reflects ';echo MARKER' as 'echoMARKER' (glued). The raw
    marker must NOT be scored as executed command output."""
    import re as _re
    from urllib.parse import urlsplit, parse_qs, unquote_plus

    async def fake(method, url, **kw):
        q = parse_qs(urlsplit(url).query)
        val = next((v[0] for v in q.values() if v), "")
        clean = _re.sub(r"\s+", "", _re.sub(r"[;|&`$()<>]", "", unquote_plus(val)))
        return _resp(body=f"<p>Results for {clean}</p>")

    findings = _run(fake)
    assert findings == [], f"whitespace-collapse reflection wrongly flagged: {findings}"


def test_bare_token_highlighter_reflection_not_flagged():
    """Regression (adversarial review): a search highlighter that extracts and
    re-displays the LAST whitespace/;-delimited token echoes the BARE marker (not
    the whole payload), slipping past the injected-value strip in
    _executed_not_reflected. The inert-marker reflection guard sends the marker as
    benign, metachar-free data and catches that the endpoint echoes it verbatim."""
    import re as _re
    from urllib.parse import urlsplit, parse_qs, unquote_plus

    async def fake(method, url, **kw):
        q = parse_qs(urlsplit(url).query)
        val = unquote_plus(next((v[0] for v in q.values() if v), ""))
        # highlight only the LAST token, split on shell separators / whitespace
        last = _re.split(r"[;\s|&`]+", val)[-1] if val else ""
        return _resp(body=f"<p>Showing results for <mark>{last}</mark></p>")

    findings = _run(fake)
    assert findings == [], f"bare-token reflection wrongly flagged as RCE: {findings}"


def test_metacharacter_gated_reflection_not_flagged():
    """Regression (adversarial re-review): an endpoint that echoes the extracted
    marker ONLY when a shell separator is present (so the plain-space inert probe
    sees nothing) but never executes. The second inert probe ';true <marker>'
    carries a metacharacter yet cannot emit the marker, exposing the reflection."""
    import re as _re
    from urllib.parse import urlsplit, parse_qs, unquote_plus

    _MARK = _re.compile(r"CMDI[0-9a-f]{8}")

    async def fake(method, url, **kw):
        q = parse_qs(urlsplit(url).query)
        val = unquote_plus(next((v[0] for v in q.values() if v), ""))
        if _re.search(r"[;|&`]", val):           # reflects only when a metachar is seen
            m = _MARK.search(val)
            if m:
                return _resp(body=f"Extracted token: {m.group(0)}")
        return _resp(body="Control: OK")

    findings = _run(fake)
    assert findings == [], f"metachar-gated reflection wrongly flagged as RCE: {findings}"


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
    test_time_based_inconsistent_long_not_flagged()
    test_time_based_jitter_median_recovers_true_positive()
    test_time_based_numeric_latency_not_flagged()
    test_time_based_slow_base_true_positive()
    test_reflected_payload_is_not_command_injection()
    print("ok")
