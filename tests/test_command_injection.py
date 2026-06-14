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


def test_time_based_blind_fallback():
    """No reflection, but sleep payloads delay markedly -> blind finding."""
    from urllib.parse import unquote

    async def fake(method, url, **kw):
        u = unquote(url)
        # echo payloads never reflect (blind), sleep payloads delay ~5s.
        # urlencode renders the space as '+', so match on the command name.
        if "sleep" in u:
            await asyncio.sleep(0.25)  # scaled-down delta; worker measures real time
            return _resp(body="done")
        return _resp(body="done")

    # Patch the threshold so the scaled-down sleep counts as a delay.
    with patch(
        "core.swarm_workers.vuln.command_injection._TIME_DELTA_MIN", 0.1
    ):
        findings = _run(fake)

    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_type"].startswith("rce:cmdi:")
    assert f["cwe"] == "CWE-78"
    assert f["confidence"] < 0.9  # blind is lower-confidence than reflection
    assert "sleep" in f["payload"]


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
    test_time_based_blind_fallback()
    test_reflected_payload_is_not_command_injection()
    print("ok")
