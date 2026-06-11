import asyncio
import base64
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner, list_workers
from core.swarm_workers.vuln._http import HttpResp


def _agent(target="http://t/index.php?file=home", timeout=5.0):
    return SwarmAgent(
        agent_id="t", objective="x", target=target,
        technique="lfi", payload={}, timeout_s=timeout,
    )


def _run(fake, agent=None):
    async def go():
        with patch("core.swarm_workers.vuln.lfi.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "lfi")(agent or _agent())
    return asyncio.run(go())


# --- registration -----------------------------------------------------------

def test_registered():
    assert "lfi" in list_workers("vuln")


# --- true positives ---------------------------------------------------------

def test_passwd_leak_is_flagged():
    passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

    async def fake(method, url, **kw):
        if "etc%2Fpasswd" in url or "etc/passwd" in url:
            return HttpResp(200, {}, passwd, url)
        return HttpResp(200, {}, "<html>welcome home</html>", url)

    findings = _run(fake)
    assert findings, "expected an LFI finding for /etc/passwd leak"
    f = findings[0]
    assert "lfi" in f["vuln_type"]
    assert f["vuln_type"].startswith("lfi:")
    assert f["cwe"] == "CWE-22"
    assert f["parameter"] == "file"
    assert 0.0 <= f["confidence"] <= 1.0


def test_passwd_alt_shadow_shape_is_flagged():
    # root line where the password field is not literally 'x'
    body = "root:$6$abc.def/:0:0:root:/root:/bin/sh\n"

    async def fake(method, url, **kw):
        if "passwd" in url:
            return HttpResp(200, {}, body, url)
        return HttpResp(200, {}, "ok", url)

    findings = _run(fake)
    assert findings and "lfi" in findings[0]["vuln_type"]


def test_win_ini_leak_is_flagged():
    win = "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n"

    async def fake(method, url, **kw):
        if "win.ini" in url:
            return HttpResp(200, {}, win, url)
        return HttpResp(200, {}, "ok", url)

    findings = _run(fake)
    assert findings, "expected an LFI finding for win.ini leak"
    assert "lfi" in findings[0]["vuln_type"]


def test_php_wrapper_base64_php_is_flagged():
    php_src = b"<?php $secret = 'admin'; include($_GET['file']); ?>" * 2
    blob = base64.b64encode(php_src).decode()

    async def fake(method, url, **kw):
        if "php://filter" in url or "php%3A" in url:
            return HttpResp(200, {}, blob, url)
        return HttpResp(200, {}, "ok", url)

    findings = _run(fake)
    assert findings, "expected an LFI finding for base64-decodes-to-PHP"
    assert "php" in findings[0]["evidence"].lower()


# --- false-positive guards --------------------------------------------------

def test_benign_response_no_finding():
    async def fake(method, url, **kw):
        return HttpResp(200, {}, "<html>nothing to see here</html>", url)

    assert _run(fake) == []


def test_control_already_contains_signature_is_suppressed():
    # The page legitimately echoes a passwd-like line for ANY value (incl.
    # the benign control). The baseline guard must suppress this param.
    passwd = "root:x:0:0:root:/root:/bin/bash\n"

    async def fake(method, url, **kw):
        # Every response contains the signature, including the control.
        return HttpResp(200, {}, passwd, url)

    assert _run(fake) == []


def test_random_base64_not_php_no_finding():
    blob = base64.b64encode(b"just some harmless binary data, not php at all!!").decode()

    async def fake(method, url, **kw):
        return HttpResp(200, {}, f"token={blob}", url)

    assert _run(fake) == []


def test_fetch_failure_no_finding():
    async def fake(method, url, **kw):
        return None

    assert _run(fake) == []


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))