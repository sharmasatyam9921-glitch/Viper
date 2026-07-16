"""WAF-adaptive injection workers: when the raw attack is WAF-blocked the worker
retries encoding mutations (via _bypass.adaptive_fetch) and re-runs the SAME
differential — so a hardened/WAF-fronted-but-vulnerable target is still found, while
an actually-blocked target yields NOTHING (never a fabricated success) and a clean
target takes the unchanged happy path.

The primary send uses the worker's own `fetch`; only a WAF block delegates to the
bypass engine (`_bypass.fetch`) — so both are patched here.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_workers.vuln import _bypass as bypass_mod  # noqa: E402
from core.swarm_workers.vuln import lfi as lfi_mod          # noqa: E402
from core.swarm_workers.vuln import xss_probe as xss_mod    # noqa: E402
from core.swarm_workers.vuln._bypass import reset_learning  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp          # noqa: E402

_PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
           "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
_BLOCK = HttpResp(403, {"content-type": "text/html"},
                  "Request blocked by Web Application Firewall", "u")
_BENIGN = HttpResp(200, {"content-type": "text/html"}, "hello, nothing here", "u")


class _Agent:
    def __init__(self, t):
        self.target = t
        self.timeout_s = 8.0
        self.payload = {}


def _injected(url: str) -> str:
    qs = parse_qs(urlsplit(url).query)
    return next((v[0] for v in qs.values() if v), "")


def _is_traversal(url: str) -> bool:
    v = _injected(url).lower()
    return ".." in v or "%2e" in v or "etc/passwd" in v or "%2f" in v


# ── LFI: server-emitted signature is payload-encoding-independent ─────────────
def _run_lfi(worker_fetch, attack_fetch):
    reset_learning()
    with patch.object(lfi_mod, "fetch", worker_fetch), \
         patch.object(bypass_mod, "fetch", attack_fetch):
        return asyncio.run(lfi_mod.run(_Agent("http://waf.test/read?file=x")))


def test_lfi_waf_bypass_confirms_past_the_wall():
    async def worker(method, url, timeout=10, **kw):
        # Control + keyword probes are benign; the raw traversal attack is WAF-blocked.
        return _BLOCK if _is_traversal(url) else _BENIGN

    n = {"i": 0}

    async def attack(method, url, timeout=10, **kw):
        n["i"] += 1
        # adaptive re-sends raw (blocked) then a mutation that leaks the signature.
        return _BLOCK if n["i"] == 1 else HttpResp(200, {}, _PASSWD, url)

    out = _run_lfi(worker, attack)
    assert any(f["vuln_type"] == "lfi:file" for f in out), "WAF-fronted LFI must be found"
    assert any("WAF-bypassed" in f.get("evidence", "") for f in out)
    assert n["i"] >= 2, "must have retried a mutation after the block"


def test_lfi_total_block_yields_nothing():
    async def worker(method, url, timeout=10, **kw):
        return _BLOCK if _is_traversal(url) else _BENIGN

    async def attack(method, url, timeout=10, **kw):
        return _BLOCK   # every variant blocked

    assert _run_lfi(worker, attack) == [], "an actually-blocked target must not fabricate"


def test_lfi_no_waf_happy_path_unchanged():
    async def worker(method, url, timeout=10, **kw):
        # Raw traversal succeeds (real read); control/keyword benign.
        if _injected(url).lower() in ("index", "file", "readme", "x"):
            return _BENIGN
        return HttpResp(200, {}, _PASSWD, url) if _is_traversal(url) else _BENIGN

    async def attack(method, url, timeout=10, **kw):
        raise AssertionError("adaptive bypass must NOT run when the raw payload isn't blocked")

    out = _run_lfi(worker, attack)
    assert any(f["vuln_type"] == "lfi:file" for f in out)
    assert all("WAF-bypassed" not in f.get("evidence", "") for f in out)


# ── XSS: only a decoding bypass preserves the reflected marker ────────────────
def _run_xss(worker_fetch, attack_fetch):
    reset_learning()
    with patch.object(xss_mod, "fetch", worker_fetch), \
         patch.object(bypass_mod, "fetch", attack_fetch):
        return asyncio.run(xss_mod.run(_Agent("http://waf.test/reflect?q=x")))


def test_xss_waf_bypass_confirms_when_marker_survives():
    async def worker(method, url, timeout=10, **kw):
        return _BLOCK   # raw payload WAF-blocked -> triggers the adaptive retry

    async def attack(method, url, timeout=10, **kw):
        val = _injected(url)
        # A url-encoded variant carries '%3c' after one decode; the app fully decodes
        # and reflects the ORIGINAL markup -> the reflection differential still fires.
        if "%3c" in val.lower():
            decoded = unquote(unquote(val))
            return HttpResp(200, {"content-type": "text/html"},
                            f"<html>{decoded}</html>", url)
        return _BLOCK

    out = _run_xss(worker, attack)
    assert any(f["type"].startswith("xss") for f in out), "WAF-fronted reflected XSS must be found"
    assert any("WAF-bypassed" in f.get("evidence", "") for f in out)


def test_xss_total_block_yields_nothing():
    async def worker(method, url, timeout=10, **kw):
        return _BLOCK

    async def attack(method, url, timeout=10, **kw):
        return _BLOCK

    assert _run_xss(worker, attack) == []


def test_xss_no_waf_happy_path_unchanged():
    async def worker(method, url, timeout=10, **kw):
        # Raw payload reflected unencoded, not blocked -> normal reflected-XSS find.
        val = unquote(_injected(url))
        return HttpResp(200, {"content-type": "text/html"}, f"<html>{val}</html>", url)

    async def attack(method, url, timeout=10, **kw):
        raise AssertionError("adaptive bypass must NOT run on the non-blocked happy path")

    out = _run_xss(worker, attack)
    assert any(f["type"].startswith("xss") for f in out)
    assert all("WAF-bypassed" not in f.get("evidence", "") for f in out)
