"""A late blind-vuln OOB callback (arriving just after the hunt) is rescued: the
gate waits a bounded window for outstanding canaries before deciding, so a genuine
late-firing SSRF/RCE/XXE is promoted instead of filed as a lead."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.audit_logger import AuditLogger  # noqa: E402
from core.hack_mode import HackMode  # noqa: E402
from core.hack_profile import LabProfile  # noqa: E402
from core.narrator import Narrator  # noqa: E402


class _FlagStore:
    def __init__(self, fired=False):
        self.fired = fired

    def has_interaction(self, token):
        return self.fired


class _OOB:
    def __init__(self, store):
        self.store = store


def _hm(tmp_path):
    audit = AuditLogger.for_hunt("t", hunts_dir=tmp_path / "h", db_path=tmp_path / "v.db")
    return HackMode(target="http://t/", profile=LabProfile(),
                    narrator=Narrator(quiet=True), audit=audit)


def _findings():
    return SimpleNamespace(findings=[{"vuln_type": "ssrf:blind", "oob_token": "canary-1"}])


def test_waits_and_returns_when_a_late_callback_fires(tmp_path):
    hm = _hm(tmp_path)
    store = _FlagStore()
    hm._oob = _OOB(store)
    result = _findings()

    async def go():
        async def fire():
            await asyncio.sleep(0.1)
            store.fired = True
        task = asyncio.create_task(fire())
        t0 = time.time()
        await hm._await_late_oob_callbacks(result, max_wait_s=2.0, poll_s=0.05)
        elapsed = time.time() - t0
        await task
        return elapsed
    elapsed = asyncio.run(go())
    assert store.fired                       # the canary fired within the window
    assert elapsed < 1.0                     # returned soon after the 0.1s callback


def test_bounded_wait_when_callback_never_arrives(tmp_path):
    hm = _hm(tmp_path)
    hm._oob = _OOB(_FlagStore(fired=False))

    async def go():
        t0 = time.time()
        await hm._await_late_oob_callbacks(_findings(), max_wait_s=0.3, poll_s=0.05)
        return time.time() - t0
    elapsed = asyncio.run(go())
    assert 0.3 <= elapsed < 1.5               # waited the full bounded window, then gave up


def test_noop_when_no_oob_server(tmp_path):
    hm = _hm(tmp_path)
    hm._oob = None

    async def go():
        t0 = time.time()
        await hm._await_late_oob_callbacks(_findings(), max_wait_s=5.0)
        return time.time() - t0
    assert asyncio.run(go()) < 0.1            # instant no-op


def test_noop_when_no_pending_token(tmp_path):
    hm = _hm(tmp_path)
    hm._oob = _OOB(_FlagStore(fired=True))    # token already has an interaction

    async def go():
        t0 = time.time()
        await hm._await_late_oob_callbacks(_findings(), max_wait_s=5.0)
        return time.time() - t0
    assert asyncio.run(go()) < 0.1            # nothing outstanding -> instant


def test_noop_when_findings_have_no_canary(tmp_path):
    hm = _hm(tmp_path)
    hm._oob = _OOB(_FlagStore(fired=False))
    result = SimpleNamespace(findings=[{"vuln_type": "xss", "url": "http://t/"}])

    async def go():
        t0 = time.time()
        await hm._await_late_oob_callbacks(result, max_wait_s=5.0)
        return time.time() - t0
    assert asyncio.run(go()) < 0.1            # no oob_token anywhere -> instant
