"""Phase 5 tests: --resume, FindingDedup, per-host rate limiter,
per-phase time budget."""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.audit_logger import AuditLogger
from core.hack_mode import HackMode
from core.hack_profile import LabProfile, CTFProfile, BugBountyProfile, Profile
from core.narrator import Narrator
from core.swarm_coordinator import FindingDedup
from core.swarm_workers import register_worker, _REGISTRY
from core.swarm_workers.vuln._rate_limit import (
    HostRateLimiter,
    reset_for_tests,
    wait_for_token,
)


# ---------------------------------------------------------------------------
# FindingDedup
# ---------------------------------------------------------------------------


class TestFindingDedup:
    def test_is_new_first_time_then_dupe(self):
        d = FindingDedup()
        f = {"target": "http://t/", "vuln_type": "sqli:id",
              "parameter": "id", "payload": "1'"}
        assert d.is_new(f) is True
        assert d.is_new(f) is False  # second call → dupe

    def test_different_findings_independent(self):
        d = FindingDedup()
        a = {"target": "t1", "vuln_type": "sqli", "parameter": "id"}
        b = {"target": "t2", "vuln_type": "sqli", "parameter": "id"}
        c = {"target": "t1", "vuln_type": "xss", "parameter": "id"}
        assert d.is_new(a) is True
        assert d.is_new(b) is True
        assert d.is_new(c) is True
        assert d.is_new(a) is False
        assert d.is_new(b) is False
        assert d.is_new(c) is False

    def test_empty_finding_always_new(self):
        d = FindingDedup()
        # No hashable fields → can't fingerprint → always allow
        assert d.is_new({}) is True
        assert d.is_new({}) is True

    def test_url_falls_back_when_target_missing(self):
        d = FindingDedup()
        a = {"url": "http://t/", "vuln_type": "sqli"}
        b = {"url": "http://t/", "vuln_type": "sqli"}
        assert d.is_new(a) is True
        assert d.is_new(b) is False

    def test_reset(self):
        d = FindingDedup()
        f = {"target": "x", "vuln_type": "y"}
        d.is_new(f)
        d.reset()
        assert d.is_new(f) is True


# ---------------------------------------------------------------------------
# Cross-coordinator dedup wired into HackMode
# ---------------------------------------------------------------------------


def _identical_runner_factory(record_list: list):
    async def runner(agent):
        record_list.append(agent.target)
        # Same finding shape every time
        return [{
            "type": "sqli", "vuln_type": "sqli:id",
            "title": "SQLi at id=", "url": "http://t/",
            "parameter": "id", "payload": "1'",
            "severity": "high",
        }]
    return runner


class TestCrossCoordinatorDedup:
    def test_duplicate_finding_across_phases_suppressed(self, tmp_path):
        """Recon and vuln workers emit the SAME finding (same hash key).
        The HackMode.dedup instance should let the recon one through and
        block the vuln-phase republish."""
        recon_calls: list[str] = []
        vuln_calls: list[str] = []
        register_worker("recon", "_t_r", _identical_runner_factory(recon_calls))
        register_worker("vuln", "_t_v", _identical_runner_factory(vuln_calls))
        try:
            profile = LabProfile()
            profile.phases = ["recon", "vuln", "report"]
            profile.workers = {"recon": ["_t_r"], "vuln": ["_t_v"]}
            audit = AuditLogger.for_hunt(
                "t",
                hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db",
            )
            hm = HackMode(
                target="t", profile=profile,
                narrator=Narrator(quiet=True), audit=audit,
            )
            result = asyncio.run(hm.run())
            # Both workers ran
            assert len(recon_calls) >= 1
            assert len(vuln_calls) >= 1
            # But the finding only appears in audit ONCE (the recon publish);
            # the vuln re-publish was deduped to finding.deduped event
            events = audit.read_jsonl()
            published = [e for e in events if e.action == "finding.published"]
            deduped = [e for e in events if e.action == "finding.deduped"]
            assert len(published) == 1, \
                f"expected 1 publish; got {len(published)}"
            assert len(deduped) >= 1, "expected deduped events to be recorded"
        finally:
            _REGISTRY["recon"].pop("_t_r", None)
            _REGISTRY["vuln"].pop("_t_v", None)


# ---------------------------------------------------------------------------
# Per-host rate limiter
# ---------------------------------------------------------------------------


class TestHostRateLimiter:
    def test_tokens_under_burst_pass_immediately(self):
        limiter = HostRateLimiter(rate_per_s=10.0, burst=5.0)

        async def go():
            t0 = time.time()
            for _ in range(5):
                ok = await limiter.acquire("example.com")
                assert ok
            return time.time() - t0

        elapsed = asyncio.run(go())
        # 5 tokens within burst → effectively instant
        assert elapsed < 0.5

    def test_over_burst_throttles(self):
        limiter = HostRateLimiter(rate_per_s=10.0, burst=2.0)

        async def go():
            t0 = time.time()
            # Consume burst + 1 more → must wait ~0.1s for refill
            for _ in range(3):
                await limiter.acquire("example.com")
            return time.time() - t0

        elapsed = asyncio.run(go())
        # ≥ 0.1s for 1 extra token at 10/s
        assert elapsed >= 0.08, f"expected throttling; took {elapsed:.3f}s"

    def test_per_host_independent(self):
        limiter = HostRateLimiter(rate_per_s=10.0, burst=2.0)

        async def go():
            # Consume both buckets in parallel — neither should block
            results = await asyncio.gather(
                limiter.acquire("a.example.com"),
                limiter.acquire("a.example.com"),
                limiter.acquire("b.example.com"),
                limiter.acquire("b.example.com"),
            )
            return results

        all_ok = asyncio.run(go())
        assert all(all_ok)

    def test_empty_host_passes(self):
        limiter = HostRateLimiter(rate_per_s=1.0, burst=1.0)
        assert asyncio.run(limiter.acquire("")) is True

    def test_url_extraction(self):
        limiter = HostRateLimiter(rate_per_s=10.0, burst=10.0)
        # URLs and hosts both work
        ok1 = asyncio.run(limiter.acquire("http://x.com/foo?q=1"))
        ok2 = asyncio.run(limiter.acquire("x.com"))
        assert ok1 and ok2

    def test_default_wait_for_token(self):
        reset_for_tests()
        ok = asyncio.run(wait_for_token("example.com"))
        assert ok is True


# ---------------------------------------------------------------------------
# Per-phase time budget (on Profile)
# ---------------------------------------------------------------------------


class TestPerPhaseBudget:
    def test_get_phase_budget_falls_back_to_split(self):
        p = LabProfile()
        p.time_budget_s = 100.0
        p.per_phase_budget_s = None
        # 4 phases (recon, vuln, exploit, post — excluding report)
        # With LabProfile(go=False), phases=["recon","vuln","report"] = 2 swarm phases
        # 100 * 0.9 / 2 = 45
        budget = p.get_phase_budget(phase_count=2)
        assert 44.0 <= budget <= 46.0

    def test_explicit_per_phase_budget_wins(self):
        p = LabProfile()
        p.time_budget_s = 1000.0
        p.per_phase_budget_s = 12.5
        # Phase count irrelevant when explicit budget is set
        assert p.get_phase_budget(phase_count=99) == 12.5

    def test_phase_budget_passed_to_coordinator(self, tmp_path):
        """Verify the coordinator's overall_timeout reflects per-phase budget."""
        captured_timeouts: list[float] = []

        class _RecordingCoord:
            PHASE = "recon"
            def __init__(self, **kw):
                captured_timeouts.append(kw.get("overall_timeout"))
            async def handle_message(self, payload):
                from core.swarm_coordinator import CoordinatorResult
                return CoordinatorResult(phase="recon", target=payload["target"])

        async def trivial(agent):
            return []

        register_worker("recon", "_t_pbudget", trivial)
        try:
            profile = LabProfile()
            profile.phases = ["recon", "report"]
            profile.workers = {"recon": ["_t_pbudget"]}
            profile.time_budget_s = 90.0  # 90s / 1 swarm phase → ~81s
            profile.per_phase_budget_s = None

            audit = AuditLogger.for_hunt(
                "t",
                hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db",
            )
            hm = HackMode(
                target="t", profile=profile,
                narrator=Narrator(quiet=True), audit=audit,
                coordinator_factory=lambda phase, common: _RecordingCoord(**common),
            )
            asyncio.run(hm.run())
            assert captured_timeouts
            # 90 * 0.9 / 1 = 81
            assert 80.0 <= captured_timeouts[0] <= 82.0
        finally:
            _REGISTRY["recon"].pop("_t_pbudget", None)


# ---------------------------------------------------------------------------
# Rate limiter integrated into fetch
# ---------------------------------------------------------------------------


class TestFetchUsesRateLimit:
    def test_fetch_blocks_when_rate_limit_starved(self):
        """When the default limiter has no tokens and max_wait is short,
        `fetch()` returns None instead of making the HTTP call."""
        from core.swarm_workers.vuln._http import fetch
        from core.swarm_workers.vuln import _rate_limit as rl_mod

        # Replace the default with an empty bucket + tight wait
        old_default = rl_mod._DEFAULT
        try:
            rl_mod._DEFAULT = HostRateLimiter(rate_per_s=0.0001, burst=0.0)

            async def go():
                # rate_limit defaults to True; this should be blocked
                return await fetch("GET", "http://blocked.example", timeout=2.0)

            result = asyncio.run(go())
            assert result is None
        finally:
            rl_mod._DEFAULT = old_default

    def test_fetch_rate_limit_can_be_bypassed(self):
        """For workers that DON'T want rate limiting, rate_limit=False."""
        from core.swarm_workers.vuln._http import fetch
        from core.swarm_workers.vuln import _rate_limit as rl_mod
        from unittest.mock import patch

        old_default = rl_mod._DEFAULT
        try:
            rl_mod._DEFAULT = HostRateLimiter(rate_per_s=0.0001, burst=0.0)

            # Even though the limiter is starved, rate_limit=False should
            # bypass the wait and let _fetch_sync run. We mock that to
            # confirm it was called.
            async def go():
                with patch(
                    "core.swarm_workers.vuln._http._fetch_sync",
                    return_value="ran",
                ):
                    return await fetch(
                        "GET", "http://bypassed.example",
                        timeout=2.0, rate_limit=False,
                    )

            result = asyncio.run(go())
            assert result == "ran"
        finally:
            rl_mod._DEFAULT = old_default
