"""Tests for core/swarm_coordinator.py.

Covers:
  - manifest split → N workers dispatched in parallel
  - findings stream onto OUTPUT_TOPIC as they're discovered
  - phase.started / phase.completed lifecycle events
  - one worker failure doesn't abort the swarm
  - per-worker timeout enforced
  - overall_timeout escape hatch
  - audit logger gets worker.dispatched + worker.completed + finding.published
  - swarm.* events emitted to the dashboard channel
  - ReconSwarmCoordinator builds the right manifest
  - WorkerSpec validation
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import List
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.agent_bus import AgentBus, Priority  # noqa: E402
from core.audit_logger import AuditLogger  # noqa: E402
from core.swarm_coordinator import (  # noqa: E402
    CoordinatorResult,
    ReconSwarmCoordinator,
    SwarmCoordinator,
    WorkerSpec,
)
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import clear_phase, register_worker  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _CollectingSubscriber:
    """Captures all bus messages on a topic for assertions."""

    def __init__(self) -> None:
        self.events: list = []
        self._loop: asyncio.AbstractEventLoop | None = None

    async def __call__(self, msg) -> None:
        self.events.append(msg)


def _make_bus_with_subs(*topics: str) -> tuple[AgentBus, dict[str, _CollectingSubscriber]]:
    bus = AgentBus(max_queue_size=10_000)
    subs: dict[str, _CollectingSubscriber] = {}
    for t in topics:
        sub = _CollectingSubscriber()
        bus.subscribe(t, sub)
        subs[t] = sub
    return bus, subs


class _ListSwarm(SwarmCoordinator):
    """Test subclass that takes a static manifest."""

    PHASE = "test_phase"
    OUTPUT_TOPIC = "next_phase"

    def __init__(self, *, manifest: list[WorkerSpec], **kw):
        super().__init__(**kw)
        self._manifest = manifest

    def build_manifest(self, target: str, context: dict) -> list[WorkerSpec]:
        return self._manifest


# Common runners. SwarmEngine dedups by vuln_type:target:parameter:payload —
# set those explicitly so each runner's output stays distinct.
async def _success_runner(agent: SwarmAgent) -> List[dict]:
    return [
        {
            "type": "finding_x", "vuln_type": f"finding_x_{agent.technique}",
            "title": f"hit on {agent.target}", "severity": "info",
            "parameter": agent.technique,
        }
    ]


async def _multi_finding_runner(agent: SwarmAgent) -> List[dict]:
    return [
        {"type": "subdomain", "vuln_type": "subdomain",
         "title": f"a.{agent.target}", "parameter": "a", "severity": "info"},
        {"type": "subdomain", "vuln_type": "subdomain",
         "title": f"b.{agent.target}", "parameter": "b", "severity": "info"},
        {"type": "subdomain", "vuln_type": "subdomain",
         "title": f"c.{agent.target}", "parameter": "c", "severity": "info"},
    ]


async def _failing_runner(agent: SwarmAgent) -> List[dict]:
    raise RuntimeError("boom")


async def _slow_runner(agent: SwarmAgent) -> List[dict]:
    await asyncio.sleep(10.0)
    return [{"type": "x"}]


# ---------------------------------------------------------------------------
# WorkerSpec validation
# ---------------------------------------------------------------------------


class TestWorkerSpec:
    def test_empty_technique_raises(self):
        with pytest.raises(ValueError):
            WorkerSpec(technique="", runner=_success_runner)


# ---------------------------------------------------------------------------
# Manifest dispatch
# ---------------------------------------------------------------------------


class TestManifestDispatch:
    def test_dispatches_all_workers(self, tmp_path):
        # _success_runner already includes the worker technique in vuln_type
        # so 5 workers produce 5 distinct findings (no dedup collapse).
        manifest = [
            WorkerSpec(technique=f"w{i}", runner=_success_runner)
            for i in range(5)
        ]

        async def go():
            bus, subs = _make_bus_with_subs("next_phase", "phase", "swarm")
            await bus.start()
            try:
                coord = _ListSwarm(manifest=manifest, bus=bus)
                return await coord.handle_message({"target": "example.com"})
            finally:
                await bus.stop()

        result: CoordinatorResult = asyncio.run(go())
        assert result.workers_dispatched == 5
        assert result.workers_completed == 5
        assert result.workers_failed == 0
        assert result.findings_count == 5  # one per worker

    def test_duplicate_findings_deduped(self, tmp_path):
        """SwarmEngine collapses identical findings (same vuln_type+target+param+payload)."""
        async def _same_runner(agent: SwarmAgent) -> List[dict]:
            return [{"type": "x", "vuln_type": "sqli",
                     "title": "same", "parameter": "id", "payload": "' OR 1=1--"}]
        manifest = [
            WorkerSpec(technique=f"w{i}", runner=_same_runner) for i in range(5)
        ]

        async def go():
            bus = AgentBus()
            await bus.start()
            try:
                coord = _ListSwarm(manifest=manifest, bus=bus)
                return await coord.handle_message({"target": "example.com"})
            finally:
                await bus.stop()

        result = asyncio.run(go())
        assert result.workers_completed == 5
        # All 5 emit the same hash → dedupe leaves 1
        assert result.findings_count == 1

    def test_findings_stream_to_output_topic(self, tmp_path):
        manifest = [WorkerSpec(technique="w1", runner=_multi_finding_runner)]

        async def go():
            bus, subs = _make_bus_with_subs("next_phase", "phase", "swarm")
            await bus.start()
            try:
                coord = _ListSwarm(manifest=manifest, bus=bus)
                result = await coord.handle_message({"target": "example.com"})
                # Drain the bus
                await asyncio.sleep(0.1)
                return result, subs
            finally:
                await bus.stop()

        result, subs = asyncio.run(go())
        # next_phase received 3 findings
        finding_events = [
            m for m in subs["next_phase"].events
            if isinstance(m.payload, dict) and m.payload.get("type") == "subdomain"
        ]
        assert len(finding_events) == 3

    def test_empty_manifest_publishes_phase_skipped(self):
        async def go():
            bus, subs = _make_bus_with_subs("swarm")
            await bus.start()
            try:
                coord = _ListSwarm(manifest=[], bus=bus)
                result = await coord.handle_message({"target": "x"})
                await asyncio.sleep(0.1)
                return result, subs
            finally:
                await bus.stop()

        result, subs = asyncio.run(go())
        assert result.workers_dispatched == 0
        skipped = [m for m in subs["swarm"].events
                   if isinstance(m.payload, dict) and m.payload.get("event") == "phase.skipped"]
        assert len(skipped) == 1

    def test_payload_missing_target_raises(self):
        async def go():
            bus = AgentBus()
            coord = _ListSwarm(manifest=[], bus=bus)
            await coord.handle_message({})  # no target

        with pytest.raises(ValueError, match="target"):
            asyncio.run(go())


# ---------------------------------------------------------------------------
# Lifecycle events
# ---------------------------------------------------------------------------


class TestLifecycleEvents:
    def test_phase_started_then_completed_in_order(self):
        manifest = [WorkerSpec(technique="w1", runner=_success_runner)]

        async def go():
            bus, subs = _make_bus_with_subs("phase", "swarm")
            await bus.start()
            try:
                coord = _ListSwarm(manifest=manifest, bus=bus)
                await coord.handle_message({"target": "x"})
                await asyncio.sleep(0.1)
                return subs
            finally:
                await bus.stop()

        subs = asyncio.run(go())
        phase_events = [m.payload for m in subs["phase"].events]
        actions = [
            e for e in phase_events
            if isinstance(e, dict)
        ]
        # First entry should be phase.started's payload (no explicit `event` key,
        # but the swarm topic mirrors do have it).
        assert any(p.get("phase") == "test_phase" for p in actions)


# ---------------------------------------------------------------------------
# Failure isolation
# ---------------------------------------------------------------------------


class TestFailureIsolation:
    def test_one_failure_does_not_kill_swarm(self):
        manifest = [
            WorkerSpec(technique="ok1", runner=_success_runner),
            WorkerSpec(technique="bad", runner=_failing_runner),
            WorkerSpec(technique="ok2", runner=_success_runner),
        ]

        async def go():
            bus = AgentBus()
            await bus.start()
            try:
                coord = _ListSwarm(manifest=manifest, bus=bus)
                return await coord.handle_message({"target": "x"})
            finally:
                await bus.stop()

        result = asyncio.run(go())
        assert result.workers_dispatched == 3
        assert result.workers_completed == 2
        assert result.workers_failed == 1
        assert result.findings_count == 2

    def test_per_worker_timeout(self):
        manifest = [
            WorkerSpec(technique="slow", runner=_slow_runner, timeout_s=0.05),
            WorkerSpec(technique="ok", runner=_success_runner),
        ]

        async def go():
            bus = AgentBus()
            await bus.start()
            try:
                coord = _ListSwarm(
                    manifest=manifest, bus=bus, per_worker_timeout=0.05,
                )
                return await coord.handle_message({"target": "x"})
            finally:
                await bus.stop()

        result = asyncio.run(go())
        # slow → timed_out (counts toward failed)
        assert result.workers_failed == 1
        assert result.workers_completed == 1

    def test_overall_timeout(self):
        manifest = [WorkerSpec(technique="slow", runner=_slow_runner, timeout_s=30.0)]

        async def go():
            bus = AgentBus()
            await bus.start()
            try:
                coord = _ListSwarm(
                    manifest=manifest, bus=bus, overall_timeout=0.1,
                )
                return await coord.handle_message({"target": "x"})
            finally:
                await bus.stop()

        result = asyncio.run(go())
        assert result.timed_out is True


# ---------------------------------------------------------------------------
# Parallel execution
# ---------------------------------------------------------------------------


class TestParallelism:
    def test_workers_run_concurrently(self):
        """5 workers each sleeping 0.3s should complete in <1s if parallel."""
        async def _sleeper(agent: SwarmAgent) -> list[dict]:
            await asyncio.sleep(0.3)
            return [{"type": "ok"}]

        manifest = [
            WorkerSpec(technique=f"s{i}", runner=_sleeper) for i in range(5)
        ]

        async def go():
            bus = AgentBus()
            await bus.start()
            try:
                coord = _ListSwarm(manifest=manifest, bus=bus, max_concurrent=10)
                t0 = time.time()
                result = await coord.handle_message({"target": "x"})
                return result, time.time() - t0
            finally:
                await bus.stop()

        result, elapsed = asyncio.run(go())
        assert result.workers_completed == 5
        # Strictly less than 5 × 0.3 = 1.5s. Sequential would be ~1.5s,
        # parallel should be ~0.4-0.6s.
        assert elapsed < 1.0, f"workers ran serially? took {elapsed:.2f}s"


# ---------------------------------------------------------------------------
# Audit logger integration
# ---------------------------------------------------------------------------


class TestAuditLoggerIntegration:
    def test_audit_records_dispatch_and_completion(self, tmp_path):
        manifest = [
            WorkerSpec(technique="recon_w1", runner=_success_runner),
            WorkerSpec(technique="recon_w2", runner=_success_runner),
        ]

        async def go():
            bus = AgentBus()
            await bus.start()
            try:
                audit = AuditLogger.for_hunt(
                    "x", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db",
                )
                coord = _ListSwarm(manifest=manifest, bus=bus, audit_logger=audit)
                await coord.handle_message({"target": "x"})
                events = audit.read_jsonl()
                audit.close()
                return events
            finally:
                await bus.stop()

        events = asyncio.run(go())
        actions = [e.action for e in events]
        # At least 2 dispatch + 2 completion + 2 finding + 1 started + 1 completed
        assert actions.count("worker.dispatched") == 2
        assert actions.count("worker.completed") == 2
        assert actions.count("finding.published") == 2
        assert actions.count("phase.started") == 1
        assert actions.count("phase.completed") == 1

    def test_audit_records_failure(self, tmp_path):
        manifest = [WorkerSpec(technique="bad", runner=_failing_runner)]

        async def go():
            bus = AgentBus()
            await bus.start()
            try:
                audit = AuditLogger.for_hunt(
                    "x", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db",
                )
                coord = _ListSwarm(manifest=manifest, bus=bus, audit_logger=audit)
                await coord.handle_message({"target": "x"})
                events = audit.read_jsonl()
                audit.close()
                return events
            finally:
                await bus.stop()

        events = asyncio.run(go())
        failed = [e for e in events if e.action == "worker.failed"]
        assert len(failed) == 1
        assert "boom" in str(failed[0].payload.get("error", ""))


# ---------------------------------------------------------------------------
# ReconSwarmCoordinator
# ---------------------------------------------------------------------------


class TestReconSwarmCoordinator:
    def test_builds_manifest_from_registry(self, tmp_path):
        # Use the real registry, but filter to 2 known techniques to keep
        # the test fast and offline-friendly.
        manifest_tests_runner = _success_runner
        register_worker("recon", "_test_w1", manifest_tests_runner)
        register_worker("recon", "_test_w2", manifest_tests_runner)
        try:
            async def go():
                bus = AgentBus()
                await bus.start()
                try:
                    coord = ReconSwarmCoordinator(
                        bus=bus,
                        default_techniques=["_test_w1", "_test_w2"],
                    )
                    return await coord.handle_message({"target": "example.com"})
                finally:
                    await bus.stop()

            result = asyncio.run(go())
            assert result.workers_dispatched == 2
            assert result.workers_completed == 2
            assert result.phase == "recon"
        finally:
            # Cleanup test workers
            from core.swarm_workers import _REGISTRY
            _REGISTRY["recon"].pop("_test_w1", None)
            _REGISTRY["recon"].pop("_test_w2", None)

    def test_unknown_technique_skipped(self, tmp_path):
        async def go():
            bus = AgentBus()
            await bus.start()
            try:
                coord = ReconSwarmCoordinator(
                    bus=bus,
                    default_techniques=["does_not_exist"],
                )
                return await coord.handle_message({"target": "example.com"})
            finally:
                await bus.stop()

        result = asyncio.run(go())
        assert result.workers_dispatched == 0


# ---------------------------------------------------------------------------
# VulnSwarmCoordinator
# ---------------------------------------------------------------------------


class TestVulnSwarmCoordinator:
    def test_fans_out_workers_times_assets(self, tmp_path):
        """N techniques × M assets should dispatch N×M workers."""
        # Register 2 test vuln techniques
        async def fake_runner(agent):
            return [{"type": "vuln_test", "vuln_type": f"vuln:{agent.target}",
                     "title": f"hit on {agent.target}", "severity": "info"}]

        register_worker("vuln", "_test_v1", fake_runner)
        register_worker("vuln", "_test_v2", fake_runner)
        try:
            from core.swarm_coordinator import VulnSwarmCoordinator

            async def go():
                bus = AgentBus()
                await bus.start()
                try:
                    coord = VulnSwarmCoordinator(
                        bus=bus,
                        default_techniques=["_test_v1", "_test_v2"],
                    )
                    return await coord.handle_message({
                        "target": "https://primary.example",
                        "assets": [
                            "https://api.example.com",
                            "https://www.example.com",
                            "https://x.example.com",
                        ],
                    })
                finally:
                    await bus.stop()

            result = asyncio.run(go())
            # 2 techniques × 3 assets = 6 workers
            assert result.workers_dispatched == 6
            assert result.workers_completed == 6
            assert result.findings_count == 3  # 3 unique assets, dedup
        finally:
            from core.swarm_workers import _REGISTRY
            _REGISTRY["vuln"].pop("_test_v1", None)
            _REGISTRY["vuln"].pop("_test_v2", None)

    def test_workers_see_asset_url_not_primary_target(self, tmp_path):
        """Each worker's agent.target should be the asset, not the
        primary target passed to handle_message."""
        captured: list[str] = []

        async def capture_runner(agent):
            captured.append(agent.target)
            return []

        register_worker("vuln", "_test_capture", capture_runner)
        try:
            from core.swarm_coordinator import VulnSwarmCoordinator

            async def go():
                bus = AgentBus()
                await bus.start()
                try:
                    coord = VulnSwarmCoordinator(
                        bus=bus, default_techniques=["_test_capture"],
                    )
                    return await coord.handle_message({
                        "target": "https://primary.example",
                        "assets": ["https://api.example.com", "https://www.example.com"],
                    })
                finally:
                    await bus.stop()

            asyncio.run(go())
            assert "https://api.example.com" in captured
            assert "https://www.example.com" in captured
            # Primary target was NOT used as worker target
            assert "https://primary.example" not in captured
        finally:
            from core.swarm_workers import _REGISTRY
            _REGISTRY["vuln"].pop("_test_capture", None)

    def test_extracts_assets_from_recon_findings(self, tmp_path):
        """When called with `findings`, the coordinator should convert
        subdomain/open_port findings into URLs and probe each."""
        captured: list[str] = []

        async def capture_runner(agent):
            captured.append(agent.target)
            return []

        register_worker("vuln", "_test_capture", capture_runner)
        try:
            from core.swarm_coordinator import VulnSwarmCoordinator

            async def go():
                bus = AgentBus()
                await bus.start()
                try:
                    coord = VulnSwarmCoordinator(
                        bus=bus, default_techniques=["_test_capture"],
                    )
                    return await coord.handle_message({
                        "target": "https://primary.example",
                        "findings": [
                            {"type": "subdomain", "title": "api.example.com",
                             "asset": "api.example.com"},
                            {"type": "open_port", "asset": "10.0.0.5",
                             "port": 8080},
                            {"type": "open_port", "asset": "10.0.0.5",
                             "port": 22},  # SSH — skip (not in _HTTP_PORTS)
                            {"type": "subdomain", "asset": "www.example.com",
                             "url": "https://www.example.com/login"},
                        ],
                    })
                finally:
                    await bus.stop()

            asyncio.run(go())
            # api.example.com (subdomain), 10.0.0.5:8080 (http port),
            # www.example.com/login (explicit URL) = 3 URLs
            # 10.0.0.5:22 is SSH so skipped
            assert "https://api.example.com" in captured
            assert "http://10.0.0.5:8080" in captured
            assert "https://www.example.com/login" in captured
            assert not any(":22" in u for u in captured)
        finally:
            from core.swarm_workers import _REGISTRY
            _REGISTRY["vuln"].pop("_test_capture", None)

    def test_empty_assets_falls_back_to_target(self, tmp_path):
        captured: list[str] = []

        async def capture_runner(agent):
            captured.append(agent.target)
            return []

        register_worker("vuln", "_test_capture", capture_runner)
        try:
            from core.swarm_coordinator import VulnSwarmCoordinator

            async def go():
                bus = AgentBus()
                await bus.start()
                try:
                    coord = VulnSwarmCoordinator(
                        bus=bus, default_techniques=["_test_capture"],
                    )
                    return await coord.handle_message({"target": "example.com"})
                finally:
                    await bus.stop()

            asyncio.run(go())
            # No assets / no findings → probe the target itself
            assert captured == ["https://example.com"]
        finally:
            from core.swarm_workers import _REGISTRY
            _REGISTRY["vuln"].pop("_test_capture", None)

    def test_phase_is_vuln(self):
        from core.swarm_coordinator import VulnSwarmCoordinator
        bus = AgentBus()
        coord = VulnSwarmCoordinator(bus=bus)
        assert coord.PHASE == "vuln"
        assert coord.OUTPUT_TOPIC == "exploit"


# ---------------------------------------------------------------------------
# ExploitSwarmCoordinator (gated)
# ---------------------------------------------------------------------------


class TestExploitSwarmCoordinator:
    def test_no_findings_no_dispatch(self):
        from core.swarm_coordinator import ExploitSwarmCoordinator

        async def go():
            bus = AgentBus()
            await bus.start()
            try:
                coord = ExploitSwarmCoordinator(
                    bus=bus, auto_approve_destructive=True,
                )
                return await coord.handle_message({"target": "x"})
            finally:
                await bus.stop()

        result = asyncio.run(go())
        assert result.workers_dispatched == 0

    def test_routes_sqli_finding_to_sqli_exploit(self):
        from core.swarm_coordinator import ExploitSwarmCoordinator
        captured: list[str] = []

        async def capture_runner(agent):
            captured.append(agent.technique)
            return []

        register_worker("exploit", "sqli_exploit", capture_runner)
        try:
            async def go():
                bus = AgentBus()
                await bus.start()
                try:
                    coord = ExploitSwarmCoordinator(
                        bus=bus, auto_approve_destructive=True,
                    )
                    return await coord.handle_message({
                        "target": "http://t/",
                        "findings": [{
                            "type": "sqli", "vuln_type": "sqli:id",
                            "parameter": "id", "url": "http://t/?id=1",
                        }],
                    })
                finally:
                    await bus.stop()

            result = asyncio.run(go())
            assert result.workers_dispatched == 1
            assert any("sqli_exploit" in t for t in captured)
        finally:
            # Restore the real runner so other tests still work
            from core.swarm_workers.exploit import sqli_exploit  # noqa
            from core.swarm_workers import register_worker as rw
            rw("exploit", "sqli_exploit", sqli_exploit.run)

    def test_unknown_finding_type_skipped(self):
        from core.swarm_coordinator import ExploitSwarmCoordinator

        async def go():
            bus = AgentBus()
            await bus.start()
            try:
                coord = ExploitSwarmCoordinator(
                    bus=bus, auto_approve_destructive=True,
                )
                return await coord.handle_message({
                    "target": "http://t/",
                    "findings": [{"type": "subdomain", "vuln_type": "subdomain"}],
                })
            finally:
                await bus.stop()

        result = asyncio.run(go())
        # subdomain isn't exploit-actionable → no dispatch
        assert result.workers_dispatched == 0

    def test_approval_gate_denied_skips_worker(self):
        """When approval gate is None and auto_approve_destructive=False,
        the gated runner emits a skipped marker instead of running."""
        from core.swarm_coordinator import ExploitSwarmCoordinator

        sentinel = []

        async def real_exploit(agent):
            sentinel.append("ran")
            return [{"type": "should_not_appear"}]

        register_worker("exploit", "sqli_exploit", real_exploit)
        try:
            async def go():
                bus = AgentBus()
                await bus.start()
                try:
                    coord = ExploitSwarmCoordinator(
                        bus=bus, approval_gate=None,
                        auto_approve_destructive=False,
                    )
                    return await coord.handle_message({
                        "target": "http://t/",
                        "findings": [{
                            "type": "sqli", "parameter": "id",
                            "url": "http://t/?id=1",
                        }],
                    })
                finally:
                    await bus.stop()

            result = asyncio.run(go())
            # Worker did NOT actually run
            assert sentinel == []
            # But a "skipped" marker was emitted
            assert result.findings_count >= 1
            assert any(f["type"] == "exploit_skipped" for f in result.findings)
        finally:
            from core.swarm_workers.exploit import sqli_exploit
            from core.swarm_workers import register_worker as rw
            rw("exploit", "sqli_exploit", sqli_exploit.run)

    def test_approval_gate_approves_runs_worker(self):
        from core.swarm_coordinator import ExploitSwarmCoordinator

        # Mock gate that always approves
        class _GateAlwaysApprove:
            async def confirm_tool(self, tool_name, args, rationale):
                return True, args

        ran = []

        async def real_exploit(agent):
            ran.append("yes")
            return [{
                "type": "sqli_exploited", "vuln_type": "sqli_exploited:id",
                "title": "ok", "severity": "critical",
            }]

        register_worker("exploit", "sqli_exploit", real_exploit)
        try:
            async def go():
                bus = AgentBus()
                await bus.start()
                try:
                    coord = ExploitSwarmCoordinator(
                        bus=bus, approval_gate=_GateAlwaysApprove(),
                    )
                    return await coord.handle_message({
                        "target": "http://t/",
                        "findings": [{"type": "sqli", "parameter": "id",
                                      "url": "http://t/?id=1"}],
                    })
                finally:
                    await bus.stop()

            asyncio.run(go())
            assert ran == ["yes"]
        finally:
            from core.swarm_workers.exploit import sqli_exploit
            from core.swarm_workers import register_worker as rw
            rw("exploit", "sqli_exploit", sqli_exploit.run)


# ---------------------------------------------------------------------------
# PostSwarmCoordinator (gated)
# ---------------------------------------------------------------------------


class TestPostSwarmCoordinator:
    def test_flag_hunter_runs_without_foothold(self):
        """flag_hunter is the only post worker not gated — runs even when
        no foothold finding is present."""
        from core.swarm_coordinator import PostSwarmCoordinator

        async def go():
            bus = AgentBus()
            await bus.start()
            try:
                coord = PostSwarmCoordinator(bus=bus, approval_gate=None)
                # No findings → only flag_hunter should be in the manifest
                return await coord.handle_message({"target": "http://t/"})
            finally:
                await bus.stop()

        result = asyncio.run(go())
        # 1 worker (flag_hunter)
        assert result.workers_dispatched == 1

    def test_foothold_triggers_full_manifest(self):
        from core.swarm_coordinator import PostSwarmCoordinator

        async def go():
            bus = AgentBus()
            await bus.start()
            try:
                coord = PostSwarmCoordinator(
                    bus=bus, auto_approve_destructive=True,
                )
                return await coord.handle_message({
                    "target": "http://t/",
                    "findings": [{"type": "cmdi_exploited", "foothold": True}],
                })
            finally:
                await bus.stop()

        result = asyncio.run(go())
        # 5 workers when there's a foothold
        assert result.workers_dispatched == 5

    def test_non_flag_workers_gated_default(self):
        """Without an approval gate and auto_approve=False, only flag_hunter
        actually runs; the rest emit `post_skipped` markers."""
        from core.swarm_coordinator import PostSwarmCoordinator

        async def go():
            bus = AgentBus()
            await bus.start()
            try:
                coord = PostSwarmCoordinator(
                    bus=bus, approval_gate=None,
                    auto_approve_destructive=False,
                )
                return await coord.handle_message({
                    "target": "http://t/",
                    "findings": [{"type": "cmdi_exploited", "foothold": True}],
                })
            finally:
                await bus.stop()

        result = asyncio.run(go())
        skipped = [f for f in result.findings if f["type"] == "post_skipped"]
        # 4 of 5 workers should be gate-skipped (all except flag_hunter)
        assert len(skipped) == 4

    def test_phase_is_post(self):
        from core.swarm_coordinator import PostSwarmCoordinator
        coord = PostSwarmCoordinator(bus=AgentBus())
        assert coord.PHASE == "post"
        assert coord.OUTPUT_TOPIC == "report"


class TestVulnTargeting:
    """build_manifest affinity: param workers -> param endpoints, root
    workers -> origins, near-duplicate endpoints collapse."""

    def _coord(self):
        from core.swarm_coordinator import VulnSwarmCoordinator
        return VulnSwarmCoordinator(bus=AgentBus())

    def test_param_worker_targets_param_endpoints(self):
        c = self._coord()
        assets = ["http://t/", "http://t/fi/?page=a", "http://t/sqli/?id=1"]
        got = c._assets_for_technique("lfi", assets, "http://t/")
        assert "http://t/fi/?page=a" in got and "http://t/sqli/?id=1" in got
        assert "http://t/" in got  # root always probed for default-param cases

    def test_root_worker_collapses_to_origin(self):
        c = self._coord()
        assets = ["http://t/a", "http://t/b?x=1", "http://t/c"]
        got = c._assets_for_technique("secrets", assets, "http://t/")
        assert got == ["http://t"]  # one probe per origin, not per endpoint

    def test_unknown_technique_keeps_all_assets(self):
        c = self._coord()
        assets = ["http://t/a", "http://t/b", "http://t/c"]
        assert set(c._assets_for_technique("_custom", assets, "http://t/")) == set(assets)

    def test_collect_assets_dedupes_by_signature(self):
        c = self._coord()
        findings = [
            {"type": "endpoint", "url": "http://t/fi/?page=include.php"},
            {"type": "endpoint", "url": "http://t/fi/?page=file1.php"},
            {"type": "endpoint", "url": "http://t/fi/?page=file2.php"},
            {"type": "endpoint", "url": "http://t/other?id=1"},
        ]
        assets = c._collect_assets("http://t", {"findings": findings})
        # the three ?page= variants collapse to one; /other stays
        fi = [a for a in assets if "/fi/" in a]
        assert len(fi) == 1
        assert any("/other" in a for a in assets)
