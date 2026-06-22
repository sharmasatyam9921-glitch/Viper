"""Tests for core/hack_mode.py — top-level autonomous hack orchestrator."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.audit_logger import AuditLogger  # noqa: E402
from core.hack_mode import HackMode, HackResult  # noqa: E402
from core.hack_profile import (  # noqa: E402
    BugBountyProfile,
    CTFProfile,
    LabProfile,
    Profile,
    StopCondition,
)
from core.narrator import Narrator  # noqa: E402
from core.swarm_coordinator import (  # noqa: E402
    CoordinatorResult,
    SwarmCoordinator,
    WorkerSpec,
)
from core.swarm_engine import SwarmAgent  # noqa: E402


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


async def _good_runner(agent: SwarmAgent) -> List[dict]:
    """Returns one unique finding per call."""
    return [{
        "type": "test_finding",
        "vuln_type": f"test_finding_{agent.technique}_{agent.target}",
        "title": f"finding for {agent.target} via {agent.technique}",
        "severity": "info",
    }]


async def _flag_runner(agent: SwarmAgent) -> List[dict]:
    """Returns a CTF flag — triggers CTF stop condition."""
    return [{
        "type": "flag_captured",
        "vuln_type": "flag",
        "title": "HTB{caught_the_flag}",
        "severity": "critical",
    }]


async def _zero_runner(agent: SwarmAgent) -> List[dict]:
    """Returns nothing — triggers bug-bounty exhaustion eventually."""
    return []


class _StubCoord(SwarmCoordinator):
    """SwarmCoordinator subclass we can inject for testing."""
    PHASE = "recon"

    def __init__(self, *, technique_runner=None, output_topic="vuln", **kw):
        super().__init__(**kw)
        self._runner = technique_runner or _good_runner
        self.OUTPUT_TOPIC = output_topic

    def build_manifest(self, target, context):
        return [
            WorkerSpec(technique="t1", runner=self._runner),
            WorkerSpec(technique="t2", runner=self._runner),
        ]


def _make_hackmode(tmp_path, *, profile=None, technique_runner=None,
                   target="example.com") -> HackMode:
    """Build a HackMode with mocked coordinator + audit + narrator."""
    if profile is None:
        profile = LabProfile()
    audit = AuditLogger.for_hunt(
        target, hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db",
    )
    narrator = Narrator(quiet=True)  # no terminal noise in tests
    hm = HackMode(
        target=target,
        profile=profile,
        narrator=narrator,
        audit=audit,
    )
    # Always inject the stub coordinator
    def factory(phase, common):
        coord = _StubCoord(technique_runner=technique_runner, **common)
        coord.PHASE = phase  # ensure phase audit-logs correctly
        return coord

    hm._coord_factory = factory
    return hm


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_for_target_auto_detects_profile_for_localhost(self, tmp_path):
        hm = HackMode.for_target(
            "127.0.0.1",
            hunts_dir=tmp_path / "hunts",
            db_path=tmp_path / "v.db",
        )
        assert hm.profile.name == "LabProfile"

    def test_for_target_auto_detects_ctf_hostname(self, tmp_path):
        hm = HackMode.for_target(
            "challenge.htb",
            hunts_dir=tmp_path / "hunts",
            db_path=tmp_path / "v.db",
        )
        assert hm.profile.name == "CTFProfile"

    def test_for_target_default_is_bugbounty(self, tmp_path):
        hm = HackMode.for_target(
            "example.com",
            hunts_dir=tmp_path / "hunts",
            db_path=tmp_path / "v.db",
        )
        assert hm.profile.name == "BugBountyProfile"

    def test_explicit_profile_override(self, tmp_path):
        hm = HackMode.for_target(
            "example.com", explicit_profile="ctf",
            hunts_dir=tmp_path / "hunts",
            db_path=tmp_path / "v.db",
        )
        assert hm.profile.name == "CTFProfile"


# ---------------------------------------------------------------------------
# Run-once integration: LabProfile (one full pass)
# ---------------------------------------------------------------------------


class TestLabProfileRun:
    def test_one_pass_produces_findings(self, tmp_path):
        hm = _make_hackmode(tmp_path, profile=LabProfile())
        result = asyncio.run(hm.run())
        assert isinstance(result, HackResult)
        assert result.iterations == 1
        assert result.findings_count > 0
        assert result.timed_out is False
        # Lab profile stop condition triggers
        assert "one_pass" in result.stop_reason or "max_iterations" in result.stop_reason

    def test_audit_log_records_lifecycle(self, tmp_path):
        hm = _make_hackmode(tmp_path, profile=LabProfile())
        result = asyncio.run(hm.run())
        events = hm.audit.read_jsonl()
        actions = [e.action for e in events]
        assert "hunt.started" in actions
        assert "hunt.completed" in actions
        assert "loop.iteration" in actions
        assert "phase.started" in actions
        assert "phase.completed" in actions
        # At least 4 worker dispatches across recon (2 + 2 across two phases)
        assert actions.count("worker.dispatched") >= 2

    def test_phase_results_populated(self, tmp_path):
        # Lab profile (without --go) runs only recon + vuln + report;
        # with our stub coordinator that's recon and vuln as no-ops/stub.
        hm = _make_hackmode(tmp_path, profile=LabProfile(allow_destructive=False))
        result = asyncio.run(hm.run())
        # The stub coordinator runs whatever phase we ask for
        assert "recon" in result.phase_results

    def test_to_dict_serializable(self, tmp_path):
        import json
        hm = _make_hackmode(tmp_path, profile=LabProfile())
        result = asyncio.run(hm.run())
        json.dumps(result.to_dict())


# ---------------------------------------------------------------------------
# CTF: stop when flag is found
# ---------------------------------------------------------------------------


class TestCTFFlagLoop:
    def test_stops_when_flag_captured(self, tmp_path):
        hm = _make_hackmode(
            tmp_path,
            profile=CTFProfile(),
            technique_runner=_flag_runner,
            target="box.htb",
        )
        result = asyncio.run(hm.run())
        # Should stop on the very first iteration when flag detected
        assert result.iterations == 1
        assert result.stop_reason == "flag_found"
        # The flag finding is captured
        flags = [f for f in result.findings if "HTB{" in str(f.get("title", ""))]
        assert len(flags) >= 1


# ---------------------------------------------------------------------------
# Hard guardrail: blocked targets never run
# ---------------------------------------------------------------------------


class TestHardGuardrail:
    def test_blocked_target_aborts_before_work(self, tmp_path):
        # A protected domain must fail the run closed, with no phases/findings.
        hm = _make_hackmode(tmp_path, target="chase.com")
        result = asyncio.run(hm.run())
        assert result.stop_reason == "guardrail_blocked"
        assert result.findings_count == 0
        assert result.phase_results == {}
        actions = [e.action for e in hm.audit.read_jsonl()]
        assert "guardrail.blocked" in actions
        # never advanced into the loop
        assert "loop.iteration" not in actions

    def test_gov_tld_blocked(self, tmp_path):
        hm = _make_hackmode(tmp_path, target="nasa.gov")
        result = asyncio.run(hm.run())
        assert result.stop_reason == "guardrail_blocked"


# ---------------------------------------------------------------------------
# Mythos-style chaining: a confirmed exploit drives a deeper round
# ---------------------------------------------------------------------------


async def _exploit_runner(agent: SwarmAgent) -> List[dict]:
    """Emit a confirmed-exploit finding with a URL → should trigger chaining."""
    return [{
        "type": "sqli_exploited",
        "vuln_type": f"sqli_exploited:{agent.target}",
        "title": "SQL injection confirmed",
        "severity": "critical",
        "url": "http://example.com/item?id=1",
    }]


async def _ssrf_runner(agent: SwarmAgent) -> List[dict]:
    """Emit a confirmed SSRF foothold → targeted expansion should scope to ssrf."""
    return [{
        "type": "ssrf",
        "vuln_type": "ssrf:confirmed",
        "title": "SSRF confirmed",
        "severity": "high",
        "url": "http://example.com/fetch?u=1",
        "foothold": True,
    }]


class TestChaining:
    def test_confirmed_exploit_expands_chain(self, tmp_path):
        # LabProfile(--go) enables exploit/post + max_chain_depth>0.
        hm = _make_hackmode(
            tmp_path,
            profile=LabProfile(allow_destructive=True),
            technique_runner=_exploit_runner,
        )
        result = asyncio.run(hm.run())
        # A chain round produced scoped phase-results …
        assert any(k.startswith("vuln@chain") for k in result.phase_results)
        # … and the audit log recorded the expansion + completion.
        actions = [e.action for e in hm.audit.read_jsonl()]
        assert "chain.expanded" in actions
        assert "chain.completed" in actions
        # Findings carry a verdict annotation for the report.
        assert any(f.get("chain_verdict") for f in result.findings)

    def test_targeted_expansion_scopes_chain_to_technique(self, tmp_path):
        # A confirmed SSRF should drive a chain round scoped to the ssrf probe
        # (targeted expansion), not a full re-run of the vuln phase.
        hm = _make_hackmode(
            tmp_path,
            profile=LabProfile(allow_destructive=True),
            technique_runner=_ssrf_runner,
        )
        result = asyncio.run(hm.run())
        assert any(k.startswith("vuln@chain") for k in result.phase_results)
        expansions = [e for e in hm.audit.read_jsonl() if e.action == "chain.expanded"]
        assert expansions
        scopes = [e.payload.get("scope") for e in expansions]
        assert any(s == ["ssrf"] for s in scopes)   # targeted, not "full"

    def test_chain_scope_gate_fails_closed(self, tmp_path):
        # A scope reasoner that denies everything must block chain expansion
        # even when a confirmed exploit is present — fail closed.
        class _DenyAll:
            def decide(self, target, **kw):
                from core.scope_reasoner import ScopeDecision
                return ScopeDecision(target=target, allowed=False,
                                     reason="test deny", source="default-deny")

        audit = AuditLogger.for_hunt(
            "example.com", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db")
        hm = HackMode(
            target="example.com",
            profile=LabProfile(allow_destructive=True),
            narrator=Narrator(quiet=True),
            audit=audit,
            scope_reasoner=_DenyAll(),
        )

        def factory(phase, common):
            coord = _StubCoord(technique_runner=_exploit_runner, **common)
            coord.PHASE = phase
            return coord

        hm._coord_factory = factory
        result = asyncio.run(hm.run())
        actions = [e.action for e in hm.audit.read_jsonl()]
        # The off-scope confirmed-exploit URL was blocked, so no expansion ran.
        assert "chain.scope_blocked" in actions
        assert not any(k.startswith("vuln@chain") for k in result.phase_results)

    def test_no_chain_when_findings_are_info(self, tmp_path):
        # info-severity findings are DOWNGRADE → never chain, even with --go.
        hm = _make_hackmode(
            tmp_path,
            profile=LabProfile(allow_destructive=True),
            technique_runner=_good_runner,
        )
        result = asyncio.run(hm.run())
        assert not any(k.startswith("vuln@chain") for k in result.phase_results)
        actions = [e.action for e in hm.audit.read_jsonl()]
        assert "chain.expanded" not in actions


# ---------------------------------------------------------------------------
# Bug-bounty: exhaustion stop after 3 zero-iterations
# ---------------------------------------------------------------------------


class TestBugBountyExhaustion:
    def test_stops_after_three_empty_iterations(self, tmp_path):
        # Profile that allows max 5 iterations and stops on exhaustion
        hm = _make_hackmode(
            tmp_path,
            profile=BugBountyProfile(),
            technique_runner=_zero_runner,
        )
        result = asyncio.run(hm.run())
        # After 3 iterations of 0 findings, the exhaustion condition fires
        assert result.iterations >= 3
        assert "exhausted" in result.stop_reason

    def test_stops_at_max_iterations(self, tmp_path):
        # Profile capped at 2 iterations; every iter produces a finding so
        # exhaustion never fires.
        profile = BugBountyProfile()
        profile.max_iterations = 2
        hm = _make_hackmode(
            tmp_path,
            profile=profile,
            technique_runner=_good_runner,
        )
        result = asyncio.run(hm.run())
        assert result.iterations == 2
        assert "max_iterations" in result.stop_reason


# ---------------------------------------------------------------------------
# Time budget enforcement
# ---------------------------------------------------------------------------


class TestTimeBudget:
    def test_time_budget_triggers_timeout(self, tmp_path):
        async def _slow_runner(agent: SwarmAgent) -> List[dict]:
            await asyncio.sleep(2.0)
            return []

        profile = LabProfile()
        profile.time_budget_s = 0.2  # 200ms — slower than the runner
        profile.per_worker_timeout = 5.0  # don't let the worker timeout first
        profile.max_iterations = 5

        hm = _make_hackmode(
            tmp_path, profile=profile, technique_runner=_slow_runner,
        )
        result = asyncio.run(hm.run())
        assert result.timed_out is True
        assert result.stop_reason == "time_budget"


# ---------------------------------------------------------------------------
# Bus / registry teardown
# ---------------------------------------------------------------------------


class TestTeardown:
    def test_bus_stopped_after_run(self, tmp_path):
        hm = _make_hackmode(tmp_path)
        asyncio.run(hm.run())
        assert hm.bus.running is False

    def test_double_run_raises(self, tmp_path):
        hm = _make_hackmode(tmp_path)
        asyncio.run(hm.run())
        with pytest.raises(RuntimeError, match="already started"):
            asyncio.run(hm.run())

    def test_audit_logger_closed_via_summary(self, tmp_path):
        hm = _make_hackmode(tmp_path)
        result = asyncio.run(hm.run())
        # We can still query the JSONL after the run
        events = hm.audit.read_jsonl()
        assert len(events) > 0


# ---------------------------------------------------------------------------
# State propagation to stop_conditions
# ---------------------------------------------------------------------------


class TestStateTracking:
    def test_findings_per_iteration_recorded(self, tmp_path):
        hm = _make_hackmode(
            tmp_path,
            profile=BugBountyProfile(),
            technique_runner=_good_runner,
        )
        # We won't reach max_iterations (10) because every iteration finds 1
        # finding (no exhaustion). Manually cap to 3 to keep test fast.
        hm.profile.max_iterations = 3
        result = asyncio.run(hm.run())
        per_iter = hm._state["findings_per_iteration"]
        assert len(per_iter) == result.iterations
        # Every iteration produced at least one finding
        assert all(n > 0 for n in per_iter)


# ---------------------------------------------------------------------------
# Profile.phases respected
# ---------------------------------------------------------------------------


class TestPhaseRouting:
    def test_only_listed_phases_run(self, tmp_path):
        # Custom profile with only recon
        profile = LabProfile()
        profile.phases = ["recon", "report"]  # report is filtered out by HackMode
        hm = _make_hackmode(tmp_path, profile=profile)
        result = asyncio.run(hm.run())
        # Only recon should appear in phase_results
        assert list(result.phase_results.keys()) == ["recon"]


# ---------------------------------------------------------------------------
# Phase 2 — recon → vuln pipeline integration
# ---------------------------------------------------------------------------


class TestPhase2Pipeline:
    """Recon → Vuln pipeline using real coordinators (not stubs) with mocked
    workers. Verifies findings flow from one phase to the next."""

    def test_vuln_phase_receives_recon_findings(self, tmp_path):
        """The vuln coordinator's `_collect_assets` should turn recon
        findings (subdomain / open_port) into asset URLs."""
        from core.swarm_workers import register_worker, _REGISTRY

        recon_seen: list[str] = []
        vuln_seen: list[str] = []

        async def recon_runner(agent):
            recon_seen.append(agent.target)
            # Pretend recon discovered three assets. vuln_type must be
            # distinct per finding or SwarmEngine.dedup collapses them.
            return [
                {"type": "subdomain", "vuln_type": "subdomain:api",
                 "asset": "api.example.com", "title": "api.example.com",
                 "url": "https://api.example.com"},
                {"type": "subdomain", "vuln_type": "subdomain:www",
                 "asset": "www.example.com", "title": "www.example.com",
                 "url": "https://www.example.com"},
                {"type": "open_port", "vuln_type": "open_port:8080",
                 "asset": "10.0.0.5", "port": 8080,
                 "url": "http://10.0.0.5:8080"},
            ]

        async def vuln_runner(agent):
            vuln_seen.append(agent.target)
            return [{"type": "test_vuln", "vuln_type": f"vuln:{agent.target}",
                     "title": f"vuln on {agent.target}", "severity": "info"}]

        register_worker("recon", "_test_recon", recon_runner)
        register_worker("vuln", "_test_vuln", vuln_runner)
        try:
            # Profile with recon + vuln phases enabled, real coordinators
            profile = LabProfile()
            profile.phases = ["recon", "vuln", "report"]
            profile.workers = {"recon": ["_test_recon"], "vuln": ["_test_vuln"]}

            audit = AuditLogger.for_hunt(
                "example.com",
                hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db",
            )
            hm = HackMode(
                target="example.com",
                profile=profile,
                narrator=Narrator(quiet=True),
                audit=audit,
            )
            # Use the real default coordinator wiring (no _coord_factory override)
            result = asyncio.run(hm.run())

            # Recon ran once against the primary target
            assert recon_seen == ["example.com"]
            # Vuln ran against each discovered asset
            assert "https://api.example.com" in vuln_seen
            assert "https://www.example.com" in vuln_seen
            assert "http://10.0.0.5:8080" in vuln_seen
            # Both phases recorded in result
            assert "recon" in result.phase_results
            assert "vuln" in result.phase_results
            assert result.phase_results["recon"].findings_count == 3
            # 3 vuln findings (one per asset)
            assert result.phase_results["vuln"].findings_count == 3
        finally:
            _REGISTRY["recon"].pop("_test_recon", None)
            _REGISTRY["vuln"].pop("_test_vuln", None)

    def test_resume_skips_completed_phases(self, tmp_path):
        """A fresh run completes; then HackMode.resume() picks up the
        same hunt and skips phases whose `phase.completed` event is
        already in the audit log."""
        from core.swarm_workers import register_worker, _REGISTRY

        recon_calls: list[str] = []
        vuln_calls: list[str] = []

        async def recon_runner(agent):
            recon_calls.append(agent.target)
            return [{
                "type": "subdomain", "vuln_type": "subdomain:api",
                "asset": "api.example.com",
                "url": "https://api.example.com",
            }]

        async def vuln_runner(agent):
            vuln_calls.append(agent.target)
            return [{
                "type": "test_vuln", "vuln_type": f"vuln:{agent.target}",
                "title": f"hit {agent.target}", "severity": "info",
            }]

        register_worker("recon", "_test_recon", recon_runner)
        register_worker("vuln", "_test_vuln", vuln_runner)
        try:
            profile = LabProfile()
            profile.phases = ["recon", "vuln", "report"]
            profile.workers = {"recon": ["_test_recon"], "vuln": ["_test_vuln"]}

            # Round 1 — fresh hunt, ts=100 so hunt_id is deterministic
            audit_1 = AuditLogger.for_hunt(
                "example.com",
                hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db",
                ts=100,
            )
            hm_1 = HackMode(
                target="example.com",
                profile=profile,
                narrator=Narrator(quiet=True),
                audit=audit_1,
            )
            asyncio.run(hm_1.run())
            assert len(recon_calls) == 1
            assert len(vuln_calls) == 1  # 1 worker × 1 asset
            hunt_id = audit_1.hunt_id

            # Round 2 — resume the same hunt. Both phases are completed,
            # max_iterations=1, so the loop runs but skips everything and
            # exits via one_pass.
            hm_2 = HackMode.resume(
                hunt_id,
                hunts_dir=tmp_path / "hunts",
                db_path=tmp_path / "v.db",
                profile=profile,
                narrator=Narrator(quiet=True),
            )
            # Resume must NOT re-run recon / vuln
            asyncio.run(hm_2.run())
            assert len(recon_calls) == 1, "resume re-ran recon"
            assert len(vuln_calls) == 1, "resume re-ran vuln"
        finally:
            _REGISTRY["recon"].pop("_test_recon", None)
            _REGISTRY["vuln"].pop("_test_vuln", None)

    def test_resume_missing_hunt_raises(self, tmp_path):
        from core.hack_mode import HackMode
        with pytest.raises(FileNotFoundError):
            HackMode.resume(
                "nonexistent_hunt_999",
                hunts_dir=tmp_path / "hunts",
                db_path=tmp_path / "v.db",
            )

    def test_resume_recovers_target_from_audit(self, tmp_path):
        """The target string is recovered from the first hunt.started event."""
        from core.swarm_workers import register_worker, _REGISTRY

        async def trivial(agent):
            return []

        register_worker("recon", "_test_trivial", trivial)
        try:
            profile = LabProfile()
            profile.phases = ["recon", "report"]
            profile.workers = {"recon": ["_test_trivial"]}

            target = "https://recovered.example.com:8443/path"
            audit_1 = AuditLogger.for_hunt(
                target,
                hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db",
                ts=200,
            )
            hm_1 = HackMode(
                target=target, profile=profile,
                narrator=Narrator(quiet=True), audit=audit_1,
            )
            asyncio.run(hm_1.run())

            hm_2 = HackMode.resume(
                audit_1.hunt_id,
                hunts_dir=tmp_path / "hunts",
                db_path=tmp_path / "v.db",
                profile=profile,
                narrator=Narrator(quiet=True),
            )
            assert hm_2.target == target
        finally:
            _REGISTRY["recon"].pop("_test_trivial", None)

    def test_vuln_phase_no_recon_findings_falls_back_to_target(self, tmp_path):
        """If recon produced nothing, vuln should still probe the
        primary target."""
        from core.swarm_workers import register_worker, _REGISTRY

        vuln_seen: list[str] = []

        async def recon_empty(agent):
            return []  # no findings

        async def vuln_runner(agent):
            vuln_seen.append(agent.target)
            return []

        register_worker("recon", "_test_recon_empty", recon_empty)
        register_worker("vuln", "_test_vuln_capture", vuln_runner)
        try:
            profile = LabProfile()
            profile.phases = ["recon", "vuln", "report"]
            profile.workers = {
                "recon": ["_test_recon_empty"],
                "vuln": ["_test_vuln_capture"],
            }

            audit = AuditLogger.for_hunt(
                "example.com",
                hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db",
            )
            hm = HackMode(
                target="example.com",
                profile=profile,
                narrator=Narrator(quiet=True),
                audit=audit,
            )
            asyncio.run(hm.run())
            # Vuln probed the primary target (https://example.com)
            assert vuln_seen == ["https://example.com"]
        finally:
            _REGISTRY["recon"].pop("_test_recon_empty", None)
            _REGISTRY["vuln"].pop("_test_vuln_capture", None)


# ---------------------------------------------------------------------------
# World model: beliefs populate from findings during a live hunt (Section 7.2)
# ---------------------------------------------------------------------------


class TestWorldModel:
    def test_findings_update_live_belief_state(self, tmp_path):
        hm = _make_hackmode(tmp_path, technique_runner=_exploit_runner)
        asyncio.run(hm.run())
        wm = hm.world_model
        # The confirmed sqli finding became a high-confidence belief...
        assert wm.has_belief("vuln:sqli@example.com")
        assert wm.beliefs["vuln:sqli@example.com"].value.get("confirmed") is True
        # ...and its URL is in the tracked attack surface.
        assert any("example.com/item" in e for e in wm.attack_surface()["endpoints"])
        # Snapshot is serializable for the dashboard / report.
        assert wm.to_dict()["observation_count"] >= 1

    def test_world_snapshot_audited_on_completion(self, tmp_path):
        hm = _make_hackmode(tmp_path, technique_runner=_exploit_runner)
        asyncio.run(hm.run())
        actions = [e.action for e in hm.audit.read_jsonl()]
        assert "world.snapshot" in actions
