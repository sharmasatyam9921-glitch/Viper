"""Unit tests for LateralAgent — Phase 5 orchestrator.

All tests run in deterministic mode with a stub PostExploitAgent so they
make zero network calls.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ---------------------------------------------------------------------------
# Stub PostExploitAgent
# ---------------------------------------------------------------------------


def make_stub_pe(*, asrep_hashes=None, tgs_hashes=None,
                 cred_dump_ok=False, lateral_hop_ok=False) -> MagicMock:
    """Build a PostExploitAgent stub with predictable async returns."""
    pe = MagicMock()
    pe.enumerate_ad = AsyncMock(return_value={
        "users": ["alice", "bob", "svc-sql"],
        "attack_paths": ["null_session", "kerberoastable"],
        "domain": "TEST.LOCAL",
    })
    pe.asreproast = AsyncMock(return_value={
        "ok": True, "parsed": {"hashes": asrep_hashes or []},
    })
    pe.kerberoast = AsyncMock(return_value={
        "ok": True, "parsed": {"hashes": tgs_hashes or []},
    })
    pe.secretsdump = AsyncMock(return_value={
        "ok": cred_dump_ok, "dry_run": not cred_dump_ok, "returncode": 0 if cred_dump_ok else -1,
    })
    pe.psexec = AsyncMock(return_value={
        "ok": lateral_hop_ok, "dry_run": not lateral_hop_ok,
    })
    return pe


# ---------------------------------------------------------------------------
# State machine basics
# ---------------------------------------------------------------------------


class TestStateMachine:
    def test_lateral_state_enum_has_all_phases(self):
        from agents.lateral_agent import LateralState
        for s in [
            "INIT", "ENUMERATE_HOST", "ANALYZE_PRIVESC", "EXECUTE_PRIVESC",
            "DETECT_AD", "AD_ENUM", "PRE_AUTH_ATTACKS", "AUTH_ATTACKS",
            "CRED_DUMP", "LATERAL_HOP", "DONE", "HALTED",
        ]:
            assert LateralState(s).value == s

    def test_lateral_agent_rejects_unknown_mode(self):
        from agents.lateral_agent import LateralAgent
        with pytest.raises(ValueError):
            LateralAgent(post_exploit_agent=None, mode="bogus")

    def test_lateral_agent_llm_mode_requires_router(self):
        from agents.lateral_agent import LateralAgent
        with pytest.raises(ValueError):
            LateralAgent(post_exploit_agent=None, mode="llm")

    def test_phase_enum_includes_lateral(self):
        from core.models import Phase
        assert Phase.LATERAL.value == "LATERAL"


# ---------------------------------------------------------------------------
# Heuristic decision policy
# ---------------------------------------------------------------------------


class TestHeuristicDecisions:
    def test_first_step_is_enumerate_host(self):
        from agents.lateral_agent import (
            FootholdInfo, LateralAgent, LateralCampaign, LateralState,
        )
        agent = LateralAgent(make_stub_pe(), mode="deterministic")
        c = LateralCampaign(foothold=FootholdInfo(target="10.10.10.10"))
        d = agent._heuristic_decide(c)
        assert d["next_state"] == LateralState.ENUMERATE_HOST.value

    def test_after_enum_low_priv_goes_to_analyze_privesc(self):
        from agents.lateral_agent import (
            CampaignStep, FootholdInfo, LateralAgent, LateralCampaign, LateralState,
        )
        agent = LateralAgent(make_stub_pe(), mode="deterministic")
        c = LateralCampaign(foothold=FootholdInfo(target="10.10.10.10", is_root=False))
        c.add_step(CampaignStep(state=LateralState.ENUMERATE_HOST, action="", succeeded=True))
        d = agent._heuristic_decide(c)
        assert d["next_state"] == LateralState.ANALYZE_PRIVESC.value

    def test_root_user_skips_privesc_goes_to_detect_ad(self):
        from agents.lateral_agent import (
            CampaignStep, FootholdInfo, LateralAgent, LateralCampaign, LateralState,
        )
        agent = LateralAgent(make_stub_pe(), mode="deterministic")
        c = LateralCampaign(foothold=FootholdInfo(target="10.10.10.10", is_root=True))
        c.add_step(CampaignStep(state=LateralState.ENUMERATE_HOST, action="", succeeded=True))
        d = agent._heuristic_decide(c)
        assert d["next_state"] == LateralState.DETECT_AD.value

    def test_no_domain_after_detection_means_done(self):
        from agents.lateral_agent import (
            CampaignStep, FootholdInfo, LateralAgent, LateralCampaign, LateralState,
        )
        agent = LateralAgent(make_stub_pe(), mode="deterministic")
        c = LateralCampaign(foothold=FootholdInfo(target="10.10.10.10", is_root=True))
        for st in (LateralState.ENUMERATE_HOST, LateralState.DETECT_AD):
            c.add_step(CampaignStep(state=st, action="", succeeded=True))
        # foothold.domain stays None → should mark DONE
        d = agent._heuristic_decide(c)
        assert d["next_state"] == LateralState.DONE.value

    def test_with_domain_proceeds_to_ad_enum(self):
        from agents.lateral_agent import (
            CampaignStep, FootholdInfo, LateralAgent, LateralCampaign, LateralState,
        )
        agent = LateralAgent(make_stub_pe(), mode="deterministic")
        f = FootholdInfo(target="10.10.10.10", is_root=True,
                         domain="TEST.LOCAL", dc_ip="10.10.10.10")
        c = LateralCampaign(foothold=f)
        for st in (LateralState.ENUMERATE_HOST, LateralState.DETECT_AD):
            c.add_step(CampaignStep(state=st, action="", succeeded=True))
        d = agent._heuristic_decide(c)
        assert d["next_state"] == LateralState.AD_ENUM.value

    def test_pre_auth_then_auth_then_creddump(self):
        from agents.lateral_agent import (
            CampaignStep, CredentialBundle, FootholdInfo, LateralAgent,
            LateralCampaign, LateralState,
        )
        agent = LateralAgent(make_stub_pe(), mode="deterministic")
        f = FootholdInfo(target="10.10.10.10", is_root=True,
                         domain="TEST.LOCAL", dc_ip="10.10.10.10")
        c = LateralCampaign(foothold=f)
        for st in (LateralState.ENUMERATE_HOST, LateralState.DETECT_AD,
                   LateralState.AD_ENUM):
            c.add_step(CampaignStep(state=st, action="", succeeded=True))
        d = agent._heuristic_decide(c)
        assert d["next_state"] == LateralState.PRE_AUTH_ATTACKS.value

        c.add_step(CampaignStep(state=LateralState.PRE_AUTH_ATTACKS, action="", succeeded=True))
        # Without creds we don't go to AUTH_ATTACKS yet
        d = agent._heuristic_decide(c)
        assert d["next_state"] != LateralState.AUTH_ATTACKS.value

        # Add a credential — now AUTH_ATTACKS
        c.creds.append(CredentialBundle(user="alice", password="pass", source="asrep"))
        d = agent._heuristic_decide(c)
        assert d["next_state"] == LateralState.AUTH_ATTACKS.value

    def test_lateral_hop_when_unowned_hosts_exist(self):
        from agents.lateral_agent import (
            CampaignStep, CredentialBundle, FootholdInfo, LateralAgent,
            LateralCampaign, LateralState,
        )
        agent = LateralAgent(make_stub_pe(), mode="deterministic")
        f = FootholdInfo(target="10.10.10.10", is_root=True,
                         domain="TEST.LOCAL", dc_ip="10.10.10.10")
        c = LateralCampaign(foothold=f)
        c.creds.append(CredentialBundle(user="da", password="pwn", source="dump"))
        c.discovered_hosts.update({"10.10.10.20", "10.10.10.30"})
        # Mark prior states as done
        for st in (LateralState.ENUMERATE_HOST, LateralState.DETECT_AD,
                   LateralState.AD_ENUM, LateralState.PRE_AUTH_ATTACKS,
                   LateralState.AUTH_ATTACKS, LateralState.CRED_DUMP):
            c.add_step(CampaignStep(state=st, action="", succeeded=True))
        d = agent._heuristic_decide(c)
        assert d["next_state"] == LateralState.LATERAL_HOP.value


# ---------------------------------------------------------------------------
# End-to-end run (deterministic, mocked PE)
# ---------------------------------------------------------------------------


class TestRunCampaign:
    def test_run_terminates_on_no_ad(self):
        """Foothold with no AD → loop should terminate cleanly at DONE."""
        from agents.lateral_agent import FootholdInfo, LateralAgent, LateralState

        pe = make_stub_pe()
        agent = LateralAgent(pe, mode="deterministic")
        # Mock the AD detection to return False (no port 88)
        with patch("agents.lateral_agent.LateralAgent._run_ad_detection",
                   new=AsyncMock(return_value=("no AD", True))):
            campaign = asyncio.run(agent.run(
                FootholdInfo(target="10.10.10.10", is_root=True)
            ))
        assert campaign.state == LateralState.DONE
        # Should have run at least: ENUMERATE_HOST + DETECT_AD
        seen = {s.state for s in campaign.history}
        assert LateralState.ENUMERATE_HOST in seen
        assert LateralState.DETECT_AD in seen

    def test_run_halts_after_two_consecutive_failures(self):
        from agents.lateral_agent import (
            CampaignStep, FootholdInfo, LateralAgent, LateralCampaign, LateralState,
        )
        pe = make_stub_pe()
        agent = LateralAgent(pe, mode="deterministic")
        c = LateralCampaign(foothold=FootholdInfo(target="10.10.10.10"))
        c.add_step(CampaignStep(state=LateralState.ENUMERATE_HOST, action="", succeeded=False))
        c.add_step(CampaignStep(state=LateralState.ANALYZE_PRIVESC, action="", succeeded=False))
        assert agent._consecutive_failures(c) == 2

    def test_max_steps_caps_run(self):
        from agents.lateral_agent import (
            FootholdInfo, LateralAgent, LateralCampaign, LateralState,
        )
        pe = make_stub_pe()
        agent = LateralAgent(pe, mode="deterministic")
        f = FootholdInfo(target="10.10.10.10", is_root=True,
                         domain="TEST.LOCAL", dc_ip="10.10.10.10")
        # Patch _decide so it always returns a noop ENUMERATE_HOST loop —
        # without max_steps, this would loop forever.
        async def fake_decide(_c):
            return {"next_state": "ENUMERATE_HOST", "reason": "test", "args": {}}
        async def fake_exec(_c, _d):
            from agents.lateral_agent import CampaignStep
            return CampaignStep(state=LateralState.ENUMERATE_HOST, action="x", succeeded=True)
        with patch.object(agent, "_decide", new=fake_decide), \
             patch.object(agent, "_execute", new=fake_exec):
            result = asyncio.run(agent.run(f, max_steps=3))
        assert result.step_count <= 3


# ---------------------------------------------------------------------------
# Campaign summary
# ---------------------------------------------------------------------------


class TestCampaignSummary:
    def test_summary_includes_all_fields(self):
        from agents.lateral_agent import (
            CredentialBundle, FootholdInfo, LateralCampaign, LateralState,
        )
        c = LateralCampaign(foothold=FootholdInfo(target="10.0.0.5"))
        c.state = LateralState.AD_ENUM
        c.creds.append(CredentialBundle(user="alice", source="asrep", password="p"))
        c.owned_hosts.add("10.0.0.5")
        c.discovered_hosts.update({"10.0.0.10", "10.0.0.20"})
        c.asrep_hashes.append("$krb5asrep$...")
        s = c.summary
        assert s["foothold"] == "10.0.0.5"
        assert s["current_state"] == "AD_ENUM"
        assert s["asrep_hash_count"] == 1
        assert s["credentials_gathered"][0]["user"] == "alice"
        assert s["credentials_gathered"][0]["has_password"] is True
        assert "10.0.0.5" in s["owned_hosts"]


# ---------------------------------------------------------------------------
# Phase engine integration
# ---------------------------------------------------------------------------


class TestPhaseEngineIntegration:
    def test_lateral_phase_in_phase_engine(self):
        from core.phase_engine import PhaseEngine
        # PhaseEngine reads phases from Phase enum — should now include LATERAL
        assert "LATERAL" in PhaseEngine.PHASES

    def test_lateral_phase_has_tools(self):
        from core.phase_engine import PhaseEngine
        tools = PhaseEngine.PHASE_TOOLS.get("LATERAL", [])
        for expected in ("kerberoast", "psexec", "bloodhound", "ligolo", "secretsdump"):
            assert expected in tools, f"missing {expected!r} from LATERAL tools"
