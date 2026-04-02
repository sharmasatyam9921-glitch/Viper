"""Tests for AgentRegistry — agent lifecycle and routing."""
import time
import pytest
from core.agent_registry import AgentRegistry, AgentStatus, AgentInfo


class TestAgentRegistration:
    def test_register_returns_agent_info(self, agent_registry):
        info = agent_registry.register("recon-1", "recon_agent", capabilities=["recon"])
        assert isinstance(info, AgentInfo)
        assert info.agent_id == "recon-1"
        assert info.name == "recon_agent"
        assert "recon" in info.capabilities

    def test_register_sets_idle_status(self, agent_registry):
        info = agent_registry.register("vuln-1", "vuln_agent", capabilities=["vuln"])
        assert info.status == AgentStatus.IDLE

    def test_register_initialises_task_count_zero(self, agent_registry):
        info = agent_registry.register("ex-1", "exploit_agent", capabilities=["exploit"])
        assert info.task_count == 0

    def test_register_multiple_agents(self, agent_registry):
        agent_registry.register("a1", "agent_a", capabilities=["recon"])
        agent_registry.register("a2", "agent_b", capabilities=["vuln"])
        assert len(agent_registry.list_agents()) == 2

    def test_deregister_removes_agent(self, agent_registry):
        agent_registry.register("del-1", "doomed", capabilities=["recon"])
        agent_registry.deregister("del-1")
        assert agent_registry.get_agent("recon") is None

    def test_deregister_nonexistent_is_noop(self, agent_registry):
        agent_registry.deregister("does-not-exist")  # should not raise

    def test_register_overwrites_same_id(self, agent_registry):
        agent_registry.register("dup-1", "first", capabilities=["recon"])
        agent_registry.register("dup-1", "second", capabilities=["vuln"])
        info = agent_registry._agents["dup-1"]
        assert info.name == "second"


class TestAgentRouting:
    def test_get_agent_returns_idle_agent_for_topic(self, agent_registry):
        agent_registry.register("r1", "recon_agent", capabilities=["recon"])
        result = agent_registry.get_agent("recon")
        assert result is not None
        assert result.agent_id == "r1"

    def test_get_agent_none_for_unknown_topic(self, agent_registry):
        agent_registry.register("r1", "recon_agent", capabilities=["recon"])
        result = agent_registry.get_agent("unknown_topic")
        assert result is None

    def test_get_agent_selects_least_busy(self, agent_registry):
        agent_registry.register("r1", "recon_a", capabilities=["recon"])
        agent_registry.register("r2", "recon_b", capabilities=["recon"])
        agent_registry.mark_busy("r1")
        agent_registry.mark_busy("r1")
        result = agent_registry.get_agent("recon")
        assert result.agent_id == "r2"

    def test_get_agent_skips_crashed(self, agent_registry):
        agent_registry.register("r1", "recon_a", capabilities=["recon"])
        agent_registry.register("r2", "recon_b", capabilities=["recon"])
        agent_registry._agents["r1"].status = AgentStatus.CRASHED
        result = agent_registry.get_agent("recon")
        assert result.agent_id == "r2"

    def test_get_agent_returns_none_all_crashed(self, agent_registry):
        agent_registry.register("r1", "recon_a", capabilities=["recon"])
        agent_registry._agents["r1"].status = AgentStatus.CRASHED
        assert agent_registry.get_agent("recon") is None

    def test_list_agents_no_filter(self, agent_registry):
        agent_registry.register("a1", "a", capabilities=["recon"])
        agent_registry.register("a2", "b", capabilities=["vuln"])
        all_agents = agent_registry.list_agents()
        assert len(all_agents) == 2

    def test_list_agents_filtered_by_topic(self, agent_registry):
        agent_registry.register("a1", "a", capabilities=["recon"])
        agent_registry.register("a2", "b", capabilities=["vuln"])
        recon_agents = agent_registry.list_agents(topic="recon")
        assert len(recon_agents) == 1
        assert recon_agents[0].agent_id == "a1"


class TestAgentStatus:
    def test_mark_busy_increments_task_count(self, agent_registry):
        agent_registry.register("w1", "worker", capabilities=["work"])
        agent_registry.mark_busy("w1")
        assert agent_registry._agents["w1"].task_count == 1
        assert agent_registry._agents["w1"].status == AgentStatus.BUSY

    def test_mark_busy_twice_increments_twice(self, agent_registry):
        agent_registry.register("w1", "worker", capabilities=["work"])
        agent_registry.mark_busy("w1")
        agent_registry.mark_busy("w1")
        assert agent_registry._agents["w1"].task_count == 2

    def test_mark_idle_sets_idle_status(self, agent_registry):
        agent_registry.register("w1", "worker", capabilities=["work"])
        agent_registry.mark_busy("w1")
        agent_registry.mark_idle("w1")
        assert agent_registry._agents["w1"].status == AgentStatus.IDLE

    def test_heartbeat_updates_timestamp(self, agent_registry):
        agent_registry.register("h1", "pinger", capabilities=["ping"])
        old_ts = agent_registry._agents["h1"].last_heartbeat
        time.sleep(0.01)
        agent_registry.heartbeat("h1")
        new_ts = agent_registry._agents["h1"].last_heartbeat
        assert new_ts >= old_ts

    def test_heartbeat_recovers_crashed_agent(self, agent_registry):
        agent_registry.register("c1", "crasher", capabilities=["crash"])
        agent_registry._agents["c1"].status = AgentStatus.CRASHED
        agent_registry.heartbeat("c1")
        assert agent_registry._agents["c1"].status == AgentStatus.IDLE

    def test_heartbeat_nonexistent_is_noop(self, agent_registry):
        agent_registry.heartbeat("ghost-99")  # should not raise

    def test_mark_busy_nonexistent_is_noop(self, agent_registry):
        agent_registry.mark_busy("ghost-99")  # should not raise


class TestAgentRegistryStats:
    def test_get_stats_returns_dict(self, agent_registry):
        stats = agent_registry.get_stats()
        assert isinstance(stats, dict)

    def test_get_stats_has_total_agents(self, agent_registry):
        agent_registry.register("s1", "sa", capabilities=["x"])
        stats = agent_registry.get_stats()
        assert stats["total_agents"] == 1

    def test_get_stats_has_by_status(self, agent_registry):
        agent_registry.register("s1", "sa", capabilities=["x"])
        stats = agent_registry.get_stats()
        assert "by_status" in stats
        assert "idle" in stats["by_status"]

    def test_get_stats_agents_list(self, agent_registry):
        agent_registry.register("s1", "sa", capabilities=["x"])
        stats = agent_registry.get_stats()
        assert "agents" in stats
        assert len(stats["agents"]) == 1

    def test_agent_to_dict(self, agent_registry):
        info = agent_registry.register("d1", "dict_agent", capabilities=["x", "y"])
        d = info.to_dict()
        assert d["agent_id"] == "d1"
        assert d["name"] == "dict_agent"
        assert "capabilities" in d
        assert "status" in d
        assert "task_count" in d


class TestAgentRegistryLifecycle:
    async def test_start_and_stop(self, agent_registry):
        await agent_registry.start()
        assert agent_registry._running is True
        await agent_registry.stop()
        assert agent_registry._running is False

    async def test_double_start_idempotent(self, agent_registry):
        await agent_registry.start()
        await agent_registry.start()
        assert agent_registry._running is True
        await agent_registry.stop()
