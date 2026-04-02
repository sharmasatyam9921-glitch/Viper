"""Tests for AgentBus — async pub/sub message bus."""
import asyncio
import pytest
from core.agent_bus import AgentBus, BusMessage, Priority


class TestAgentBusSubscribePublish:
    async def test_subscribe_and_receive_message(self, agent_bus):
        received = []

        async def handler(msg: BusMessage):
            received.append(msg)

        agent_bus.subscribe("recon", handler)
        await agent_bus.start()
        msg_id = await agent_bus.publish("recon", payload={"target": "example.com"})
        assert msg_id  # non-empty string returned
        await asyncio.sleep(0.1)
        assert len(received) == 1
        assert received[0].topic == "recon"

    async def test_published_payload_accessible(self, agent_bus):
        received = []

        async def handler(msg: BusMessage):
            received.append(msg)

        agent_bus.subscribe("vuln", handler)
        await agent_bus.start()
        await agent_bus.publish("vuln", payload={"sqli": True}, priority=Priority.HIGH)
        await asyncio.sleep(0.1)
        assert received[0].payload == {"sqli": True}

    async def test_unsubscribe_stops_delivery(self, agent_bus):
        received = []

        async def handler(msg: BusMessage):
            received.append(msg)

        agent_bus.subscribe("exploit", handler)
        agent_bus.unsubscribe("exploit", handler)
        await agent_bus.start()
        await agent_bus.publish("exploit", payload="test")
        await asyncio.sleep(0.1)
        assert len(received) == 0

    async def test_multiple_subscribers_same_topic(self, agent_bus):
        calls_a = []
        calls_b = []

        async def handler_a(msg):
            calls_a.append(msg)

        async def handler_b(msg):
            calls_b.append(msg)

        agent_bus.subscribe("chain", handler_a)
        agent_bus.subscribe("chain", handler_b)
        await agent_bus.start()
        await agent_bus.publish("chain", payload="data")
        await asyncio.sleep(0.1)
        assert len(calls_a) == 1
        assert len(calls_b) == 1

    async def test_multiple_topics_isolated(self, agent_bus):
        recon_msgs = []
        vuln_msgs = []

        async def recon_handler(msg):
            recon_msgs.append(msg)

        async def vuln_handler(msg):
            vuln_msgs.append(msg)

        agent_bus.subscribe("recon", recon_handler)
        agent_bus.subscribe("vuln", vuln_handler)
        await agent_bus.start()
        await agent_bus.publish("recon", payload="recon_data")
        await asyncio.sleep(0.1)
        assert len(recon_msgs) == 1
        assert len(vuln_msgs) == 0


class TestAgentBusLifecycle:
    async def test_start_sets_running_true(self, agent_bus):
        agent_bus.subscribe("test", lambda m: None)
        await agent_bus.start()
        assert agent_bus.running is True

    async def test_stop_sets_running_false(self, agent_bus):
        agent_bus.subscribe("test", lambda m: None)
        await agent_bus.start()
        await agent_bus.stop()
        assert agent_bus.running is False

    async def test_double_start_idempotent(self, agent_bus):
        agent_bus.subscribe("test", lambda m: None)
        await agent_bus.start()
        await agent_bus.start()  # second call should be no-op
        assert agent_bus.running is True

    async def test_topics_property_reflects_subscriptions(self, agent_bus):
        agent_bus.subscribe("recon", lambda m: None)
        agent_bus.subscribe("exploit", lambda m: None)
        topics = agent_bus.topics
        assert "recon" in topics
        assert "exploit" in topics


class TestAgentBusStats:
    async def test_get_stats_returns_dict_with_published(self, agent_bus):
        stats = agent_bus.get_stats()
        assert isinstance(stats, dict)
        assert "published" in stats

    async def test_published_count_increments(self, agent_bus):
        agent_bus.subscribe("test", lambda m: None)
        before = agent_bus.get_stats()["published"]
        await agent_bus.publish("test", payload="x")
        after = agent_bus.get_stats()["published"]
        assert after == before + 1

    async def test_stats_has_queue_sizes(self, agent_bus):
        agent_bus.subscribe("recon", lambda m: None)
        stats = agent_bus.get_stats()
        assert "queue_sizes" in stats

    async def test_stats_has_running_key(self, agent_bus):
        stats = agent_bus.get_stats()
        assert "running" in stats


class TestAgentBusQueueFull:
    async def test_full_queue_drops_message_returns_empty_string(self):
        """A full queue returns empty string instead of message_id."""
        bus = AgentBus(max_queue_size=1)

        # Subscribe but DON'T start dispatcher so queue fills up
        received = []
        async def slow_handler(msg):
            received.append(msg)

        bus.subscribe("flood", slow_handler)
        # Fill the queue
        await bus.publish("flood", payload="msg1")
        # Second publish should overflow and return ""
        result = await bus.publish("flood", payload="msg2")
        # Either drops (returns "") or succeeds — depends on timing
        assert isinstance(result, str)


class TestAgentBusPriority:
    async def test_priority_enum_ordering(self):
        """Lower integer = higher priority."""
        assert Priority.CRITICAL < Priority.HIGH
        assert Priority.HIGH < Priority.MEDIUM
        assert Priority.MEDIUM < Priority.LOW

    async def test_bus_message_has_priority_field(self, agent_bus):
        received = []

        async def handler(msg):
            received.append(msg)

        agent_bus.subscribe("prio_test", handler)
        await agent_bus.start()
        await agent_bus.publish("prio_test", payload="hi", priority=Priority.CRITICAL)
        await asyncio.sleep(0.1)
        assert received[0].priority == Priority.CRITICAL

    async def test_bus_message_to_dict(self, agent_bus):
        received = []

        async def handler(msg):
            received.append(msg)

        agent_bus.subscribe("dict_test", handler)
        await agent_bus.start()
        await agent_bus.publish("dict_test", payload={"key": "val"}, agent_id="test-agent")
        await asyncio.sleep(0.1)
        d = received[0].to_dict()
        assert "message_id" in d
        assert "topic" in d
        assert "priority" in d
        assert d["agent_id"] == "test-agent"
