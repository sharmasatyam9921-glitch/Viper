"""Shared fixtures for VIPER test suite."""

import asyncio
import sys
import os
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

import pytest

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ── RoE Engine ──

@pytest.fixture
def roe_engine():
    """RoEEngine with test scope."""
    from core.roe_engine import RoEEngine, RulesOfEngagement
    roe = RulesOfEngagement(
        client_name="TestCorp",
        in_scope_targets=["testphp.vulnweb.com", "demo.testfire.net", "*.example.com"],
        excluded_hosts=[
            {"host": "admin.example.com", "reason": "production admin"},
        ],
        allow_dos=False,
        allow_brute_force=True,
        allow_exploitation=True,
        allow_social_engineering=False,
        allow_data_exfiltration=False,
        max_severity_phase="exploitation",
        forbidden_tools=["metasploit"],
        forbidden_categories=["destructive"],
    )
    return RoEEngine(roe)


# ── Agent Bus ──

@pytest.fixture
async def agent_bus():
    """AgentBus with async teardown."""
    from core.agent_bus import AgentBus
    bus = AgentBus(max_queue_size=100)
    yield bus
    if bus.running:
        await bus.stop()


# ── Agent Registry ──

@pytest.fixture
def agent_registry():
    """AgentRegistry without health-check loop."""
    from core.agent_registry import AgentRegistry
    return AgentRegistry(check_interval=999, heartbeat_timeout=999)


# ── Approval Gate ──

@pytest.fixture
def approval_gate():
    """ApprovalGate in non-auto mode."""
    from core.approval_gate import ApprovalGate
    return ApprovalGate(auto_approve=False)


@pytest.fixture
def approval_gate_auto():
    """ApprovalGate in auto-approve mode."""
    from core.approval_gate import ApprovalGate
    return ApprovalGate(auto_approve=True)


# ── Target Guardrail ──

@pytest.fixture
def guardrail():
    """TargetGuardrail without LLM."""
    from core.guardrails import TargetGuardrail
    return TargetGuardrail()


# ── Stealth Engine ──

@pytest.fixture(params=[0, 1, 2, 3])
def stealth_engine(request):
    """StealthEngine at each level."""
    from core.stealth import StealthEngine
    return StealthEngine(level=request.param)


@pytest.fixture
def stealth_basic():
    from core.stealth import StealthEngine
    return StealthEngine(level=1)


@pytest.fixture
def stealth_paranoid():
    from core.stealth import StealthEngine
    return StealthEngine(level=3, proxies=["http://proxy1:8080", "http://proxy2:8080"])


# ── Rate Limiter ──

@pytest.fixture
def rate_limiter():
    """Fresh RateLimiter instance (not singleton)."""
    from core.rate_limiter import RateLimiter
    return RateLimiter()


# ── Chain Writer ──

@pytest.fixture
def mock_graph():
    """Mock graph engine for ChainWriter."""
    graph = MagicMock()
    graph.add_attack_chain = MagicMock()
    graph.add_step = MagicMock()
    graph.add_finding = MagicMock()
    return graph


@pytest.fixture
def chain_writer(mock_graph):
    """ChainWriter with mock graph engine."""
    from core.chain_writer import ChainWriter
    return ChainWriter(mock_graph)


# ── EvoGraph ──

@pytest.fixture
def evograph_db(tmp_path):
    """EvoGraph with isolated temp SQLite DB."""
    from core.evograph import EvoGraph
    db_path = tmp_path / "test_evograph.db"
    eg = EvoGraph(db_path=db_path)
    yield eg
    eg.conn.close()


# ── Finding Validator ──

@pytest.fixture
def finding_validator():
    """FindingValidator with no HTTP client (pattern-only)."""
    from core.finding_validator import FindingValidator
    return FindingValidator(http_client=None)


# ── State Machine ──

@pytest.fixture
def state_machine():
    """Factory for fresh StateMachine instances."""
    from core.orchestrator import StateMachine
    return StateMachine()
