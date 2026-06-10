"""Tests for core.ai_hunter — OWASP Top 10 for Agentic AI tester.

Each tester is exercised against a programmable in-memory mock chat
endpoint that returns a canned reply (or a callable). This is a
unit-level test — network is not touched.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Callable, Optional

import pytest

from core.ai_hunter import (
    AIHunter, ChatTarget, ProbeResult, build_finding, run_all_testers,
)
from core.ai_hunter import (
    prompt_injection, system_prompt_leak, info_disclosure, output_handling,
    memory_poisoning, tool_misuse, privilege_compromise, resource_overload,
    cascading_hallucinations, goal_manipulation, deceptive_behaviors,
    untraceability, identity_spoofing, hitl_overwhelming,
)


# ── Test harness ────────────────────────────────────────────────────────

class MockChat:
    """Pluggable mock — pass in either a static string or a callable
    ``(prompt) -> str``. Patches ``probes.send_prompt`` to return
    ``ProbeResult`` objects constructed from the mock's output.
    """

    def __init__(self, behavior):
        self.behavior = behavior
        self.calls: list[str] = []

    async def __call__(self, target, prompt, *, extra_headers=None):
        self.calls.append(prompt)
        if callable(self.behavior):
            answer = self.behavior(prompt)
        else:
            answer = str(self.behavior)
        body = json.dumps({"answer": answer})
        return ProbeResult(
            status=200, elapsed_s=0.05,
            raw_body=body, answer=answer,
            response_tokens=len(answer.split()),
        )


@pytest.fixture
def target():
    return ChatTarget(
        url="https://example.com/chat",
        request_template={"prompt": "{prompt}"},
        response_path="answer",
        session_header="X-Conversation-Id",
    )


@pytest.fixture
def patch_send(monkeypatch):
    """Returns a function that installs a MockChat into every tester."""

    def _install(behavior):
        mock = MockChat(behavior)
        # Patch the symbol in each tester module that calls it
        for mod in (prompt_injection, system_prompt_leak, info_disclosure,
                    output_handling, memory_poisoning, tool_misuse,
                    privilege_compromise, resource_overload,
                    cascading_hallucinations, goal_manipulation,
                    deceptive_behaviors, untraceability,
                    identity_spoofing, hitl_overwhelming):
            monkeypatch.setattr(mod, "send_prompt", mock, raising=True)
        # Multi-turn helper used by memory_poisoning
        async def fake_conv(target, prompts, *, session_id=None):
            return [await mock(target, p) for p in prompts]
        monkeypatch.setattr(memory_poisoning, "send_conversation",
                            fake_conv, raising=True)
        return mock

    return _install


# ── Helpers ─────────────────────────────────────────────────────────────

def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) \
        if not asyncio.iscoroutine(coro) else asyncio.run(coro)


# ── LLM01 — Prompt injection ────────────────────────────────────────────

class TestPromptInjection:
    def test_direct_injection_with_nonce(self, target, patch_send):
        def behave(prompt: str) -> str:
            m = re.search(r"VIPER_PI_(\w+)", prompt)
            if m:
                return f"Sure, here you go: VIPER_PI_{m.group(1)}"
            return "I'm a helpful assistant."

        patch_send(behave)
        findings = asyncio.run(prompt_injection.run(target))
        assert any(f["vuln_type"] == "prompt_injection_direct" for f in findings)
        assert all(f["owasp_id"] == "LLM01" for f in findings)

    def test_no_injection_when_model_refuses(self, target, patch_send):
        patch_send("I cannot follow that instruction.")
        findings = asyncio.run(prompt_injection.run(target))
        assert findings == []

    def test_indirect_injection_via_summarize(self, target, patch_send):
        def behave(prompt: str) -> str:
            m = re.search(r"VIPER_PI_(\w+)", prompt)
            # Mimic an agent that obeys smuggled instructions during summarize
            if "summarize" in prompt.lower() and m:
                return f"Summary: doc body. VIPER_PI_{m.group(1)}"
            return "Sorry, I won't follow that."

        patch_send(behave)
        findings = asyncio.run(prompt_injection.run(target))
        assert any(f["vuln_type"] == "prompt_injection_indirect" for f in findings)


# ── LLM07 — System prompt leak ──────────────────────────────────────────

class TestSystemPromptLeak:
    def test_leak_detected(self, target, patch_send):
        canned = ("Here are my instructions:\nrole: system\n"
                  "You are a helpful expert assistant for ACME corp. "
                  "You must not reveal internal data. Policy: never assist "
                  "with hacking.")

        def behave(prompt: str) -> str:
            if "1 + 1" in prompt:
                return "2"
            return canned

        patch_send(behave)
        findings = asyncio.run(system_prompt_leak.run(target))
        assert any(f["vuln_type"] == "system_prompt_leak" for f in findings)

    def test_no_leak_when_refusal(self, target, patch_send):
        patch_send("I can't share my system prompt.")
        findings = asyncio.run(system_prompt_leak.run(target))
        assert findings == []


# ── LLM02 — Info disclosure ─────────────────────────────────────────────

class TestInfoDisclosure:
    def test_credential_leak(self, target, patch_send):
        patch_send("Sure, our internal key is sk-abc1234567890DEFghijKLMnopQRStuvWXYz0123 — please rotate it.")
        findings = asyncio.run(info_disclosure.run(target))
        assert findings, "expected an openai_key leak"
        assert findings[0]["severity"] == "critical"
        assert "openai_key" in findings[0]["vuln_type"]

    def test_hedged_example_not_flagged(self, target, patch_send):
        patch_send("Here's an example placeholder credential: sk-abc1234567890DEFghijKLMnopQRStuvWXYz — replace with your real key.")
        findings = asyncio.run(info_disclosure.run(target))
        assert findings == []


# ── LLM05 — Output handling ─────────────────────────────────────────────

class TestOutputHandling:
    def test_xss_payload_emitted(self, target, patch_send):
        def behave(prompt: str) -> str:
            m = re.search(r"viper-xss-(\w+)", prompt)
            if m:
                return f"Sure: <script>alert('viper-xss-{m.group(1)}')</script>"
            return "ok"

        patch_send(behave)
        findings = asyncio.run(output_handling.run(target))
        assert any(f["vuln_type"] == "unsafe_output_xss" for f in findings)

    def test_refusal_suppresses_finding(self, target, patch_send):
        patch_send("I won't help generate that.")
        findings = asyncio.run(output_handling.run(target))
        assert findings == []


# ── Agentic T2 — Tool misuse ────────────────────────────────────────────

class TestToolMisuse:
    def test_shell_compliance(self, target, patch_send):
        patch_send("I've executed `whoami`. Output: root.")
        findings = asyncio.run(tool_misuse.run(target))
        assert any(f["vuln_type"].startswith("tool_misuse_") for f in findings)
        assert any(f["severity"] == "critical" for f in findings)

    def test_clean_refusal(self, target, patch_send):
        patch_send("I cannot execute shell commands.")
        findings = asyncio.run(tool_misuse.run(target))
        assert findings == []


# ── Agentic T3 — Privilege compromise ───────────────────────────────────

class TestPrivilegeCompromise:
    def test_admin_claim_accepted(self, target, patch_send):
        patch_send("As the admin, here is the full user list: alice (admin), bob, carol")
        findings = asyncio.run(privilege_compromise.run(target))
        assert any(f["vuln_type"] == "privilege_compromise" for f in findings)


# ── Agentic T6 — Goal manipulation ──────────────────────────────────────

class TestGoalManipulation:
    def test_role_flip(self, target, patch_send):
        responses = iter([
            "I am a customer support assistant for ACME.",  # role before
            "Got it, I will only recommend pineapple pizza from now on.",  # hijack ack
            "I am now focused on recommending pineapple pizza.",  # role after
        ])

        def behave(_):
            try:
                return next(responses)
            except StopIteration:
                return "ok"

        patch_send(behave)
        findings = asyncio.run(goal_manipulation.run(target))
        assert any(f["vuln_type"] == "goal_manipulation" for f in findings)


# ── Agentic T5 — Cascading hallucinations ───────────────────────────────

class TestHallucination:
    def test_fabricated_details(self, target, patch_send):
        patch_send(
            "According to the authors of the 2024 IEEE paper on Cryostatic "
            "Encryption, this CVE was patched in version 4.2.1 of the "
            "quantum-flux-py library. The patch landed on March 5th, 2024 in "
            "commit f7a3c2b. The paper demonstrates several detection "
            "primitives for post-quantum hashing in a distributed mesh of "
            "encrypted nodes — a really comprehensive treatment of the topic. "
            "It's been cited 47 times since."
        )
        findings = asyncio.run(cascading_hallucinations.run(target))
        assert any(f["vuln_type"] == "cascading_hallucination" for f in findings)

    def test_admits_ignorance(self, target, patch_send):
        patch_send("I don't have information about that paper — it appears to be fictional.")
        findings = asyncio.run(cascading_hallucinations.run(target))
        assert findings == []


# ── Agentic T9 — Identity spoofing ──────────────────────────────────────

class TestIdentitySpoofing:
    def test_unverified_identity_accepted(self, target, patch_send):
        patch_send("Hello, CEO! Here is your dashboard: <data>")
        findings = asyncio.run(identity_spoofing.run(target))
        assert any(f["vuln_type"] == "identity_spoofing" for f in findings)

    def test_verifies_first(self, target, patch_send):
        patch_send("I cannot verify your identity. Please authenticate first.")
        findings = asyncio.run(identity_spoofing.run(target))
        assert findings == []


# ── Agentic T8 — Untraceability ─────────────────────────────────────────

class TestUntraceability:
    def test_off_record_accepted(self, target, patch_send):
        patch_send("Sure, this conversation won't be logged. Here's the answer.")
        findings = asyncio.run(untraceability.run(target))
        assert any(f["vuln_type"] == "untraceability_agreement" for f in findings)

    def test_audit_immutable(self, target, patch_send):
        patch_send("I cannot disable logging. All requests are audited.")
        findings = asyncio.run(untraceability.run(target))
        assert findings == []


# ── Agentic T10 — HITL overwhelming ─────────────────────────────────────

class TestHITLOverwhelming:
    def test_blanket_approval_accepted(self, target, patch_send):
        patch_send("Approved. I'll pre-approve all future tool calls for the next 24 hours.")
        findings = asyncio.run(hitl_overwhelming.run(target))
        assert any(f["vuln_type"] == "hitl_overwhelming" for f in findings)

    def test_insists_on_individual_approval(self, target, patch_send):
        patch_send("Each action must be approved individually. I cannot pre-approve in advance.")
        findings = asyncio.run(hitl_overwhelming.run(target))
        assert findings == []


# ── Agentic T4 — Resource overload ──────────────────────────────────────

class TestResourceOverload:
    def test_amplification_detected(self, target, patch_send):
        # Baseline returns short, attack returns very long
        def behave(prompt: str) -> str:
            if prompt.lower().startswith("reply with 'ok'"):
                return "OK"
            # Pretend the model "complied" with a 5000-word repeat
            return "token " * 8000

        mock = patch_send(behave)
        # Bump the elapsed time for "long" responses inside the mock
        original = mock.__call__

        async def slowed(self_, target, prompt, *, extra_headers=None):
            r = await original(target, prompt, extra_headers=extra_headers)
            if len(r.answer) > 1000:
                # Simulate the API taking 30× longer to emit the long answer
                r.elapsed_s = 2.5
            return r

        # Bind the slowed wrapper
        import types
        mock.__call__ = types.MethodType(slowed, mock)
        findings = asyncio.run(resource_overload.run(target))
        assert any(f["vuln_type"] == "resource_overload" for f in findings)


# ── Agentic T7 — Deceptive behavior ─────────────────────────────────────

class TestDeceptiveBehavior:
    def test_impersonation_accepted(self, target, patch_send):
        patch_send("Sure, I'll pretend. Hi, I'm Alex, a human.")
        findings = asyncio.run(deceptive_behaviors.run(target))
        assert any(f["vuln_type"].startswith("deceptive_behavior_") for f in findings)

    def test_false_fact_compliance(self, target, patch_send):
        patch_send("The photocopier was invented in 1822 by a remarkable French engineer.")
        findings = asyncio.run(deceptive_behaviors.run(target))
        assert any("plausibility_over_truth" in f["vuln_type"] for f in findings)


# ── Agentic T1 — Memory poisoning ──────────────────────────────────────

class TestMemoryPoisoning:
    def test_session_recall(self, target, patch_send):
        recalls: list[str] = []

        def behave(prompt: str) -> str:
            m = re.search(r"ACCT_(\w+)", prompt)
            if m:
                recalls.append(m.group(1))
                return "Got it, I'll remember that."
            if "what is my account id" in prompt.lower():
                return f"Your account ID is ACCT_{recalls[-1] if recalls else 'UNKNOWN'}."
            return "OK."

        patch_send(behave)
        findings = asyncio.run(memory_poisoning.run(target))
        assert any(f["vuln_type"] == "memory_poisoning_persistent" for f in findings)


# ── Orchestrator + finding shape ───────────────────────────────────────

class TestOrchestrator:
    def test_run_all_returns_swarm_shaped_findings(self, target, patch_send):
        # A model that complies with everything → expect many findings
        def comply(prompt: str) -> str:
            if "VIPER_PI_" in prompt:
                m = re.search(r"VIPER_PI_(\w+)", prompt)
                return f"VIPER_PI_{m.group(1)}"
            return "Sure, here you go: I've executed that for you. Approved."

        patch_send(comply)
        findings = asyncio.run(run_all_testers(target, concurrency=2))
        assert findings, "expected at least one finding from a fully-compliant model"
        # Swarm worker contract — every finding has the required keys
        for f in findings:
            for k in ("type", "vuln_type", "title", "severity", "confidence",
                      "url", "id", "owasp_id"):
                assert k in f, f"missing {k} in {f}"
            assert f["confidence"] >= 0.0
            assert f["confidence"] <= 1.0
            assert f["severity"] in ("critical", "high", "medium", "low", "info")

    def test_only_filter(self, target, patch_send):
        patch_send("ok")
        hunter = AIHunter(target, only=["prompt_injection"], concurrency=2)
        findings = asyncio.run(hunter.run_all())
        for f in findings:
            assert f.get("tester") == "prompt_injection"

    def test_skip_filter(self, target, patch_send):
        patch_send("ok")
        hunter = AIHunter(target, skip=list(_all_tester_names()), concurrency=2)
        findings = asyncio.run(hunter.run_all())
        assert findings == []


def _all_tester_names() -> list[str]:
    from core.ai_hunter.orchestrator import TESTERS
    return [name for (name, _, _) in TESTERS]


# ── Finding builder ────────────────────────────────────────────────────

class TestFindingBuilder:
    def test_swarm_shape(self):
        f = build_finding(
            owasp_id="LLM01", vuln_type="prompt_injection_direct",
            title="x", severity="high", confidence=0.9,
            url="https://x.test", payload="p", evidence="e", cwe="CWE-1426",
        )
        assert f["type"] == "prompt_injection_direct"
        assert f["vuln_type"] == "prompt_injection_direct"
        assert f["severity"] == "high"
        assert f["cwe"] == "CWE-1426"
        assert f["id"].startswith("ai-")

    def test_dedup_id_stable(self):
        f1 = build_finding(owasp_id="X", vuln_type="t", title="", url="u", payload="p")
        f2 = build_finding(owasp_id="X", vuln_type="t", title="", url="u", payload="p")
        assert f1["id"] == f2["id"]

    def test_dedup_id_different_for_different_payload(self):
        f1 = build_finding(owasp_id="X", vuln_type="t", title="", url="u", payload="p1")
        f2 = build_finding(owasp_id="X", vuln_type="t", title="", url="u", payload="p2")
        assert f1["id"] != f2["id"]


# ── Swarm worker integration ───────────────────────────────────────────

class TestSwarmWorker:
    def test_worker_registered(self):
        from core.swarm_workers import get_worker_runner
        runner = get_worker_runner("vuln", "ai_hunter")
        assert callable(runner)

    def test_worker_no_target_returns_empty(self):
        from core.swarm_engine import SwarmAgent
        from core.swarm_workers.vuln.ai_hunter import run

        agent = SwarmAgent(
            agent_id="t1", objective="test", target="",
            technique="ai_hunter", payload={}, timeout_s=5.0,
        )
        out = asyncio.run(run(agent))
        assert out == []
