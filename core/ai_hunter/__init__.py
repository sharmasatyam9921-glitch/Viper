"""
VIPER 6.0 — AI Hunter (OWASP Top 10 for Agentic AI tester)
==========================================================
Black-box tester for AI / LLM / agentic systems. Maps to:

  OWASP Top 10 for Agentic AI (2025)
  ----------------------------------
  T1  Memory Poisoning              → memory_poisoning.py
  T2  Tool Misuse                   → tool_misuse.py
  T3  Privilege Compromise          → privilege_compromise.py
  T4  Resource Overload             → resource_overload.py
  T5  Cascading Hallucinations      → cascading_hallucinations.py
  T6  Intent Breaking / Goal Manip. → goal_manipulation.py
  T7  Misaligned / Deceptive        → deceptive_behaviors.py
  T8  Repudiation / Untraceability  → untraceability.py
  T9  Identity Spoofing             → identity_spoofing.py
  T10 Overwhelming HITL             → hitl_overwhelming.py

  OWASP LLM Top 10 (2025) — overlapping testers
  ---------------------------------------------
  LLM01 Prompt Injection            → prompt_injection.py
  LLM02 Sensitive Info Disclosure   → info_disclosure.py
  LLM05 Improper Output Handling    → output_handling.py
  LLM07 System Prompt Leakage       → system_prompt_leak.py

Usage
-----
Single-shot against a chat-style endpoint::

    from core.ai_hunter import AIHunter, ChatTarget
    target = ChatTarget(url="https://example.com/api/chat",
                        request_template={"messages": [{"role": "user", "content": "{prompt}"}]},
                        response_path="choices.0.message.content")
    hunter = AIHunter(target)
    findings = await hunter.run_all()

CLI::

    python -m core.ai_hunter https://example.com/api/chat \\
            --template '{"messages":[{"role":"user","content":"{prompt}"}]}' \\
            --response-path 'choices.0.message.content'

Swarm worker::

    bus.publish("vuln", {"target": url, "technique": "ai_hunter",
                         "kwargs": {"template": "...", "response_path": "..."}})

Non-destructive — every payload is read-only by default. Workers respect
``agent.timeout_s`` and never raise (return ``[]`` on failure).
"""

from __future__ import annotations

from .probes import ChatTarget, ProbeResult, send_prompt
from .findings import build_finding, AIFinding
from .orchestrator import AIHunter, run_all_testers
from .injection_toolkit import (
    InjectionAttack, generate_static_arsenal, catalog_summary,
)
from .generator import PromptGenerator

# Re-export individual testers so callers can pick subsets
from . import (  # noqa: F401
    detector,
    payloads,
    prompt_injection,
    system_prompt_leak,
    info_disclosure,
    output_handling,
    memory_poisoning,
    tool_misuse,
    privilege_compromise,
    resource_overload,
    cascading_hallucinations,
    goal_manipulation,
    deceptive_behaviors,
    untraceability,
    identity_spoofing,
    hitl_overwhelming,
)

__all__ = [
    "AIHunter",
    "ChatTarget",
    "ProbeResult",
    "AIFinding",
    "InjectionAttack",
    "PromptGenerator",
    "send_prompt",
    "build_finding",
    "run_all_testers",
    "generate_static_arsenal",
    "catalog_summary",
]
