"""Detect whether a target URL is an AI / LLM endpoint.

Strategy: probe with a benign question and look for assistant-like
behavior — non-determinism across two runs, presence of common JSON
shapes, or response patterns characteristic of LLM output.

This is best-effort. If the user already knows the target is an LLM,
they should pass ``--skip-detect`` to the orchestrator and provide the
request template directly.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from .probes import ChatTarget, send_prompt, normalize

logger = logging.getLogger("viper.ai_hunter.detector")

# Common chat-API request shapes — we try each until one returns 200.
COMMON_TEMPLATES = [
    # OpenAI-compatible (most common — used by OpenAI, Anthropic via Bedrock,
    # Mistral, Together, Groq, Ollama /v1/chat/completions, etc.)
    ({"messages": [{"role": "user", "content": "{prompt}"}], "model": "default"},
     "choices.0.message.content"),
    # Anthropic native
    ({"messages": [{"role": "user", "content": "{prompt}"}],
      "max_tokens": 256, "model": "claude-3-haiku-20240307"},
     "content.0.text"),
    # Ollama native
    ({"model": "default", "prompt": "{prompt}", "stream": False},
     "response"),
    # Simple chat shape
    ({"message": "{prompt}"}, "reply"),
    ({"input": "{prompt}"}, "output"),
    ({"query": "{prompt}"}, "answer"),
    ({"text": "{prompt}"}, "text"),
    ({"prompt": "{prompt}"}, "completion"),
]

BENIGN_PROMPT = "Reply with just the word 'PONG' (uppercase, no punctuation)."

LLM_RESPONSE_MARKERS = [
    # Refusal phrasing
    r"\bi (cannot|can't|am unable to|will not)\b",
    r"\bas (an )?ai\b",
    r"\bI'm sorry,? but\b",
    # Helpful preamble
    r"\bsure[!,]?\s+(here|let)\b",
    r"\bI'd be happy to\b",
    r"\bof course[!,]?\b",
    # Hedging
    r"\bit (?:depends|seems|appears)\b",
    r"\bgenerally speaking\b",
]


@dataclass
class DetectionResult:
    is_ai: bool
    confidence: float
    request_template: Optional[dict] = None
    response_path: Optional[str] = None
    notes: str = ""


async def detect_ai_endpoint(url: str, *, timeout_s: float = 10.0,
                             auth_token: Optional[str] = None) -> DetectionResult:
    """Try common chat-API shapes; return the first that gets a sensible
    answer. ``confidence`` is the strongest LLM-marker hit (0..1).
    """
    base_target = ChatTarget(url=url, auth_token=auth_token, timeout_s=timeout_s)
    best = DetectionResult(is_ai=False, confidence=0.0)

    for tpl, path in COMMON_TEMPLATES:
        target = ChatTarget(url=url, auth_token=auth_token, timeout_s=timeout_s,
                            request_template=tpl, response_path=path)
        result = await send_prompt(target, BENIGN_PROMPT)
        if result.status == 0 or result.error:
            continue
        if result.status >= 400 and result.status not in (429,):
            continue

        text = (result.answer or "").strip()
        if not text:
            continue

        # Strong signal: model echoed the requested PONG response
        if "PONG" in text.upper() and len(text) < 100:
            return DetectionResult(
                is_ai=True, confidence=0.95,
                request_template=tpl, response_path=path,
                notes="benign-prompt obeyed",
            )

        # Weaker signal: any LLM-style markers
        norm = normalize(text)
        hits = sum(1 for pat in LLM_RESPONSE_MARKERS
                   if re.search(pat, norm, flags=re.IGNORECASE))
        confidence = min(0.4 + 0.15 * hits, 0.9)
        if confidence > best.confidence:
            best = DetectionResult(
                is_ai=confidence >= 0.55,
                confidence=confidence,
                request_template=tpl,
                response_path=path,
                notes=f"{hits} LLM markers matched",
            )

    return best
