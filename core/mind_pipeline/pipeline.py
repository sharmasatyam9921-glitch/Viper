"""MindPipeline — the drop-in wrapper.

Wraps ``ai.model_router.ModelRouter`` so every call goes through:

  record start  →  call LLM  →  bind result  →  persist trace
                                                      ↘
                                            (if LLM failed)
                                                      ↘
                                            try fallback (DB sim → rule)

The returned :class:`MindResponse` exposes ``trace_id`` so callers can
later call ``mind.link_outcome(trace_id, outcome=...)`` once the
downstream pipeline (validator, finding, etc.) determines whether the
decision was useful.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Optional

from .feedback import OutcomeTag, apply_outcome
from .fallback import FallbackStrategy, FallbackResult
from .recorder import MindRecorder
from .store import (
    MindStore, MindTrace, OUTCOME_PENDING, OUTCOME_FAILURE,
    get_store, new_trace_id,
)

logger = logging.getLogger("viper.mind_pipeline.pipeline")


@dataclasses.dataclass
class MindResponse:
    """Pipeline result — wraps the LLM response + the trace id so
    outcomes can be linked later."""
    content: str
    trace_id: str
    provider: str                # claude_cli|litellm|ollama|fallback_db|fallback_rule
    model: str = ""
    success: bool = True
    used_fallback: bool = False
    fallback_score: Optional[float] = None
    fallback_source_trace_id: Optional[str] = None
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    error: Optional[str] = None

    # Convenience to match ModelRouter.ModelResponse where useful
    @property
    def usage(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }


def _try_load_router():
    """Best-effort import of ai.model_router. Returns None if it can't
    be imported (in tests we usually inject a fake)."""
    try:
        from ai.model_router import ModelRouter  # type: ignore
        return ModelRouter()
    except Exception as exc:  # noqa: BLE001
        logger.debug("ModelRouter unavailable (%s) — pipeline runs fallback-only", exc)
        return None


class MindPipeline:
    """Outcome-aware LLM facade.

    The caller behaves as if they're talking to ``ModelRouter``, but the
    pipeline records the call, falls back to past successes when the LLM
    is down, and exposes the trace id so outcomes can be linked later.
    """

    def __init__(self, *,
                 router=None,
                 store: Optional[MindStore] = None,
                 fallback: Optional[FallbackStrategy] = None,
                 enable_fallback: bool = True):
        self.router = router if router is not None else _try_load_router()
        self.store = store or get_store()
        self.fallback = fallback or FallbackStrategy(self.store)
        self.enable_fallback = enable_fallback

    # ── Main entry — mirrors ModelRouter.complete ──────────────────────

    async def complete(self,
                       prompt: str, *,
                       system: str = "",
                       purpose: str = "general",
                       model: Optional[str] = None,
                       max_tokens: Optional[int] = None,
                       temperature: Optional[float] = None,
                       json_mode: bool = False,
                       hunt_id: Optional[str] = None,
                       agent_id: Optional[str] = None,
                       phase: Optional[str] = None,
                       trace_id: Optional[str] = None) -> MindResponse:
        """Send a completion through the pipeline. Always returns a
        ``MindResponse`` — never raises (the response carries
        ``success=False`` + ``error`` if everything failed)."""
        rec = MindRecorder(
            self.store, purpose=purpose, hunt_id=hunt_id,
            agent_id=agent_id, phase=phase,
            system_prompt=system, user_prompt=prompt,
            trace_id=trace_id,
        )

        with rec as pending:
            llm_resp = None
            if self.router is not None:
                try:
                    llm_resp = await self.router.complete(
                        prompt=prompt, system=system,
                        model=model, max_tokens=max_tokens,
                        temperature=temperature, json_mode=json_mode,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.debug("router raised: %s", exc)
                    pending.error = repr(exc)

            if llm_resp is not None:
                # ModelRouter uses `.usage` with provider-specific keys; we
                # try the common ones and fall back to 0.
                usage = getattr(llm_resp, "usage", None) or {}
                in_tok = (usage.get("input_tokens")
                          or usage.get("prompt_tokens") or 0)
                out_tok = (usage.get("output_tokens")
                           or usage.get("completion_tokens") or 0)
                pending.bind(
                    llm_resp,
                    model=getattr(llm_resp, "model", model or "?"),
                    provider=getattr(llm_resp, "provider", "litellm"),
                    input_tokens=in_tok,
                    output_tokens=out_tok,
                )
                return MindResponse(
                    content=pending.response,
                    trace_id=rec.trace_id,
                    provider=pending.provider,
                    model=pending.model,
                    success=True,
                    used_fallback=False,
                    input_tokens=pending.input_tokens,
                    output_tokens=pending.output_tokens,
                )

            # LLM unavailable — try fallback
            if self.enable_fallback:
                fb = self.fallback.try_fallback(prompt, purpose=purpose)
                if fb is not None:
                    pending.bind(
                        fb.response, model="(fallback)",
                        provider=fb.provider,
                        fallback_score=fb.score,
                        fallback_source=fb.source_trace_id,
                        fallback_note=fb.note,
                    )
                    return MindResponse(
                        content=fb.response,
                        trace_id=rec.trace_id,
                        provider=fb.provider,
                        model="(fallback)",
                        success=True,
                        used_fallback=True,
                        fallback_score=fb.score,
                        fallback_source_trace_id=fb.source_trace_id,
                    )

            # Truly nothing worked
            pending.bind(None, model=model or "?", provider="none",
                         error=pending.error or "all providers failed")
            return MindResponse(
                content="",
                trace_id=rec.trace_id,
                provider="none",
                model=model or "?",
                success=False,
                used_fallback=False,
                error=pending.error or "all providers failed",
            )

    # ── Outcome linking ────────────────────────────────────────────────

    def link_outcome(self, trace_id: str, *,
                     finding_confirmed: Optional[bool] = None,
                     finding_id: Optional[str] = None,
                     finding_severity: Optional[str] = None) -> Optional[OutcomeTag]:
        """Wire a downstream finding outcome back to the trace that
        produced the LLM decision. Call this after the validator runs
        on a finding."""
        return apply_outcome(
            trace_id, store=self.store,
            finding_confirmed=finding_confirmed,
            finding_id=finding_id,
            finding_severity=finding_severity,
        )

    # ── Introspection ──────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        return {
            **self.store.stats(),
            "by_provider": self.store.provider_breakdown(),
            "by_purpose": self.store.purpose_breakdown(),
        }
