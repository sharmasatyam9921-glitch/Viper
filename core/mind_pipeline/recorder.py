"""Mind-trace recorder — context-manager for one LLM call.

Usage::

    rec = MindRecorder(store, purpose="vuln_classification",
                       hunt_id="hunt-123", agent_id="vuln-1")
    with rec as t:
        resp = await llm.complete(prompt, system=sys)
        t.bind(resp, model="claude-sonnet", provider="claude_cli")
    # → trace already persisted on context exit
    rec.link_finding(finding_id="f-abc", outcome="success")
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from .store import (
    MindStore, MindTrace, OUTCOME_PENDING, OUTCOME_FAILURE,
    new_trace_id, now_ms, get_store,
)

logger = logging.getLogger("viper.mind_pipeline.recorder")


class _PendingTrace:
    """Builder passed to the ``with`` block — caller calls ``bind()``."""

    def __init__(self, trace_id: str):
        self.trace_id = trace_id
        self.model = ""
        self.provider = ""
        self.response = ""
        self.success = False
        self.input_tokens = 0
        self.output_tokens = 0
        self.error: Optional[str] = None
        self.metadata: dict[str, Any] = {}

    def bind(self, response: Any, *,
             model: str,
             provider: str,
             input_tokens: int = 0,
             output_tokens: int = 0,
             error: Optional[str] = None,
             **metadata: Any) -> None:
        """Attach the LLM result to the in-flight trace."""
        # Tolerate dict-shaped responses, ModelRouter.ModelResponse, or strings
        if response is None:
            self.response = ""
            self.success = False
        elif isinstance(response, str):
            self.response = response
            self.success = bool(response.strip())
        elif isinstance(response, dict):
            text = response.get("content") or response.get("text")
            self.response = str(text if text is not None else response)
            self.success = bool(self.response.strip())
        else:
            # Duck-type. ModelRouter.ModelResponse exposes `.text`; other
            # providers / wrappers may expose `.content` instead.
            text = getattr(response, "text", None) or getattr(response, "content", None)
            self.response = str(text if text is not None else response)
            self.success = bool(self.response.strip())
        self.model = model
        self.provider = provider
        self.input_tokens = int(input_tokens or 0)
        self.output_tokens = int(output_tokens or 0)
        self.error = error
        self.metadata.update(metadata)


class MindRecorder:
    """Records one LLM call. Use as an ``with`` block; on exit the trace
    is persisted (even if no ``bind()`` happened — in that case it's
    persisted as a failure)."""

    def __init__(self, store: Optional[MindStore] = None, *,
                 purpose: str,
                 hunt_id: Optional[str] = None,
                 agent_id: Optional[str] = None,
                 phase: Optional[str] = None,
                 system_prompt: str = "",
                 user_prompt: str = "",
                 trace_id: Optional[str] = None):
        self.store = store or get_store()
        self.purpose = purpose
        self.hunt_id = hunt_id
        self.agent_id = agent_id
        self.phase = phase
        self.system_prompt = system_prompt
        self.user_prompt = user_prompt
        self.trace_id = trace_id or new_trace_id()
        self._pending: Optional[_PendingTrace] = None
        self._start_ts: Optional[float] = None

    # ── Sync + async context manager ───────────────────────────────────

    def __enter__(self) -> _PendingTrace:
        self._start_ts = time.time()
        self._pending = _PendingTrace(self.trace_id)
        return self._pending

    def __exit__(self, exc_type, exc, tb):
        self._persist(exc=exc)
        return False  # don't swallow

    async def __aenter__(self) -> _PendingTrace:
        return self.__enter__()

    async def __aexit__(self, exc_type, exc, tb):
        return self.__exit__(exc_type, exc, tb)

    # ── Persist + outcome linking ──────────────────────────────────────

    def _persist(self, exc: Optional[BaseException] = None) -> None:
        if self._pending is None or self._start_ts is None:
            return
        latency_ms = int((time.time() - self._start_ts) * 1000)
        pending = self._pending
        if exc is not None and not pending.error:
            pending.error = repr(exc)
            pending.success = False

        trace = MindTrace(
            id=self.trace_id,
            ts=now_ms(),
            hunt_id=self.hunt_id,
            agent_id=self.agent_id,
            phase=self.phase,
            purpose=self.purpose,
            model=pending.model,
            provider=pending.provider or "unknown",
            system_prompt=self.system_prompt,
            user_prompt=self.user_prompt,
            response=pending.response,
            latency_ms=latency_ms,
            input_tokens=pending.input_tokens,
            output_tokens=pending.output_tokens,
            success=pending.success,
            outcome=OUTCOME_PENDING if pending.success else OUTCOME_FAILURE,
            error=pending.error,
            metadata=pending.metadata,
        )
        try:
            self.store.insert(trace)
        except Exception as e:  # noqa: BLE001
            logger.warning("MindRecorder persist failed: %s", e)

    def link_finding(self, finding_id: Optional[str] = None, *,
                     outcome: str,
                     score: Optional[float] = None) -> bool:
        """Attach the downstream outcome to this trace. Returns True if
        the update hit a row."""
        return self.store.update_outcome(
            self.trace_id, outcome=outcome,
            finding_id=finding_id, feedback_score=score,
        )
