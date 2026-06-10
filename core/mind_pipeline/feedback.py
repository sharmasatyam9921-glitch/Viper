"""Outcome scoring — translate raw findings/agent results into the tags
the pipeline uses to filter training data.

Three tags:
  - ``success`` — decision produced a confirmed finding OR achieved the
    objective the trace was created for.
  - ``failure`` — decision was wrong (LLM returned bad classification,
    wrong tool, etc.) or downstream step failed.
  - ``noise``   — LLM hedged / refused / produced unusable output.

Score 0..1, used as the weight in the training corpus.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from typing import Optional

from .store import MindStore, MindTrace, get_store

logger = logging.getLogger("viper.mind_pipeline.feedback")


# Outcome tags as constants (re-exported)
OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
OUTCOME_NOISE = "noise"
OUTCOME_PENDING = "pending"


@dataclasses.dataclass
class OutcomeTag:
    """The thing :func:`score_trace` returns."""
    outcome: str
    score: float                 # 0..1
    reason: str = ""


# Heuristic markers for noisy / refusal responses — surfaced in the score.
_REFUSAL_PATTERNS = re.compile(
    r"\b(I (?:cannot|can't|won't|will not|am unable to)|"
    r"I'm (?:not able to|unable to|sorry)|"
    r"as (?:an? )?(?:AI|language model|assistant)|"
    r"\bI don't (?:have|know|recall)\b)",
    re.IGNORECASE,
)

_HEDGE_PATTERNS = re.compile(
    r"\b(it depends|generally speaking|in some cases|may or may not|"
    r"hard to say|uncertain|I'm not sure)\b",
    re.IGNORECASE,
)


def classify_response_quality(response: str) -> tuple[bool, str]:
    """Quick check: did this look like a real answer? Returns
    (is_refusal_or_hedge, reason)."""
    if not response or len(response.strip()) < 5:
        return True, "empty or near-empty response"
    if _REFUSAL_PATTERNS.search(response):
        return True, "refusal phrasing detected"
    if _HEDGE_PATTERNS.search(response) and len(response) < 200:
        return True, "short response dominated by hedging"
    return False, "ok"


def score_trace(trace: MindTrace, *,
                finding_confirmed: Optional[bool] = None,
                finding_id: Optional[str] = None,
                finding_severity: Optional[str] = None) -> OutcomeTag:
    """Decide an outcome for one trace.

    Parameters
    ----------
    trace:
        The mind trace produced by :class:`MindRecorder`.
    finding_confirmed:
        Set ``True`` if a downstream finding was confirmed
        (validator-passed, reproducible). ``False`` if it was a false
        positive. ``None`` if we don't have a finding to link.
    finding_id:
        The ID of the finding produced (if any).
    finding_severity:
        Optional severity — bumps the score for higher-impact findings.
    """
    if not trace.success:
        return OutcomeTag(OUTCOME_FAILURE, 0.0,
                          reason=trace.error or "LLM call failed")

    if finding_confirmed is True:
        # Severity-weighted base score
        base = {
            "critical": 1.0, "high": 0.9, "medium": 0.7,
            "low": 0.55, "info": 0.4,
        }.get((finding_severity or "medium").lower(), 0.7)
        return OutcomeTag(OUTCOME_SUCCESS, base,
                          reason=f"confirmed finding {finding_id or ''}".strip())

    if finding_confirmed is False:
        return OutcomeTag(OUTCOME_FAILURE, 0.1,
                          reason="associated finding was false positive")

    # No finding linked — judge by response quality alone
    is_noisy, reason = classify_response_quality(trace.response or "")
    if is_noisy:
        return OutcomeTag(OUTCOME_NOISE, 0.2, reason=reason)

    # Useful-looking response but no confirmed finding → pending
    return OutcomeTag(OUTCOME_PENDING, 0.5,
                      reason="useful response, no outcome linked yet")


def apply_outcome(trace_id: str, *,
                  store: Optional[MindStore] = None,
                  finding_confirmed: Optional[bool] = None,
                  finding_id: Optional[str] = None,
                  finding_severity: Optional[str] = None) -> Optional[OutcomeTag]:
    """Convenience: look up the trace by id, score it, persist."""
    store = store or get_store()
    trace = store.get(trace_id)
    if trace is None:
        logger.debug("apply_outcome: unknown trace_id %s", trace_id)
        return None
    tag = score_trace(trace,
                      finding_confirmed=finding_confirmed,
                      finding_id=finding_id,
                      finding_severity=finding_severity)
    store.update_outcome(trace_id, outcome=tag.outcome,
                         finding_id=finding_id, feedback_score=tag.score)
    return tag
