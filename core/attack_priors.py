"""Cross-hunt attack priors — close the evograph write->read learning loop.

``core/evograph.py`` records per ``(tech_signature, attack_type)`` attempt outcomes
and can rank attacks by historical success rate — but nothing ever CALLED
``record_attack``, so the map stayed empty and every hunt relearned from zero. This
module is the thin, fully best-effort wrapper that finally closes the loop:

  * during a hunt it RECORDS each technique's per-phase outcome, and
  * before a phase dispatches it REORDERS the technique list so attacks that have
    historically succeeded against the target's detected stack run FIRST (more
    value inside a fixed time budget).

It NEVER touches the validation gate. It changes only exploration ORDER and records
outcomes, so the precision-1.00 confirmation invariant is completely untouched — a
mis-ranked or mis-recorded attempt can at most waste a little time, never turn a
lead into a false submission. Every method is defensive: any failure (missing or
locked DB, schema drift) degrades to a no-op that returns its input unchanged, so
the learning layer can never break a hunt.
"""
from __future__ import annotations

import logging
import re
from typing import List, Optional

logger = logging.getLogger("viper.attack_priors")

# A technology finding's title looks like "nginx 1.18" / "PHP" / "Apache/2.4".
# We want the stable product token ("nginx", "php", "apache"), never the version.
_TOKEN_SPLIT = re.compile(r"[\s/,;:()]+")
_TOKEN_CLEAN = re.compile(r"[^a-z0-9.+#-]")


def tech_tokens_from_findings(findings) -> List[str]:
    """Extract stable technology tokens from a hunt's ``type == 'technology'``
    findings (emitted by the wappalyzer recon worker). ``[{'type':'technology',
    'title':'nginx 1.18'}]`` -> ``['nginx']``. Version-leading tokens are skipped.
    Deduped, order-preserving. Never raises."""
    toks: List[str] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        if str(f.get("type") or "").lower() != "technology":
            continue
        title = str(f.get("title") or f.get("name") or "")
        for w in _TOKEN_SPLIT.split(title):
            w = _TOKEN_CLEAN.sub("", w.lower())
            if len(w) >= 2 and not w[0].isdigit():
                toks.append(w)
                break   # first real product token per finding is enough
    return list(dict.fromkeys(toks))


class AttackPriors:
    """Best-effort recorder + ranker over evograph's tech_attack_map."""

    def __init__(self, enabled: bool = True, evograph=None):
        self._eg = evograph          # dependency-injected (tests) or lazily built
        self._session: Optional[int] = None
        if self._eg is None and enabled:
            try:
                from core.evograph import EvoGraph
                self._eg = EvoGraph()
            except Exception as e:  # noqa: BLE001 — disabled, not fatal
                logger.debug("attack priors off (evograph unavailable): %s", e)
                self._eg = None

    @property
    def active(self) -> bool:
        return self._eg is not None

    def start(self, target: str, tech_stack: Optional[List[str]] = None) -> None:
        """Open an evograph session so recorded attempts have a home. No-op if the
        evograph is unavailable."""
        if not self._eg:
            return
        try:
            self._session = self._eg.start_session(target, list(tech_stack or []))
        except Exception as e:  # noqa: BLE001
            logger.debug("attack priors start_session failed: %s", e)
            self._session = None

    def rank(self, techniques, tech_stack: Optional[List[str]]) -> List[str]:
        """Reorder ``techniques`` so attacks with a POSITIVE success history for
        ``tech_stack`` run first (highest rate first); everything else keeps its
        original relative order, appended after. Never drops, adds, or duplicates a
        technique — the returned set always equals the input set. No-op (returns the
        input order) when there is no history, no tech stack, or fewer than 2 items."""
        techs = list(techniques or [])
        if not self._eg or len(techs) < 2 or not tech_stack:
            return techs
        try:
            best = self._eg.get_best_attacks_for_tech(list(tech_stack), top_n=50)
            rate = {b["attack_type"]: float(b.get("success_rate") or 0.0) for b in best}
        except Exception as e:  # noqa: BLE001
            logger.debug("attack priors rank query failed: %s", e)
            return techs
        ranked = sorted((t for t in techs if rate.get(t, 0.0) > 0.0),
                        key=lambda t: -rate[t])
        ranked_set = set(ranked)
        rest = [t for t in techs if t not in ranked_set]   # unknowns + zero-history
        out = ranked + rest
        if set(out) != set(techs) or len(out) != len(techs):
            return techs   # invariant guard: never change the set (fail safe)
        return out

    def record(self, technique: str, tech_stack: Optional[List[str]], success: bool,
               confidence: float = 0.0) -> None:
        """Record one technique's outcome for this hunt's tech stack. No-op if no
        session was opened or the evograph is unavailable."""
        if not self._eg or self._session is None or not technique:
            return
        try:
            self._eg.record_attack(
                self._session, technique, list(tech_stack or []),
                bool(success), confidence=float(confidence),
                reward=1.0 if success else 0.0)
        except Exception as e:  # noqa: BLE001
            logger.debug("attack priors record_attack failed: %s", e)
