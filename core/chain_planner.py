"""ChainPlanner — turn a confirmed finding into the next hypothesis.

This is the piece that makes VIPER *chain* vulnerabilities instead of stopping
one hop deep. After a phase pass produces findings, the planner assigns each a
verdict and, for the ones that open new attack surface, emits follow-up tasks
(re-probe / deeper-exploit the newly-revealed URL). The HackMode loop runs those
follow-ups, feeds the results back in, and repeats — until the surface stops
growing (convergence), a depth budget is hit, or the global time budget expires.

Design properties (the "bounded DO-NOT-STOP" contract):

* **Explicit verdicts**, modelled on a triage gate, so exploration converges
  instead of looping forever:
    - ``KILL``           — noise / skipped / known false-positive. No chain.
    - ``DOWNGRADE``      — informational; recorded, never chained.
    - ``PASS``           — a real finding, but it reveals no new surface.
    - ``CHAIN_REQUIRED`` — a confirmed primitive / foothold / high-sev hit with
                           a concrete URL → spawn a follow-up task.
* **Cycle detection** via a seen-set keyed on (asset, origin), so the same
  confirmed-SQLi URL never re-spawns the same chain.
* **Depth budget** (``max_depth``) and a per-round task cap (``max_tasks``) so a
  pathological target can't fan out without bound.
* **Convergence, not a timeout, is the terminator**: when a round produces no
  new CHAIN_REQUIRED surface, the planner returns no tasks and the loop ends.

The planner is intentionally pure (no I/O, no bus, no async) so it is trivially
unit-testable; HackMode owns all the dispatch side-effects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from core.expansion import expand as _expand

# Verdicts
KILL = "KILL"
DOWNGRADE = "DOWNGRADE"
PASS = "PASS"
CHAIN_REQUIRED = "CHAIN-REQUIRED"

# Finding `type` suffixes that mean "a primitive was confirmed" → always chain.
_CONFIRMED_SUFFIXES = ("_exploited", "_confirmed", "_captured")
# Findings we never chain from (gate-skips, dedup markers, pure noise).
_KILL_TYPES = {"exploit_skipped", "post_skipped", "deduped"}
_INFO_SEVERITIES = {"info", "informational", "none", ""}
_HIGH_SEVERITIES = {"high", "critical"}


@dataclass
class ChainTask:
    """One follow-up the loop should dispatch against newly-revealed surface.

    ``techniques`` (when non-empty) scopes the follow-up to the specific probes
    that escalate the seed finding — so the loop runs the RIGHT next test, not the
    whole vuln phase. ``new_host`` marks a freshly-discovered host that warrants a
    full sweep. Both come from ``core.expansion``.
    """
    asset_url: str
    origin_type: str
    reason: str
    depth: int
    seed: dict = field(default_factory=dict)
    techniques: list = field(default_factory=list)
    new_host: bool = False


@dataclass
class ChainDecision:
    """Result of planning over one round of findings."""
    verdicts: list[tuple[str, str]] = field(default_factory=list)  # (signature, verdict)
    new_tasks: list[ChainTask] = field(default_factory=list)

    @property
    def converged(self) -> bool:
        """True when there is nothing new to chain — the loop should stop."""
        return not self.new_tasks


def _sig(finding: dict) -> str:
    """A stable-ish signature for a finding, for verdict reporting + dedup."""
    return "|".join(str(finding.get(k, "")) for k in
                    ("type", "vuln_type", "url", "parameter", "payload"))


def _url_of(finding: dict) -> str:
    return str(finding.get("url") or finding.get("endpoint")
               or finding.get("target") or "").strip()


class ChainPlanner:
    """Stateful across a single hunt: remembers what it has already chained."""

    def __init__(self, *, max_depth: int = 3, max_tasks: int = 24) -> None:
        self.max_depth = max(0, int(max_depth))
        self.max_tasks = max(1, int(max_tasks))
        self._seen: set[tuple[str, str]] = set()

    # -- verdict ----------------------------------------------------------

    def verdict(self, finding: dict) -> str:
        """Classify a single finding. Pure; no side effects."""
        t = str(finding.get("type", "")).lower()
        sev = str(finding.get("severity", "info")).lower()

        if t in _KILL_TYPES or finding.get("false_positive") or finding.get("skipped"):
            return KILL
        # A confirmed primitive or a foothold always warrants a follow-up.
        if finding.get("foothold") or t.endswith(_CONFIRMED_SUFFIXES):
            return CHAIN_REQUIRED
        # A high/critical finding with a concrete URL opens surface worth probing.
        if sev in _HIGH_SEVERITIES and _url_of(finding):
            return CHAIN_REQUIRED
        if sev in _INFO_SEVERITIES:
            return DOWNGRADE
        return PASS

    # -- planning ---------------------------------------------------------

    def plan(self, findings: list[dict], depth: int) -> ChainDecision:
        """Assign verdicts to `findings` and emit follow-up tasks.

        `depth` is the depth of the round that PRODUCED these findings; new
        tasks are stamped at depth+1. At/over max_depth we still classify but
        emit no tasks (so the loop terminates).
        """
        decision = ChainDecision()
        budget_left = depth < self.max_depth
        for f in findings or []:
            v = self.verdict(f)
            decision.verdicts.append((_sig(f), v))
            if v != CHAIN_REQUIRED or not budget_left:
                continue
            url = _url_of(f)
            if not url:
                continue
            origin = str(f.get("type", "")).lower() or "finding"
            # Targeted expansion picks the right next probe(s) and may retarget to
            # an origin (new host). Falls back to a generic re-probe if it declines.
            et = _expand(f)
            target = et.target if et else url
            key = (target, origin)
            if key in self._seen:
                continue
            self._seen.add(key)
            decision.new_tasks.append(ChainTask(
                asset_url=target,
                origin_type=origin,
                reason=(et.reason if et else
                        f"chain from {origin} ({f.get('severity', 'info')})"),
                depth=depth + 1,
                seed=f,
                techniques=list(et.techniques) if et else [],
                new_host=bool(et.new_host) if et else False,
            ))
            if len(decision.new_tasks) >= self.max_tasks:
                break
        return decision

    def reset(self) -> None:
        self._seen.clear()
