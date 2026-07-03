"""Adversarial self-verifier — a reproducibility refutation pass over the gate.

The validation gate confirms a finding with ONE independent re-test. That is a
different cognitive act from *refutation*: trying to prove the finding false. A real
vulnerability re-confirms EVERY time; a transient one — a load-dependent timing blip,
an intermittent 5xx that happened to look like a DB error, a race that fired once —
may have confirmed on a single lucky re-test. This pass re-runs the gate's own
re-test on each ALREADY-SUBMITTABLE finding a few more times and DEMOTES any that do
not reproduce in all of them, tagging why.

Safety by construction — it can only ever move a finding from submittable -> lead:

  * It never touches a finding that was not already submittable (never promotes).
  * A deterministic true positive re-confirms every round, so it is never demoted —
    which is the "never lower recall on a known TP" guarantee the scorecard's vuln
    scenarios lock down (see tests). Only a NON-reproducible confirmation is demoted.
  * Out-of-band and two-identity confirmations re-check the same persisted proof
    (an interaction / owner+attacker provenance), so they reproduce and survive.

So it can only IMPROVE precision on flaky real-world targets, never cost recall on a
genuine bug. Best-effort: any error while re-testing a finding leaves it exactly as
the gate left it.
"""
from __future__ import annotations

import logging
from typing import List, Optional

logger = logging.getLogger("viper.adversarial_verifier")


async def refute_unreproducible(
    findings: List[dict],
    *,
    fetch=None,
    rounds: int = 1,
    timeout: float = 10.0,
    bola_config=None,
    oob_store=None,
    min_confidence: float = 0.5,
) -> int:
    """Demote any SUBMITTABLE finding whose gate confirmation does not reproduce across
    ``rounds`` additional independent re-tests. Mutates the findings in place; returns
    the number demoted. Never promotes and never touches a non-submittable finding.

    ``rounds`` is the number of EXTRA re-tests (1 = one more confirmation required).
    ``fetch``/``bola_config``/``oob_store`` mirror what the gate was given, so the
    re-test runs through the same scope/auth/OOB context.
    """
    if fetch is None:
        from core.swarm_workers.vuln._http import fetch as _swarm_fetch
        fetch = _swarm_fetch
    from core.swarm_validation import _reconfirm

    demoted = 0
    for f in findings:
        if not f.get("submittable"):
            continue
        refuted = False
        for _ in range(max(1, int(rounds))):
            try:
                ok, conf, reason = await _reconfirm(
                    dict(f), fetch, timeout, bola_config, oob_store=oob_store)
            except Exception as exc:   # noqa: BLE001 — an error is not a refutation
                logger.debug("refutation re-test errored for %s: %s",
                             f.get("vuln_type"), exc)
                break                  # fail OPEN
            if ok and float(conf) >= min_confidence:
                continue               # reproduced this round — keep looking
            # It did NOT reproduce this round. Only treat that as a refutation when the
            # re-test actually RAN a differential and found the bug absent — never when
            # the re-test was inconclusive (a network/rate-limit failure, an
            # unreachable target, an executor error). An inconclusive re-test is not
            # evidence the bug is gone, so it must not demote a real finding.
            if _is_inconclusive(reason):
                continue               # fail OPEN for this round
            refuted = True
            break
        if refuted:
            f["submittable"] = False
            f["validated"] = False
            f["refuted"] = True
            f["validation_reason"] = ((f.get("validation_reason") or "").rstrip()
                                      + " | REFUTED: an independent re-test ran but did "
                                        "not reproduce the gate's confirmation (likely "
                                        "transient/flaky) — demoted to lead")
            demoted += 1
    return demoted


# Reasons that mean the re-test could NOT be carried out (infrastructure/execution
# failure), as opposed to a real "the bug is not there" verdict. A refutation requires
# the latter — a failed re-test is inconclusive and must never demote a finding.
_INCONCLUSIVE_MARKERS = (
    "re-fetch failed", "re-query failed", "request failed", "no url to re-test",
    "re-run error", "escalation error", "unavailable", "validation error",
    "invalid format",
)


def _is_inconclusive(reason: Optional[str]) -> bool:
    r = (reason or "").lower()
    return any(m in r for m in _INCONCLUSIVE_MARKERS)
