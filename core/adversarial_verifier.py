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
        reproduced = True
        for _ in range(max(1, int(rounds))):
            try:
                ok, conf, _reason = await _reconfirm(
                    dict(f), fetch, timeout, bola_config, oob_store=oob_store)
            except Exception as exc:   # noqa: BLE001 — a re-test error is not a refutation
                logger.debug("refutation re-test errored for %s: %s",
                             f.get("vuln_type"), exc)
                reproduced = True      # fail OPEN: don't demote on our own error
                break
            if not (ok and float(conf) >= min_confidence):
                reproduced = False
                break
        if not reproduced:
            f["submittable"] = False
            f["validated"] = False
            f["refuted"] = True
            f["validation_reason"] = ((f.get("validation_reason") or "").rstrip()
                                      + " | REFUTED: the gate's confirmation did not "
                                        "reproduce on an independent re-test (likely "
                                        "transient/flaky) — demoted to lead")
            demoted += 1
    return demoted
