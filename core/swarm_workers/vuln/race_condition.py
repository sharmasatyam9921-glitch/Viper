"""Race condition / TOCTOU probe (CWE-362).

WARNING — STATE-CHANGING. Unlike the other vuln workers (which are passive
GET probes), confirming a race requires firing *several concurrent identical
requests* at the same endpoint. Even with GET that can trip a real
side-effect on the server (e.g. a "claim", "redeem", or counter endpoint
mapped to GET). Because of that this worker is **opt-in and self-gated**:

  * It does NOTHING by default. The very first thing `run()` does is check
    `agent.payload["enable_race"]`. With no payload, or the flag unset/false,
    it returns `[]` immediately and never touches the network.
  * An operator enables it deliberately, per-hunt, on a sanctioned target by
    spawning the agent with `payload={"enable_race": True}`.

When enabled it fires a small burst (<=8) of identical concurrent requests
(``asyncio.gather`` of :func:`fetch`) and flags a *candidate* only if the
responses diverge in a way a race would produce — e.g. more than one
"success" where exactly one should win, or distinct status/length clusters.
Findings are deliberately low-confidence (<=0.5) and
``needs_manual_confirmation=True``: a timing divergence is a hint, not proof.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from typing import List, Optional

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url, HttpResp

logger = logging.getLogger("viper.swarm_workers.vuln.race_condition")

TECHNIQUE = "race_condition"

# Keep the burst small — this is state-changing and we only need enough
# parallelism to surface a divergence, not to hammer the target.
_DEFAULT_BURST = 6
_MAX_BURST = 8

# Status codes we treat as a "success" (a request that got through / did work).
_SUCCESS = range(200, 300)


def _success(r: Optional[HttpResp]) -> bool:
    return r is not None and r.status in _SUCCESS


async def run(agent: SwarmAgent) -> List[dict]:
    # --- Self-gate (CRITICAL SAFETY) ---------------------------------------
    # Off by default. Only an operator who explicitly set enable_race on a
    # sanctioned target gets past here. No payload -> no-op.
    if not agent.payload or not agent.payload.get("enable_race"):
        return []

    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)

    # Burst size: operator-tunable, hard-capped at _MAX_BURST.
    try:
        burst = int(agent.payload.get("race_burst", _DEFAULT_BURST))
    except (TypeError, ValueError):
        burst = _DEFAULT_BURST
    burst = max(2, min(burst, _MAX_BURST))

    findings: List[dict] = []

    # Fire N identical requests concurrently. follow_redirects off so a 302
    # that lands everyone on the same page doesn't mask the divergence.
    results = await asyncio.gather(
        *[fetch("GET", url, timeout=timeout, follow_redirects=False)
          for _ in range(burst)],
        return_exceptions=False,
    )

    responses = [r for r in results if r is not None]
    if len(responses) < 2:
        # Couldn't get enough live responses to compare — no signal.
        return []

    successes = [r for r in responses if _success(r)]
    status_counts = Counter(r.status for r in responses)
    # Bucket body sizes into a few coarse clusters so trivial 1-byte jitter
    # (timestamps etc.) doesn't read as divergence, but a genuinely different
    # response body (e.g. "claimed" vs "already claimed") does.
    len_clusters = Counter(len(r.body) // 64 for r in responses)

    distinct_statuses = len(status_counts)
    distinct_len_clusters = len(len_clusters)
    n_success = len(successes)

    # --- Divergence heuristics --------------------------------------------
    # (a) Multiple successes where a single-winner resource should yield one.
    multi_success = n_success > 1 and distinct_statuses > 1
    # (b) Responses split into distinct status clusters (e.g. some 200, some
    #     409/429) — the classic "one won, the rest lost the race" shape.
    status_split = distinct_statuses > 1 and any(
        c < len(responses) for c in status_counts.values()
    )
    # (c) Same status everywhere but bodies fall into distinct clusters — the
    #     endpoint returned materially different content per concurrent hit.
    body_split = distinct_statuses == 1 and distinct_len_clusters > 1

    diverged = multi_success or status_split or body_split
    if not diverged:
        return []

    evidence = (
        "STATE-CHANGING PROBE — confirm manually before reporting. "
        f"Fired {len(responses)} concurrent identical GET requests; responses "
        f"diverged: statuses={dict(status_counts)}, "
        f"body_size_clusters={distinct_len_clusters}, successes={n_success}. "
        "Divergence under concurrency suggests a race / TOCTOU (CWE-362), but "
        "may also be load-balancer or caching noise — reproduce with a "
        "single-winner action (claim/redeem/transfer) and verify the invariant "
        "is actually violated."
    )

    findings.append({
        "type": "race_condition",
        # MUST contain "race_condition" for the scorer family; business_logic
        # is the broader bucket this belongs to.
        "vuln_type": "business_logic:race_condition",
        "title": "Possible race condition / TOCTOU under concurrent requests",
        "severity": "high",
        "url": url,
        "cwe": "CWE-362",
        # Timing divergence is a hint, never proof — keep confidence low.
        "confidence": 0.4,
        "needs_manual_confirmation": True,
        "evidence": evidence,
        "payload": f"{burst}x concurrent GET (state-changing, operator-enabled)",
    })

    return findings


register_worker("vuln", TECHNIQUE, run)
