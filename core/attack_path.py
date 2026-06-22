"""Attack-path graph — shortest grounded escalation path to a crown jewel.

Models the hunt's CONFIRMED findings as edges in a capability state-graph and
finds the cheapest path from an external attacker to a high-value goal (RCE,
account takeover, cloud takeover, PII read, data exfil).

FP-resistance is the whole point — this is a planning/prioritization aid, not a
finding source, and it is built to never overclaim:

* **Grounded only.** Every path begins with a CONFIRMED (submittable) finding.
  A candidate/lead never creates an edge, so a path is never pure speculation.
* **Typed hops.** Each hop is ``confirmed`` (backed by a real submittable finding)
  or ``potential`` (a known escalation technique that WOULD apply). They are never
  conflated.
* **No fabricated wins.** A goal is reported ``fully_confirmed`` only if EVERY hop
  is confirmed; otherwise it's a ``partial`` path that explicitly shows the proven
  prefix and the speculative remainder.
* **Plans, not findings.** Output is AttackPath objects only — it cannot enter the
  submission pipeline.
"""
from __future__ import annotations

import heapq
import itertools
from dataclasses import dataclass, field
from typing import List, Optional

_START = "start"

# Confirmed-finding head -> the capability edge it establishes (start -> state).
_FINDING_EDGE = {
    "ssrf": "internal",
    "lfi": "file_read", "path_traversal": "file_read", "xxe": "file_read",
    "sqli": "db_access", "auth_bypass": "db_access", "login_sqli": "db_access",
    "xss": "session", "dom_xss": "session", "cors": "session",
    "open_redirect": "token_theft", "redirect": "token_theft",
    "host_header": "token_theft",
    "idor": "pii_read", "bola": "pii_read",           # directly reads other users' data
    "secret": "credentials", "secrets": "credentials",
    "env_exposed": "credentials", "git_exposed": "credentials",
    "js_secret": "credentials", "github_secret": "credentials",
    "cloud_exposure": "data_exfil",
    "rce": "rce", "cmdi": "rce", "command_injection": "rce", "ssti": "rce",
}

# Known escalation techniques between capabilities (ALWAYS potential / unproven).
_POTENTIAL_EDGES = [
    ("internal", "cloud_creds", "SSRF to the cloud metadata endpoint (169.254.169.254)"),
    ("internal", "rce", "SSRF to an internal admin / actuator endpoint"),
    ("file_read", "credentials", "read app config / .env / private keys"),
    ("db_access", "pii_read", "SELECT from user / PII tables"),
    ("db_access", "credentials", "dump stored password hashes"),
    ("credentials", "account_takeover", "authenticate as the victim"),
    ("credentials", "db_access", "reuse leaked DB credentials"),
    ("cloud_creds", "cloud_takeover", "assume role / take over cloud resources"),
    ("cloud_creds", "data_exfil", "dump cloud object storage"),
    ("token_theft", "account_takeover", "replay the stolen auth token"),
    ("session", "account_takeover", "ride the hijacked session"),
    ("session", "pii_read", "read the victim's data via their session"),
]

_GOALS = {"rce": "critical", "account_takeover": "critical",
          "cloud_takeover": "critical", "data_exfil": "high", "pii_read": "high"}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Hop:
    src: str
    dst: str
    kind: str          # "confirmed" | "potential"
    via: str           # finding title (confirmed) or technique label (potential)


@dataclass
class AttackPath:
    goal: str
    severity: str
    hops: List[Hop]
    fully_confirmed: bool
    confirmed_hops: int
    potential_hops: int
    narrative: str = ""


def _head(f: dict) -> str:
    return str(f.get("vuln_type") or f.get("type") or "").lower().split(":")[0]


def _is_confirmed(f: dict) -> bool:
    # Only gate-confirmed (submittable / validated) findings ground an edge.
    return bool(f.get("submittable") is True or f.get("validated") is True)


def _title(f: dict) -> str:
    return str(f.get("title") or f.get("vuln_type") or f.get("type") or "finding")


def _best_path(graph, goal) -> Optional[List[Hop]]:
    """Cheapest path START->goal: fewest POTENTIAL hops first, then shortest."""
    counter = itertools.count()
    pq = [(0, 0, next(counter), _START, [])]   # potential, length, tiebreak, node, hops
    best: dict = {}
    while pq:
        pot, length, _, node, hops = heapq.heappop(pq)
        if node == goal:
            return hops
        if node in best and best[node] <= (pot, length):
            continue
        best[node] = (pot, length)
        visited = {_START} | {h.dst for h in hops}
        for dst, kind, via in graph.get(node, []):
            if dst in visited:
                continue                       # no cycles
            npot = pot + (1 if kind == "potential" else 0)
            nhops = hops + [Hop(node, dst, kind, via)]
            heapq.heappush(pq, (npot, length + 1, next(counter), dst, nhops))
    return None


def find_paths(findings) -> List[AttackPath]:
    # 1. confirmed edges from submittable findings only (grounding)
    confirmed: dict = {}
    for f in findings or []:
        if not _is_confirmed(f):
            continue
        dst = _FINDING_EDGE.get(_head(f))
        if dst:
            confirmed.setdefault(dst, _title(f))
    if not confirmed:
        return []                              # nothing grounded -> no paths

    # 2. build the graph: confirmed start-edges + static potential edges
    graph: dict = {}
    for dst, title in confirmed.items():
        graph.setdefault(_START, []).append((dst, "confirmed", title))
    for src, dst, label in _POTENTIAL_EDGES:
        graph.setdefault(src, []).append((dst, "potential", label))

    # 3. shortest grounded path to each reachable goal
    paths: List[AttackPath] = []
    for goal, sev in _GOALS.items():
        hops = _best_path(graph, goal)
        if not hops or not any(h.kind == "confirmed" for h in hops):
            continue
        conf = sum(1 for h in hops if h.kind == "confirmed")
        pot = sum(1 for h in hops if h.kind == "potential")
        paths.append(AttackPath(
            goal=goal, severity=sev, hops=hops,
            fully_confirmed=(pot == 0), confirmed_hops=conf, potential_hops=pot,
            narrative=_narrate(hops, goal, pot == 0)))
    # 4. rank: fully-confirmed first, then by severity, then fewest potential hops
    paths.sort(key=lambda p: (not p.fully_confirmed, _SEV_RANK.get(p.severity, 9),
                              p.potential_hops, len(p.hops)))
    return paths


def _narrate(hops: List[Hop], goal: str, fully: bool) -> str:
    parts = []
    for h in hops:
        tag = "" if h.kind == "confirmed" else "[potential] "
        parts.append(f"{tag}{h.via} -> {h.dst}")
    head = "CONFIRMED chain" if fully else "Partial chain (confirmed start, potential tail)"
    return f"{head} to {goal}: " + " ; ".join(parts)
