"""Vuln-phase swarm workers.

Each module registers one worker with the parent registry. Workers
take a `SwarmAgent` (whose `target` has been remapped to the asset URL
under test) and return `List[dict]` of findings.

Common finding shape:
    {
        "type": "<vuln_type>",      # e.g. "sqli", "xss", "cors_misconfig"
        "vuln_type": "<vuln_type>", # used by SwarmEngine dedup
        "title": "<short label>",
        "url": "<vulnerable URL>",
        "severity": "critical" | "high" | "medium" | "low" | "info",
        "evidence": "<short note explaining how it was confirmed>",
        "confidence": 0.0..1.0,
        "cwe": "CWE-89",            # optional
        "parameter": "id",          # optional, for injection-style findings
        "payload": "...",           # optional
    }

Workers MUST be:
  - async
  - non-destructive (no DROP TABLE, no POST that mutates real data
    unless explicitly approval-gated upstream)
  - robust to network failure (return [] on errors, never raise)
  - bounded by agent.timeout_s
"""

from __future__ import annotations

from . import (  # noqa: F401
    ai_hunter,
    bola,
    cors,
    graphql,
    idor,
    jwt,
    login_sqli,
    nuclei,
    secrets,
    sqli_probe,
    xss_probe,
)

__all__ = [
    "ai_hunter", "bola", "cors", "graphql", "idor", "jwt", "login_sqli",
    "nuclei", "secrets", "sqli_probe", "xss_probe",
]
