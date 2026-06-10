"""Finding builder for AI-specific vulnerabilities.

Findings follow the swarm-worker contract (see
``core/swarm_workers/vuln/__init__.py``) so they slot directly into the
dashboard, validator, and reporter without translation.
"""

from __future__ import annotations

import dataclasses
import hashlib
import time
from typing import Any, Optional


@dataclasses.dataclass
class AIFinding:
    """Strongly-typed AI vulnerability finding (serialises to the
    swarm-worker finding dict)."""

    # OWASP category code: "LLM01", "AGENTIC_T1", etc.
    owasp_id: str
    # Short stable label like "prompt_injection_direct"
    vuln_type: str
    title: str
    severity: str = "medium"          # critical|high|medium|low|info
    confidence: float = 0.6           # 0..1
    url: str = ""
    payload: str = ""
    evidence: str = ""
    cwe: Optional[str] = None         # e.g. CWE-1426 for LLM prompt injection
    extra: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": self.vuln_type,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "confidence": float(self.confidence),
            "url": self.url,
            "payload": self.payload,
            "evidence": self.evidence,
            "owasp_id": self.owasp_id,
            "discovered_at": time.time(),
        }
        if self.cwe:
            d["cwe"] = self.cwe
        d.update(self.extra)
        d["id"] = _finding_id(d)
        return d


def _finding_id(d: dict[str, Any]) -> str:
    """Stable hash so duplicate findings dedupe at the engine level."""
    key = f"{d['vuln_type']}|{d.get('url','')}|{d.get('payload','')[:120]}"
    return "ai-" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


# Convenience constructor — keeps tester modules concise.
def build_finding(
    owasp_id: str,
    vuln_type: str,
    title: str,
    *,
    severity: str = "medium",
    confidence: float = 0.6,
    url: str = "",
    payload: str = "",
    evidence: str = "",
    cwe: Optional[str] = None,
    **extra: Any,
) -> dict[str, Any]:
    return AIFinding(
        owasp_id=owasp_id, vuln_type=vuln_type, title=title,
        severity=severity, confidence=confidence,
        url=url, payload=payload, evidence=evidence, cwe=cwe,
        extra=extra,
    ).to_dict()
