"""Loss-preserving (de)serialization of a swarm finding for ``--resume``.

The ``finding.published`` audit event is what a resumed hunt replays to carry findings
forward. Historically it recorded only ``title``/``technique``/``url`` — so a resumed
finding lost the very fields the validation gate keys on (``vuln_type``, ``parameter``,
``payload``, ``oob_token``), and its chain-of-custody hash no longer matched. A carried-
forward true positive could therefore silently fail to re-confirm.

This module is the SINGLE SOURCE OF TRUTH for which fields survive a resume. The set is
kept small and NON-SENSITIVE on purpose: it carries the candidate's identity + re-test
inputs, never ``proof_requests`` or any auth material (those are recomputed by the gate
in the resumed run).
"""
from __future__ import annotations

from typing import Dict

# The fields the gate needs to RE-CONFIRM a carried-forward candidate, plus the few the
# report/custody hash render. All are worker-emitted, small, and non-sensitive.
RESUME_FIELDS = (
    "type", "vuln_type", "title", "url", "parameter", "payload",
    "evidence", "cwe", "severity", "confidence", "oob_token", "method", "asset",
)


def finding_to_resume_payload(finding: Dict) -> Dict:
    """The subset of a worker finding to persist in its ``finding.published`` event so a
    resume can reconstruct it faithfully. Drops ``None``/absent fields to stay compact."""
    return {k: finding[k] for k in RESUME_FIELDS if finding.get(k) is not None}


def finding_from_resume_payload(payload: Dict) -> Dict:
    """Reconstruct a worker-shaped finding from a ``finding.published`` event payload.

    Prefers the faithfully-persisted fields; falls back to the LEGACY shape (older logs
    that only stored ``title`` + ``technique``) so resuming a pre-upgrade hunt still
    works — just less completely."""
    payload = payload or {}
    out: Dict = {k: payload[k] for k in RESUME_FIELDS if payload.get(k) is not None}
    if "type" not in out:                       # legacy: derive from the title head
        title = str(payload.get("title") or "")
        out["type"] = title.split(":")[0] or "finding"
    if "vuln_type" not in out and payload.get("technique"):
        out["vuln_type"] = f"{payload['technique']}:{payload.get('title', '')}"
    out.setdefault("severity", "info")
    return out
