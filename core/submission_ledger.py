"""Cross-hunt duplicate suppression for submissions.

A bug-bounty dup earns nothing and costs reputation. VIPER already dedups
findings WITHIN a hunt (the swarm engine hashes vuln_type:target:param:payload);
this adds dedup ACROSS hunts: a persistent ledger of what was already drafted /
submitted, so re-hunting the same target doesn't re-draft the same class on the
same endpoint.

The signature is class + host + normalized path + parameter — object ids in the
path are collapsed (``/api/orders/123`` == ``/api/orders/456``) so the SAME
weakness on the SAME endpoint is recognized as one, regardless of the specific
object. Stored in a gitignored local JSON ledger.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

_ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = _ROOT / "reports" / "submission_ledger.json"

# A path segment that is an object id (numeric or long hex/uuid) -> collapsed.
_ID_SEG = re.compile(r"^(?:\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{16,})$")


def _norm_path(path: str) -> str:
    segs = [("{id}" if _ID_SEG.match(s) else s) for s in (path or "/").split("/")]
    return "/".join(segs) or "/"


def signature(finding: dict) -> str:
    """class | host | normalized-path | parameter — the dedup key."""
    from core.submission_draft import _norm_head
    vt = finding.get("vuln_type") or finding.get("type") or ""
    cls = _norm_head(vt)
    parts = urlsplit(finding.get("url") or finding.get("target") or "")
    host = (parts.hostname or "").lower()
    path = _norm_path(parts.path)
    param = (finding.get("parameter") or "").lower()
    return f"{cls}|{host}|{path}|{param}"


class SubmissionLedger:
    """Persistent record of already-drafted/submitted finding signatures."""

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else LEDGER_PATH
        self._seen: dict = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._seen = dict(data.get("signatures") or {})
            except Exception:
                self._seen = {}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"signatures": self._seen}, indent=1),
                             encoding="utf-8")

    def is_duplicate(self, finding: dict) -> bool:
        return signature(finding) in self._seen

    def record(self, finding: dict, *, status: str = "drafted") -> None:
        sig = signature(finding)
        prev = self._seen.get(sig) or {}
        self._seen[sig] = {
            "vuln_type": finding.get("vuln_type"),
            "url": finding.get("url"),
            "status": status,
            "first_seen": prev.get("first_seen") or _now(),
            "count": int(prev.get("count") or 0) + 1,
        }

    def partition_new(self, findings: List[dict]) -> Tuple[List[dict], List[dict]]:
        """Split into (new, duplicates) WITHOUT recording — caller decides."""
        new, dups = [], []
        seen_now: set = set()
        for f in findings:
            sig = signature(f)
            if sig in self._seen or sig in seen_now:
                dups.append(f)
            else:
                new.append(f)
                seen_now.add(sig)          # collapse intra-batch dups too
        return new, dups


def _now() -> str:
    # ISO-ish UTC without importing datetime's tz machinery
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
