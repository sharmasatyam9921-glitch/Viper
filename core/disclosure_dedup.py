"""Public-disclosure dedup — flag a finding that matches a program's ALREADY-DISCLOSED
issues so VIPER doesn't draft a known duplicate (submitting a public-disclosure dupe wastes
the triager's time and costs researcher reputation). The submission_ledger dedups a
researcher's OWN prior hunts; this dedups against the PROGRAM's public disclosures.

Read-only + offline: the operator supplies a disclosures cache — a JSON file
(``VIPER_DISCLOSED_ISSUES=/path.json`` or passed explicitly) shaped as
``{"disclosures": [{"vuln_type"|"class": ..., "url": ..., "parameter": ...}, ...]}`` — and
each finding is matched by the SAME class|host|path[|param] signature the ledger uses. A
match is TAGGED (``likely_duplicate`` + a reason), never dropped: the operator decides, and
prioritization sorts tagged findings below novel ones. Never touches the gate or scope.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional

from core.submission_ledger import signature as _sig


def _class_host_path(finding_or_entry: dict) -> str:
    """The looser dedup key: class|host|path with the parameter dropped — a public
    disclosure usually names the endpoint + weakness class but not the exact parameter."""
    return "|".join(_sig(finding_or_entry).split("|")[:3])


class DisclosureCache:
    """A set of a program's public disclosures, matched by finding signature."""

    def __init__(self, entries: Optional[List[dict]] = None):
        self._exact: dict[str, str] = {}          # class|host|path|param -> title
        self._loose: dict[str, str] = {}          # class|host|path       -> title
        for e in entries or []:
            if not isinstance(e, dict):
                continue
            title = str(e.get("title") or e.get("id") or e.get("vuln_type")
                        or e.get("class") or "disclosed issue")
            # A disclosure may carry `class` instead of `vuln_type`; signature() reads both.
            entry = dict(e)
            if "vuln_type" not in entry and entry.get("class"):
                entry["vuln_type"] = entry["class"]
            try:
                self._exact.setdefault(_sig(entry), title)
                self._loose.setdefault(_class_host_path(entry), title)
            except Exception:  # noqa: BLE001 — a malformed entry is skipped, never fatal
                continue

    @property
    def size(self) -> int:
        return len(self._loose)

    @classmethod
    def from_file(cls, path) -> "DisclosureCache":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 — missing/malformed cache -> empty (no-op)
            return cls([])
        items = data.get("disclosures") if isinstance(data, dict) else data
        return cls(items if isinstance(items, list) else [])

    @classmethod
    def autoload(cls) -> "DisclosureCache":
        """Load from the ``VIPER_DISCLOSED_ISSUES`` env path, else an empty (no-op) cache."""
        p = os.environ.get("VIPER_DISCLOSED_ISSUES")
        return cls.from_file(p) if p else cls([])

    def match(self, finding: dict) -> Optional[str]:
        """The matching disclosure's title if the finding matches a known disclosure —
        exact class|host|path|param first, then the looser class|host|path — else None."""
        try:
            hit = self._exact.get(_sig(finding))
            return hit if hit is not None else self._loose.get(_class_host_path(finding))
        except Exception:  # noqa: BLE001
            return None

    def annotate(self, findings: List[dict]) -> int:
        """Tag each finding that matches a public disclosure. Returns the count tagged.
        Read-only bookkeeping — the finding is kept; prioritization sorts it lower."""
        n = 0
        for f in findings or []:
            if not isinstance(f, dict) or f.get("likely_duplicate"):
                continue
            title = self.match(f)
            if title:
                f["likely_duplicate"] = True
                f["duplicate_reason"] = f"matches a public disclosure: {title}"
                n += 1
        return n
