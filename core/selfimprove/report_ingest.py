"""Ingest disclosed bug-bounty reports into structured, vetted knowledge.

A disclosed report (HackerOne-style markdown or plain text) is a rich source of
real-world detection payloads. This module parses one report into structured
knowledge:

  * infers the vulnerability class from keywords,
  * extracts candidate payloads from fenced code blocks and inline code,
  * runs EVERY candidate through :func:`core.knowledge.safety_gate.is_allowed`
    so weaponized markers are dropped and NEVER stored, and
  * harvests false-positive / "not a vuln" notes for the FP filter.

The safety gate is a hard boundary: rejected payloads are returned only as
``(payload, reason)`` pairs so a human can audit the decision — they are never
written to the library by :func:`promote_to_library`.

Public API:
    ingest_report(text, *, source="") -> dict
    promote_to_library(result, library_path=None, *, propose_only=False) -> dict

The ingest result dict has the shape::

    {
        "vuln_class": str | None,
        "payloads":   [str],            # accepted, deduped, order-preserved
        "signals":    [str],            # short detection signals for the class
        "fp_notes":   [str],            # false-positive / not-a-vuln lines
        "accepted":   [str],            # == payloads (explicit, for callers)
        "rejected":   [(payload, reason)],  # dropped weaponization (audit only)
    }
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import safety_gate

__all__ = ["ingest_report", "promote_to_library"]


# ── Vuln-class inference ───────────────────────────────────────────────────
# Maps a canonical class name (matching the vuln scorer classes) to the keyword
# patterns that signal it. Order matters: the first class whose pattern matches
# the most distinctively wins, so specific phrases come before generic ones.
_CLASS_KEYWORDS: List[Tuple[str, re.Pattern]] = [
    ("sql_injection", re.compile(r"\bsql\s*inject|\bsqli\b|union\s+select|\bsqlmap\b|or\s+1\s*=\s*1", re.I)),
    ("xss", re.compile(r"\bxss\b|cross[\s-]site\s+script|<script|onerror\s*=|alert\(", re.I)),
    ("ssti", re.compile(r"\bssti\b|server[\s-]side\s+template|template\s+inject|\{\{.*\}\}|\$\{.*\}", re.I)),
    ("ssrf", re.compile(r"\bssrf\b|server[\s-]side\s+request\s+forgery|169\.254\.169\.254|metadata\s+endpoint", re.I)),
    ("xxe", re.compile(r"\bxxe\b|xml\s+external\s+entity|<!ENTITY|<!DOCTYPE", re.I)),
    ("nosql_injection", re.compile(r"\bnosql\b|mongo(?:db)?\s+inject|\$ne\b|\$gt\b|\$where\b", re.I)),
    ("lfi", re.compile(r"\blfi\b|local\s+file\s+inclusion|path\s+travers|directory\s+travers|\.\./\.\.", re.I)),
    ("open_redirect", re.compile(r"open\s+redirect|unvalidated\s+redirect|\bredirect_uri\b", re.I)),
    ("jwt", re.compile(r"\bjwt\b|json\s+web\s+token|alg\s*[:=]\s*none|\bnone\s+algorithm\b", re.I)),
    ("csrf", re.compile(r"\bcsrf\b|cross[\s-]site\s+request\s+forgery|missing\s+csrf\s+token", re.I)),
    ("access_control", re.compile(r"\bidor\b|insecure\s+direct\s+object|broken\s+access\s+control|privilege\s+escalat", re.I)),
    ("cors", re.compile(r"\bcors\b|access-control-allow-origin|cross[\s-]origin\s+resource", re.I)),
    ("rce", re.compile(r"\brce\b|remote\s+code\s+execution|command\s+inject|os\s+command", re.I)),
]

# Short, per-class detection signals attached to every ingest so downstream
# scorers know what a confirmation looks like. These are descriptions, not
# payloads, and are never executed.
_CLASS_SIGNALS: Dict[str, List[str]] = {
    "sql_injection": ["boolean differential (1=1 vs 1=2)", "time delay via SLEEP", "DB error string in response"],
    "xss": ["injected script marker reflected unescaped", "alert/marker fires in DOM"],
    "ssti": ["arithmetic marker evaluated (e.g. 7*7 -> 49)"],
    "ssrf": ["server fetches attacker-controlled URL", "internal/metadata response leaked"],
    "xxe": ["external entity expands into response", "file/SSRF read via entity"],
    "nosql_injection": ["always-true operator bypasses auth", "boolean differential via $ne/$gt"],
    "lfi": ["known file contents reflected (e.g. /etc/passwd marker)"],
    "open_redirect": ["Location header / meta-refresh bounces to attacker host"],
    "jwt": ["alg:none accepted", "signature stripped yet token honored"],
    "csrf": ["state-changing request succeeds without anti-CSRF token"],
    "access_control": ["other user's object returned by id swap", "admin route reached as low-priv user"],
    "cors": ["ACAO reflects arbitrary origin with credentials"],
    "rce": ["benign read-only command output reflected", "time delay via sleep"],
}

# Lines carrying these phrases are harvested as false-positive / triage notes.
_FP_PHRASES = re.compile(
    r"false\s+positive|not\s+exploitable|out\s+of\s+scope|duplicate|informative|not\s+a\s+(?:vuln|bug|security)|won'?t\s+fix|by\s+design",
    re.I,
)

# Fenced code blocks: ``` ... ``` or ~~~ ... ~~~ (optional language tag).
_FENCE = re.compile(r"(?:```|~~~)[^\n]*\n(.*?)(?:```|~~~)", re.S)
# Inline code: `payload`.
_INLINE = re.compile(r"`([^`\n]+)`")


def _infer_vuln_class(text: str) -> Optional[str]:
    """Return the canonical vuln class with the strongest keyword evidence."""
    best: Optional[str] = None
    best_hits = 0
    for name, pattern in _CLASS_KEYWORDS:
        hits = len(pattern.findall(text))
        if hits > best_hits:
            best, best_hits = name, hits
    return best


def _extract_candidates(text: str) -> List[str]:
    """Pull candidate payloads from fenced blocks and inline code, order-preserved."""
    candidates: List[str] = []

    for block in _FENCE.findall(text):
        # A fenced block may contain several payload lines; keep the whole block
        # AND each non-trivial line so single-line markers survive deduping.
        block_stripped = block.strip()
        if block_stripped:
            candidates.append(block_stripped)
        for line in block.splitlines():
            line = line.strip()
            if line and line != block_stripped:
                candidates.append(line)

    # Inline code that lives outside fenced blocks.
    text_no_fences = _FENCE.sub("\n", text)
    for inline in _INLINE.findall(text_no_fences):
        inline = inline.strip()
        if inline:
            candidates.append(inline)

    # Dedupe while preserving first-seen order.
    seen = set()
    out: List[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _extract_fp_notes(text: str) -> List[str]:
    """Collect deduped lines that read like false-positive / triage notes."""
    notes: List[str] = []
    seen = set()
    for raw in text.splitlines():
        line = raw.strip(" \t#*->").strip()
        if line and _FP_PHRASES.search(line) and line not in seen:
            seen.add(line)
            notes.append(line)
    return notes


def ingest_report(text: str, *, source: str = "") -> Dict[str, object]:
    """Ingest one disclosed report into structured, safety-vetted knowledge.

    Args:
        text: The report body (markdown or plain text).
        source: Optional provenance label (URL, report id) for traceability.

    Returns:
        A dict with keys ``vuln_class``, ``payloads``, ``signals``, ``fp_notes``,
        ``accepted``, ``rejected`` and ``source`` (see module docstring). Every
        candidate is run through the safety gate; rejected weaponization appears
        only under ``rejected`` and is never placed in ``payloads``/``accepted``.
    """
    if not isinstance(text, str) or not text.strip():
        return {
            "vuln_class": None,
            "payloads": [],
            "signals": [],
            "fp_notes": [],
            "accepted": [],
            "rejected": [],
            "source": source,
        }

    vuln_class = _infer_vuln_class(text)
    candidates = _extract_candidates(text)

    accepted: List[str] = []
    rejected: List[Tuple[str, str]] = []
    for cand in candidates:
        verdict = safety_gate.classify_payload(cand)
        if verdict.get("allowed"):
            accepted.append(cand)
        else:
            rejected.append((cand, str(verdict.get("reason", "rejected by safety gate"))))

    signals = list(_CLASS_SIGNALS.get(vuln_class, [])) if vuln_class else []
    fp_notes = _extract_fp_notes(text)

    return {
        "vuln_class": vuln_class,
        "payloads": accepted,
        "signals": signals,
        "fp_notes": fp_notes,
        "accepted": accepted,
        "rejected": rejected,
        "source": source,
    }


def _default_library_path() -> Path:
    """Repo-root ``knowledge/payloads.json`` regardless of CWD."""
    # core/knowledge/report_ingest.py -> repo root is two parents up.
    return Path(__file__).resolve().parent / "payloads.json"


def promote_to_library(
    result: Dict[str, object],
    library_path: Optional[str] = None,
    *,
    propose_only: bool = False,
) -> Dict[str, object]:
    """Append a report's accepted payloads to the payload library under its class.

    Only payloads in ``result["accepted"]`` are considered — rejected
    weaponization is already absent from the ingest result and can never be
    promoted. Existing entries are preserved and the merge is deduped.

    Args:
        result: The dict returned by :func:`ingest_report`.
        library_path: Target ``payloads.json``. Defaults to repo
            ``knowledge/payloads.json``.
        propose_only: When ``True``, compute what *would* be added but write
            nothing to disk (dry run).

    Returns:
        ``{"vuln_class", "added", "written", "library_path"}`` where ``added`` is
        the list of newly-introduced payloads and ``written`` reflects whether
        the file was actually updated.
    """
    vuln_class = result.get("vuln_class")
    accepted = list(result.get("accepted") or result.get("payloads") or [])

    path = Path(library_path) if library_path else _default_library_path()

    if not vuln_class or not accepted:
        return {
            "vuln_class": vuln_class,
            "added": [],
            "written": False,
            "library_path": str(path),
        }

    # Re-vet at the boundary: never trust that callers preserved the gate.
    accepted = [p for p in accepted if safety_gate.is_allowed(p)]

    # Load existing library (tolerant of missing / empty / malformed file).
    library: Dict[str, List[str]] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8") or "{}")
            if isinstance(loaded, dict):
                library = {k: list(v) for k, v in loaded.items() if isinstance(v, list)}
        except (json.JSONDecodeError, OSError):
            library = {}

    existing = library.get(vuln_class, [])
    seen = set(existing)
    added: List[str] = []
    for p in accepted:
        if p not in seen:
            seen.add(p)  # dedupe against the library AND within this batch
            added.append(p)

    if propose_only:
        return {
            "vuln_class": vuln_class,
            "added": added,
            "written": False,
            "library_path": str(path),
        }

    if added:
        library[vuln_class] = existing + added
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(library, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return {
        "vuln_class": vuln_class,
        "added": added,
        "written": bool(added),
        "library_path": str(path),
    }
