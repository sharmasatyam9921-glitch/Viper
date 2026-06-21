"""Lazy skill catalog — load only the skills relevant to the moment.

A *skill* is a unit of attack knowledge: a curated prompt/playbook, a CWE
weakness, a CAPEC attack pattern, or an imported external test case. The registry
holds a lightweight INDEX of every skill (id, name, phase, technique, tags,
CWE/CAPEC/ATT&CK refs) eagerly — small and cheap — while each skill's full BODY
text is loaded lazily, only when that skill is actually selected for rendering.

That is what keeps prompt token cost flat as the catalog grows to thousands of
entries: :meth:`SkillRegistry.select` returns at most ``limit`` skills for the
current phase/technique/intent, and :meth:`SkillRegistry.render` loads bodies for
only those few. Ten thousand more indexed skills do not enlarge the prompt.

No external dependencies; pure data + ranking. The catalog content is assembled
in ``core.skill_catalog`` from VIPER's vendored offline MITRE DB and the existing
skill-prompt modules (no downloads).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> List[str]:
    return _WORD.findall((text or "").lower())


def _norm_cwe(x) -> str:
    """Extract the bare CWE number ('CWE-89', '89', 'cwe_89' -> '89')."""
    m = re.match(r"\s*(?:cwe[-_]?)?(\d+)", str(x).lower())
    return m.group(1) if m else ""


@dataclass
class Skill:
    """One indexed skill. ``body`` is loaded lazily via ``_loader``.

    Treated as immutable after construction: the default registry is a process
    cache shared across callers, so callers must read fields, never mutate them
    (only the private ``_body_cache`` is written, once, on first ``body()``).
    """

    id: str
    name: str
    source: str                       # "prompt" | "cwe" | "capec" | "external"
    summary: str = ""                 # short one-liner (eager, for listings)
    phases: Tuple[str, ...] = ()       # kill-chain / VIPER phases it applies to
    techniques: Tuple[str, ...] = ()   # attack_path_type aliases / keywords
    tags: Tuple[str, ...] = ()         # searchable lowercased keywords
    severity: str = "info"
    cwe: Tuple[str, ...] = ()          # related CWE numbers (as strings)
    capec: Tuple[str, ...] = ()        # related CAPEC numbers
    attack: Tuple[str, ...] = ()       # ATT&CK technique ids (e.g. T1059)
    tools: Tuple[str, ...] = ()        # tools the skill's workflow uses (nmap, ...)
    _loader: Optional[Callable[[], str]] = field(default=None, repr=False)
    _body_cache: Optional[str] = field(default=None, repr=False)

    def body(self) -> str:
        """Full skill text — loaded once on first access, then cached."""
        if self._body_cache is None:
            try:
                self._body_cache = (self._loader() if self._loader else "") or ""
            except Exception:
                self._body_cache = ""
        return self._body_cache

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "source": self.source,
            "summary": self.summary, "phases": list(self.phases),
            "techniques": list(self.techniques), "tags": list(self.tags),
            "severity": self.severity, "cwe": list(self.cwe),
            "capec": list(self.capec), "attack": list(self.attack),
            "tools": list(self.tools),
        }


class SkillRegistry:
    """An index of skills with lazy bodies and relevance-ranked selection."""

    def __init__(self):
        self._skills: Dict[str, Skill] = {}

    # --- population --------------------------------------------------------

    def add(self, skill: Skill) -> None:
        self._skills[skill.id] = skill

    def add_many(self, skills) -> None:
        for s in skills:
            self.add(s)

    def __len__(self) -> int:
        return len(self._skills)

    def __contains__(self, skill_id: str) -> bool:
        return skill_id in self._skills

    def get(self, skill_id: str) -> Optional[Skill]:
        return self._skills.get(skill_id)

    def all(self) -> List[Skill]:
        return list(self._skills.values())

    def stats(self) -> dict:
        by_source: Dict[str, int] = {}
        for s in self._skills.values():
            by_source[s.source] = by_source.get(s.source, 0) + 1
        return {"total": len(self._skills), "by_source": by_source}

    # --- search + select ---------------------------------------------------

    def search(self, query: str, limit: int = 20) -> List[Skill]:
        """Free-text search over id/name/tags/cwe/capec (cheap, index-only)."""
        q = (query or "").strip().lower()
        if not q:
            return []
        qtoks = set(_tokens(q))
        scored = []
        for s in self._skills.values():
            hay = " ".join((s.id, s.name, " ".join(s.tags))).lower()
            score = 0
            if q in hay:
                score += 50
            hits = qtoks & (set(s.tags) | set(_tokens(s.name)))
            score += 10 * len(hits)
            if _norm_cwe(q) in s.cwe:
                score += 40
            if score and s.source == "prompt":
                score += 25            # curated playbooks rank above raw CWE/CAPEC
            if score:
                scored.append((score, s))
        scored.sort(key=lambda x: (-x[0], x[1].id))
        return [s for _, s in scored[:limit]]

    def _score(self, s: Skill, phase, technique, intent_toks, tags, cwe) -> int:
        # `content` = real relevance (technique/intent/tags/cwe). Phase is a weak
        # signal added on top and does NOT earn the curated-prompt edge — so a
        # phase-only match never outranks a genuine content match.
        content = 0
        if technique:
            t = technique.lower()
            if t in s.techniques:
                content += 100                       # exact alias
            else:
                # whole-token match against alias words (min length 3) so a short
                # technique like "i" can't substring-match "sql_injection".
                alias_toks = set()
                for a in s.techniques:
                    alias_toks.update(_tokens(a))
                if len(t) >= 3 and t in alias_toks:
                    content += 40
            if len(t) >= 3 and (t in s.tags or t in s.name.lower()):
                content += 15
        for tok in intent_toks:
            if tok in s.tags:
                content += 10
            elif tok in s.name.lower():
                content += 6
            if tok.isdigit() and tok in s.cwe:       # a CWE number named in the intent
                content += 50
        for tg in (tags or ()):
            if tg.lower() in s.tags:
                content += 8
        if cwe and _norm_cwe(cwe) in s.cwe:
            content += 60
        score = content
        if phase:
            p = phase.lower()
            if any(p == ph or p in ph or ph in p for ph in s.phases):
                score += 20
        if content > 0 and s.source == "prompt":
            score += 3                               # curated edge — only on real relevance
        return score

    def select(self, *, phase: Optional[str] = None,
               technique: Optional[str] = None, intent: Optional[str] = None,
               tags: Optional[List[str]] = None, cwe=None,
               limit: int = 5) -> List[Skill]:
        """Return up to `limit` skills most relevant to the given context.

        This is the lazy gate: only the returned skills ever get their bodies
        loaded by :meth:`render`, so prompt size is bounded by `limit`, not by
        catalog size.
        """
        intent_toks = set(_tokens(intent or ""))
        scored = []
        for s in self._skills.values():
            sc = self._score(s, phase, technique, intent_toks, tags, cwe)
            if sc > 0:
                scored.append((sc, s))
        scored.sort(key=lambda x: (-x[0], x[1].source != "prompt", x[1].id))
        return [s for _, s in scored[:max(0, limit)]]

    def render(self, skills: List[Skill], *, max_chars: int = 1800,
               header: bool = True) -> str:
        """Render selected skills into a bounded prompt block (lazy body load).

        Bodies are loaded here, for the passed skills only. The result is hard
        capped at `max_chars` so the injected block never blows the token budget.
        """
        if not skills:
            return ""
        parts = ["# Relevant attack skills (load-on-demand)"] if header else []
        for s in skills:
            body = s.body().strip()
            block = f"\n## {s.name}\n{body}" if body else f"\n## {s.name}\n{s.summary}"
            # account for the join newlines by measuring the would-be output.
            if len("\n".join(parts + [block])) > max_chars:
                marker = " ...[truncated]"
                # reserve room for the marker so the final (capped) output keeps it
                remaining = max_chars - len("\n".join(parts)) - 1 - len(marker)
                if remaining > 60:
                    parts.append(block[:remaining] + marker)
                break
            parts.append(block)
        # absolute hard cap — guarantees the contract even if the header alone is
        # larger than max_chars.
        return "\n".join(parts).strip()[:max_chars]

    def select_and_render(self, *, max_chars: int = 1800, **select_kw) -> str:
        return self.render(self.select(**select_kw), max_chars=max_chars)
