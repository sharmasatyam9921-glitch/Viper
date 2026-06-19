"""Assemble the default skill catalog from data VIPER already ships.

No downloads: the catalog is built from
  * the 16 curated skill-prompt modules in ``core.skill_prompts`` (promoted to
    first-class, lazily-rendered entries), and
  * the vendored offline MITRE database (``data/mitre_db/resources``): 969 CWE
    weaknesses and 615 CAPEC attack patterns, each becoming a skill whose body is
    formatted lazily from the local metadata.

That yields ~1,597 indexed skills with zero network access. An importer
(:func:`import_external`) ingests a normalized list for any future corpus (e.g.
a vendored ATT&CK/WSTG export) without changing the engine.

Everything is lazy: building the index reads the JSON once but does NOT format
any skill body. Bodies are produced only when a skill is selected and rendered.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

from core.skill_registry import Skill, SkillRegistry

_ROOT = Path(__file__).resolve().parents[1]
_RES = _ROOT / "data" / "mitre_db" / "resources"

_TID = re.compile(r"ENTRY ID:(T?\d+(?:\.\d+)?)")
_CWE_SEV = {"high": "high", "medium": "medium", "low": "low"}
_CAPEC_SEV = {"very high": "critical", "high": "high", "medium": "medium",
              "low": "low", "very low": "low"}


# --- curated prompt-module skills -----------------------------------------
# (skill_id suffix, display name, get_skill_prompt key, phase, technique
#  aliases, extra tags, cwe, severity)
_PROMPT_SKILLS = [
    ("sql_injection", "SQL Injection", "sql_injection", "exploitation",
     ["sql_injection", "sqli"], ["sql", "injection", "database"], ["89"], "high"),
    ("xss", "Cross-Site Scripting", "xss_exploitation", "exploitation",
     ["xss", "cross_site_scripting", "xss_exploitation"],
     ["xss", "javascript", "reflected", "stored", "dom"], ["79"], "high"),
    ("ssrf", "Server-Side Request Forgery", "ssrf_exploitation", "exploitation",
     ["ssrf", "server_side_request_forgery", "ssrf_exploitation"],
     ["ssrf", "metadata", "cloud"], ["918"], "high"),
    ("api_security", "API Security (IDOR/BOLA/JWT/GraphQL)", "api_security",
     "exploitation",
     ["api_security", "api_testing", "idor", "bola", "jwt_exploitation",
      "graphql_exploitation"],
     ["api", "idor", "bola", "jwt", "graphql", "authorization"],
     ["639", "287"], "high"),
    ("cve_exploit", "CVE Exploitation", "cve_exploit", "exploitation",
     ["cve_exploit", "cve"], ["cve", "exploit", "rce"], ["1395"], "high"),
    ("brute_force", "Credential Brute Force", "brute_force_credential_guess",
     "exploitation", ["brute_force_credential_guess", "brute_force"],
     ["brute", "credential", "password", "login"], ["307"], "medium"),
    ("phishing", "Phishing / Social Engineering", "phishing_social_engineering",
     "delivery", ["phishing_social_engineering", "phishing"],
     ["phishing", "social", "engineering"], ["1056"], "medium"),
    ("dos", "Denial of Service", "denial_of_service", "exploitation",
     ["denial_of_service", "dos"], ["dos", "availability", "flood"], ["400"],
     "medium"),
    ("active_directory", "Active Directory", "active_directory",
     "post_exploitation", ["active_directory", "ad", "ldap_exploit"],
     ["ad", "kerberos", "ldap", "lateral"], ["287"], "high"),
    ("ctf_web", "CTF Web", "ctf_web", "exploitation",
     ["ctf_web", "ctf", "ctf_challenge"], ["ctf", "web", "challenge"], [], "info"),
    ("linux_privesc", "Linux Privilege Escalation", "linux_privesc",
     "post_exploitation", ["linux_privesc", "privesc_linux", "post_exploit_linux"],
     ["privesc", "linux", "escalation"], ["269"], "high"),
    ("windows_privesc", "Windows Privilege Escalation", "windows_privesc",
     "post_exploitation",
     ["windows_privesc", "privesc_windows", "post_exploit_windows"],
     ["privesc", "windows", "escalation"], ["269"], "high"),
    ("ai_security", "AI / LLM Security", "ai_security", "exploitation",
     ["ai_security", "llm_security", "prompt_injection", "ai_red_team"],
     ["ai", "llm", "prompt", "injection"], ["1427"], "high"),
]


def _add_prompt_skills(reg: SkillRegistry) -> None:
    from core.skill_prompts import get_skill_prompt

    for sid, name, key, phase, aliases, tags, cwe, sev in _PROMPT_SKILLS:
        full_tags = tuple(sorted(set(tags) | set(aliases)))

        def _loader(k=key, p=phase):
            return get_skill_prompt(k, p)

        reg.add(Skill(
            id=f"prompt:{sid}", name=name, source="prompt",
            summary=f"Curated {name} attack playbook.",
            phases=(phase,), techniques=tuple(aliases), tags=full_tags,
            severity=sev, cwe=tuple(cwe), _loader=_loader,
        ))


# --- vendored MITRE skills -------------------------------------------------

@lru_cache(maxsize=1)
def _load_mitre() -> Dict[str, dict]:
    out: Dict[str, dict] = {"cwe": {}, "capec": {}, "capec_db": {}}
    for key, fname in (("cwe", "cwe_metadata.json"),
                       ("capec", "capec_metadata.json"),
                       ("capec_db", "capec_db.json")):
        p = _RES / fname
        if p.exists():
            try:
                out[key] = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                out[key] = {}
    return out


def mitre_available() -> bool:
    return (_RES / "cwe_metadata.json").exists() and \
           (_RES / "capec_metadata.json").exists()


def _phases_from_name(name: str) -> tuple:
    n = (name or "").lower()
    phases = ["exploitation"]
    if any(w in n for w in ("disclos", "exposure", "enumerat", "information",
                            "fingerprint", "discovery")):
        phases.insert(0, "reconnaissance")
    if any(w in n for w in ("privilege", "escalat", "persistence", "lateral")):
        phases.append("post_exploitation")
    return tuple(dict.fromkeys(phases))


def _fmt_cwe_body(num: str) -> str:
    m = _load_mitre()["cwe"].get(num)
    if not m:
        return ""
    parts = [f"CWE-{num}: {m.get('name', '')}"]
    if m.get("description"):
        parts.append(m["description"])
    if m.get("extended_description"):
        parts.append(str(m["extended_description"])[:600])
    cons = m.get("consequences")
    if cons:
        parts.append("Consequences: " + str(cons)[:300])
    mit = m.get("mitigations")
    if mit:
        parts.append("Mitigations: " + str(mit)[:400])
    det = m.get("detection_methods")
    if det:
        parts.append("Detection: " + str(det)[:300])
    return "\n".join(parts)


def _fmt_capec_body(num: str) -> str:
    m = _load_mitre()["capec"].get(num)
    if not m:
        return ""
    parts = [f"CAPEC-{num}: {m.get('name', '')}"]
    if m.get("description"):
        parts.append(str(m["description"])[:600])
    if m.get("prerequisites"):
        parts.append("Prerequisites: " + str(m["prerequisites"])[:300])
    if m.get("execution_flow"):
        parts.append("Execution flow: " + str(m["execution_flow"])[:600])
    return "\n".join(parts)


def _attack_ids_for_capec(num: str) -> tuple:
    rec = _load_mitre()["capec_db"].get(num) or {}
    tech = rec.get("techniques") or ""
    ids = []
    for raw in _TID.findall(str(tech)):
        ids.append(raw if raw.upper().startswith("T") else "T" + raw)
    return tuple(dict.fromkeys(ids))


def _add_cwe_skills(reg: SkillRegistry) -> None:
    from core.skill_registry import _tokens
    for num, m in _load_mitre()["cwe"].items():
        name = m.get("name", f"CWE-{num}")
        sev = _CWE_SEV.get(str(m.get("likelihood_of_exploit", "")).lower(), "info")
        tags = tuple(sorted(set(_tokens(name)) | {"cwe", "weakness"}))
        reg.add(Skill(
            id=f"cwe:{num}", name=f"CWE-{num}: {name}", source="cwe",
            summary=str(m.get("description", ""))[:160],
            phases=_phases_from_name(name), techniques=(), tags=tags,
            severity=sev, cwe=(str(num),),
            _loader=(lambda n=num: _fmt_cwe_body(n)),
        ))


def _add_capec_skills(reg: SkillRegistry) -> None:
    from core.skill_registry import _tokens
    for num, m in _load_mitre()["capec"].items():
        name = m.get("name", f"CAPEC-{num}")
        sev = _CAPEC_SEV.get(str(m.get("severity", "")).lower(), "info")
        related_cwe = tuple(str(c) for c in (m.get("related_cwes") or [])
                            if str(c).isdigit())
        tags = tuple(sorted(set(_tokens(name)) | {"capec", "attack-pattern"}))
        reg.add(Skill(
            id=f"capec:{num}", name=f"CAPEC-{num}: {name}", source="capec",
            summary=str(m.get("description", ""))[:160],
            phases=_phases_from_name(name), techniques=(), tags=tags,
            severity=sev, cwe=related_cwe, capec=(str(num),),
            attack=_attack_ids_for_capec(num),
            _loader=(lambda n=num: _fmt_capec_body(n)),
        ))


# --- external importer -----------------------------------------------------

def import_external(reg: SkillRegistry, entries: List[dict]) -> int:
    """Ingest a normalized external skill list (future ATT&CK/WSTG corpora).

    Each entry: {id, name, body|summary, phases, techniques, tags, severity,
    cwe, capec, attack}. ``body`` may be a string (wrapped as a lazy loader).
    Returns the number of skills added.
    """
    n = 0
    for e in entries:
        if not isinstance(e, dict) or not e.get("id") or not e.get("name"):
            continue
        body = e.get("body")
        loader = (lambda b=body: b) if isinstance(body, str) else None
        reg.add(Skill(
            id=f"external:{e['id']}", name=e["name"], source="external",
            summary=str(e.get("summary", ""))[:160],
            phases=tuple(e.get("phases", ()) or ()),
            techniques=tuple(e.get("techniques", ()) or ()),
            tags=tuple(t.lower() for t in (e.get("tags", ()) or ())),
            severity=str(e.get("severity", "info")),
            cwe=tuple(str(c) for c in (e.get("cwe", ()) or ())),
            capec=tuple(str(c) for c in (e.get("capec", ()) or ())),
            attack=tuple(e.get("attack", ()) or ()),
            _loader=loader,
        ))
        n += 1
    return n


# --- assembly --------------------------------------------------------------

def build_registry(include_mitre: bool = True) -> SkillRegistry:
    """Build a fresh registry from prompts (+ vendored MITRE if available)."""
    reg = SkillRegistry()
    _add_prompt_skills(reg)
    if include_mitre and mitre_available():
        _add_cwe_skills(reg)
        _add_capec_skills(reg)
    return reg


_DEFAULT: Optional[SkillRegistry] = None


def default_registry() -> SkillRegistry:
    """Process-wide cached catalog (built once)."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = build_registry()
    return _DEFAULT
