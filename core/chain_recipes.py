"""Attack-chain recipes — recognize low->critical escalations across findings.

Individual findings are often low/medium on their own; the money is in the chain
(open-redirect + OAuth -> account takeover; SSRF + cloud metadata -> credential
compromise; source/config exposure + a leaked secret -> full compromise). This
module correlates the FINAL finding set against declarative recipes and emits a
synthetic ``chain:*`` finding with the escalated severity and a narrative.

A chain is only as trustworthy as its parts: a chain is marked submittable iff
EVERY contributing finding is itself submittable (gate-confirmed). Otherwise it
is a high-value lead for manual review. This keeps the FP-averse contract — a
chain never manufactures confidence the components don't have.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

Predicate = Callable[[dict], bool]


def _head(f: dict) -> str:
    return (f.get("vuln_type") or f.get("type") or "").lower()


def _text(f: dict) -> str:
    return " ".join(str(f.get(k, "")) for k in ("title", "evidence", "vuln_type")).lower()


def _word_in(name: str, head0: str) -> bool:
    # match `name` as a whole underscore-delimited word of head0 (so "xss" matches
    # "xss_text" and "redirect" matches "open_redirect", but "admin" never matches
    # "badminton" and "cors" never matches "cors_xyz" via a bare substring).
    return (name == head0 or head0.startswith(name + "_")
            or head0.endswith("_" + name) or ("_" + name + "_") in ("_" + head0 + "_"))


def is_type(*names: str) -> Predicate:
    def p(f: dict) -> bool:
        segs = _head(f).split(":")        # e.g. ["idor","bola","/x"] / ["xss_text","q"]
        head0 = segs[0]
        return any(_word_in(n, head0) or n in segs for n in names)
    return p


def text_has(*keywords: str) -> Predicate:
    def p(f: dict) -> bool:
        t = _text(f)
        return any(k in t for k in keywords)
    return p


def both(*preds: Predicate) -> Predicate:
    def p(f: dict) -> bool:
        return all(pred(f) for pred in preds)
    return p


@dataclass
class ChainRecipe:
    id: str
    name: str
    severity: str
    cwe: str
    impact: str
    requires: List[Predicate] = field(default_factory=list)

    def match(self, findings: List[dict]) -> Optional[List[dict]]:
        """Assign a DISTINCT finding to each requirement; return them, or None."""
        used: set = set()
        chosen: List[dict] = []
        for pred in self.requires:
            hit = None
            for i, f in enumerate(findings):
                if i in used:
                    continue
                if pred(f):
                    hit = i
                    break
            if hit is None:
                return None
            used.add(hit)
            chosen.append(findings[hit])
        return chosen


# The recipe library. Each recipe needs a DISTINCT finding per requirement, so a
# single finding can't satisfy a multi-step chain by itself.
RECIPES: List[ChainRecipe] = [
    ChainRecipe(
        "ssrf_cloud_creds", "SSRF to cloud metadata -> credential compromise",
        "critical", "CWE-918",
        "An SSRF reaching the cloud metadata service yields IAM credentials, "
        "escalating a server-side request to full cloud-account compromise.",
        [both(is_type("ssrf"),
              text_has("metadata", "instance-id", "imds", "169.254.169.254",
                       "accesskey", "credential", "iam"))],
    ),
    ChainRecipe(
        "exposure_to_secret", "Source/config exposure + leaked secret -> compromise",
        "critical", "CWE-200",
        "An exposed source/config artifact alongside a live credential lets an "
        "attacker authenticate as the application or its dependencies.",
        [is_type("git_exposed", "env_exposed", "information_disclosure", "dir_listing"),
         is_type("secret", "secrets", "js_secret", "github_secret")],
    ),
    ChainRecipe(
        "open_redirect_oauth_ato", "Open redirect + OAuth/token flow -> account takeover",
        "high", "CWE-601",
        "An open redirect in an OAuth/SSO/token flow can leak the authorization "
        "code or token to an attacker-controlled host -> account takeover.",
        [is_type("open_redirect", "redirect"),
         is_type("oauth", "jwt", "sso", "auth_bypass", "login_sqli")],
    ),
    ChainRecipe(
        "xss_session_ato", "XSS + weak session/CORS -> account takeover",
        "high", "CWE-79",
        "Reflected/stored XSS combined with an accessible session cookie or "
        "permissive CORS lets an attacker exfiltrate the victim's session.",
        [is_type("xss"),
         both(is_type("cors", "cors_misconfig", "csrf"),
              text_has("credential", "cookie", "authenticated", "true"))],
    ),
    ChainRecipe(
        "lfi_to_rce", "LFI + log/session poisoning -> RCE",
        "critical", "CWE-98",
        "Local file inclusion that can read attacker-influenced logs or session "
        "files is a path to remote code execution.",
        [both(is_type("lfi", "path_traversal"),
              text_has("log", "/proc", "session", "access.log", "php"))],
    ),
    ChainRecipe(
        "bola_pii", "BOLA/IDOR over PII -> mass data exposure",
        "high", "CWE-639",
        "Object-level authorization bypass over records containing PII enables "
        "enumeration of other users' personal data at scale.",
        [both(is_type("bola", "idor"),
              text_has("email", "ssn", "phone", "address", "passwordhash",
                       "national", "dob", "pii"))],
    ),
]


def _component_confidence(components: List[dict]) -> float:
    confs = [float(c.get("validation_confidence") or c.get("confidence") or 0.0)
             for c in components]
    return round(min(confs), 3) if confs else 0.0


def correlate_chains(findings: List[dict]) -> List[dict]:
    """Return synthetic ``chain:*`` findings for every recipe that matches.

    A chain is submittable iff all of its components are submittable.
    """
    chains: List[dict] = []
    for recipe in RECIPES:
        comp = recipe.match(findings)
        if not comp:
            continue
        all_submittable = all(c.get("submittable") for c in comp)
        titles = "; ".join(str(c.get("title") or c.get("vuln_type")) for c in comp)
        chains.append({
            "type": "chain",
            "vuln_type": f"chain:{recipe.id}",
            "title": recipe.name,
            "severity": recipe.severity,
            "cwe": recipe.cwe,
            "url": next((c.get("url") for c in comp if c.get("url")), ""),
            "confidence": _component_confidence(comp),
            "evidence": f"{recipe.impact} Chained from: {titles}.",
            "chain_of": [c.get("vuln_type") or c.get("type") for c in comp],
            "validated": all_submittable,
            "validation_confidence": _component_confidence(comp) if all_submittable else 0.0,
            "validation_reason": (
                "all chained components are independently confirmed (submittable)"
                if all_submittable else
                "chain of unconfirmed components — high-value lead for manual review"),
            "submittable": bool(all_submittable),
            "needs_manual_verification": not all_submittable,
        })
    return chains
