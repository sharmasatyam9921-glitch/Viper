"""Grade a RunResult against a Challenge.

Two modes:
  flag        — XBOW-style capture-the-flag. Solved iff the flag string (or
                flag_regex) appears anywhere in VIPER's artifacts (findings JSON,
                stdout, stderr). This is the number directly comparable to XBOW's
                published solve rate on validation-benchmarks.
  vuln_class  — Solved iff VIPER reported a finding whose vuln type matches one of
                the expected classes (case-insensitive synonym match), optionally
                gated by url_contains and min_severity. Used for graded apps like
                Juice Shop / DVWA where there's no single flag token.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .models import Challenge, RunResult, Score, severity_rank


# Canonical vuln class -> tokens VIPER might emit for it. Matching is substring
# based after normalization, so short stems ("sqli", "xss") catch variants like
# "sqli_union", "reflected_xss", "stored_xss_comment".
SYNONYMS: dict[str, list[str]] = {
    "sql_injection": ["sql_injection", "sqli", "sql_inj", "blind_sql", "error_sql", "union_sql"],
    "xss": ["xss", "cross_site_scripting", "reflected_xss", "stored_xss", "dom_xss"],
    "idor": ["idor", "insecure_direct_object", "bola", "broken_object_level"],
    "auth_bypass": ["auth_bypass", "authentication_bypass", "broken_auth", "login_bypass",
                    "auth_bypass_header"],
    "access_control": ["access_control", "broken_access", "privilege_escalation", "privesc",
                       "forced_browsing", "missing_authorization"],
    "ssrf": ["ssrf", "server_side_request_forgery"],
    "rce": ["rce", "remote_code_execution", "command_injection", "cmd_injection", "os_command"],
    "lfi": ["lfi", "local_file_inclusion", "path_traversal", "directory_traversal", "file_read"],
    "rfi": ["rfi", "remote_file_inclusion"],
    "xxe": ["xxe", "xml_external_entity"],
    "csrf": ["csrf", "cross_site_request_forgery"],
    "ssti": ["ssti", "server_side_template", "template_injection"],
    "open_redirect": ["open_redirect", "redirect"],
    "cors": ["cors", "cross_origin", "cors_misconfig"],
    "jwt": ["jwt", "json_web_token", "alg_none", "jwt_none"],
    "graphql": ["graphql", "introspection", "graphql_injection"],
    "nosql_injection": ["nosql", "nosql_injection", "mongo_injection"],
    "deserialization": ["deserial", "insecure_deserialization", "object_injection"],
    "info_disclosure": ["info_disclosure", "information_disclosure", "sensitive_data",
                        "data_exposure", "secret_exposure", "exposed_secret"],
    "file_upload": ["file_upload", "unrestricted_upload", "malicious_upload"],
    "business_logic": ["business_logic", "logic_flaw", "price_manipulation", "race_condition"],
}


def _norm(s: Any) -> str:
    s = str(s or "").lower().strip()
    return re.sub(r"[\s\-./]+", "_", s)


def _expected_tokens(vuln_types: list[str]) -> list[tuple[str, list[str]]]:
    """For each expected class, return (display, [normalized match tokens])."""
    out: list[tuple[str, list[str]]] = []
    for vt in vuln_types:
        key = _norm(vt)
        tokens = set(SYNONYMS.get(key, []))
        tokens.add(key)
        # Also map a raw synonym someone wrote directly (e.g. "sqli") to its family.
        for canon, syns in SYNONYMS.items():
            if key in syns:
                tokens.update(syns)
                tokens.add(canon)
        out.append((vt, sorted(_norm(t) for t in tokens)))
    return out


def _finding_vuln_label(f: dict[str, Any]) -> str:
    for k in ("vuln_type", "attack", "type", "category", "weakness", "name", "title"):
        v = f.get(k)
        if v:
            return _norm(v)
    return ""


def _finding_blob(f: dict[str, Any]) -> str:
    """All searchable text of a finding, for flag hunting."""
    try:
        return json.dumps(f, default=str).lower()
    except Exception:
        return str(f).lower()


# -- flag mode -------------------------------------------------------------

def _score_flag(ch: Challenge, run: RunResult) -> Score:
    sc = Score(challenge_id=ch.id, name=ch.name, category=ch.category, mode="flag",
               duration_s=run.duration_s, timed_out=run.timed_out, error=run.error)

    haystacks = [run.stdout_tail or "", run.stderr_tail or ""]
    haystacks += [_finding_blob(f) for f in run.findings]
    blob = "\n".join(haystacks)

    if ch.flag_regex:
        m = re.search(ch.flag_regex, blob, re.IGNORECASE | re.MULTILINE)
        if m:
            sc.solved = True
            sc.reason = f"flag_regex matched: {m.group(0)[:80]!r}"
            sc.matched = [{"flag": m.group(0)}]
            return sc
        sc.reason = "flag_regex not found in artifacts"
        return sc

    if ch.flag:
        needle = ch.flag.lower()
        if needle in blob.lower():
            sc.solved = True
            sc.reason = f"flag string found: {ch.flag[:80]!r}"
            sc.matched = [{"flag": ch.flag}]
            return sc
        sc.reason = "flag string not found in artifacts"
        return sc

    sc.reason = "flag mode but challenge defines no flag/flag_regex"
    return sc


# -- vuln_class mode -------------------------------------------------------

def _score_vuln_class(ch: Challenge, run: RunResult) -> Score:
    sc = Score(challenge_id=ch.id, name=ch.name, category=ch.category, mode="vuln_class",
               duration_s=run.duration_s, timed_out=run.timed_out, error=run.error)

    if not ch.expect.vuln_types:
        sc.reason = "vuln_class mode but expect.vuln_types is empty"
        return sc

    want = _expected_tokens(ch.expect.vuln_types)
    url_sub = _norm(ch.expect.url_contains) if ch.expect.url_contains else ""
    min_rank = severity_rank(ch.expect.min_severity) if ch.expect.min_severity else -1

    for f in run.findings:
        label = _finding_vuln_label(f)
        if not label:
            continue
        # Class match: any expected token is a substring of the finding label,
        # or vice-versa (handles both "sqli" in "sqli_union" and "sql" specs).
        hit_class = None
        for display, tokens in want:
            for tok in tokens:
                if not tok:
                    continue
                if tok in label or label in tok:
                    hit_class = display
                    break
            if hit_class:
                break
        if not hit_class:
            continue
        # Optional URL gate.
        if url_sub:
            f_url = _norm(f.get("url") or f.get("endpoint") or f.get("location"))
            if url_sub not in f_url:
                continue
        # Optional severity gate.
        if min_rank >= 0:
            if severity_rank(f.get("severity")) < min_rank:
                continue
        sc.solved = True
        sc.matched.append({
            "expected": hit_class,
            "vuln_type": f.get("vuln_type") or f.get("attack") or label,
            "severity": f.get("severity"),
            "url": f.get("url"),
            "confidence": f.get("confidence"),
        })

    if sc.solved:
        classes = sorted({m["expected"] for m in sc.matched})
        sc.reason = f"matched {len(sc.matched)} finding(s) for class(es): {', '.join(classes)}"
    else:
        n = len(run.findings)
        sc.reason = (f"no finding matched {ch.expect.vuln_types} "
                     f"(VIPER reported {n} finding(s))")
    return sc


def score(ch: Challenge, run: RunResult) -> Score:
    if run.error and not run.findings and not run.stdout_tail:
        return Score(challenge_id=ch.id, name=ch.name, category=ch.category,
                     mode=ch.mode, solved=False, reason=f"run error: {run.error}",
                     duration_s=run.duration_s, timed_out=run.timed_out, error=run.error)
    if ch.mode == "flag":
        return _score_flag(ch, run)
    return _score_vuln_class(ch, run)
