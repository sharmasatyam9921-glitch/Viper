"""Dashboard operator API — backs the bug-bounty control panel endpoints.

Each function returns a JSON-serializable dict (never raises to the handler; it
catches and returns an ``error`` field) so the dashboard can drive VIPER's operator
surface: scope pull/import/show, the precision scorecard, class coverage, the
coverage critic, the attack-path graph, submission drafts, and the dedup ledger.

These are READ/setup operations (and the scope pull uses the operator's OWN H1
token to read their program scope). Launching a hunt stays the existing
/api/hack/start path — the human's trigger.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

_ROOT = Path(__file__).resolve().parents[1]


def _err(e) -> dict:
    return {"error": f"{type(e).__name__}: {e}"}


# ── scope ────────────────────────────────────────────────────────────────

def get_scope() -> dict:
    p = _ROOT / "scopes" / "current_scope.json"
    if not p.exists():
        return {"loaded": False, "in_scope": [], "out_of_scope": [],
                "hint": "POST /api/scope/pull {handle} or /api/scope/import {path}"}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return {"loaded": True, "program_name": d.get("program_name"),
                "program_url": d.get("program_url"),
                "in_scope": d.get("in_scope", []),
                "out_of_scope": d.get("out_of_scope", [])}
    except Exception as e:  # noqa: BLE001
        return _err(e)


# Bug-bounty platforms. Only HackerOne has automated API scope-pull today; the
# others fall back to the offline importer (honest — not faked).
_PLATFORMS = {
    "hackerone": {"label": "HackerOne", "auto_pull": True, "env": "HACKERONE_API_TOKEN"},
    "bugcrowd": {"label": "Bugcrowd", "auto_pull": True, "env": "BUGCROWD_API_TOKEN"},
    "intigriti": {"label": "Intigriti", "auto_pull": True, "env": "INTIGRITI_API_TOKEN"},
    "yeswehack": {"label": "YesWeHack", "auto_pull": False, "env": ""},
    "other": {"label": "Other / manual", "auto_pull": False, "env": ""},
}
_AUTO_PLATFORMS = {"hackerone", "h1", "bugcrowd", "intigriti"}
_COMPLIANCE = {
    "owasp": "OWASP Top 10 (2021)", "pci_dss": "PCI DSS v4.0",
    "nist": "NIST SP 800-53", "hipaa": "HIPAA Security Rule",
    "soc2": "SOC 2 Trust Services Criteria",
}
# Operating modes: a mode picks a hunt profile + the UI surface it needs.
_MODES = [
    {"id": "bugbounty", "label": "Bug Bounty", "profile": "bugbounty", "go": False,
     "desc": "Scope-locked hunt on a public program: auto-pull scope, FP-averse "
             "gate, submission drafts + dedup ledger."},
    {"id": "pentest", "label": "Pentest (enterprise)", "profile": "bugbounty",
     "go": True, "desc": "Authorized engagement: RoE + authorization, multi-target, "
             "compliance mapping, executive report, evidence chain-of-custody."},
    {"id": "ctf", "label": "CTF", "profile": "ctf", "go": True,
     "desc": "Flag-capture: aggressive, fast, exploitation-focused (less FP-averse)."},
]


def get_modes() -> dict:
    return {"modes": _MODES, "platforms": _PLATFORMS,
            "compliance": [{"id": k, "label": v} for k, v in _COMPLIANCE.items()]}


def get_compliance() -> dict:
    return {"frameworks": [{"id": k, "label": v} for k, v in _COMPLIANCE.items()]}


def scope_pull(data: dict) -> dict:
    handle = (data or {}).get("handle", "").strip()
    platform = (data or {}).get("platform", "hackerone").strip().lower() or "hackerone"
    if not handle:
        return {"ok": False, "error": "handle required"}
    if platform not in _AUTO_PLATFORMS:
        return {"ok": False, "error": f"automated scope-pull for "
                f"'{platform}' isn't wired yet — export the program scope and use "
                "Import (HackerOne / Bugcrowd / Intigriti auto-pull work today)"}
    try:
        from scope.hackerone_scope import save_current_scope, to_scope
        from scope.platform_scope import fetch_scope, platform_creds
        user, token = platform_creds(platform)
        if not token:
            env = _PLATFORMS.get(platform, {}).get("env", "<token>")
            return {"ok": False, "error": f"no {platform} API token (set {env}"
                    + (" + HACKERONE_API_USERNAME)" if platform in ("hackerone", "h1") else ")")}
        raw = fetch_scope(platform, handle, username=user, token=token)
        scope = to_scope(raw, program_name=f"{handle} ({platform})", handle=handle)
        save_current_scope(scope, str(_ROOT / "scopes" / "current_scope.json"))
        return {"ok": True, "platform": platform, "handle": handle,
                "in_scope": len(scope.in_scope), "out_of_scope": len(scope.out_of_scope)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, **_err(e)}


def compliance_report(data: dict) -> dict:
    """Map findings -> compliance controls (filtered to the selected frameworks)."""
    frameworks = set((data or {}).get("frameworks") or [])
    findings = (data or {}).get("findings") or _load_latest_findings()
    if not findings:
        return {"ok": False, "error": "no findings to map"}
    try:
        from core.compliance_mapper import enrich_finding
        hits: dict = {}
        for f in findings:
            for std, ref in (enrich_finding(f).get("compliance") or {}).items():
                if not frameworks or std in frameworks:
                    hits.setdefault(std, set()).add(ref)
        return {"ok": True, "finding_count": len(findings),
                "frameworks": [{"id": k, "label": _COMPLIANCE.get(k, k.upper()),
                                "controls": sorted(v)} for k, v in sorted(hits.items())]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, **_err(e)}


def scope_import(data: dict) -> dict:
    path = (data or {}).get("path", "").strip()
    burp = (data or {}).get("burp", "").strip()
    if not path:
        return {"ok": False, "error": "path required (exported scope csv)"}
    try:
        from scope.hackerone_scope import (parse_burp_excludes, parse_csv_scopes,
                                           save_current_scope, to_scope)
        excl = parse_burp_excludes(burp) if burp else ()
        if path.lower().endswith(".csv"):
            raw = parse_csv_scopes(path)
            scope = to_scope(raw, program_name="imported", extra_excludes=excl)
        else:
            scope = to_scope([], program_name="imported",
                             extra_excludes=parse_burp_excludes(path))
        save_current_scope(scope, str(_ROOT / "scopes" / "current_scope.json"))
        return {"ok": True, "in_scope": len(scope.in_scope),
                "out_of_scope": len(scope.out_of_scope)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, **_err(e)}


# ── precision scorecard + class coverage ──────────────────────────────────

def get_scorecard() -> dict:
    try:
        from core.gate_benchmark import overall, run_benchmark
        scores = run_benchmark()                       # dict: class -> ClassScore
        ov = overall(scores)
        return {"classes": [{"cls": s.cls, "precision": round(s.precision, 3),
                             "recall": round(s.recall, 3), "tp": s.tp, "fp": s.fp,
                             "tn": s.tn, "fn": s.fn} for s in scores.values()],
                "overall": {"precision": round(ov.precision, 3),
                            "recall": round(ov.recall, 3), "tp": ov.tp,
                            "fp": ov.fp, "tn": ov.tn, "fn": ov.fn}}
    except Exception as e:  # noqa: BLE001
        return _err(e)


def get_classes() -> dict:
    try:
        from core.ops_cli import (_GATE_CONFIRMED, _OOB_CAPABLE,
                                   _load_vuln_techniques)
        techs = _load_vuln_techniques()
        rows = []
        for t in techs:
            rows.append({
                "technique": t,
                "gate_confirmed": any(t.startswith(c) or c == t for c in _GATE_CONFIRMED),
                "oob_capable": t in _OOB_CAPABLE})
        return {"count": len(rows), "classes": rows}
    except Exception as e:  # noqa: BLE001
        return _err(e)


# ── findings-derived views (coverage critic, attack-path graph) ───────────

def _load_latest_findings() -> List[dict]:
    """Newest findings/*.json that actually holds a list of finding dicts."""
    fdir = _ROOT / "findings"
    if not fdir.exists():
        return []
    for p in sorted(fdir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        items = d.get("findings") if isinstance(d, dict) else d
        if isinstance(items, list):
            dicts = [f for f in items if isinstance(f, dict)]
            if dicts:
                return dicts
    return []


def get_coverage(findings: Optional[List[dict]] = None) -> dict:
    try:
        from core.coverage_critic import critique
        fs = findings if findings is not None else _load_latest_findings()
        gaps = critique(fs)
        return {"finding_count": len(fs),
                "gaps": [{"kind": g.kind, "detail": g.detail,
                          "suggestion": g.suggestion} for g in gaps]}
    except Exception as e:  # noqa: BLE001
        return _err(e)


def get_attack_paths(findings: Optional[List[dict]] = None) -> dict:
    try:
        from core.attack_path import find_paths
        fs = findings if findings is not None else _load_latest_findings()
        paths = find_paths(fs)
        return {"finding_count": len(fs), "paths": [{
            "goal": p.goal, "severity": p.severity,
            "fully_confirmed": p.fully_confirmed,
            "confirmed_hops": p.confirmed_hops, "potential_hops": p.potential_hops,
            "narrative": p.narrative} for p in paths]}
    except Exception as e:  # noqa: BLE001
        return _err(e)


# ── submissions + dedup ledger ────────────────────────────────────────────

def get_submissions() -> dict:
    out = []
    for base in (_ROOT / "reports", _ROOT / "findings"):
        if not base.exists():
            continue
        for p in base.rglob("*submission*.md"):
            out.append({"file": str(p.relative_to(_ROOT)),
                        "size": p.stat().st_size, "mtime": p.stat().st_mtime})
        for idx in base.rglob("INDEX.md"):
            out.append({"file": str(idx.relative_to(_ROOT)), "index": True,
                        "mtime": idx.stat().st_mtime})
    out.sort(key=lambda r: r.get("mtime", 0), reverse=True)
    return {"count": len(out), "submissions": out[:100]}


def verify_findings(data: dict) -> dict:
    """Re-confirm POSTed candidate findings through the validation gate."""
    import asyncio
    findings = (data or {}).get("findings") or []
    if not findings:
        return {"ok": False, "error": "findings list required"}
    try:
        from core.swarm_validation import validate_findings
        out = asyncio.run(validate_findings(
            findings, default_target=(data or {}).get("target", "")))
        sub = [f for f in out if f.get("submittable")]
        return {"ok": True, "total": len(out), "submittable": len(sub),
                "results": [{"vuln_type": f.get("vuln_type"),
                             "submittable": bool(f.get("submittable")),
                             "confidence": f.get("validation_confidence"),
                             "reason": f.get("validation_reason")} for f in out]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, **_err(e)}


def get_ledger() -> dict:
    try:
        from core.submission_ledger import SubmissionLedger
        led = SubmissionLedger()
        sigs = getattr(led, "_seen", {}) or {}
        return {"count": len(sigs),
                "entries": [{"signature": k, "info": v} for k, v in
                            list(sigs.items())[:200]]}
    except Exception as e:  # noqa: BLE001
        return _err(e)
