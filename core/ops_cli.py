"""Operator visibility CLIs: `viper.py classes` and `viper.py ledger`.

  viper.py classes              # vulnerability classes VIPER can test/confirm
  viper.py ledger [list]        # what's been drafted (cross-hunt dedup)
  viper.py ledger clear         # wipe the dedup ledger
"""
from __future__ import annotations

import importlib
import pkgutil
from typing import List

# Classes whose findings the validation gate independently CONFIRMS (re-test or a
# two-identity/out-of-band proof) — vs candidate-only classes that stay leads.
_GATE_CONFIRMED = {
    "xss", "sqli", "ssti", "lfi", "cmdi", "command_injection", "secrets",
    "cors", "env_exposed", "git_exposed", "information_disclosure", "idor",
    "bola", "bola_multi", "bfla", "bfla_multi", "host_header",
    "subdomain_takeover", "access_control", "ssrf", "crlf",
    "web_cache_deception", "xxe", "clickjacking", "cloud_exposure",
    "open_redirect", "graphql", "graphql_authz", "nosql_injection", "jwt",
    "ldap_injection", "xpath_injection",
}
_OOB_CAPABLE = {"ssrf", "command_injection", "xxe", "sqli", "host_header"}


def _load_vuln_techniques() -> List[str]:
    from core.swarm_workers import vuln as vpkg
    for m in pkgutil.iter_modules(vpkg.__path__):
        if not m.name.startswith("_"):
            try:
                importlib.import_module(f"core.swarm_workers.vuln.{m.name}")
            except Exception:
                pass
    from core.swarm_workers import _REGISTRY
    return sorted(_REGISTRY.get("vuln", {}).keys())


def run_classes_cli(argv: List[str]) -> int:
    techs = _load_vuln_techniques()
    print(f"VIPER vulnerability coverage - {len(techs)} test technique(s):\n")
    for t in techs:
        flags = []
        if any(t.startswith(c) or c == t for c in _GATE_CONFIRMED):
            flags.append("gate-confirmed")
        if t in _OOB_CAPABLE:
            flags.append("OOB")
        tag = ("  [" + ", ".join(flags) + "]") if flags else ""
        print(f"  {t}{tag}")
    print("\n  gate-confirmed = the validation gate independently re-confirms it "
          "(submittable);\n  OOB = also confirms blind variants via an out-of-band "
          "callback (--oob).")
    print("  Per-class gate precision: viper.py scorecard")
    return 0


def run_ledger_cli(argv: List[str]) -> int:
    from core.submission_ledger import SubmissionLedger
    cmd = argv[0] if argv else "list"
    led = SubmissionLedger()
    if cmd == "clear":
        try:
            if led.path.exists():
                led.path.unlink()
            print(f"cleared dedup ledger: {led.path}")
        except Exception as e:  # noqa: BLE001
            print(f"could not clear ledger: {e}")
            return 1
        return 0
    entries = led._seen
    if not entries:
        print("dedup ledger is empty (no submissions drafted yet).")
        return 0
    print(f"{len(entries)} drafted finding signature(s):")
    for sig, meta in sorted(entries.items()):
        print(f"  [{meta.get('status','?'):<9}] x{meta.get('count',1)} "
              f"{meta.get('vuln_type','?'):<26} {meta.get('url','')}")
        print(f"      sig: {sig}")
    return 0


def _load_findings_for_leads(path=None) -> List[dict]:
    """Load findings from an explicit JSON path, or the newest findings/*.json that
    holds a list of finding dicts. Accepts a bare list or a {"findings":[...]}
    envelope. Never raises; returns [] if nothing usable is found."""
    import json
    from pathlib import Path

    def _dicts(d):
        items = d.get("findings") if isinstance(d, dict) else d
        return [f for f in items if isinstance(f, dict)] if isinstance(items, list) else []

    if path:
        try:
            return _dicts(json.loads(Path(path).read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            return []
    fdir = Path(__file__).resolve().parents[1] / "findings"
    if not fdir.exists():
        return []
    for p in sorted(fdir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            got = _dicts(json.loads(p.read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            continue
        if got:
            return got
    return []


def _lead_reason_bucket(reason: str) -> str:
    """Collapse a per-finding validation_reason to a stable bucket by stripping the
    volatile specifics (urls, numbers, quoted tokens) so leads group cleanly."""
    import re
    r = (reason or "").strip() or "not gate-evaluated"
    r = re.sub(r"https?://\S+", "<url>", r)
    r = re.sub(r"\b\d+(?:\.\d+)?\b", "N", r)
    r = re.sub(r"'[^']*'", "'X'", r)
    r = re.sub(r'"[^"]*"', '"X"', r)
    return r[:110]


def run_leads_cli(argv: List[str]) -> int:
    """`viper.py leads [findings.json] [--show N]` — group the non-submittable
    findings (leads) by WHY the gate demoted them. Pure read-out of the
    (submittable, validation_reason) the gate already stamped — no network, no
    re-test — so an operator can see what to corroborate (two sessions for BOLA, an
    OOB listener for blind vulns) instead of guessing."""
    import argparse
    from collections import defaultdict
    p = argparse.ArgumentParser(
        prog="viper.py leads",
        description="Group leads (non-submittable findings) by gate-failure reason")
    p.add_argument("file", nargs="?",
                   help="findings JSON (default: newest in findings/)")
    p.add_argument("--show", type=int, default=3,
                   help="example leads to list per reason (default 3)")
    args = p.parse_args(argv)

    findings = _load_findings_for_leads(args.file)
    if not findings:
        print("no findings found - run a hunt, or pass a findings JSON path.")
        return 0
    leads = [f for f in findings if not f.get("submittable")]
    subs = len(findings) - len(leads)
    print(f"{len(findings)} finding(s): {subs} submittable, {len(leads)} lead(s)\n")
    if not leads:
        print("no leads - every finding was independently gate-confirmed.")
        return 0

    groups = defaultdict(list)
    for f in leads:
        groups[_lead_reason_bucket(f.get("validation_reason"))].append(f)
    for reason, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        print(f"[{len(items):>3}] {reason}")
        for f in items[:max(0, args.show)]:
            vt = f.get("vuln_type") or f.get("type") or "?"
            url = f.get("url") or f.get("target") or ""
            conf = f.get("validation_confidence")
            ctag = f" (conf {conf})" if conf is not None else ""
            print(f"       - {vt}{ctag}  {url}")
        if len(items) > args.show:
            print(f"       ... and {len(items) - args.show} more")
        print()
    print("Leads are candidates the gate could not INDEPENDENTLY reproduce. To promote "
          "them: supply two sessions (--cookie-b + --owner-marker) for access-control "
          "classes, run an OOB listener (--oob) for blind vulns, or review manually.")
    return 0
