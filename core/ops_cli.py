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
