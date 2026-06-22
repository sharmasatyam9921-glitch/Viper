"""`viper.py verify <findings.json>` — re-confirm saved findings via the gate.

Load a finding (or array of findings) from JSON and run VIPER's INDEPENDENT
validation gate over them — the same re-confirmation a hunt applies — printing
which are submittable. Useful for triage, or to re-check a finding against the
live (authorized) target before submitting. The gate re-tests over real HTTP, so
only run it against a target you are authorized to test.

    viper.py verify finding.json
    viper.py verify reports/submissions/<hunt>/VIPER-1.json --min-confidence 0.6
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import List


def _load_findings(path: str) -> List[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        # accept either a bare finding or a {"findings": [...]} envelope
        if isinstance(data.get("findings"), list):
            return [f for f in data["findings"] if isinstance(f, dict)]
        return [data]
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]
    return []


def run_verify_cli(argv: List[str]) -> int:
    p = argparse.ArgumentParser(prog="viper.py verify",
                                description="Re-confirm saved findings via the gate")
    p.add_argument("file", help="JSON finding or array of findings")
    p.add_argument("--target", default="", help="default target URL for findings")
    p.add_argument("--min-confidence", type=float, default=0.5)
    args = p.parse_args(argv)

    try:
        findings = _load_findings(args.file)
    except Exception as e:  # noqa: BLE001
        print(f"could not read findings from {args.file!r}: {e}")
        return 1
    if not findings:
        print(f"no findings in {args.file!r}")
        return 1

    from core.swarm_validation import validate_findings
    out = asyncio.run(validate_findings(
        findings, default_target=args.target, min_confidence=args.min_confidence))

    sub = sum(1 for f in out if f.get("submittable"))
    print(f"verified {len(out)} finding(s) via the validation gate "
          f"-> {sub} submittable:\n")
    for f in out:
        tag = "SUBMITTABLE" if f.get("submittable") else "lead       "
        conf = f.get("validation_confidence")
        cs = f"{conf:.0%}" if isinstance(conf, (int, float)) else "n/a"
        print(f"  [{tag}] {str(f.get('vuln_type') or f.get('type')):<28} "
              f"conf={cs}  {f.get('url','')}")
        reason = f.get("validation_reason")
        if reason:
            print(f"      {reason}")
    return 0
