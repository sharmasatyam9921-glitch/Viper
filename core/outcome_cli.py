"""`viper.py outcome <disposition> <findings.json> [--tech t1,t2]`

Close the OUTER learning loop. After a human submits and a program dispositions a
finding (accepted / paid / duplicate / rejected / ...), feed that back so VIPER learns
which classes actually pay out on a given stack:

  * records the disposition in the cross-hunt submission ledger, and
  * feeds a reward-weighted signal into the evograph attack priors (paid > accepted >
    triaged > duplicate/informative > rejected), so next time the technique dispatch on
    a similar tech stack runs the historically-rewarding classes first.

Ordering only — it never touches the validation gate. `--tech` supplies the target's
stack (submitted findings don't carry it); each finding's own `technique` (or vuln_type
head) is the key rewarded.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

_DISPOSITIONS = ("paid", "resolved", "accepted", "triaged", "informative",
                 "duplicate", "rejected", "n/a")


def run_outcome_cli(argv: List[str]) -> int:
    if len(argv) < 2 or argv[0].strip().lower() not in _DISPOSITIONS:
        print("usage: viper.py outcome <" + "|".join(_DISPOSITIONS) +
              "> <findings.json> [--tech t1,t2]")
        return 2
    disposition = argv[0].strip().lower()
    rest = list(argv[1:])
    tech: List[str] = []
    if "--tech" in rest:
        i = rest.index("--tech")
        raw = rest[i + 1] if i + 1 < len(rest) else ""
        tech = [t.strip() for t in raw.split(",") if t.strip()]
        del rest[i:i + 2]
    if not rest:
        print("error: no findings.json given")
        return 2
    try:
        data = json.loads(Path(rest[0]).read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        print(f"error: could not read findings {rest[0]!r}: {e}")
        return 2
    findings = data if isinstance(data, list) else (data.get("findings") or [])
    findings = [f for f in findings if isinstance(f, dict)]
    if not findings:
        print("no findings in file — nothing to record.")
        return 0

    from core.attack_priors import AttackPriors
    from core.submission_ledger import SubmissionLedger
    priors = AttackPriors()
    ledger = SubmissionLedger()
    fed = 0
    for f in findings:
        ledger.set_disposition(f, disposition)
        technique = f.get("technique") or str(
            f.get("vuln_type") or f.get("type") or "").split(":")[0]
        if technique and priors.record_outcome(technique, tech, disposition):
            fed += 1
    ledger.save()
    stack = f" (stack: {','.join(tech)})" if tech else " (no --tech; recorded globally)"
    print(f"outcome '{disposition}' recorded for {len(findings)} finding(s); "
          f"{fed} fed into cross-hunt attack priors{stack}.")
    return 0
