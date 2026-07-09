"""One-shot validation-gate invariant check for CI and local pre-merge.

Runs the two adversarial harnesses that guard the gate's precision-1.00 / 0-FP invariant
and returns a single exit code:

  * the labeled scorecard (``gate_benchmark --strict``) — every SAFE responder must stay a
    lead (precision 1.00) AND every confirmed class must still confirm (recall 1.00); and
  * the mutation / perturbation harness (``gate_mutations --strict``) — no SAFE responder
    may leak under any confidence threshold or benign response perturbation.

Exit 0 iff BOTH hold. Run locally before touching the gate, and in CI on every change to
``core/`` so precision 1.00 is an ENFORCED merge-gate, not just a measured snapshot:

    python -m core.gate_ci
"""
from __future__ import annotations


def main(argv=None) -> int:
    from core.gate_benchmark import main as bench_main
    from core.gate_mutations import main as mut_main

    print("== validation-gate scorecard (precision AND recall must be 1.00) ==")
    rc_bench = bench_main(["--strict"])
    print("\n== gate mutation / perturbation harness (no safe responder may leak) ==")
    rc_mut = mut_main(["--strict"])

    rc = rc_bench or rc_mut
    print("\n" + ("GATE CI: PASS - precision 1.00 invariant holds." if rc == 0
                  else "GATE CI: FAIL - the gate's precision-1.00 invariant regressed."))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
