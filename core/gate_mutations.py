"""Mutation / regression harness for the validation gate.

The scorecard (:mod:`core.gate_benchmark`) proves precision 1.00 at the DEFAULT
confidence threshold on the canonical responders. That is a snapshot. This harness
hardens it into a *guarded* invariant: it re-runs every SAFE scenario

  (1) across a grid of ``min_confidence`` values (0.05 -> 0.95), and
  (2) under semantic-preserving perturbations of the responder (body whitespace,
      a content-type charset suffix),

and asserts a SAFE responder NEVER becomes ``submittable`` under any combination. A
leak means an edit decalibrated the gate — a safe input that leaks at a lowered
threshold, or a gate branch that matches too rigidly to survive a benign reformat.

The perturbations are deliberately conservative (they never change what a response
*means*), so a leak is always a real fragility, never a test artifact. The gate reads
headers case-insensitively and content-types by substring, so these mutations must
not change any verdict — if one does, that is the finding.

    python -m core.gate_mutations           # print the report
    python -m core.gate_mutations --strict   # exit 1 if any safe responder leaks
"""
from __future__ import annotations

import asyncio

from core.gate_benchmark import BENCHMARK, _fetch
from core.swarm_validation import validate_findings
from core.swarm_workers.vuln._http import HttpResp

# Thresholds spanning well below and above the default 0.5 — a safe responder must
# stay held back at ALL of them (lowering the bar must never surface a false bug).
CONF_GRID = (0.05, 0.25, 0.5, 0.75, 0.95)


def _identity(r: HttpResp) -> HttpResp:
    return r


def _pad_body(r: HttpResp) -> HttpResp:
    """Surround the body with whitespace — a browser/proxy-benign reformat."""
    return HttpResp(r.status, dict(r.headers or {}),
                    "\n  " + (r.body or "") + "  \n", getattr(r, "final_url", ""))


def _charset(r: HttpResp) -> HttpResp:
    """Append a charset to the content-type — the gate matches it by substring."""
    h = dict(r.headers or {})
    ct = h.get("content-type")
    if ct and "charset=" not in ct:
        h["content-type"] = ct + "; charset=utf-8"
    return HttpResp(r.status, h, r.body, getattr(r, "final_url", ""))


PERTURBATIONS = {"identity": _identity, "pad_body": _pad_body, "charset": _charset}

# These gate branches RE-RUN the real worker against a live target (unreachable in
# the offline benchmark), so perturbing the responder is a no-op — they ignore it —
# and each re-run is slow. They stay leads at every threshold by construction (not
# reproduced), so the harness skips them; their behaviour is covered by their own
# worker+gate tests (test_cmdi_*, test_xxe_gate, test_crlf_gate).
_WORKER_RERUN_CLASSES = {"cmdi", "xxe", "crlf"}


def _perturbed(responder, mut):
    """Wrap a benchmark responder so its RESPONSE is perturbed, preserving the
    (method, url, headers[, body]) calling convention (incl. body-aware responders)."""
    if getattr(responder, "wants_body", False):
        def w(m, url, h, body):
            return mut(responder(m, url, h, body))
        w.wants_body = True
        return w

    def w(m, url, h):
        return mut(responder(m, url, h))
    return w


def _submittable(sc, responder, min_conf) -> bool:
    out = asyncio.run(validate_findings(
        [dict(sc.finding)], fetch=_fetch(responder), bola_config=sc.bola_config,
        min_confidence=min_conf))
    return bool(out[0].get("submittable"))


def find_leaks(scenarios=None):
    """Return a list of (cls, scenario_name, perturbation, threshold) for every SAFE
    responder that became submittable under some (perturbation, min_confidence). An
    empty list means the gate held across the whole grid — the guarded invariant."""
    scenarios = scenarios if scenarios is not None else BENCHMARK
    leaks = []
    for sc in scenarios:
        if sc.label != "safe" or sc.cls in _WORKER_RERUN_CLASSES:
            continue
        for pname, mut in PERTURBATIONS.items():
            responder = _perturbed(sc.responder, mut)
            for mc in CONF_GRID:
                try:
                    leaked = _submittable(sc, responder, mc)
                except Exception as e:   # noqa: BLE001 — a gate crash is itself a defect
                    leaks.append((sc.cls, sc.name, pname, f"ERROR: {e}"))
                    continue
                if leaked:
                    leaks.append((sc.cls, sc.name, pname, mc))
    return leaks


def _counts(scenarios=None):
    scenarios = scenarios if scenarios is not None else BENCHMARK
    safe = [s for s in scenarios
            if s.label == "safe" and s.cls not in _WORKER_RERUN_CLASSES]
    return len(safe), len(safe) * len(PERTURBATIONS) * len(CONF_GRID)


def format_report(leaks, scenarios=None) -> str:
    n_safe, n_checks = _counts(scenarios)
    lines = [
        "VIPER gate mutation / regression harness",
        f"(each SAFE responder x {len(PERTURBATIONS)} perturbations x "
        f"{len(CONF_GRID)} thresholds must never be submittable)",
        "",
        f"safe scenarios: {n_safe}   total checks: {n_checks}",
    ]
    if not leaks:
        lines.append("")
        lines.append("PASS: no safe responder leaked under any perturbation or threshold.")
    else:
        lines.append("")
        lines.append(f"FAIL: {len(leaks)} leak(s) - a safe responder became submittable:")
        for cls, name, pert, mc in leaks:
            lines.append(f"  - [{cls}] {name}  (perturbation={pert}, min_confidence={mc})")
    return "\n".join(lines)


def main(argv=None) -> int:
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    leaks = find_leaks()
    print(format_report(leaks))
    if "--strict" in argv and leaks:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
