#!/usr/bin/env python3
"""End-to-end self-test of the benchmark harness — no Docker, no real hunt.

What it proves, against the REAL orchestrator (run_benchmark.main):
  * TargetManager (external) health-polls a live HTTP server before scoring.
  * ViperRunner launches a subprocess, passes the right flags, parses --output JSON.
  * scorer grades vuln_class (synonym + severity gate) and flag modes correctly.
  * the scorecard writer emits JSON + Markdown with the right solve rate.

VIPER itself is swapped for stub_viper.py (same CLI contract) so the result is
deterministic: exactly 2 of 4 challenges should solve (one vuln_class hit, one
flag hit; one plain miss, one severity-gate miss).

Run:  python benchmark/_selftest/run_selftest.py
Exit: 0 on PASS, 1 on FAIL.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

import run_benchmark  # noqa: E402
import harness.runner as runner_mod  # noqa: E402
from harness.targets import _http_ok  # noqa: E402

PORT = 4055
RESULTS = HERE / "results_selftest"
EXPECT_SOLVED = 2
EXPECT_TOTAL = 4
EXPECT_SOLVED_IDS = {"selftest_sqli", "selftest_flag"}


def _start_http_server() -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(PORT)],
        cwd=str(HERE), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"http://localhost:{PORT}/"
    for _ in range(40):
        if _http_ok(url):
            return proc
        time.sleep(0.25)
    proc.terminate()
    raise RuntimeError("self-test HTTP server never came up")


def _latest_scorecard() -> dict:
    cards = sorted(RESULTS.glob("scorecard_*.json"), key=lambda p: p.stat().st_mtime)
    if not cards:
        raise RuntimeError("no scorecard was written")
    with open(cards[-1], "r", encoding="utf-8") as fh:
        return json.load(fh)


def main() -> int:
    # Swap real viper.py for the stub (build_cmd reads this module global at call time).
    stub = HERE / "stub_viper.py"
    runner_mod.VIPER_PY = stub
    print(f"[selftest] VIPER_PY patched -> {stub}")

    server = _start_http_server()
    print(f"[selftest] target up on :{PORT}")
    try:
        rc = run_benchmark.main([
            "--suite", str(HERE / "suite_external.json"),
            "--time", "1",
            "--out", str(RESULTS),
        ])
        if rc != 0:
            print(f"[selftest] FAIL: orchestrator returned {rc}")
            return 1
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except Exception:
            server.kill()
        print("[selftest] target down")

    card = _latest_scorecard()
    solved = card["solved"]
    total = card["total"]
    got_ids = {r["challenge_id"] for r in card["results"] if r["solved"]}

    print("\n[selftest] ---- assertions ----")
    ok = True

    def check(label, cond, detail=""):
        nonlocal ok
        status = "PASS" if cond else "FAIL"
        if not cond:
            ok = False
        print(f"  [{status}] {label}{(' — ' + detail) if detail else ''}")

    check(f"total == {EXPECT_TOTAL}", total == EXPECT_TOTAL, f"got {total}")
    check(f"solved == {EXPECT_SOLVED}", solved == EXPECT_SOLVED, f"got {solved}")
    check("solved ids == {selftest_sqli, selftest_flag}",
          got_ids == EXPECT_SOLVED_IDS, f"got {sorted(got_ids)}")
    check("solve_rate == 50.0", card["solve_rate_pct"] == 50.0,
          f"got {card['solve_rate_pct']}")
    check("scorecard .md exists",
          any(RESULTS.glob("scorecard_*.md")))
    # Per-challenge reason spot-checks.
    by_id = {r["challenge_id"]: r for r in card["results"]}
    check("sev_gate miss is unsolved",
          not by_id["selftest_sev_gate"]["solved"])
    check("miss is unsolved", not by_id["selftest_miss"]["solved"])

    print(f"\n[selftest] {'PASS' if ok else 'FAIL'}  "
          f"({solved}/{total} solved, rate {card['solve_rate_pct']}%)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
