#!/usr/bin/env python3
"""VIPER benchmark orchestrator.

Loads a challenge suite, runs VIPER against each target in isolation, scores the
outcome, and writes an XBOW-style scorecard (overall solve rate + per-category).

Examples
--------
    # Dry-run: list what the suite would do, start nothing.
    python benchmark/run_benchmark.py --suite suite/local.json --dry-run

    # Real run, 10 min budget per challenge, JSON + Markdown scorecard.
    python benchmark/run_benchmark.py --suite suite/local.json --time 10

    # Only specific challenges, keep targets up for debugging.
    python benchmark/run_benchmark.py --suite suite/local.json \
        --only juice_sqli,juice_xss --keep-targets

The headline number printed at the end ("Solve rate: X/N = YY%") is what you
compare against a competitor's published benchmark (e.g. XBOW on
validation-benchmarks). Use the flag-mode suite for an apples-to-apples figure.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# Windows consoles default to cp1252; make decorative/Unicode output safe so a
# print can never crash the run (scorecards themselves are always UTF-8 files).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

from harness.models import Challenge, Score  # noqa: E402
from harness.runner import ViperRunner  # noqa: E402
from harness.scorer import score as score_run  # noqa: E402
from harness.targets import TargetError, TargetManager  # noqa: E402


def _load_suite(path: Path) -> tuple[dict, list[Challenge]]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        meta, raw = {}, data
    else:
        meta = {k: v for k, v in data.items() if k != "challenges"}
        raw = data.get("challenges", [])
    challenges = [Challenge.from_dict(c) for c in raw]
    return meta, challenges


def _filter(challenges: list[Challenge], only: str, skip: str) -> list[Challenge]:
    if only:
        wanted = {x.strip() for x in only.split(",") if x.strip()}
        challenges = [c for c in challenges if c.id in wanted]
    if skip:
        unwanted = {x.strip() for x in skip.split(",") if x.strip()}
        challenges = [c for c in challenges if c.id not in unwanted]
    return challenges


def _bar(label: str) -> None:
    print("\n" + "=" * 70)
    print(label)
    print("=" * 70, flush=True)


def _write_scorecard(out_dir: Path, suite_name: str, meta: dict,
                     scores: list[Score], time_minutes: int) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    total = len(scores)
    solved = sum(1 for s in scores if s.solved)
    rate = (solved / total * 100.0) if total else 0.0

    by_cat: dict[str, list[Score]] = {}
    for s in scores:
        by_cat.setdefault(s.category or "uncategorized", []).append(s)

    card = {
        "suite": suite_name,
        "suite_meta": meta,
        "generated_utc": stamp,
        "time_minutes_per_challenge": time_minutes,
        "total": total,
        "solved": solved,
        "solve_rate_pct": round(rate, 1),
        "by_category": {
            cat: {
                "solved": sum(1 for x in items if x.solved),
                "total": len(items),
            }
            for cat, items in sorted(by_cat.items())
        },
        "results": [s.to_row() for s in scores],
    }
    json_path = out_dir / f"scorecard_{stamp}.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(card, fh, indent=2)

    # Markdown twin for humans / PR pasting.
    lines = [
        f"# VIPER Benchmark Scorecard — {suite_name}",
        "",
        f"- **Generated:** {stamp} UTC",
        f"- **Budget:** {time_minutes} min/challenge",
        f"- **Solve rate:** **{solved}/{total} = {rate:.1f}%**",
        "",
        "## By category",
        "",
        "| Category | Solved | Total | Rate |",
        "| --- | --- | --- | --- |",
    ]
    for cat, items in sorted(by_cat.items()):
        cs = sum(1 for x in items if x.solved)
        ct = len(items)
        lines.append(f"| {cat} | {cs} | {ct} | {cs/ct*100:.0f}% |")
    lines += ["", "## Per challenge", "",
              "| Challenge | Cat | Mode | Solved | Time(s) | Reason |",
              "| --- | --- | --- | --- | --- | --- |"]
    for s in scores:
        mark = "✅" if s.solved else ("⏱️" if s.timed_out else "❌")
        reason = (s.reason or "").replace("|", "\\|")[:80]
        lines.append(
            f"| {s.challenge_id} | {s.category} | {s.mode} | {mark} | "
            f"{s.duration_s:.0f} | {reason} |")
    md_path = out_dir / f"scorecard_{stamp}.md"
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return json_path, md_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run the VIPER benchmark suite.")
    p.add_argument("--suite", default="suite/local.json",
                   help="Path to a suite JSON (relative to benchmark/ or absolute).")
    p.add_argument("--time", type=int, default=10,
                   help="Minutes budget per challenge (passed to viper --time).")
    p.add_argument("--only", default="", help="Comma-separated challenge ids to include.")
    p.add_argument("--skip", default="", help="Comma-separated challenge ids to exclude.")
    p.add_argument("--out", default="results", help="Output dir for scorecards.")
    p.add_argument("--python", default=sys.executable, help="Python interpreter for viper.py.")
    p.add_argument("--viper-arg", action="append", default=[],
                   help="Extra arg forwarded to viper.py (repeatable).")
    p.add_argument("--keep-targets", action="store_true",
                   help="Don't tear targets down (debugging).")
    p.add_argument("--dry-run", action="store_true",
                   help="List challenges and exit; start/run nothing.")
    p.add_argument("--mode", choices=("full", "hack"), default="full",
                   help="VIPER pipeline: 'full' (legacy ViperCore) or 'hack' "
                        "(swarm HackMode — the app-logic worker pipeline).")
    p.add_argument("--external-url", default="",
                   help="Run every challenge against this already-running URL "
                        "instead of booting a container per challenge. Avoids the "
                        "cumulative boot pressure that can starve the tail of a "
                        "multi-challenge run; you manage the target's lifecycle.")
    p.add_argument("--auth-setup", default="", metavar="FLOW",
                   help="Named auth flow to run once before hunting (e.g. 'dvwa'): "
                        "logs in and threads the session cookie into every hunt via "
                        "--cookie, so workers test the app authenticated.")
    p.add_argument("--auth-base", default="",
                   help="Base URL for --auth-setup (defaults to --external-url, "
                        "else the first challenge's target URL).")
    args = p.parse_args(argv)

    suite_path = Path(args.suite)
    if not suite_path.is_absolute():
        suite_path = HERE / suite_path
    if not suite_path.exists():
        print(f"error: suite not found: {suite_path}", file=sys.stderr)
        return 2

    meta, challenges = _load_suite(suite_path)
    challenges = _filter(challenges, args.only, args.skip)

    # Shared-target override: point every challenge at one already-running URL.
    if args.external_url:
        for c in challenges:
            c.target.type = "external"
            c.target.url = args.external_url
    if not challenges:
        print("error: no challenges selected", file=sys.stderr)
        return 2

    suite_name = meta.get("name", suite_path.stem)
    _bar(f"VIPER BENCHMARK — {suite_name}  ({len(challenges)} challenge(s))")
    for c in challenges:
        tgt = c.target.url or f"{c.target.type}:{c.target.image or c.target.compose_file}"
        print(f"  • {c.id:24s} [{c.mode:10s}] {c.category:14s} -> {tgt}")

    if args.dry_run:
        print("\n(dry run — nothing started)")
        return 0

    # Optional one-time auth flow → thread the captured session cookie into
    # every hunt so workers test the app as a logged-in user.
    extra_args = list(args.viper_arg)
    if args.auth_setup:
        from harness.dvwa import SETUPS, DvwaSetupError
        flow = SETUPS.get(args.auth_setup)
        if flow is None:
            print(f"error: unknown --auth-setup {args.auth_setup!r} "
                  f"(known: {', '.join(SETUPS)})", file=sys.stderr)
            return 2
        auth_base = args.auth_base or args.external_url or (
            challenges[0].target.url if challenges else "")
        if not auth_base:
            print("error: --auth-setup needs --auth-base or --external-url",
                  file=sys.stderr)
            return 2
        try:
            cookie = flow(auth_base)
        except DvwaSetupError as e:
            print(f"error: auth setup failed: {e}", file=sys.stderr)
            return 2
        print(f"  [auth] {args.auth_setup} logged in -> cookie threaded into hunts")
        extra_args += ["--cookie", cookie]

    runner = ViperRunner(python=args.python, time_minutes=args.time,
                         extra_args=extra_args, mode=args.mode)
    scores: list[Score] = []
    t0 = time.time()

    for i, ch in enumerate(challenges, 1):
        _bar(f"[{i}/{len(challenges)}] {ch.id} — {ch.name}")
        mgr = TargetManager(ch.target, keep=args.keep_targets)
        try:
            with mgr.manage() as url:
                run = runner.run(ch, url)
                sc = score_run(ch, run)
        except TargetError as e:
            sc = Score(challenge_id=ch.id, name=ch.name, category=ch.category,
                       mode=ch.mode, solved=False, reason=f"target error: {e}",
                       error=str(e))
            print(f"    [target] ERROR: {e}", flush=True)
        except KeyboardInterrupt:
            print("\ninterrupted — writing partial scorecard", flush=True)
            break
        mark = "SOLVED" if sc.solved else ("TIMEOUT" if sc.timed_out else "MISS")
        print(f"    => {mark}: {sc.reason}", flush=True)
        scores.append(sc)

    out_dir = Path(args.out)
    if not out_dir.is_absolute():
        out_dir = HERE / out_dir
    json_path, md_path = _write_scorecard(out_dir, suite_name, meta, scores, args.time)

    total = len(scores)
    solved = sum(1 for s in scores if s.solved)
    rate = (solved / total * 100.0) if total else 0.0
    _bar("RESULT")
    print(f"  Solve rate: {solved}/{total} = {rate:.1f}%")
    print(f"  Wall time : {(time.time()-t0)/60:.1f} min")
    print(f"  Scorecard : {json_path}")
    print(f"              {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
