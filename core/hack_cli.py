"""argparse handler for `python viper.py hack <target>`.

Kept in its own module so the main `viper.py` shim stays one line. Wires
flags → `core.hack_mode.HackMode` and prints a clean summary on exit.

Exit codes (match plan):
    0  clean run
    1  preflight failure (no target, scope file missing, network)
    2  guardrail blocked
    3  approval denied
    4  scan error
    5  time budget exhausted
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from .audit_logger import AuditLogger
from .hack_mode import HackMode
from .hack_profile import detect_profile
from .narrator import Narrator
from .scope_reasoner import ScopeReasoner

logger = logging.getLogger("viper.hack_cli")


# ----- argparse spec --------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="viper.py hack",
        description=(
            "Autonomous pentest. One command: VIPER fans out workers across "
            "every phase, shares findings on a bus, narrates progress in "
            "plain English."
        ),
        epilog=(
            "Examples:\n"
            "  python viper.py hack example.com           # bug bounty scout\n"
            "  python viper.py hack 10.10.10.5 --go       # owned lab box, full chain\n"
            "  python viper.py hack box.htb               # CTF (auto-detected)\n"
            "  python viper.py hack example.com --scope p.json --go\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", help="URL / hostname / IP to hack")
    p.add_argument(
        "--go", action="store_true",
        help="Enable destructive workers (exploit + privesc + lateral). "
             "Approval gate fires per action. OFF by default.",
    )
    p.add_argument(
        "--profile", choices=("ctf", "bugbounty", "lab"),
        help="Force a profile. Default: auto-detect.",
    )
    p.add_argument("--scope", help="Bug-bounty scope JSON file path")
    p.add_argument(
        "--time", type=int, default=None,
        help="Total time budget in minutes (default: depends on profile)",
    )
    p.add_argument(
        "--workers", type=int, default=None,
        help="Max concurrent workers per swarm (default: 12)",
    )
    p.add_argument("--quiet", action="store_true",
                   help="Suppress terminal narration")
    p.add_argument("--no-dashboard", action="store_true",
                   help="Don't auto-launch the dashboard")
    p.add_argument(
        "--report", choices=("html", "md", "json"), default="json",
        help="Report format on completion (default: json)",
    )
    p.add_argument(
        "--output",
        help="Optional path to write summary JSON. Default: state/hunts/<id>/summary.json",
    )
    p.add_argument(
        "--hunts-dir", default="state/hunts",
        help="Where to put audit.jsonl + summary files",
    )
    p.add_argument(
        "--db-path", default="data/viper.db",
        help="SQLite DB path for the audit_log mirror",
    )
    p.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colors in terminal output",
    )
    return p


# ----- Entry point ----------------------------------------------------------


def run_hack_cli(argv: list[str]) -> int:
    """Parse `argv` (already stripped of the leading "hack"), run, return exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # 1. Preflight
    if not args.target or not args.target.strip():
        print("[ERR] target is required", file=sys.stderr)
        return 1
    if args.scope and not Path(args.scope).exists():
        print(f"[ERR] scope file not found: {args.scope}", file=sys.stderr)
        return 1

    # 2. Build profile
    try:
        profile = detect_profile(
            args.target,
            scope_file=args.scope,
            explicit=args.profile,
            go=args.go,
        )
    except ValueError as e:
        print(f"[ERR] profile selection: {e}", file=sys.stderr)
        return 1

    # Apply CLI overrides
    if args.time is not None:
        profile.time_budget_s = args.time * 60.0
    if args.workers is not None:
        profile.max_concurrent = max(1, args.workers)

    # 3. Build collaborators
    audit = AuditLogger.for_hunt(
        args.target,
        hunts_dir=Path(args.hunts_dir),
        db_path=Path(args.db_path),
    )
    narrator = Narrator(quiet=args.quiet, use_color=not args.no_color)

    scope_reasoner: Optional[ScopeReasoner] = None
    if profile.use_scope_reasoner:
        try:
            scope_reasoner = _build_scope_reasoner(args.scope, args.db_path)
        except Exception as e:  # noqa: BLE001
            print(f"[WARN] scope reasoner unavailable: {e}", file=sys.stderr)

    # 4. Run
    hm = HackMode(
        target=args.target,
        profile=profile,
        narrator=narrator,
        audit=audit,
        scope_reasoner=scope_reasoner,
    )
    try:
        result = asyncio.run(hm.run())
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] hack cancelled by user", file=sys.stderr)
        audit.event("hunt.completed", outcome="interrupted")
        audit.close()
        return 130
    except Exception as e:  # noqa: BLE001
        logger.exception("hack failed")
        print(f"[ERR] scan error: {e!r}", file=sys.stderr)
        audit.event("error", outcome="failure", payload={"error": repr(e)})
        audit.close()
        return 4

    # 5. Write summary
    summary_path = (
        Path(args.output)
        if args.output
        else Path(args.hunts_dir) / result.hunt_id / "summary.json"
    )
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(result.to_dict(), indent=2, default=str),
        encoding="utf-8",
    )
    print(f"\n[+] hunt_id:    {result.hunt_id}")
    print(f"[+] audit:      {result.audit_path}")
    print(f"[+] summary:    {summary_path}")
    print(f"[+] findings:   {result.findings_count}")
    print(f"[+] iterations: {result.iterations}")
    print(f"[+] stop:       {result.stop_reason}")
    audit.close()

    # Exit code semantics
    if result.timed_out:
        return 5
    return 0


# ----- Helpers --------------------------------------------------------------


def _build_scope_reasoner(scope_file: Optional[str], db_path: str) -> Optional[ScopeReasoner]:
    """Wrap a ScopeManager around the scope file (if provided) and build a
    reasoner. If no scope file, returns a reasoner with no manager —
    decisions fall back to default-deny."""
    from scope.scope_manager import ScopeManager
    sm = ScopeManager(verbose=False)
    if scope_file:
        ok = sm.load_scope(scope_file)
        if not ok:
            print(f"[WARN] failed to load scope file: {scope_file}", file=sys.stderr)
            return None
    return ScopeReasoner(scope_manager=sm, db_path=Path(db_path))


if __name__ == "__main__":
    sys.exit(run_hack_cli(sys.argv[1:]))
