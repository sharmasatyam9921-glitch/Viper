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
    p.add_argument(
        "target", nargs="?", default=None,
        help="URL / hostname / IP to hack (omit when using --resume)",
    )
    p.add_argument(
        "--resume", metavar="HUNT_ID",
        help="Resume a previous hunt from its audit log. The audit.jsonl "
             "must exist under --hunts-dir/<HUNT_ID>/.",
    )
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
    p.add_argument("--auth-bearer", metavar="TOKEN",
                   help="Session Bearer token applied to every request "
                        "(tests the app as a logged-in user).")
    p.add_argument("--cookie", metavar="COOKIE",
                   help="Session Cookie header applied to every request.")
    p.add_argument("--auth-header", action="append", default=[], metavar="K:V",
                   help="Extra auth header 'Name: value' (repeatable).")
    p.add_argument("--proxy", metavar="URL",
                   help="Route every worker request through this proxy so you can "
                        "watch/intercept the hunt in Burp Suite or ZAP. HTTPS is "
                        "MITM-intercepted (cert verification is already off).")
    p.add_argument("--burp", action="store_true",
                   help="Shortcut for --proxy http://127.0.0.1:8080 (Burp default).")

    # --- Two-account BOLA / IDOR (specialist) -----------------------------
    # Identity A is the primary session above (--cookie / --auth-bearer /
    # --auth-header). Supply a SECOND identity B + identity-A's private markers
    # to activate the bola_multi worker: it replays A's object URLs as B and
    # confirms cross-user reads. Read-only; opt-in; needs two accounts you own.
    bola = p.add_argument_group(
        "two-account BOLA/IDOR (specialist)",
        "Provide a second identity (B) + identity-A markers to test broken "
        "object-level authorization - the #1 bug-bounty class a single-session "
        "scanner cannot find. Identity A = the primary session flags above.",
    )
    bola.add_argument("--cookie-b", metavar="COOKIE",
                      help="Second identity (B): Cookie header.")
    bola.add_argument("--auth-bearer-b", metavar="TOKEN",
                      help="Second identity (B): Bearer token.")
    bola.add_argument("--auth-header-b", action="append", default=[], metavar="K:V",
                      help="Second identity (B): extra header 'Name: value' "
                           "(repeatable).")
    bola.add_argument("--owner-marker", action="append", default=[], metavar="STR",
                      help="A string unique to identity A's PRIVATE data (email, "
                           "user-id, account number). Repeatable. Required to "
                           "activate BOLA: a finding fires only when B's response "
                           "still contains one of A's markers.")
    bola.add_argument("--attacker-marker", action="append", default=[], metavar="STR",
                      help="Optional: a string unique to identity B's own data "
                           "(used to distinguish 'B sees only his own' from a "
                           "real leak). Repeatable.")
    bola.add_argument("--bola-no-unauth-control", action="store_true",
                      help="Skip the unauthenticated control request that "
                           "suppresses public objects (keep it on unless the "
                           "app has no anonymous access at all).")
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
    p.add_argument("--log-level", default=None,
                   help="Log level: DEBUG/INFO/WARNING/ERROR (default: config)")
    p.add_argument("--log-json", action="store_true",
                   help="Emit structured JSON logs (for shippers/files)")
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

    # 0. Config + structured logging (single bootstrap for the hunt process).
    from .config import get_config
    from .logging_setup import bind_hunt_id, configure_logging
    cfg = get_config()
    configure_logging(
        level=args.log_level or cfg.log_level,
        json_output=args.log_json or cfg.log_json,
    )

    # 1. Preflight
    if args.resume:
        # When resuming, target is recovered from the audit log
        if args.target:
            print(
                "[WARN] --resume ignores positional target; using the "
                "target recorded in the audit log.",
                file=sys.stderr,
            )
    else:
        if not args.target or not args.target.strip():
            print("[ERR] target is required (or pass --resume HUNT_ID)",
                  file=sys.stderr)
            return 1
    if args.scope and not Path(args.scope).exists():
        print(f"[ERR] scope file not found: {args.scope}", file=sys.stderr)
        return 1

    # 2. Build profile (skipped for --resume — recovered from audit log)
    if args.resume:
        profile = None  # HackMode.resume() will recover it
    else:
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
        # Apply CLI overrides on a fresh profile
        if args.time is not None:
            profile.time_budget_s = args.time * 60.0
        if args.workers is not None:
            profile.max_concurrent = max(1, args.workers)

    # 3. Build collaborators
    narrator = Narrator(quiet=args.quiet, use_color=not args.no_color)

    # Session auth (operator-supplied) — applied to every worker request so the
    # hunt tests the app authenticated, where IDOR/BOLA/business-logic live.
    auth_headers: dict[str, str] = {}
    if args.auth_bearer:
        auth_headers["Authorization"] = f"Bearer {args.auth_bearer.strip()}"
    if args.cookie:
        auth_headers["Cookie"] = args.cookie.strip()
    for raw in (args.auth_header or []):
        if ":" in raw:
            k, v = raw.split(":", 1)
            if k.strip():
                auth_headers[k.strip()] = v.strip()

    # Two-account BOLA/IDOR config (opt-in). Identity A = auth_headers above;
    # identity B = the *-b flags. Only activated when BOTH a B session and
    # identity-A markers are present — otherwise the worker self-gates off.
    bola_config = _build_bola_config(args, auth_headers)

    # Optional intercepting proxy (Burp/ZAP) for the whole hunt.
    proxy = args.proxy or ("http://127.0.0.1:8080" if args.burp else None)
    if proxy and not args.quiet:
        print(f"[i] routing all worker traffic through {proxy} "
              "(watch it in Burp/ZAP)", file=sys.stderr)

    scope_reasoner: Optional[ScopeReasoner] = None
    # Resume path doesn't yet know `profile`, so always build the reasoner
    # if a scope file was provided
    need_scope = args.scope is not None or (
        profile is not None and profile.use_scope_reasoner
    )
    if need_scope:
        try:
            if args.scope:
                scope_reasoner = _build_scope_reasoner(args.scope, args.db_path)
            elif args.target:
                # Scope-aware profile but no scope file: auto-scope to the
                # target's own domain so the fail-closed worker gate permits the
                # intended target (+subdomains) and denies everything else.
                scope_reasoner = _auto_scope_reasoner(args.target, args.db_path)
                if not args.quiet:
                    print(
                        f"[i] no --scope given — auto-scoped to {args.target} "
                        f"(+subdomains); off-scope hosts are blocked.",
                        file=sys.stderr,
                    )
        except Exception as e:  # noqa: BLE001
            print(f"[WARN] scope reasoner unavailable: {e}", file=sys.stderr)

    # 4. Run — resume or fresh
    if args.resume:
        try:
            hm = HackMode.resume(
                args.resume,
                hunts_dir=Path(args.hunts_dir),
                db_path=Path(args.db_path),
                narrator=narrator,
                scope_reasoner=scope_reasoner,
            )
        except FileNotFoundError as e:
            print(f"[ERR] {e}", file=sys.stderr)
            return 1
        except Exception as e:  # noqa: BLE001
            print(f"[ERR] resume failed: {e}", file=sys.stderr)
            return 1
        # CLI overrides on the resumed profile
        if args.time is not None:
            hm.profile.time_budget_s = args.time * 60.0
        if args.workers is not None:
            hm.profile.max_concurrent = max(1, args.workers)
        hm._proxy = proxy  # route the resumed hunt through Burp/ZAP too
        audit = hm.audit
    else:
        audit = AuditLogger.for_hunt(
            args.target,
            hunts_dir=Path(args.hunts_dir),
            db_path=Path(args.db_path),
        )
        hm = HackMode(
            target=args.target,
            profile=profile,
            narrator=narrator,
            audit=audit,
            scope_reasoner=scope_reasoner,
            auth_headers=auth_headers or None,
            bola_config=bola_config,
            proxy=proxy,
        )
    try:
        with bind_hunt_id(audit.hunt_id):
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


def _parse_headers(cookie: Optional[str], bearer: Optional[str],
                   raw_headers: list[str]) -> dict[str, str]:
    """Build an auth-header dict from cookie / bearer / 'K: V' flags."""
    h: dict[str, str] = {}
    if bearer:
        h["Authorization"] = f"Bearer {bearer.strip()}"
    if cookie:
        h["Cookie"] = cookie.strip()
    for raw in (raw_headers or []):
        if ":" in raw:
            k, v = raw.split(":", 1)
            if k.strip():
                h[k.strip()] = v.strip()
    return h


def _build_bola_config(args, owner_headers: dict) -> Optional[dict]:
    """Assemble the two-account BOLA config, or None if not (fully) requested.

    Activates only when the operator supplied a SECOND identity (B) *and*
    identity-A markers. Partial config prints a guidance warning and disables
    BOLA (the worker would self-gate off anyway) so a half-wired run is loud,
    not silently inert.
    """
    attacker_headers = _parse_headers(
        getattr(args, "cookie_b", None),
        getattr(args, "auth_bearer_b", None),
        getattr(args, "auth_header_b", []) or [],
    )
    markers = [m.strip() for m in (getattr(args, "owner_marker", []) or [])
               if m and m.strip()]
    requested = bool(attacker_headers or markers)
    if not requested:
        return None  # BOLA not asked for — stay quiet on normal hunts.

    problems: list[str] = []
    if not owner_headers:
        problems.append("identity A is unauthenticated — give --cookie / "
                        "--auth-bearer / --auth-header for the victim account")
    if not attacker_headers:
        problems.append("no identity B — give --cookie-b / --auth-bearer-b / "
                        "--auth-header-b for the second account")
    if not markers:
        problems.append("no --owner-marker — supply ≥1 string unique to "
                        "identity A's private data (email, user-id, account #)")
    if problems:
        print("[WARN] BOLA/IDOR testing requested but not fully configured; "
              "it will NOT run:", file=sys.stderr)
        for pr in problems:
            print(f"        - {pr}", file=sys.stderr)
        return None

    print(f"[i] two-account BOLA/IDOR armed: identity A ({len(owner_headers)} "
          f"header(s), {len(markers)} marker(s)) vs identity B "
          f"({len(attacker_headers)} header(s)).", file=sys.stderr)
    return {
        "owner_name": "A",
        "owner_headers": dict(owner_headers),
        "owner_markers": markers,
        "attacker_name": "B",
        "attacker_headers": attacker_headers,
        "attacker_markers": [m.strip() for m in
                             (getattr(args, "attacker_marker", []) or [])
                             if m and m.strip()],
        "unauth_control": not getattr(args, "bola_no_unauth_control", False),
    }


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


def _auto_scope_reasoner(target: str, db_path: str) -> ScopeReasoner:
    """Build a reasoner scoped to the target's own domain (+ subdomains).

    Used when a scope-aware profile runs without an explicit --scope file:
    rather than denying everything (unusable) or allowing everything (unsafe),
    permit exactly the target and its subdomains and deny all else.
    """
    from urllib.parse import urlparse

    from scope.scope_manager import BugBountyScope, ScopeEntry, ScopeManager

    host = target.strip()
    if "://" in host:
        host = urlparse(host).hostname or host
    host = host.split("/", 1)[0].split(":", 1)[0].strip().rstrip(".")

    sm = ScopeManager(verbose=False)
    scope = BugBountyScope(program_name=f"auto:{host}")
    # A 'domain' entry matches the host and all of its subdomains.
    scope.in_scope.append(ScopeEntry(target=host, asset_type="domain"))
    sm.active_scope = scope
    return ScopeReasoner(scope_manager=sm, db_path=Path(db_path))


if __name__ == "__main__":
    sys.exit(run_hack_cli(sys.argv[1:]))
