"""`viper.py bola` — focused two-account BOLA/IDOR check.

The specialist capture-then-replay workflow as one command. Identity A's session
and object URLs come from a Burp export (you browsed the target as A with Burp in
the loop) or from flags; identity B is a second session you control. VIPER replays
A's object URLs as B and confirms cross-user reads — read-only, low false-positive,
optionally routed back through Burp so you can watch every request.

Examples:
  # From two Burp exports (A browsed; B is a second account):
  python viper.py bola https://target --burp-import A.xml --burp-import-b B.xml \
      --owner-marker alice@you.io --burp

  # Sessions by cookie, object URLs from a Burp export of A's browsing:
  python viper.py bola https://target --burp-import A.xml \
      --cookie-b "session=B..." --owner-marker 12345

  # Fully manual (cookies + explicit object URLs):
  python viper.py bola https://target --cookie "session=A" --cookie-b "session=B" \
      --owner-marker alice@you.io --url https://target/api/orders/1001

Create the two accounts with the temp-mail helper (core.specialist.new_mailbox)
if the program lets you self-register; account creation / CAPTCHA stays with you.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import List, Optional
from urllib.parse import urlsplit

from core.specialist import (
    load_burp,
    object_urls,
    run_bola,
    session_headers,
)

_BURP_DEFAULT = "http://127.0.0.1:8080"


def _headers_from(cookie, bearer, header_kvs) -> dict:
    h: dict = {}
    if bearer:
        h["Authorization"] = f"Bearer {bearer.strip()}"
    if cookie:
        h["Cookie"] = cookie.strip()
    for raw in header_kvs or []:
        if ":" in raw:
            k, v = raw.split(":", 1)
            if k.strip():
                h[k.strip()] = v.strip()
    return h


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="viper.py bola",
        description="Two-account BOLA/IDOR: replay identity A's object URLs as "
                    "identity B and confirm cross-user reads (read-only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?",
                   help="Target base URL. Defines the IN-SCOPE host: replays only "
                        "go to this host (and any explicit --url host), never to "
                        "third-party hosts found in an imported Burp capture.")
    # Identity A
    p.add_argument("--burp-import", metavar="FILE",
                   help="Burp XML export captured as identity A: supplies A's "
                        "session headers AND A's object URLs.")
    p.add_argument("--cookie", help="Identity A: Cookie header (overrides Burp).")
    p.add_argument("--auth-bearer", metavar="TOKEN", help="Identity A: Bearer token.")
    p.add_argument("--auth-header", action="append", default=[], metavar="K:V",
                   help="Identity A: extra header 'Name: value' (repeatable).")
    # Identity B
    p.add_argument("--burp-import-b", metavar="FILE",
                   help="Burp XML export captured as identity B: supplies B's session.")
    p.add_argument("--cookie-b", help="Identity B: Cookie header.")
    p.add_argument("--auth-bearer-b", metavar="TOKEN", help="Identity B: Bearer token.")
    p.add_argument("--auth-header-b", action="append", default=[], metavar="K:V",
                   help="Identity B: extra header 'Name: value' (repeatable).")
    # Markers + candidate URLs
    p.add_argument("--owner-marker", action="append", default=[], metavar="STR",
                   help="A string unique to identity A's PRIVATE data (email, "
                        "user-id, ...). Repeatable. REQUIRED.")
    p.add_argument("--attacker-marker", action="append", default=[], metavar="STR",
                   help="Optional: a string unique to identity B's own data.")
    p.add_argument("--url", action="append", default=[], metavar="URL",
                   help="An object URL to test (repeatable; in addition to Burp).")
    p.add_argument("--urls-file", metavar="FILE",
                   help="File of object URLs, one per line.")
    # Routing / control
    p.add_argument("--proxy", metavar="URL",
                   help="Route every replay through this proxy (e.g. Burp).")
    p.add_argument("--burp", action="store_true",
                   help=f"Shortcut for --proxy {_BURP_DEFAULT}.")
    p.add_argument("--no-unauth-control", action="store_true",
                   help="Skip the unauthenticated control that suppresses public "
                        "objects (keep on unless the app has no anonymous access).")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="Per-request timeout seconds (default 10).")
    p.add_argument("--output", metavar="FILE", help="Write findings JSON here.")
    return p


def run_bola_cli(argv: List[str]) -> int:
    args = build_parser().parse_args(argv)

    # --- Identity A: Burp session, then flag overrides ---
    owner_headers: dict = {}
    candidates: List[str] = []
    if args.burp_import:
        items = load_burp(args.burp_import)
        owner_headers.update(session_headers(items))
        candidates.extend(object_urls(items))
        print(f"[i] identity A from {args.burp_import}: "
              f"{len(owner_headers)} session header(s), "
              f"{len(candidates)} object URL(s)", file=sys.stderr)
    owner_headers.update(_headers_from(args.cookie, args.auth_bearer, args.auth_header))

    # --- Identity B: Burp session, then flag overrides ---
    attacker_headers: dict = {}
    if args.burp_import_b:
        attacker_headers.update(session_headers(load_burp(args.burp_import_b)))
    attacker_headers.update(_headers_from(args.cookie_b, args.auth_bearer_b,
                                          args.auth_header_b))

    # --- Extra candidate URLs ---
    candidates.extend(args.url or [])
    if args.urls_file:
        try:
            with open(args.urls_file, "r", encoding="utf-8", errors="replace") as fh:
                candidates.extend(ln.strip() for ln in fh if ln.strip())
        except OSError as e:
            print(f"[ERR] cannot read --urls-file: {e}", file=sys.stderr)
            return 2

    # --- Host allowlist: operator-typed inputs ONLY (target + explicit --url).
    # The imported Burp file's hosts are NEVER trusted to define scope, so a
    # third-party request in the capture can't get identity A/B's session.
    allowed_hosts = set()
    if args.target:
        h = urlsplit(args.target).hostname
        if h:
            allowed_hosts.add(h.lower())
    for u in (args.url or []):
        h = urlsplit(u).hostname
        if h:
            allowed_hosts.add(h.lower())

    # --- Validate ---
    problems = []
    if not owner_headers:
        problems.append("no identity A session (give --burp-import / --cookie / "
                        "--auth-bearer)")
    if not attacker_headers:
        problems.append("no identity B session (give --burp-import-b / --cookie-b "
                        "/ --auth-bearer-b)")
    if not args.owner_marker:
        problems.append("no --owner-marker (>=1 string unique to identity A)")
    if not candidates:
        problems.append("no object URLs to test (give --burp-import / --url / "
                        "--urls-file)")
    if not allowed_hosts:
        problems.append("no in-scope host: give the target URL (positional) or a "
                        "--url so replays are restricted to a host you authorized")
    if problems:
        print("[ERR] cannot run BOLA:", file=sys.stderr)
        for p in problems:
            print(f"      - {p}", file=sys.stderr)
        return 2

    proxy = args.proxy or (_BURP_DEFAULT if args.burp else None)
    in_scope = [u for u in candidates if urlsplit(u).netloc.lower() in allowed_hosts]
    skipped = len(candidates) - len(in_scope)
    if skipped:
        print(f"[i] {skipped} candidate URL(s) on other hosts will NOT be replayed "
              f"(allowed: {', '.join(sorted(allowed_hosts))})", file=sys.stderr)
    print(f"[i] replaying {len(in_scope)} in-scope candidate URL(s) as identity B"
          f"{' via ' + proxy if proxy else ''} ...", file=sys.stderr)

    findings = asyncio.run(run_bola(
        owner_headers=owner_headers,
        owner_markers=args.owner_marker,
        attacker_headers=attacker_headers,
        attacker_markers=args.attacker_marker,
        candidate_urls=candidates,
        proxy=proxy,
        unauth_control=not args.no_unauth_control,
        timeout=args.timeout,
        allowed_hosts=allowed_hosts,
    ))

    print(f"\n[+] BOLA findings: {len(findings)}")
    for f in findings:
        print(f"  - {f['severity'].upper()} {f['vuln_type']}  ({f['cwe']})")
        print(f"    {f['url']}")
        print(f"    {f['evidence']}")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        print(f"[i] wrote {args.output}", file=sys.stderr)
    return 0
