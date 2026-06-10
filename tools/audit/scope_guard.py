"""Strict scope guard for VIPER hunts.

Given a URL / host, return whether it's in the currently-loaded scope.
Handles HackerOne-style wildcards (``*.indriverapp.com``, ``mch*.indriverapp.com``),
explicit URL entries, and IPs/CIDRs.

Used to gate every active probe so we never hit out-of-scope hosts even
if a recon worker discovers them. **This module fails closed**: if the
scope file is missing or unparseable, ``allowed()`` returns ``False``.

CLI::

    python -m tools.audit.scope_guard check https://careers.indrive.com
    python -m tools.audit.scope_guard filter < list-of-urls.txt

Library::

    from tools.audit.scope_guard import load_scope, allowed
    sc = load_scope()  # reads scopes/current_scope.json
    if allowed("https://api-gw-cf.aws.indriverapp.com", sc):
        ...
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import sys
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCOPE = REPO_ROOT / "scopes" / "current_scope.json"

# Third-party hosting fingerprints. A `*.program.com` subdomain that
# CNAMEs to one of these is the VENDOR'S infrastructure, not the
# program's — probing it is OUT OF SCOPE even though the name matches.
# (This is the classic trap: coaching.x.com → teachable.com, status.x.com
# → statuspage.io, etc. Attacking it hits the SaaS provider, not the
# program owner.)
THIRD_PARTY_INFRA_MARKERS = (
    "teachable.com", "thinkific.com", "kajabi.com", "podia.com",
    "github.io", "herokuapp.com", "herokudns.com", "netlify.app",
    "vercel.app", "vercel-dns.com", "wpengine.com", "wordpress.com",
    "myshopify.com", "shopifydns.com", "squarespace.com", "wixdns.net",
    "zendesk.com", "freshdesk.com", "helpscoutdocs.com", "statuspage.io",
    "readme.io", "gitbook.io", "surge.sh", "pantheonsite.io",
    "unbounce.com", "hubspot.net", "pardot.com", "marketo.com",
    "bigcommerce.com", "webflow.io", "instapage.com", "launchrock.com",
    "tilda.ws", "carrd.co", "notion.site", "bubbleapps.io",
)


def _wildcard_to_regex(pattern: str) -> re.Pattern[str]:
    """Convert ``*.indriverapp.com`` or ``api-gw-cf.*.aws.indriverapp.com``
    into a case-insensitive regex anchored at host-end.

    HackerOne wildcard convention:
        - A leading wildcard ``*.example.com`` matches any subdomain depth
          (e.g. ``a.example.com``, ``a.b.example.com``).
        - A middle wildcard ``foo.*.example.com`` matches one OR more
          labels in that position (``foo.bar.example.com``,
          ``foo.bar.baz.example.com``).
        - A label-internal wildcard ``mch*.example.com`` matches a single
          label prefix only (no dots).

    The conservative choice on ambiguity is to be PERMISSIVE about
    wildcards (subdomain depth ≥ 1) so we don't accidentally exclude
    explicitly in-scope assets — the program owner used the wildcard
    deliberately. We still anchor to the suffix so we never match
    `example.com.attacker.net`.
    """
    p = pattern.strip().lower()
    if "://" in p:
        p = urlsplit(p).hostname or ""
    p = p.split("/")[0].split(":")[0]
    if not p:
        return re.compile(r"$.", re.IGNORECASE)  # never matches

    # Split on label boundaries to decide whether each `*` is
    # standalone-label (full wildcard) or label-prefix/-suffix
    # (single-label only).
    parts = p.split(".")
    out: list[str] = []
    for i, lbl in enumerate(parts):
        if i > 0:
            out.append(r"\.")
        if lbl == "*":
            # Whole-label wildcard. Anchored at first or last → unlimited
            # subdomain depth on that side. Internal → one or more labels.
            if i == 0:
                out.append(r"(?:[a-z0-9-]+\.)*[a-z0-9-]+")
            else:
                out.append(r"(?:[a-z0-9-]+\.)*[a-z0-9-]+")
        elif "*" in lbl:
            # Label-internal wildcard (mch*, *foo, m*ch) — single label only
            sub = "".join(
                r"[a-z0-9-]*" if ch == "*" else re.escape(ch) for ch in lbl
            )
            out.append(sub)
        else:
            out.append(re.escape(lbl))
    return re.compile(r"^" + "".join(out) + r"$", re.IGNORECASE)


def load_scope(path: Path = DEFAULT_SCOPE) -> dict:
    """Load scope file. Returns {} (deny-all) if missing or broken."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _host_of(target: str) -> str:
    t = target.strip()
    if "://" not in t:
        t = "http://" + t
    return (urlsplit(t).hostname or "").lower()


def _ip_in_range(host: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


def allowed(target: str, scope: dict | None = None) -> bool:
    """Return True iff ``target``'s hostname matches the scope.

    Args:
        target: a URL, hostname, or IP
        scope:  parsed scope dict (from load_scope()). If None, loads default.

    Behavior:
        - Empty / missing scope ⇒ False (fail closed)
        - Exact hostname match in `url_targets` ⇒ True
        - Wildcard match in `wildcard_patterns` ⇒ True
        - IP in any CIDR in `ip_ranges` ⇒ True
        - Otherwise False
    """
    scope = scope or load_scope()
    if not scope or not scope.get("in_scope"):
        return False

    host = _host_of(target)
    if not host:
        return False

    # 1) Explicit URL entries (strip the protocol prefix)
    for u in scope.get("url_targets", []):
        u_host = _host_of(u)
        if u_host and u_host == host:
            return True

    # 2) Wildcard patterns
    for pat in scope.get("wildcard_patterns", []):
        if _wildcard_to_regex(pat).match(host):
            return True

    # 3) IP CIDRs
    for cidr in scope.get("ip_ranges", []):
        if _ip_in_range(host, cidr):
            return True

    # 4) Plain in_scope[] entries (fall-back)
    for entry in scope.get("in_scope", []):
        asset = entry.get("asset", "").strip()
        if not asset:
            continue
        a_host = _host_of(asset)
        if a_host == host:
            return True
        if "*" in asset and _wildcard_to_regex(asset).match(host):
            return True

    return False


def reason(target: str, scope: dict | None = None) -> str:
    """Human-readable explanation of in/out-of-scope decision."""
    scope = scope or load_scope()
    if not scope:
        return "DENY: no scope file loaded"
    host = _host_of(target)
    if not host:
        return f"DENY: cannot parse host from {target!r}"
    for u in scope.get("url_targets", []):
        if _host_of(u) == host:
            return f"ALLOW: exact URL match — {u}"
    for pat in scope.get("wildcard_patterns", []):
        if _wildcard_to_regex(pat).match(host):
            return f"ALLOW: wildcard match — {pat}"
    for cidr in scope.get("ip_ranges", []):
        if _ip_in_range(host, cidr):
            return f"ALLOW: IP in {cidr}"
    return f"DENY: {host} not in scope ({len(scope.get('in_scope', []))} assets loaded)"


def filter_lines(lines: Iterable[str], scope: dict | None = None) -> list[str]:
    """Pass-through every line whose URL is in scope; drop the rest."""
    scope = scope or load_scope()
    return [ln.strip() for ln in lines if ln.strip() and allowed(ln.strip(), scope)]


def verify_owner(target: str) -> tuple[bool, str]:
    """Resolve the host; flag it if it points to third-party infra.

    A name match (`*.program.com`) is necessary but NOT sufficient — the
    subdomain must point at the program's own infrastructure. If it
    CNAMEs/resolves to a SaaS vendor, probing it attacks the vendor.

    Returns (owned_or_unknown, detail). ``False`` ⇒ third-party ⇒ deny.
    """
    host = _host_of(target)
    if not host:
        return False, "cannot parse host"
    try:
        canon = socket.getfqdn(host)
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except Exception as e:  # noqa: BLE001
        return True, f"unresolvable ({type(e).__name__}) — verify manually"

    blob = (canon + " " + " ".join(ips)).lower()
    # Also resolve PTR of each IP — third-party infra often only shows in PTR
    ptrs = []
    for ip in ips[:3]:
        try:
            ptrs.append(socket.gethostbyaddr(ip)[0].lower())
        except Exception:
            pass
    blob += " " + " ".join(ptrs)

    for marker in THIRD_PARTY_INFRA_MARKERS:
        if marker in blob:
            return False, (f"points to third-party infra ({marker}) — "
                           f"OUT OF SCOPE (attacking the vendor, not the program). "
                           f"canon={canon} ips={ips[:2]}")

    detail = f"no third-party markers — resolves to {', '.join(ips[:3])}"
    if ptrs:
        detail += f" (PTR {ptrs[0]})"
    return True, detail


# ─── CLI ────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="scope_guard")
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("check", help="check one URL/host")
    pc.add_argument("target")
    pc.add_argument("--scope", default=str(DEFAULT_SCOPE))
    pc.add_argument("--verify-owner", action="store_true",
                    help="also resolve + deny if it points to third-party infra")

    pf = sub.add_parser("filter", help="filter lines from stdin")
    pf.add_argument("--scope", default=str(DEFAULT_SCOPE))

    pl = sub.add_parser("list", help="list all in-scope assets")
    pl.add_argument("--scope", default=str(DEFAULT_SCOPE))

    args = p.parse_args(argv)
    scope = load_scope(Path(args.scope))

    if args.cmd == "check":
        ok = allowed(args.target, scope)
        print(("[OK] " if ok else "[X]  ") + args.target)
        print("  " + reason(args.target, scope))
        if ok and getattr(args, "verify_owner", False):
            owned, detail = verify_owner(args.target)
            print(("  [OWNED-OK]  " if owned else "  [3RD-PARTY] ") + detail)
            if not owned:
                return 3  # name in scope but vendor infra → deny
        return 0 if ok else 1

    if args.cmd == "filter":
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            if allowed(line, scope):
                print(line)
        return 0

    if args.cmd == "list":
        print(f"Program: {scope.get('program', '?')} ({scope.get('handle','?')})")
        print(f"Researcher: {scope.get('researcher', '?')}")
        print(f"In-scope assets: {len(scope.get('in_scope', []))}")
        for cat in ("url_targets", "wildcard_patterns", "ip_ranges"):
            items = scope.get(cat) or []
            if items:
                print(f"\n{cat} ({len(items)}):")
                for it in items[:30]:
                    print(f"  - {it}")
                if len(items) > 30:
                    print(f"  ... and {len(items)-30} more")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
