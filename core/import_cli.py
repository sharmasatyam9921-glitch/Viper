"""`viper.py import <file.har|collection.json> [--host HOST]`

Inspect an operator's HAR / Postman export before folding it into a hunt: what endpoints,
parameter names, and (name-only) request headers it carries. Read-only — the VALUES of
auth headers and cookies are never read, shown, or persisted. With --host, previews the
in-scope subset a hunt would actually use.
"""
from __future__ import annotations

from collections import Counter
from urllib.parse import urlsplit

from core.har_import import _norm_host, load_surface_file


def _usage() -> int:
    print("usage: viper.py import <file.har|postman_collection.json> [--host HOST]")
    print("  Inspect the endpoints/params an operator export would add to a hunt.")
    print("  --host HOST   preview only the endpoints on HOST (scope filter)")
    return 1


def run_import_cli(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        return _usage()
    path = argv[0]
    host = None
    rest = argv[1:]
    i = 0
    while i < len(rest):
        if rest[i] == "--host" and i + 1 < len(rest):
            host = rest[i + 1]
            i += 2
        else:
            print(f"unknown argument: {rest[i]}")
            return _usage()
    try:
        kind, surf = load_surface_file(path)
    except FileNotFoundError:
        print(f"file not found: {path}")
        return 2
    except ValueError as exc:
        print(f"could not parse {path}: {exc}")
        return 2

    print(f"Parsed {kind.upper()} export: {path}")
    print(f"  endpoints: {len(surf.endpoints)}   params: {len(surf.params)}   "
          f"header names: {len(surf.header_names)}")

    host_counts = Counter(_norm_host(urlsplit(u).netloc) for u in surf.endpoints)
    if host_counts:
        print("  hosts:")
        for h, n in host_counts.most_common(20):
            print(f"    {n:>4}  {h}")

    if host:
        scoped = surf.scoped(host)
        print(f"\nIn scope for {host}: {len(scoped.endpoints)} endpoint(s), "
              f"{len(scoped.params)} param(s)")
        for u in scoped.endpoints[:40]:
            print(f"    {u}")
        if len(scoped.endpoints) > 40:
            print(f"    ... (+{len(scoped.endpoints) - 40} more)")

    if surf.params:
        shown = sorted(surf.params)[:60]
        print(f"\n  param names: {', '.join(shown)}"
              + (f" ... (+{len(surf.params) - 60})" if len(surf.params) > 60 else ""))
    if surf.header_names:
        print(f"  request header names (values NOT read): "
              f"{', '.join(sorted(surf.header_names)[:40])}")
    print("\nFeed this into a hunt with HackMode(profile.import_file=<this file>); "
          "endpoints/params are scoped to the target host, auth values are never imported.")
    return 0
