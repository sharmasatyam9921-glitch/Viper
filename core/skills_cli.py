"""`viper.py skills` — inspect the lazy skill catalog.

    viper.py skills                       # catalog stats
    viper.py skills stats
    viper.py skills search <query>        # free-text search (id/name/tags/CWE)
    viper.py skills show <id>             # render one skill's full body
    viper.py skills select --phase exploitation --technique idor --intent "web idor"
"""
from __future__ import annotations

import argparse
from typing import List


def _print_skill_line(s) -> None:
    tags = ",".join(s.tags[:6])
    print(f"  {s.id:<22} [{s.severity:<8}] {s.name[:54]}")
    if tags:
        print(f"      tags: {tags}")


def run_skills_cli(argv: List[str]) -> int:
    from core.skill_catalog import default_registry, mitre_available

    p = argparse.ArgumentParser(prog="viper.py skills",
                                description="Inspect the lazy skill catalog")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("stats", help="catalog statistics")
    sp = sub.add_parser("search", help="free-text search")
    sp.add_argument("query", nargs="+")
    sp.add_argument("--limit", type=int, default=15)
    sh = sub.add_parser("show", help="render one skill body")
    sh.add_argument("skill_id")
    se = sub.add_parser("select", help="relevance-rank skills for a context")
    se.add_argument("--phase")
    se.add_argument("--technique")
    se.add_argument("--intent", default="")
    se.add_argument("--cwe")
    se.add_argument("--limit", type=int, default=5)
    se.add_argument("--render", action="store_true",
                    help="also print the rendered prompt block")
    pi = sub.add_parser("import", help="absorb an external Agent-Skills (SKILL.md) dir")
    pi.add_argument("directory")
    pt = sub.add_parser("tools", help="tools the catalog knows / who uses one")
    pt.add_argument("tool", nargs="?")

    args = p.parse_args(argv)

    if args.cmd == "import":
        from core.skill_import import import_skill_directory
        n, ntools = import_skill_directory(args.directory)
        if not n:
            print(f"no SKILL.md files found under {args.directory!r}")
            return 1
        print(f"absorbed {n} skill(s); learned {ntools} distinct tool(s).")
        print("rebuild the catalog (next run) picks them up automatically; "
              "try: viper.py skills tools")
        return 0

    reg = default_registry()

    if args.cmd == "tools":
        from core.skill_catalog import tool_index
        idx = tool_index(reg)
        if args.tool:
            users = idx.get(args.tool, [])
            print(f"{len(users)} skill(s) use {args.tool!r}:")
            for sid in users[:30]:
                print(f"  {sid}")
            if users:
                print("\n(each skill body shows the exact commands; "
                      f"viper.py skills show {users[0]})")
            return 0 if users else 1
        print(f"{len(idx)} tool(s) the catalog knows how to use:")
        for t, users in sorted(idx.items(), key=lambda kv: -len(kv[1]))[:40]:
            print(f"  {t:<22} ({len(users)} skill(s))")
        return 0

    if args.cmd in (None, "stats"):
        st = reg.stats()
        print("VIPER skill catalog")
        print(f"  total indexed skills: {st['total']}")
        for src, n in sorted(st["by_source"].items()):
            print(f"    {src:<10} {n}")
        print(f"  vendored MITRE DB available: {mitre_available()}")
        print("  bodies are loaded lazily; only selected skills are rendered.")
        return 0

    if args.cmd == "search":
        q = " ".join(args.query)
        hits = reg.search(q, limit=args.limit)
        print(f"{len(hits)} match(es) for {q!r}:")
        for s in hits:
            _print_skill_line(s)
        return 0

    if args.cmd == "show":
        s = reg.get(args.skill_id)
        if not s:
            print(f"no such skill: {args.skill_id}")
            return 1
        print(f"# {s.id}  ({s.source}, severity={s.severity})")
        print(f"name: {s.name}")
        if s.cwe:
            print(f"cwe: {', '.join(s.cwe)}")
        if s.attack:
            print(f"att&ck: {', '.join(s.attack)}")
        print("-" * 60)
        print(s.body() or s.summary or "(no body)")
        return 0

    if args.cmd == "select":
        sel = reg.select(phase=args.phase, technique=args.technique,
                         intent=args.intent, cwe=args.cwe, limit=args.limit)
        print(f"{len(sel)} selected skill(s):")
        for s in sel:
            _print_skill_line(s)
        if args.render:
            print("-" * 60)
            print(reg.render(sel))
        return 0

    p.print_help()
    return 0
