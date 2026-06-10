"""Phase 7 — Documentation truth.

Walks CLAUDE.md for every .py filename mention. For each, check whether
the file actually exists on disk (skipping archive/quarantine/vendored).
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Skip caches, archives, vendored trees, and any underscore-prefixed dir.
SKIP_DIRS = ("archive", "juice-shop-src", ".venv", "node_modules")


def main() -> int:
    text = (ROOT / "CLAUDE.md").read_text(encoding="utf-8", errors="replace")
    claimed = set(re.findall(r"\b([a-z][a-z0-9_]+\.py)\b", text))

    missing = []
    present = []
    for name in sorted(claimed):
        hits = []
        for h in ROOT.rglob(name):
            s = str(h).replace("\\", "/")
            if any(skip in s for skip in SKIP_DIRS):
                continue
            # Skip any underscore-prefixed directory (caches, scratch, vendored).
            if any(seg.startswith("_") for seg in s.split("/")[:-1]):
                continue
            hits.append(h)
        (present if hits else missing).append(name)

    print(f"CLAUDE.md mentions {len(claimed)} .py files")
    print(f"  present: {len(present)}")
    print(f"  missing: {len(missing)}")
    if missing:
        print()
        print("Missing:")
        for m in missing[:30]:
            print(f"  - {m}")
        if len(missing) > 30:
            print(f"  ... and {len(missing) - 30} more")

    # Module-count claims
    counts = {
        "core":     len([p for p in (ROOT / "core").rglob("*.py")
                         if "__pycache__" not in str(p)]),
        "recon":    len(list((ROOT / "recon").glob("*.py"))),
        "tools":    len(list((ROOT / "tools").rglob("*.py"))),
        "scanners": len(list((ROOT / "scanners").glob("*.py"))),
        "ai":       len(list((ROOT / "ai").glob("*.py"))),
        "agents":   len(list((ROOT / "agents").glob("*.py"))),
        "scope":    len(list((ROOT / "scope").glob("*.py"))),
    }
    print()
    print("Module counts (CLAUDE.md vs actual):")
    claims = {
        "core": "85+", "recon": "21", "tools": "14",
        "scanners": "4", "ai": "3", "agents": "6", "scope": "2"
    }
    for d, n in counts.items():
        c = claims.get(d, "?")
        try:
            cmin = int(c.rstrip("+"))
            ok = "OK " if n >= cmin else "LOW"
        except ValueError:
            ok = "  "
        print(f"  {ok} {d}/: claimed {c}, actual {n}")

    out = ROOT / "findings" / "doc-truth.md"
    out.parent.mkdir(exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        f.write(f"# Documentation truth\n\n")
        f.write(f"- mentions in CLAUDE.md: {len(claimed)} .py filenames\n")
        f.write(f"- present on disk: {len(present)}\n")
        f.write(f"- missing: {len(missing)}\n\n")
        if missing:
            f.write("## Missing files\n\n")
            for m in missing:
                f.write(f"- `{m}`\n")
        f.write("\n## Module counts\n\n")
        for d, n in counts.items():
            f.write(f"- `{d}/`: claimed `{claims.get(d, '?')}`, actual `{n}`\n")
    print(f"\nReport: {out}")
    return 0 if not missing else 1


if __name__ == "__main__":
    raise SystemExit(main())
