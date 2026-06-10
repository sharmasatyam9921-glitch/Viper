"""Phase 1 — walk every CLAUDE.md module claim and verify it.

Output: findings/capability-matrix.csv with one row per claim:
    claim_path,exists,imports_clean,public_symbols,last_modified,error
"""
from __future__ import annotations

import csv
import importlib
import os
import re
import sys
import time
import traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"
OUT_CSV = REPO_ROOT / "findings" / "capability-matrix.csv"

# Top-level dirs in VIPER. Every .py underneath = a "claim" we verify
# (CLAUDE.md tree is too lossy to grep; the filesystem is the source of truth.)
SCAN_DIRS = ("core", "recon", "ai", "tools", "scanners", "agents", "scope")

SKIP_DIRS = {"__pycache__", "skill_prompts/__pycache__"}


def _enumerate_modules(root: Path) -> list[str]:
    out = []
    for d in SCAN_DIRS:
        base = root / d
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.py")):
            if any(part in SKIP_DIRS or part.startswith(".") for part in p.parts):
                continue
            # Skip CLI entry points — they call argparse + sys.exit on import.
            if p.name == "__main__.py":
                continue
            out.append(str(p.relative_to(root)).replace("\\", "/"))
    return out


def main() -> int:
    claims = _enumerate_modules(REPO_ROOT)
    if not claims:
        print(f"[!] no modules found under {REPO_ROOT}", file=sys.stderr)
        return 1

    sys.path.insert(0, str(REPO_ROOT))

    rows = []
    summary = {"total": 0, "exists": 0, "imports": 0,
               "missing": 0, "import_failed": 0}
    for rel in claims:
        summary["total"] += 1
        path = REPO_ROOT / rel
        exists = path.is_file()
        if not exists:
            summary["missing"] += 1
            rows.append({
                "claim_path": rel, "exists": False,
                "imports_clean": False, "public_symbols": 0,
                "last_modified": "", "error": "file missing",
            })
            continue
        summary["exists"] += 1

        # Last modified
        mtime = time.strftime(
            "%Y-%m-%d", time.gmtime(path.stat().st_mtime)
        )

        # Build dotted module name
        dotted = rel.replace("/", ".").removesuffix(".py")
        if dotted.endswith(".__init__"):
            dotted = dotted.removesuffix(".__init__")

        err = ""
        public = 0
        try:
            mod = importlib.import_module(dotted)
            public = sum(
                1 for n in dir(mod) if not n.startswith("_")
            )
            summary["imports"] += 1
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"[:240]
            summary["import_failed"] += 1

        rows.append({
            "claim_path": rel, "exists": True,
            "imports_clean": (err == ""), "public_symbols": public,
            "last_modified": mtime, "error": err,
        })

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f, fieldnames=["claim_path", "exists", "imports_clean",
                           "public_symbols", "last_modified", "error"])
        w.writeheader()
        w.writerows(rows)

    # Print summary
    print(f"== Capability matrix == ({summary['total']} claims)")
    print(f"  exists:        {summary['exists']}")
    print(f"  missing:       {summary['missing']}")
    print(f"  imports clean: {summary['imports']}")
    print(f"  import failed: {summary['import_failed']}")
    print()
    print("MISSING files claimed in CLAUDE.md:")
    for r in rows:
        if not r["exists"]:
            print(f"  - {r['claim_path']}")
    print()
    print("Import failures:")
    for r in rows:
        if r["exists"] and not r["imports_clean"]:
            print(f"  - {r['claim_path']}: {r['error']}")

    print(f"\nFull CSV: {OUT_CSV}")
    return 0 if summary["missing"] == 0 and summary["import_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
