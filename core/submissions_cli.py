"""`viper.py submissions [hunt_id] [--show N]` — review gate-confirmed bug drafts.

After a hunt, every SUBMITTABLE finding (independently re-confirmed by the
validation gate) is drafted to reports/submissions/<hunt_id>/. This command lets
the operator list those drafts and print one to review before submitting. VIPER
never submits on its own — this is the human review step.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

_DRAFT_ROOT = Path("reports/submissions")


def _hunts() -> List[Path]:
    if not _DRAFT_ROOT.exists():
        return []
    dirs = [d for d in _DRAFT_ROOT.iterdir() if d.is_dir()]
    return sorted(dirs, key=lambda d: d.stat().st_mtime, reverse=True)


def _title(md_path: Path) -> str:
    try:
        for line in md_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                return line.lstrip("# ").strip()
    except OSError:
        pass
    return md_path.name


def _pick(drafts: List[Path], sel: str) -> Optional[Path]:
    if sel.isdigit():
        i = int(sel) - 1
        return drafts[i] if 0 <= i < len(drafts) else None
    for f in drafts:
        if sel in f.name:
            return f
    return None


def run_submissions_cli(argv: List[str]) -> int:
    p = argparse.ArgumentParser(
        prog="viper.py submissions",
        description="List / print gate-confirmed (submittable) bug-report drafts.")
    p.add_argument("hunt_id", nargs="?",
                   help="Hunt id (omit to list hunts that have drafts).")
    p.add_argument("--show", metavar="N",
                   help="Print draft number N (or a filename substring).")
    args = p.parse_args(argv)

    if not args.hunt_id:
        hunts = _hunts()
        if not hunts:
            print("No submission drafts yet. Run a hunt — submittable findings are "
                  "drafted to reports/submissions/<hunt_id>/.")
            return 0
        print("Hunts with submission drafts:")
        for d in hunts:
            n = len(list(d.glob("*.md")))
            print(f"  {d.name}  ({n} draft{'s' if n != 1 else ''})")
        print("\nView: python viper.py submissions <hunt_id>")
        return 0

    d = _DRAFT_ROOT / args.hunt_id
    if not d.is_dir():
        print(f"[ERR] no drafts for hunt '{args.hunt_id}' (looked in {d})",
              file=sys.stderr)
        return 1
    drafts = sorted(d.glob("*.md"))
    if not drafts:
        print(f"No drafts in {d}")
        return 0

    if args.show:
        target = _pick(drafts, args.show)
        if target is None:
            print(f"[ERR] draft '{args.show}' not found in {d}", file=sys.stderr)
            return 1
        print(target.read_text(encoding="utf-8", errors="replace"))
        return 0

    print(f"{len(drafts)} submission draft(s) for {args.hunt_id} "
          "(independently re-confirmed):\n")
    for i, f in enumerate(drafts, 1):
        print(f"  [{i}] {_title(f)}")
        print(f"      {f}")
    print(f"\nReview one: python viper.py submissions {args.hunt_id} --show 1")
    return 0
