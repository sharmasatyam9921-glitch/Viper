#!/usr/bin/env python3
"""VIPER unified entrypoint.

Goal: keep existing command surfaces working while routing execution through
one implementation.

- Primary engine: skills/hackagent/viper_v2/ViperCore (hybrid tool-driven)
- Legacy engines remain available for backward compatibility.

This module provides a stable API for:
- training targets (targets.json)
- training state (skills/hackagent/training/*.json)
- reports (skills/hackagent/reports/)
- crons / old scripts calling viper_autonomous.py etc.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure repo root on sys.path when executed as a script
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

HACKAGENT_DIR = Path(__file__).resolve().parent
DEFAULT_TARGETS_FILE = HACKAGENT_DIR / "targets.json"
REPORTS_DIR = HACKAGENT_DIR / "reports"
TRAINING_DIR = HACKAGENT_DIR / "training"


def _load_targets(targets_file: Path = DEFAULT_TARGETS_FILE) -> Dict[str, Any]:
    if targets_file.exists():
        return json.loads(targets_file.read_text(encoding="utf-8"))
    return {"targets": []}


def list_training_targets(targets_file: Path = DEFAULT_TARGETS_FILE) -> List[Dict[str, Any]]:
    data = _load_targets(targets_file)
    out = []
    for t in data.get("targets", []):
        if t.get("type") == "training" and t.get("active", True):
            out.append(t)
    return out


def resolve_training_target(name_or_url: str, targets_file: Path = DEFAULT_TARGETS_FILE) -> str:
    # If it's already a URL, just return.
    if "://" in name_or_url:
        return name_or_url

    name_norm = name_or_url.strip().lower()
    for t in list_training_targets(targets_file):
        if t.get("name", "").strip().lower() == name_norm:
            return t.get("url")

    # Try substring match
    for t in list_training_targets(targets_file):
        if name_norm in t.get("name", "").strip().lower():
            return t.get("url")

    return name_or_url


async def v2_hunt(domain_or_url: str, *, quick: bool = False, skip_recon: bool = False, skip_exploit: bool = False) -> Dict[str, Any]:
    # Lazy import to keep startup fast and avoid circulars
    from skills.hackagent.viper_v2.viper_core import ViperCore as V2Core

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    v2 = V2Core()

    # v2 expects domain in many places; allow passing full URL and strip netloc.
    domain = domain_or_url
    if "://" in domain_or_url:
        try:
            from urllib.parse import urlparse

            domain = urlparse(domain_or_url).netloc
            if not domain:
                domain = domain_or_url
        except Exception:
            domain = domain_or_url

    if quick:
        return await v2.quick_scan(domain)

    return await v2.hunt(domain, skip_recon=skip_recon, skip_exploit=skip_exploit)


def _print_json(obj: Any):
    print(json.dumps(obj, indent=2, default=str))


def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="viper", description="VIPER unified entrypoint")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("targets", help="List known training targets")
    sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("hunt", help="Run VIPER hunt")
    sp.add_argument("target", help="Domain/URL or training target name")
    sp.add_argument("--quick", action="store_true")
    sp.add_argument("--skip-recon", action="store_true")
    sp.add_argument("--skip-exploit", action="store_true")

    sp = sub.add_parser("scan", help="Alias for hunt (compat)")
    sp.add_argument("target")
    sp.add_argument("--quick", action="store_true")
    sp.add_argument("--skip-recon", action="store_true")
    sp.add_argument("--skip-exploit", action="store_true")

    return p


async def _run_from_args(args: argparse.Namespace) -> int:
    if args.cmd == "targets":
        targets = list_training_targets()
        if args.json:
            _print_json(targets)
        else:
            for t in targets:
                print(f"- {t.get('name')}: {t.get('url')}")
        return 0

    if args.cmd in ("hunt", "scan"):
        target = resolve_training_target(args.target)
        res = await v2_hunt(target, quick=args.quick, skip_recon=args.skip_recon, skip_exploit=args.skip_exploit)
        _print_json(res)
        return 0 if res.get("success", True) else 2

    build_cli().print_help()
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_cli()
    args = parser.parse_args(argv)
    return asyncio.run(_run_from_args(args))


if __name__ == "__main__":
    raise SystemExit(main())
