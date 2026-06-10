#!/usr/bin/env python3
"""Generate a flag-mode benchmark suite from an XBOW validation-benchmarks clone.

XBOW publishes ~104 dockerized web-security challenges with ground-truth flags at
https://github.com/xbow-engineering/validation-benchmarks . Their reported solve
rate (~75-77%) is measured against this set, so running VIPER over the same set in
flag mode yields a directly comparable number.

This script walks a local clone and emits a suite JSON the harness can run. It is
dependency-free (no pyyaml): benchmark metadata is read from each challenge's
benchmark.json, and the host port is sniffed from docker-compose.yml with a light
regex (good enough for the common `ports: ["HOST:CONT"]` shape).

Usage
-----
    git clone https://github.com/xbow-engineering/validation-benchmarks
    python benchmark/suite/xbow/gen_xbow_suite.py \
        --root /path/to/validation-benchmarks \
        --out  benchmark/suite/xbow/xbow_generated.json

    python benchmark/run_benchmark.py --suite suite/xbow/xbow_generated.json --time 15

Assumptions (verify against your clone, adjust if the layout differs):
  * Challenges live in <root>/benchmarks/<ID>/ each with benchmark.json + docker-compose.yml.
  * The flag is a random token of the form FLAG{...}; we match by regex unless the
    benchmark pins an exact flag string.
  * Each challenge exposes one HTTP port; the first host port found in the compose
    file is used as http://localhost:<port>.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PORTS_RE = re.compile(r'(?:-\s*["\']?|["\'])(\d{2,5}):(\d{2,5})', re.MULTILINE)
FLAG_DEFAULT_REGEX = r"FLAG\{[^}]+\}"


def _read_json(path: Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _host_port(compose_path: Path) -> int | None:
    if not compose_path.exists():
        return None
    try:
        text = compose_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None
    m = PORTS_RE.search(text)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def _challenge_dirs(root: Path) -> list[Path]:
    base = root / "benchmarks"
    if not base.is_dir():
        base = root  # tolerate a flatter layout
    dirs = []
    for d in sorted(base.iterdir()):
        if d.is_dir() and (d / "benchmark.json").exists():
            dirs.append(d)
    return dirs


def build(root: Path, default_port: int) -> dict:
    challenges = []
    for d in _challenge_dirs(root):
        meta = _read_json(d / "benchmark.json")
        cid = d.name
        name = meta.get("name") or meta.get("title") or cid
        tags = meta.get("tags") or []
        category = (tags[0] if tags else meta.get("category", "web")) or "web"
        difficulty = str(meta.get("level") or meta.get("difficulty") or "")

        compose = d / "docker-compose.yml"
        if not compose.exists():
            compose = d / "docker-compose.yaml"
        port = _host_port(compose) or default_port

        # Prefer an exact flag if the benchmark pins one; else match the format.
        flag = meta.get("flag") or ""
        flag_regex = "" if flag else (meta.get("flag_format") or FLAG_DEFAULT_REGEX)

        challenges.append({
            "id": cid,
            "name": name,
            "category": str(category),
            "difficulty": difficulty,
            "mode": "flag",
            "target": {
                "type": "docker_compose",
                "compose_dir": str(d),
                "compose_file": str(compose),
                "url": f"http://localhost:{port}",
                "health_path": "/",
                "health_timeout": 180
            },
            "flag": flag,
            "flag_regex": flag_regex,
            "tags": [str(t) for t in tags]
        })

    return {
        "name": "xbow-validation-benchmarks",
        "description": ("Flag-mode suite generated from an XBOW validation-benchmarks "
                        "clone. Solve rate here is comparable to XBOW's published number."),
        "source": "https://github.com/xbow-engineering/validation-benchmarks",
        "challenges": challenges,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--root", required=True, help="Path to validation-benchmarks clone.")
    p.add_argument("--out", required=True, help="Output suite JSON path.")
    p.add_argument("--default-port", type=int, default=80,
                   help="Fallback host port when none is found in compose (default 80).")
    args = p.parse_args(argv)

    root = Path(args.root).expanduser().resolve()
    if not root.exists():
        print(f"error: root not found: {root}")
        return 2

    suite = build(root, args.default_port)
    n = len(suite["challenges"])
    if n == 0:
        print(f"error: no challenges found under {root} "
              "(expected <root>/benchmarks/<ID>/benchmark.json)")
        return 1

    out = Path(args.out).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(suite, fh, indent=2)
    print(f"wrote {n} challenge(s) -> {out}")
    print("next: python benchmark/run_benchmark.py "
          f"--suite {out} --time 15")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
