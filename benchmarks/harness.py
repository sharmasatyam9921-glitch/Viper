"""Run a tool against the ground-truth app and score precision/recall/time.

VIPER is run for real (its workers + the validation gate). Competitor runners
(nuclei) run only if their binary is present, else they are reported as 'not
installed' — never faked. Scoring is identical for every tool: a CONFIRMED finding
is a true positive iff its (path, class) is in GROUND_TRUTH, else a false positive.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import os
import pkgutil
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit

from .ground_truth import GROUND_TRUTH, PROBE_MAP, start_app

_CLASS_WORKER = {"xss": "xss_probe", "sqli": "sqli_probe", "lfi": "lfi",
                 "ssti": "ssti_probe", "secrets": "secrets", "cors": "cors"}
def _bench_class(head: str) -> str:
    """Map a finding's vuln_type head to the benchmark's class label."""
    h = head.split(":")[0].lower()
    if h.startswith("cors"):
        return "cors"
    if h.startswith("xss") or h == "dom_xss":
        return "xss"
    if h.startswith("sqli") or h == "auth_bypass":
        return "sqli"
    if h in ("lfi", "path_traversal"):
        return "lfi"
    if h.startswith("ssti"):
        return "ssti"
    if h in ("secret", "secrets", "env_exposed", "js_secret", "git_exposed"):
        return "secrets"
    return h


@dataclass
class Score:
    tool: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    seconds: float = 0.0
    found: list = field(default_factory=list)     # (path, class) confirmed
    missed: list = field(default_factory=list)    # (path, class) not found
    false_positives: list = field(default_factory=list)

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return 1.0 if d == 0 else self.tp / d

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return 0.0 if d == 0 else self.tp / d


def _load_workers():
    import core.swarm_workers.vuln as v
    for m in pkgutil.iter_modules(v.__path__):
        if not m.name.startswith("_"):
            importlib.import_module(f"core.swarm_workers.vuln.{m.name}")
    from core.swarm_workers import _REGISTRY
    return _REGISTRY.get("vuln", {})


class _Agent:
    def __init__(self, target):
        self.target = target
        self.timeout_s = 8.0
        self.payload = {}


def _norm(url: str, head: str):
    path = urlsplit(url).path or "/"
    return path, _bench_class(head)


def score(tool: str, confirmed: List[dict], seconds: float) -> Score:
    s = Score(tool=tool, seconds=seconds)
    truth = set(GROUND_TRUTH)
    got = set()
    for f in confirmed:
        head = str(f.get("vuln_type") or f.get("type") or "")
        path, cls = _norm(f.get("url") or f.get("target") or "", head)
        key = (path, cls)
        if key in truth:
            got.add(key)
        else:
            s.fp += 1
            s.false_positives.append(key)
    s.tp = len(got)
    s.found = sorted(got)
    s.missed = sorted(truth - got)
    s.fn = len(s.missed)
    return s


async def _run_viper(base: str) -> List[dict]:
    from core.swarm_validation import validate_findings
    workers = _load_workers()
    findings: List[dict] = []
    for path, (param, cls) in PROBE_MAP.items():
        run = workers.get(_CLASS_WORKER.get(cls, ""))
        if run is None:
            continue
        url = f"{base}{path}" + (f"?{param}=1" if param else "")
        try:
            findings += await run(_Agent(url))
        except Exception:
            pass
    out = await validate_findings(findings, default_target=base)
    return [f for f in out if f.get("submittable")]


def run_viper(base: str) -> Score:
    t0 = time.monotonic()
    confirmed = asyncio.get_event_loop().run_until_complete(_run_viper(base))
    return score("VIPER", confirmed, time.monotonic() - t0)


def _nuclei_bin() -> Optional[str]:
    for cand in (os.environ.get("NUCLEI_PATH"), shutil.which("nuclei"),
                 r"C:\tools\nuclei\nuclei.exe"):
        if cand and os.path.exists(cand):
            return cand
    return None


def run_nuclei(base: str) -> Optional[Score]:
    """Run nuclei if installed; map template tags -> class; score identically."""
    binary = _nuclei_bin()
    if not binary:
        return None
    t0 = time.monotonic()
    try:
        proc = subprocess.run([binary, "-u", base, "-silent", "-jsonl", "-duc"],
                              capture_output=True, text=True, timeout=300)
    except Exception:
        return None
    confirmed = []
    for line in proc.stdout.splitlines():
        try:
            j = json.loads(line)
        except Exception:
            continue
        tags = " ".join(j.get("info", {}).get("tags", [])) + " " + str(j.get("template-id", ""))
        tl = tags.lower()
        cls = next((c for c in ("xss", "sqli", "lfi", "ssti", "cors") if c in tl), None)
        if "exposure" in tl or "secret" in tl or ".env" in tl:
            cls = "secrets"
        if cls:
            confirmed.append({"vuln_type": cls, "url": j.get("matched-at", base)})
    return score("nuclei", confirmed, time.monotonic() - t0)


def run_all() -> List[Score]:
    srv, base = start_app()
    try:
        scores = [run_viper(base)]
        nuc = run_nuclei(base)
        scores.append(nuc if nuc else Score(tool="nuclei (not installed)"))
        return scores
    finally:
        srv.shutdown()


def format_report(scores: List[Score]) -> str:
    lines = [f"Ground-truth benchmark: {len(GROUND_TRUTH)} seeded vulns + "
             f"{len([p for p in PROBE_MAP if (p, PROBE_MAP[p][1]) not in GROUND_TRUTH])} "
             "same-class decoys",
             "",
             f"{'tool':<22} {'prec':>5} {'recall':>7} {'TP':>3} {'FP':>3} {'FN':>3} {'secs':>6}",
             "-" * 60]
    for s in scores:
        if s.tp == s.fp == s.fn == 0 and "not installed" in s.tool:
            lines.append(f"{s.tool:<22}   (skipped - binary not found)")
            continue
        lines.append(f"{s.tool:<22} {s.precision:>5.2f} {s.recall:>7.2f} "
                     f"{s.tp:>3} {s.fp:>3} {s.fn:>3} {s.seconds:>6.1f}")
        if s.false_positives:
            lines.append(f"    FALSE POSITIVES: {s.false_positives}")
        if s.missed:
            lines.append(f"    missed: {s.missed}")
    return "\n".join(lines)
