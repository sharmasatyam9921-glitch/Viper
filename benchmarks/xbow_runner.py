"""Run VIPER against the XBOW validation-benchmarks (a shared standard corpus).

Each XBOW benchmark is a folder with docker-compose.yml + benchmark/
benchmark-config.json (name, level, win_condition, tags, canaries). A flag is
injected at build time; solving means the vuln is exploited.

This runner brings a benchmark up via docker compose, runs a VIPER hunt against
the exposed URL, and scores TWO honest metrics:

  * detected     — VIPER confirmed a gate-passing finding whose class matches the
                   benchmark's tags. This is the bug-bounty-relevant metric:
                   find + independently confirm the vulnerability.
  * flag_captured — the injected flag string appears in a finding's evidence. This
                   is the stricter CTF metric. VIPER does READ-ONLY confirmation,
                   so it often detects without dumping the flag — we report both
                   rather than conflate "found the bug" with "captured the flag".

The Docker orchestration is gated: if the daemon is down it raises a clear error
instead of pretending. Config parsing, tag->class mapping, and scoring are pure
and unit-tested without Docker.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

# XBOW tag -> VIPER confirmed-class. Keys are normalized (hyphens/underscores
# collapsed) via _norm_tag, so "command_injection" and "command-injection" both hit.
_TAG_CLASS = {
    "xss": "xss", "reflectedxss": "xss", "storedxss": "xss", "domxss": "xss",
    "sqli": "sqli", "sqlinjection": "sqli", "blindsqli": "sqli", "nosqli": "sqli",
    "lfi": "lfi", "pathtraversal": "lfi", "fileread": "lfi", "rfi": "lfi",
    "ssti": "ssti", "templateinjection": "ssti",
    "ssrf": "ssrf", "rce": "rce", "commandinjection": "rce", "codeinjection": "rce",
    "xxe": "xxe", "idor": "idor", "bola": "idor",
    "brokenaccesscontrol": "access_control",
    "cors": "cors", "crlf": "crlf", "httpresponsesplitting": "crlf",
    "hostheaderinjection": "host_header", "secrets": "secrets",
    "informationdisclosure": "secrets", "exposure": "secrets",
    "subdomaintakeover": "subdomain_takeover", "cloud": "cloud_exposure",
}


def _norm_tag(t: str) -> str:
    return t.lower().strip().replace("-", "").replace("_", "").replace(" ", "")


@dataclass
class BenchmarkSpec:
    name: str
    level: int
    win_condition: str
    tags: List[str]
    canaries: List[str] = field(default_factory=list)
    path: str = ""

    @property
    def expected_classes(self) -> set:
        return {c for c in (_TAG_CLASS.get(_norm_tag(t)) for t in self.tags) if c}


@dataclass
class BenchmarkResult:
    name: str
    expected_classes: set
    matched_classes: set
    detected: bool
    flag_captured: bool
    error: Optional[str] = None


def load_config(bench_dir) -> BenchmarkSpec:
    """Parse <bench_dir>/benchmark/benchmark-config.json (or benchmark.json)."""
    d = Path(bench_dir)
    for rel in ("benchmark/benchmark-config.json", "benchmark.json",
                "benchmark-config.json"):
        f = d / rel
        if f.exists():
            j = json.loads(f.read_text(encoding="utf-8"))
            return BenchmarkSpec(
                name=str(j.get("name") or d.name),
                level=int(j.get("level", 0) or 0),
                win_condition=str(j.get("win_condition", "flag")),
                tags=[str(t) for t in (j.get("tags") or [])],
                canaries=[str(c) for c in (j.get("canaries") or [])],
                path=str(d))
    raise FileNotFoundError(f"no benchmark-config.json under {bench_dir}")


def score_findings(spec: BenchmarkSpec, findings: List[dict],
                   flag: str = "") -> BenchmarkResult:
    """Score CONFIRMED (submittable) findings against the benchmark's expected
    classes (detection) and the injected flag (capture)."""
    expected = spec.expected_classes
    matched = set()
    captured = False
    for f in findings or []:
        head = str(f.get("vuln_type") or f.get("type") or "").lower().split(":")[0]
        cls = _TAG_CLASS.get(_norm_tag(head), head)
        if cls in expected:
            matched.add(cls)
        blob = " ".join(str(f.get(k, "")) for k in ("evidence", "body", "poc_request",
                                                     "title"))
        if flag and flag in blob:
            captured = True
    return BenchmarkResult(
        name=spec.name, expected_classes=expected, matched_classes=matched,
        detected=bool(expected and matched), flag_captured=captured)


def _compose(bench_dir: str, *args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    # encoding/errors set explicitly: Docker emits UTF-8 (progress bars, box chars)
    # that the Windows default cp1252 decoder chokes on.
    return subprocess.run(["docker", "compose", *args], cwd=bench_dir,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)


def docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=20).returncode == 0
    except Exception:
        return False


def read_flag(bench_dir: str) -> str:
    """The XBOW flag lives in <bench_dir>/.env as FLAG="flag{...}"."""
    env = Path(bench_dir) / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.strip().startswith("FLAG"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def published_url(bench_dir: str) -> Optional[str]:
    """The app maps :80 to a random host port; find it via `compose ps`."""
    p = _compose(bench_dir, "ps", "--format", "json", timeout=30)
    for line in p.stdout.splitlines():
        try:
            j = json.loads(line)
        except Exception:
            continue
        for pub in (j.get("Publishers") or []):
            port = pub.get("PublishedPort")
            if port and pub.get("TargetPort") in (80, 8080, 3000, 5000):
                return f"http://127.0.0.1:{port}"
    # fallback: first published port
    for line in p.stdout.splitlines():
        try:
            j = json.loads(line)
        except Exception:
            continue
        for pub in (j.get("Publishers") or []):
            if pub.get("PublishedPort"):
                return f"http://127.0.0.1:{pub['PublishedPort']}"
    return None


def run_benchmark(bench_dir: str, hunt_fn: Callable, *,
                  flag: Optional[str] = None, base_url: str = "http://127.0.0.1:80",
                  bring_up: bool = True) -> BenchmarkResult:
    """Build+up the benchmark (compose reads .env for FLAG), run `hunt_fn(url,
    classes)`, score, tear down."""
    spec = load_config(bench_dir)
    if bring_up and not docker_available():
        return BenchmarkResult(spec.name, spec.expected_classes, set(), False, False,
                               error="docker daemon not running")
    flag = flag or read_flag(bench_dir) or "VIPER_BENCH_FLAG"
    try:
        if bring_up:
            b = _compose(bench_dir, "build", timeout=1200)
            if b.returncode != 0:
                return BenchmarkResult(spec.name, spec.expected_classes, set(),
                                       False, False, error=f"build failed: {b.stderr[-200:]}")
            u = _compose(bench_dir, "up", "-d", "--wait", timeout=300)
            if u.returncode != 0:
                return BenchmarkResult(spec.name, spec.expected_classes, set(),
                                       False, False, error=f"up failed: {u.stderr[-200:]}")
            base_url = published_url(bench_dir) or base_url
        findings = hunt_fn(base_url, spec.expected_classes)
        return score_findings(spec, findings, flag)
    except Exception as exc:   # noqa: BLE001
        return BenchmarkResult(spec.name, spec.expected_classes, set(), False, False,
                               error=f"{type(exc).__name__}: {exc}")
    finally:
        if bring_up:
            try:
                _compose(bench_dir, "down", "-v", timeout=120)
            except Exception:
                pass


def viper_hunt(url: str, classes: Optional[set] = None, *, oob=None,
               **_kw) -> List[dict]:
    """Discovery-strong find+confirm hunt -> gate-confirmed (submittable) findings.

    Delegates to core.lean_hunt (crawl + form/param mining -> param-aware workers
    -> gate), so the XBOW runner gets the recall fix: it probes the app's REAL
    parameter names, not just static defaults. `classes` scopes workers to the
    benchmark's declared tags for speed; `oob` wires an OOBServer for blind
    classes."""
    import asyncio

    from core.lean_hunt import hunt
    return asyncio.run(hunt(url, classes=classes, oob=oob))


def summarize(results: List[BenchmarkResult]) -> str:
    n = len(results) or 1
    det = sum(1 for r in results if r.detected)
    cap = sum(1 for r in results if r.flag_captured)
    errs = sum(1 for r in results if r.error)
    lines = [f"XBOW benchmark run: {len(results)} challenges",
             f"  detected (vuln confirmed):  {det}/{len(results)}  ({det/n:.0%})",
             f"  flag captured (full exploit): {cap}/{len(results)}  ({cap/n:.0%})",
             f"  errors / not-run:           {errs}", ""]
    for r in results:
        tag = "ERR " if r.error else ("DET " if r.detected else "miss")
        extra = f" [flag]" if r.flag_captured else ""
        lines.append(f"  {tag} {r.name[:40]:<40} {sorted(r.expected_classes)}{extra}"
                     + (f"  ({r.error})" if r.error else ""))
    return "\n".join(lines)
