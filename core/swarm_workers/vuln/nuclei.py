"""Nuclei wrapper worker.

Best-effort wrap around `scanners.nuclei_scanner.NucleiScanner` if it's
available; otherwise, runs `nuclei` directly with a fast template set.
Falls back to no-op if neither is installed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.nuclei")

TECHNIQUE = "nuclei"

# Module-level scanner cache. NucleiScanner's constructor logs "Found
# nuclei + Discovered N templates" — without caching that ran on every
# single dispatch (14 log lines per invocation, hundreds of times per
# hunt).
_SCANNER = None
_SCANNER_INIT_FAILED = False


def _get_scanner():
    global _SCANNER, _SCANNER_INIT_FAILED
    if _SCANNER is not None:
        return _SCANNER
    if _SCANNER_INIT_FAILED:
        return None
    try:
        from scanners.nuclei_scanner import NucleiScanner  # type: ignore
        _SCANNER = NucleiScanner(verbose=False)
        return _SCANNER
    except Exception as e:  # noqa: BLE001
        logger.debug("NucleiScanner unavailable: %s", e)
        _SCANNER_INIT_FAILED = True
        return None


async def _run_nuclei_subprocess(url: str, timeout: float) -> List[dict]:
    """Direct nuclei subprocess. Uses -jsonl + -silent. Streams findings."""
    if not shutil.which("nuclei"):
        return []
    cmd = [
        "nuclei", "-u", url, "-jsonl", "-silent",
        "-disable-update-check", "-stats=false",
        "-timeout", "10",
        # Limit to fast, low-noise templates
        "-severity", "low,medium,high,critical",
        "-tags", "cve,exposure,misconfig,xss,sqli,ssrf,rce,oast",
        "-rate-limit", "30",
    ]
    # Route through the typed egress gateway so the spawn is scope-checked,
    # audited, and timeout-bounded under the active hunt. With no hunt context
    # installed (tests / standalone) the gateway runs in permissive passthrough.
    from core.tool_gateway import run_subprocess
    res = await run_subprocess(cmd, scope_target=url, timeout=timeout)
    if res is None:
        logger.debug("nuclei egress scope-denied for %s", url)
        return []
    out_text = res.stdout

    findings: list[dict] = []
    for line in out_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info", {}) or {}
        sev = (info.get("severity") or "info").lower()
        name = info.get("name") or row.get("template-id") or "nuclei finding"
        findings.append({
            "type": "nuclei",
            "vuln_type": f"nuclei:{row.get('template-id', name)}",
            "title": name,
            "severity": sev,
            "url": row.get("matched-at") or url,
            "cwe": (info.get("classification") or {}).get("cwe-id"),
            "confidence": 0.85,
            "evidence": (info.get("description") or "")[:300],
            "template_id": row.get("template-id"),
        })
    return findings


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = max(min(agent.timeout_s, 90.0), 5.0)

    # Path A — NucleiScanner module if present.
    # NucleiScanner.scan is `async def` (see scanners/nuclei_scanner.py),
    # so we must await it directly. Earlier code wrapped it in
    # asyncio.to_thread, which returned an un-awaited coroutine — the
    # scan never ran and emitted "coroutine 'NucleiScanner.scan' was
    # never awaited" at GC time.
    #
    # We also cache the scanner instance at module level so we don't
    # rediscover templates + re-print 12 log lines on every dispatch.
    try:
        scanner = _get_scanner()
        if scanner is None:
            raise RuntimeError("NucleiScanner unavailable")
        result = await asyncio.wait_for(scanner.scan(url), timeout=timeout)
        # NucleiScanner returns its own shape; normalize.
        out: list[dict] = []
        for r in result.findings if hasattr(result, "findings") else (result or []):
            r = dict(r) if isinstance(r, dict) else {"raw": str(r)}
            r.setdefault("type", "nuclei")
            r.setdefault("vuln_type", f"nuclei:{r.get('template_id') or r.get('title') or 'unknown'}")
            r.setdefault("url", url)
            r.setdefault("severity", "info")
            out.append(r)
        if out:
            return out
    except Exception as e:  # noqa: BLE001
        logger.debug("NucleiScanner unavailable / failed: %s", e)

    # Path B — direct subprocess
    return await _run_nuclei_subprocess(url, timeout)


register_worker("vuln", TECHNIQUE, run)
