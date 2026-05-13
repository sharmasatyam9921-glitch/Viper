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
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
        logger.debug("nuclei subprocess error on %s: %s", url, e)
        return []

    findings: list[dict] = []
    for line in out.decode("utf-8", errors="replace").splitlines():
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

    # Path A — NucleiScanner module if present
    try:
        from scanners.nuclei_scanner import NucleiScanner  # type: ignore
        scanner = NucleiScanner()
        result = await asyncio.wait_for(
            asyncio.to_thread(scanner.scan, url),
            timeout=timeout,
        )
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
