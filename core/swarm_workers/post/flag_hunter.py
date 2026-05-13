"""CTF flag hunter — pattern grep against web responses + foothold artifacts.

Looks for common CTF flag formats:
    flag{...}       FLAG{...}       Flag{...}
    HTB{...}        picoCTF{...}    THM{...}       TM{...}
    CTF{...}        AKTU{...}       FLAG-...       fl4g{...}
    user.txt / root.txt contents (HackTheBox / TryHackMe convention)

Sources scanned:
  1. Baseline GET of agent.target — many web CTFs put the flag in HTML
  2. /flag, /flag.txt, /robots.txt — common direct exposure paths
  3. Any URLs in `agent.payload["findings"]` that look like file reads

Emits a SEVERITY=critical finding with `type=flag_captured` —
HackMode's CTFProfile stop_condition is wired to halt on this.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ..vuln._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.post.flag_hunter")

TECHNIQUE = "flag_hunter"

# Per-format regex. Each capturing group should contain the flag.
_FLAG_PATTERNS = [
    (re.compile(r"\b(flag|FLAG|Flag|fl4g)\{[^}\s]{3,200}\}"), "generic"),
    (re.compile(r"\bHTB\{[^}\s]{3,200}\}"), "hackthebox"),
    (re.compile(r"\bpicoCTF\{[^}\s]{3,200}\}"), "picoctf"),
    (re.compile(r"\bT[HM]M\{[^}\s]{3,200}\}"), "tryhackme"),
    (re.compile(r"\bCTF\{[^}\s]{3,200}\}"), "ctf_generic"),
    (re.compile(r"\bAKTU\{[^}\s]{3,200}\}"), "aktu"),
    # Long-form prefix-flag (some CTFs use FLAG-XXXX-XXXX-XXXX)
    (re.compile(r"\bFLAG-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4,}\b"), "prefix_dash"),
]

_PROBE_PATHS = ["/flag", "/flag.txt", "/FLAG.txt", "/.flag",
                 "/user.txt", "/root.txt", "/robots.txt",
                 "/admin/flag", "/api/flag"]


def _scan_text(text: str) -> list[tuple[str, str]]:
    """Return (flag_format, captured_flag) tuples."""
    out: list[tuple[str, str]] = []
    if not text:
        return out
    for pat, kind in _FLAG_PATTERNS:
        for m in pat.finditer(text[:512 * 1024]):
            out.append((kind, m.group(0)))
    return out


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)
    findings: list[dict] = []
    seen: set[str] = set()

    async def _check(target_url: str) -> None:
        resp = await fetch("GET", target_url, timeout=timeout)
        if not resp or not resp.ok:
            return
        for kind, flag in _scan_text(resp.body):
            if flag in seen:
                continue
            seen.add(flag)
            findings.append({
                "type": "flag_captured",
                "vuln_type": f"flag:{kind}",
                "title": flag,
                "severity": "critical",
                "url": target_url,
                "confidence": 1.0,
                "exploited": True,
                "flag_format": kind,
                "flag_value": flag,
                "evidence": f"flag pattern matched in response from {target_url}",
            })

    # Scan baseline + likely paths concurrently
    targets = [url] + [url.rstrip("/") + p for p in _PROBE_PATHS]
    await asyncio.gather(*(_check(u) for u in targets), return_exceptions=True)

    # Also scan any URLs already published by prior phases
    for f in (agent.payload or {}).get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        # Scan a finding's evidence + title in case earlier workers
        # already captured a flag-shaped string
        for kind, flag in _scan_text(
            (f.get("evidence") or "") + " " + (f.get("title") or "")
        ):
            if flag in seen:
                continue
            seen.add(flag)
            findings.append({
                "type": "flag_captured",
                "vuln_type": f"flag:{kind}",
                "title": flag,
                "severity": "critical",
                "url": f.get("url") or url,
                "confidence": 1.0,
                "exploited": True,
                "flag_format": kind,
                "flag_value": flag,
                "evidence": f"flag found in prior finding's evidence",
            })

    return findings


register_worker("post", TECHNIQUE, run)
