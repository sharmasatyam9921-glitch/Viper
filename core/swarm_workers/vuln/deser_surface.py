"""Insecure-deserialization SURFACE detector (CWE-502) — READ-ONLY.

Confirming a deserialization vulnerability means sending a gadget-chain payload that
EXECUTES on the target — an RCE, destructive and out of scope for an autonomous run.
So this worker never sends a payload: it only OBSERVES the normal response and flags
the magic markers of a serialized-object format crossing the trust boundary (in a
cookie, a reflected parameter, the body, or the content-type). Serialized application
objects round-tripping through the client are the classic insecure-deserialization
surface; a human then verifies exploitability with a gadget in a controlled test.

Every finding is a confidence-capped LEAD. FP-averse: the markers are format-specific
magic (Java's ``rO0AB`` base64 / ``aced0005`` hex, PHP's ``O:<n>:"Class":`` object
serialization, ``!!python/object`` YAML, node-serialize's ``_$$ND_FUNC$$_``), not
loose substrings.
"""
from __future__ import annotations

import logging
import re
from typing import List
from urllib.parse import parse_qsl, unquote, urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.deser_surface")

TECHNIQUE = "deser_surface"

# (format, compiled regex, severity-ish confidence). Each matches a serialized blob's
# UNAMBIGUOUS magic, not a generic token.
_MARKERS = [
    # Java serialization: 0xAC 0xED 0x00 0x05 -> base64 "rO0AB", or the hex bytes.
    ("java", re.compile(r"rO0AB[A-Za-z0-9+/=]{16,}"), 0.5),
    ("java", re.compile(r"\baced0005[0-9a-f]{8,}", re.I), 0.5),
    # node-serialize RCE marker (unserialize() of a function).
    ("node", re.compile(r"_\$\$ND_FUNC\$\$_"), 0.55),
    # PyYAML unsafe load / Python object tag.
    ("python-yaml", re.compile(r"!!python/(?:object|name|module)"), 0.5),
    # Python pickle opcodes (protocol 2+ base64, or reduce markers).
    ("python-pickle", re.compile(r"\bgAS[A-Za-z0-9+/=]{12,}|c__builtin__\n|ccopy_reg\n"), 0.45),
    # PHP serialized OBJECT (not a bare array): O:<len>:"<Class>":<n>:{
    ("php", re.compile(r'O:\d+:"[A-Za-z_\x80-\xff][\w\\]*":\d+:\{'), 0.45),
    # .NET ViewState blob (surface — unprotected VIEWSTATE is the deser vector).
    ("dotnet-viewstate", re.compile(r"__VIEWSTATE=[A-Za-z0-9+/%]{24,}", re.I), 0.4),
    # Ruby Marshal base64 (\x04\x08 -> "BAh").
    ("ruby-marshal", re.compile(r"\bBAh[A-Za-z0-9+/=]{12,}"), 0.4),
]

_CT_SERIALIZED = re.compile(
    r"application/(?:x-java-serialized-object|x-java-serialized|"
    r"x-python-serialize|vnd\.php\.serialized)", re.I)


def _lead(url: str, fmt: str, where: str, evidence: str, conf: float) -> dict:
    return {
        "type": "insecure_deserialization",
        "vuln_type": f"insecure_deserialization:{fmt}",
        "title": f"Insecure-deserialization surface: {fmt} serialized data in {where}",
        "severity": "medium",
        "url": url,
        "cwe": "CWE-502",
        "confidence": conf,
        "evidence": f"{fmt} serialized-object marker in {where}: {evidence[:80]}",
        # Confirming RCE needs a gadget-chain payload (destructive) — a human verifies.
        "needs_manual_verification": True,
    }


def _scan(text: str, url: str, where: str) -> List[dict]:
    if not text:
        return []
    text = text[:256 * 1024]
    out: List[dict] = []
    seen: set = set()
    for fmt, pat, conf in _MARKERS:
        if fmt in seen:
            continue
        m = pat.search(text)
        if m:
            seen.add(fmt)
            out.append(_lead(url, fmt, where, m.group(0), conf))
    return out


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)
    resp = await fetch("GET", url, timeout=timeout)
    if not resp:
        return []
    findings: List[dict] = []
    headers = resp.headers or {}

    # Content-type advertising a serialized format is itself a strong signal.
    ct = headers.get("content-type", "")
    if _CT_SERIALIZED.search(ct):
        findings.append(_lead(url, "java" if "java" in ct.lower() else "serialized",
                              "the Content-Type", ct, 0.5))

    # Reflected serialized data in the URL's own parameter values.
    for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        findings.extend(_scan(unquote(v), url, f"parameter '{k}'"))

    # Serialized tokens the server SETS on the client (cookies) — the classic
    # round-trip-through-the-client deserialization surface.
    findings.extend(_scan(headers.get("set-cookie", ""), url, "a Set-Cookie value"))
    # And in the response body (hidden ViewState field, embedded token, etc.).
    findings.extend(_scan(resp.body or "", url, "the response body"))

    uniq: dict = {}
    for f in findings:
        uniq.setdefault((f["vuln_type"], f["url"]), f)
    return list(uniq.values())[:6]


register_worker("vuln", TECHNIQUE, run)
