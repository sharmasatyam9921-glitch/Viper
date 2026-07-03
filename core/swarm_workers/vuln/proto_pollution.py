"""Client-side prototype-pollution gadget scanner (CWE-1321) — READ-ONLY.

Server-side prototype pollution can only be *confirmed* by polluting the target's
global ``Object.prototype`` (via a behavioural gadget like ``json spaces`` / a status
override), which changes behaviour for EVERY user of the process — a destructive,
service-affecting action VIPER does not perform. So this worker stays entirely
read-only: it statically analyses the target's JavaScript for the two halves of a
DOM prototype-pollution gadget — a user-controlled SOURCE (URL / hash / postMessage
parsed into an object) reaching a prototype-touching SINK (a recursive merge/extend,
or an explicit ``__proto__`` write) — and flags known-vulnerable merge libraries.

Because confirming client-side pollution needs a real browser/DOM (out of scope for
a static HTTP worker), every finding is a confidence-capped LEAD for manual review,
never an auto-submitted claim. FP-averse by construction: a lead requires a rare
prototype-reaching sink to CO-OCCUR with a user-input source in the same script (a
bare ``location.hash`` or a bare ``Object.assign`` alone is never enough), or a
positively version-matched vulnerable library.
"""
from __future__ import annotations

import logging
import re
from typing import List, Optional
from urllib.parse import urljoin, urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.proto_pollution")

TECHNIQUE = "prototype_pollution"

# User-controlled SOURCES: input a page attacker can influence, turned into object
# keys/values. Each is a real "attacker controls structured input" signal.
_SOURCES = [
    ("location", re.compile(r"\blocation\s*\.\s*(?:hash|search|href)", re.I)),
    ("document_url", re.compile(r"\bdocument\s*\.\s*(?:URL|documentURI|referrer)", re.I)),
    ("window_name", re.compile(r"\bwindow\s*\.\s*name\b", re.I)),
    ("urlsearchparams", re.compile(r"\bURLSearchParams\b")),
    ("postmessage", re.compile(r"addEventListener\s*\(\s*['\"]message['\"]", re.I)),
    ("querystring", re.compile(r"\b(?:qs|querystring)\s*\.\s*parse\b|\bdeparam\b|"
                              r"\bparseParams\b", re.I)),
]

# Prototype-TOUCHING sinks: a recursive merge / deep-extend / path-set that walks a
# user key path into an object — the classic PP sink. These are specific and rare
# (unlike a shallow Object.assign, which is not flagged on its own).
_SINKS = [
    ("jquery_deep_extend", re.compile(r"(?:\$|jQuery)\s*\.\s*extend\s*\(\s*true\b")),
    ("lodash_merge", re.compile(r"\b_\s*\.\s*(?:merge|mergeWith|defaultsDeep)\s*\(")),
    ("lodash_set", re.compile(r"\b_\s*\.\s*set\s*\(|\blodash\.set\b")),
    ("deepmerge", re.compile(r"\bdeep[-_ ]?merge\b|\bdeepExtend\b|\bmergeDeep\b|"
                             r"\bdeepAssign\b|\bextend\s*\(\s*true\b", re.I)),
    ("object_path_set", re.compile(r"\bobjectPath\s*\.\s*set\b|\bdot[-_]?prop\b|"
                                   r"\bsetValue\s*\(", re.I)),
]

# An explicit __proto__ / constructor.prototype write in code (not a string literal
# in prose) — a direct pollution primitive.
_PROTO_WRITE = re.compile(
    r"\[\s*['\"]__proto__['\"]\s*\]|"        # obj["__proto__"]
    r"\.__proto__\s*(?:\[|\.)|"               # obj.__proto__[...] / .__proto__.x
    r"constructor\s*\.\s*prototype\s*(?:\[|\.)",  # constructor.prototype[...]
    re.I)

# Known prototype-pollution-vulnerable library versions. Each: (name, version-regex
# capturing the semver, fixed-version tuple). A match BELOW the fixed version, with a
# relevant sink present, is a positively-identified vulnerable dependency.
_LODASH_VER = re.compile(r"lodash[@ /]v?(\d+)\.(\d+)\.(\d+)|"
                         r"VERSION\s*=\s*['\"](\d+)\.(\d+)\.(\d+)['\"]", re.I)
_JQUERY_VER = re.compile(r"jQuery\s*(?:JavaScript Library\s*)?v?(\d+)\.(\d+)\.(\d+)", re.I)


def _semver(*parts) -> tuple:
    return tuple(int(p) for p in parts if p is not None)


def _vuln_library(body: str) -> Optional[str]:
    """Return a description if a positively version-matched PP-vulnerable library is
    present, else None. lodash < 4.17.12 (merge PP), jQuery < 3.4.0 (deep $.extend,
    CVE-2019-11358)."""
    m = _LODASH_VER.search(body)
    if m:
        g = [x for x in m.groups() if x is not None]
        if len(g) >= 3:
            ver = _semver(*g[:3])
            if ver < (4, 17, 12) and _SINKS[1][1].search(body):
                return f"lodash {'.'.join(map(str, ver))} (< 4.17.12) with a merge sink"
    j = _JQUERY_VER.search(body)
    if j:
        ver = _semver(*j.groups()[:3])
        if ver < (3, 4, 0) and _SINKS[0][1].search(body):
            return (f"jQuery {'.'.join(map(str, ver))} (< 3.4.0, CVE-2019-11358) with a "
                    "deep $.extend sink")
    return None


def _lead(url: str, title: str, evidence: str, conf: float) -> dict:
    return {
        "type": "prototype_pollution",
        "vuln_type": "prototype_pollution:client",
        "title": title,
        "severity": "medium",
        "url": url,
        "cwe": "CWE-1321",
        "confidence": conf,
        "evidence": evidence,
        # Confirming client-side PP needs a real browser/DOM — this is a lead the
        # operator verifies (e.g. with a DOM-pollution probe), never an auto-submission.
        "needs_manual_verification": True,
    }


def _scan_js(body: str, url: str) -> List[dict]:
    """Flag a PP gadget only when a prototype-reaching sink (or explicit __proto__
    write) co-occurs with a user-input source, or a vulnerable library is matched."""
    if not body:
        return []
    body = body[:512 * 1024]   # cap
    sources = [n for n, p in _SOURCES if p.search(body)]
    sinks = [n for n, p in _SINKS if p.search(body)]
    out: List[dict] = []
    if sources and sinks:
        out.append(_lead(
            url, "Client-side prototype-pollution gadget (source + sink)",
            f"user-input source ({sources[0]}) reaches a prototype-touching sink "
            f"({sinks[0]}) in the same script", 0.45))
    elif sources and _PROTO_WRITE.search(body):
        out.append(_lead(
            url, "Client-side prototype-pollution gadget (__proto__ write)",
            f"explicit __proto__/constructor.prototype write reachable from a "
            f"user-input source ({sources[0]})", 0.5))
    lib = _vuln_library(body)
    if lib:
        out.append(_lead(
            url, "Known prototype-pollution-vulnerable JS library",
            f"{lib} — a documented prototype-pollution CVE class", 0.5))
    return out


_SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)
_JS_SUFFIXES = (".js", ".mjs", ".cjs")
_MAX_LINKED_JS = 6


def _is_js(resp, url: str) -> bool:
    ctype = (resp.headers.get("content-type", "") if resp.headers else "").lower()
    if "javascript" in ctype or "ecmascript" in ctype:
        return True
    return urlsplit(url).path.lower().endswith(_JS_SUFFIXES)


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)
    resp = await fetch("GET", url, timeout=timeout)
    if not resp or not resp.body:
        return []

    # Dispatched directly at a JS asset — scan it and stop.
    if _is_js(resp, url):
        return _scan_js(resp.body, url)

    findings: List[dict] = []
    body = resp.body
    for m in _INLINE_SCRIPT.finditer(body):
        findings.extend(_scan_js(m.group(1), url))

    seen: set = set()
    for src in _SCRIPT_SRC.findall(body)[: _MAX_LINKED_JS * 2]:
        js_url = urljoin(url, src)
        base = js_url.lower().split("?", 1)[0]
        if js_url in seen or not base.endswith(_JS_SUFFIXES):
            continue
        seen.add(js_url)
        if len(seen) > _MAX_LINKED_JS:
            break
        r = await fetch("GET", js_url, timeout=timeout)
        if r and r.body:
            findings.extend(_scan_js(r.body, js_url))

    # Dedupe by (title, url).
    uniq: dict = {}
    for f in findings:
        uniq.setdefault((f["title"], f["url"]), f)
    return list(uniq.values())[:6]


register_worker("vuln", TECHNIQUE, run)
