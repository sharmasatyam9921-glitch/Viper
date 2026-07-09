"""Source-map (.map) content mining (read-only).

A production build that ships its JavaScript SOURCE MAPS hands you the original,
un-minified source — routinely including hardcoded API keys, internal base URLs, and
full route tables that a regex over minified JS never recovers. VIPER already locates
`.map` URLs, but only HEAD-checks them; the CONTENT was never read. This worker fetches
the map and mines it two ways:

  * SECRETS — runs the validation gate's OWN shape-specific credential regex
    (_SECRET_SHAPE, minus placeholders) over the served map and emits a `secrets`
    finding per live-looking key, with url = the .map URL. That routes straight through
    the already-proven _recheck_secrets gate (it re-fetches the map and re-matches the
    same regex), so these confirm at the existing precision with ZERO new gate logic.
  * ENDPOINTS / PARAMS — parses the sourcemap JSON, extracts same-host routes and
    query-parameter names from `sourcesContent`, feeds params to add_discovered_params,
    and emits endpoint findings so the confirmed vuln workers probe the real routes.

Strictly read-only GETs of static debug artifacts the server chose to publish — no
writes, no mutation, no account creation. Discovery + a gate-confirmable secret; it
cannot regress precision 1.00 (the secret half reuses the secrets gate unchanged).
"""
from __future__ import annotations

import json
import logging
import re
from typing import List, Set, Tuple
from urllib.parse import urljoin, urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ..vuln._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.recon.sourcemap")

TECHNIQUE = "sourcemap"

# Reuse the GATE's exact credential shapes so what we FIND is what the gate CONFIRMS.
from core.swarm_validation import _SECRET_PLACEHOLDER, _SECRET_SHAPE  # noqa: E402

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\'>]+\.js[^"\'>]*)["\']', re.I)
_SOURCEMAP_RE = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*([^\s\'"]+)', re.I)
# Quoted root-relative routes or absolute URLs found in reconstructed source.
_ROUTE_RE = re.compile(r'''["'`](/(?:api|v\d|graphql|admin|internal|user|account|auth)'''
                       r'''[a-zA-Z0-9_\-./{}:?=&%]*|https?://[^"'`\s]+)["'`]''')
_JS_CAP, _MAP_CAP, _ENDPOINT_CAP, _PARAM_CAP = 12, 6, 60, 120


def _script_srcs(body: str, base_url: str, netloc: str) -> List[str]:
    """Same-host <script src=...> .js bundle URLs from an HTML page."""
    out: List[str] = []
    seen: Set[str] = set()
    for m in _SCRIPT_SRC_RE.finditer(body or ""):
        raw = m.group(1).strip()
        full = raw if raw.startswith(("http://", "https://")) else (
            "https:" + raw if raw.startswith("//") else urljoin(base_url, raw))
        p = urlsplit(full)
        if p.netloc and p.netloc != netloc:
            continue
        if full not in seen:
            seen.add(full)
            out.append(full)
    return out[:_JS_CAP]


def _sourcemap_url(js_body: str, js_url: str) -> str:
    """Resolve a JS bundle's sourcemap URL: the `//# sourceMappingURL=` annotation if
    present (the authoritative pointer), else the conventional `<bundle>.js.map`."""
    m = _SOURCEMAP_RE.search(js_body or "")
    if m:
        ref = m.group(1).strip()
        if ref.startswith("data:"):        # inline map — nothing to fetch
            return ""
        return urljoin(js_url, ref)
    return js_url + ".map"


def _secrets_in(body: str) -> List[str]:
    """Live-looking shape-specific credentials in a served map body (placeholders out).
    Uses the gate's regexes so a hit here is confirmable by _recheck_secrets."""
    out: List[str] = []
    for mm in _SECRET_SHAPE.finditer(body or ""):
        tok = mm.group(0)
        ctx = body[max(0, mm.start() - 12):mm.end() + 12]
        if not _SECRET_PLACEHOLDER.search(tok) and not _SECRET_PLACEHOLDER.search(ctx):
            if tok not in out:
                out.append(tok)
    return out


def mine_sourcemap(map_text: str, base_url: str) -> Tuple[List[str], Set[str]]:
    """Parse a sourcemap and return (same-host endpoint URLs, query-param names) mined
    from its `sourcesContent`. Never raises; ([], set()) on a non-map / parse failure."""
    try:
        data = json.loads(map_text)
    except (ValueError, TypeError):
        return [], set()
    if not isinstance(data, dict):
        return [], set()
    contents = data.get("sourcesContent")
    if not isinstance(contents, list):
        return [], set()
    netloc = urlsplit(base_url).netloc
    endpoints: List[str] = []
    seen: Set[str] = set()
    params: Set[str] = set()
    for src in contents:
        if not isinstance(src, str):
            continue
        for m in _ROUTE_RE.finditer(src):
            raw = m.group(1)
            full = raw if raw.startswith("http") else urljoin(base_url, raw)
            p = urlsplit(full)
            if p.netloc and p.netloc != netloc:
                continue
            clean = full.split("#", 1)[0]
            for k in _query_keys(clean):
                params.add(k)
            if clean not in seen and len(endpoints) < _ENDPOINT_CAP:
                seen.add(clean)
                endpoints.append(clean)
        if len(endpoints) >= _ENDPOINT_CAP and len(params) >= _PARAM_CAP:
            break
    return endpoints[:_ENDPOINT_CAP], set(list(params)[:_PARAM_CAP])


def _query_keys(url: str) -> List[str]:
    from urllib.parse import parse_qs
    return list(parse_qs(urlsplit(url).query).keys())


async def run(agent: SwarmAgent) -> List[dict]:
    base = normalize_target_url(agent.target)
    if not base:
        return []
    timeout = min(agent.timeout_s, 8.0)
    netloc = urlsplit(base).netloc

    idx = await fetch("GET", base, timeout=timeout)
    if not idx or not getattr(idx, "body", None):
        return []
    findings: List[dict] = []
    all_params: Set[str] = set()
    maps_done: Set[str] = set()

    for js_url in _script_srcs(idx.body, base, netloc):
        jr = await fetch("GET", js_url, timeout=timeout)
        if not jr or not getattr(jr, "body", None):
            continue
        map_url = _sourcemap_url(jr.body, js_url)
        if not map_url or map_url in maps_done or len(maps_done) >= _MAP_CAP:
            continue
        maps_done.add(map_url)
        mr = await fetch("GET", map_url, timeout=timeout)
        if not mr or not (200 <= getattr(mr, "status", 0) < 300) or not getattr(mr, "body", None):
            continue
        body = mr.body
        for tok in _secrets_in(body):
            findings.append({
                "type": "secrets",
                "vuln_type": "secrets:sourcemap",
                "title": f"Credential leaked in a served source map ({tok[:4]}…)",
                "severity": "high",
                "url": map_url,
                "cwe": "CWE-540",
                "confidence": 0.85,
                "evidence": f"shape-specific credential {tok[:4]}… present in {map_url}",
            })
        endpoints, params = mine_sourcemap(body, base)
        all_params |= params
        for u in endpoints:
            findings.append({
                "type": "endpoint",
                "vuln_type": f"endpoint:{u}",
                "title": u,
                "asset": netloc,
                "url": u,
                "severity": "info",
                "evidence": f"route recovered from source map {map_url}",
            })

    if all_params:
        try:
            from core.payload_library import add_discovered_params
            add_discovered_params(all_params)
        except Exception as e:  # noqa: BLE001 — seeding is best-effort
            logger.debug("sourcemap param seeding failed: %s", e)
    logger.info("sourcemap: %d maps, %d findings, %d params",
                len(maps_done), len(findings), len(all_params))
    return findings


register_worker("recon", TECHNIQUE, run)
