"""Discovery-strong find+confirm hunt: crawl + form/param mining -> param-aware
workers -> validation gate. Closes the recall gap on unknown apps where the vuln
parameter or endpoint isn't a common guess (the XBOW-019 failure mode: the param
was discovered but the workers didn't probe it).

Pipeline:
  1. crawl href/action links + seed common paths
  2. mine parameter names from URL query keys AND <form> inputs
  3. feed them to payload_library.add_discovered_params so EVERY injection worker
     probes the app's real param names
  4. run workers (scoped to known classes when provided) per endpoint
  5. optionally install an OOBServer so blind classes (ssrf/cmdi/xxe/host-header)
     can confirm via callback
  6. gate everything -> submittable findings only

Returns gate-confirmed findings; never auto-submits.
"""
from __future__ import annotations

import asyncio
import importlib
import pkgutil
import re
from typing import List, Optional
from urllib.parse import parse_qsl, urljoin, urlsplit

_COMMON_PATHS = ("/", "/search", "/login", "/admin", "/api", "/index.php", "/home",
                 "/view", "/page", "/file", "/download", "/profile", "/user",
                 "/products", "/item", "/resource", "/render")
_INJECT_WORKERS = ("xss_probe", "sqli_probe", "lfi", "ssti_probe", "command_injection",
                   "ssrf", "open_redirect", "crlf", "host_header", "xxe")
_SURFACE_WORKERS = ("secrets", "cors", "cloud_exposure", "host_header",
                    "subdomain_takeover")
_CLASS_WORKER = {
    "xss": "xss_probe", "sqli": "sqli_probe", "lfi": "lfi", "ssti": "ssti_probe",
    "rce": "command_injection", "ssrf": "ssrf", "open_redirect": "open_redirect",
    "crlf": "crlf", "host_header": "host_header", "xxe": "xxe", "secrets": "secrets",
    "cors": "cors", "cloud_exposure": "cloud_exposure",
    "subdomain_takeover": "subdomain_takeover",
}
_FORM = re.compile(r"<form[^>]*>(.*?)</form>", re.I | re.S)
_NAME = re.compile(r"""name\s*=\s*["']([^"'>\s]+)""")
_LINK = re.compile(r"""(?:href|action)\s*=\s*["']([^"'>\s]+)""")


class _Agent:
    def __init__(self, target: str):
        self.target = target
        self.timeout_s = 8.0
        self.payload = {}


def _load_workers():
    import core.swarm_workers.vuln as v
    for m in pkgutil.iter_modules(v.__path__):
        if not m.name.startswith("_"):
            importlib.import_module(f"core.swarm_workers.vuln.{m.name}")
    from core.swarm_workers import _REGISTRY
    return _REGISTRY.get("vuln", {})


async def discover(base: str, *, max_pages: int = 30, timeout: float = 6.0) -> dict:
    """Crawl + mine params. Returns {base, endpoints: {path: set(params)}, urls}."""
    from core.swarm_workers.vuln._http import fetch
    host = urlsplit(base).netloc
    seen: set = set()
    endpoints: dict = {}
    queue = [base]                      # crawl the real surface first ...
    common = [urljoin(base + "/", p.lstrip("/")) for p in _COMMON_PATHS]
    added_common = False
    while len(seen) < max_pages:
        if not queue:                   # ... only fall back to common paths
            if added_common:
                break
            queue.extend(common)
            added_common = True
            continue
        u = queue.pop(0)
        if u in seen:
            continue
        seen.add(u)
        # Do NOT follow redirects: a 3xx endpoint (e.g. /login) is itself attack
        # surface (host-header/open-redirect); following it would record the target
        # path instead and the vulnerable endpoint would never be probed.
        r = await fetch("GET", u, timeout=timeout, follow_redirects=False)
        if not r:
            continue
        sp = urlsplit(u)
        path = sp.path or "/"
        params = endpoints.setdefault(path, set())
        for k, _ in parse_qsl(sp.query):
            params.add(k)
        # a redirect Location may reveal a new same-host endpoint to crawl
        loc = (getattr(r, "headers", {}) or {}).get("location") or ""
        if loc:
            link = urljoin(u, loc)
            if urlsplit(link).netloc in ("", host) and link not in seen:
                queue.append(link)
        if not (200 <= getattr(r, "status", 0) < 400):
            continue
        body = r.body or ""
        new_links = []
        for m in _LINK.finditer(body):
            link = urljoin(u, m.group(1))
            if (urlsplit(link).netloc == host and link not in seen
                    and link not in queue and (len(seen) + len(queue)) < max_pages * 3):
                new_links.append(link)
        queue = new_links + queue       # depth-prioritise freshly-found links
        for fm in _FORM.finditer(body):
            for nm in _NAME.finditer(fm.group(1)):
                params.add(nm.group(1))
    return {"base": base, "endpoints": endpoints, "urls": sorted(seen)}


def _scope(names, classes):
    if not classes:
        return names
    want = {_CLASS_WORKER.get(c) for c in classes}
    return tuple(n for n in names if n in want)


async def hunt(base: str, *, classes: Optional[set] = None, oob=None,
               max_pages: int = 30, fast: bool = False) -> List[dict]:
    """Discovery-strong find+confirm hunt -> gate-confirmed findings.

    `fast=True` disables the politeness rate limiter (~10x faster) and is ONLY for
    AUTHORIZED localhost / benchmark targets; leave it off for real engagements.
    """
    from core.payload_library import (add_discovered_params, clear_discovered_params,
                                       get_business_logic_params)
    from core.swarm_validation import validate_findings
    from core.swarm_workers.vuln._http import clear_oob, set_oob
    from core.swarm_workers.vuln._rate_limit import set_unthrottled

    workers = _load_workers()
    clear_discovered_params()
    if fast:
        set_unthrottled(True)
    oob_store = None
    try:
        surf = await discover(base, max_pages=max_pages)
        discovered: set = set()
        for params in surf["endpoints"].values():
            discovered |= params
        add_discovered_params(discovered)
        # Seed common access-control / object-reference parameter names (mined from
        # disclosed business-logic reports) so the IDOR + injection workers probe
        # the params real authz/logic bugs hide in. Bounded so the sweep stays fast.
        add_discovered_params(get_business_logic_params("object_ref")[:15])

        names = list(dict.fromkeys(_scope(_INJECT_WORKERS, classes)
                                   + _scope(_SURFACE_WORKERS, classes)))
        if oob is not None:
            set_oob(oob)
            oob_store = getattr(oob, "store", None)
        sem = asyncio.Semaphore(16)

        async def _probe(ep: str, wn: str) -> List[dict]:
            run = workers.get(wn)
            if run is None:
                return []
            async with sem:
                try:
                    return await run(_Agent(ep))
                except Exception:
                    return []
        tasks = [
            _probe(base.rstrip("/") + (p if p.startswith("/") else "/" + p), wn)
            for p in list(surf["endpoints"])[:30] for wn in names
        ]
        findings: List[dict] = [f for group in await asyncio.gather(*tasks)
                                for f in group]
        out = await validate_findings(findings, default_target=base,
                                      oob_store=oob_store)
        return [f for f in out if f.get("submittable")]
    finally:
        if oob is not None:
            clear_oob()
        clear_discovered_params()
        if fast:
            set_unthrottled(False)      # never leak fast mode into later hunts

