"""Completeness critic — the 'what did I miss?' reflection pass.

After a hunt, this looks at the discovered attack surface against what was actually
probed and names the GAPS: hosts found but never swept, parameter-bearing endpoints
with no finding/attempt, and vuln classes that never ran. Pure and deterministic
(surface + ran-techniques in, gaps out), so it's unit-tested — and the gaps convert
straight into expansion tasks to drive another round, closing the autonomy loop.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List
from urllib.parse import urlsplit, urlunsplit

# Finding heads that represent discovered surface (not a vuln itself).
_SURFACE = {"endpoint", "historical_url", "wayback", "js_file", "url",
            "subdomain", "subdomain_alive", "dns_a", "dns_cname", "asset",
            "parameter", "technology", "tech"}
_NEW_HOST = {"subdomain", "subdomain_alive", "dns_a", "dns_cname", "asset"}
# Classes a thorough hunt should exercise.
CANON_CLASSES = {"sqli", "xss", "ssrf", "lfi", "idor", "open_redirect", "cors",
                 "crlf", "xxe", "ssti", "command_injection", "host_header"}


@dataclass(frozen=True)
class CoverageGap:
    kind: str          # unswept_host | untested_params | class_not_run
    detail: str        # the host / url / class
    suggestion: str


def _head(f: dict) -> str:
    return (str(f.get("vuln_type") or f.get("type") or "").lower().split(":")[0])


def _url(f: dict) -> str:
    return str(f.get("url") or f.get("endpoint") or f.get("target") or "").strip()


def _host(url: str) -> str:
    try:
        return urlsplit(url).netloc.lower()
    except Exception:
        return ""


def _origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit(p._replace(path="", query="", fragment="")) if p.netloc else url


def _norm(url: str) -> str:
    """Path-level identity (ignore query values) for matching probes to surface."""
    p = urlsplit(url)
    return f"{p.netloc.lower()}{p.path}"


def critique(findings: Iterable[dict], *,
             ran_techniques: Iterable[str] = ()) -> List[CoverageGap]:
    findings = list(findings)
    ran = {str(t).lower() for t in ran_techniques}

    discovered_hosts: set = set()
    probed_hosts: set = set()
    param_endpoints: set = set()
    finding_paths: set = set()

    for f in findings:
        head = _head(f)
        url = _url(f)
        if head in _SURFACE:
            if head in _NEW_HOST and (url or f.get("host")):
                discovered_hosts.add(_origin(url) if url else str(f.get("host")))
            if url and ("?" in url or head in ("endpoint", "url", "historical_url")):
                param_endpoints.add(url)
        else:                                   # a vuln finding == surface was probed
            if _host(url):
                probed_hosts.add(_host(url))
            if url:
                finding_paths.add(_norm(url))

    gaps: List[CoverageGap] = []
    seen: set = set()

    def _add(g: CoverageGap):
        key = (g.kind, g.detail)
        if key not in seen:
            seen.add(key)
            gaps.append(g)

    for h in sorted(discovered_hosts):
        if _host(h) and _host(h) not in probed_hosts:
            _add(CoverageGap("unswept_host", h,
                             "discovered but never probed - run a full vuln sweep"))
    for ep in sorted(param_endpoints):
        if "?" in ep and _norm(ep) not in finding_paths:
            _add(CoverageGap("untested_params", ep,
                             "parameter-bearing endpoint with no finding - inject "
                             "its parameters (sqli/xss/ssrf/lfi)"))
    if ran:                                     # only judge classes if we know what ran
        for c in sorted(CANON_CLASSES - ran):
            _add(CoverageGap("class_not_run", c,
                             f"no {c} probe ran this hunt - consider enabling it"))
    return gaps


def gaps_to_targets(gaps: Iterable[CoverageGap]) -> List[str]:
    """The concrete URLs worth re-probing next round (hosts + endpoints)."""
    out, seen = [], set()
    for g in gaps:
        if g.kind in ("unswept_host", "untested_params") and g.detail not in seen:
            seen.add(g.detail)
            out.append(g.detail)
    return out
