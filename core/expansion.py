"""Finding-driven targeted expansion — pick the RIGHT next probe per finding.

The generic chain planner re-runs the whole vuln phase on any high-severity URL.
This is the targeted brain that makes the recursion *smart*: given a finding, it
emits the specific follow-up techniques that escalate THAT finding — so an SSRF
pivots to internal/metadata, an LFI reaches for config/secret files, a discovered
endpoint gets its parameters injected, a new subdomain triggers a full sweep, an
open redirect chases an OAuth token, an IDOR enumerates adjacent objects.

Pure and deterministic (a finding in, a task plan out), so it is unit-tested and
fed to the swarm's chain loop. It never widens scope — every task targets the
finding's own host/URL.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit, urlunsplit

# Broad probe set for freshly-discovered request surface.
_SURFACE_PROBES = ["sqli", "xss", "ssrf", "open_redirect", "lfi", "host_header",
                   "cors", "crlf", "command_injection", "ssti"]

# finding head -> follow-up techniques that escalate it (target = finding's URL).
_ESCALATE = {
    # discovered surface -> probe it
    "endpoint": _SURFACE_PROBES,
    "historical_url": _SURFACE_PROBES,
    "wayback": _SURFACE_PROBES,
    "js_file": _SURFACE_PROBES,
    "url": _SURFACE_PROBES,
    "technology": [],                      # info; nothing to chain directly
    # confirmed primitives -> targeted escalation
    "ssrf": ["ssrf"],                      # internal / cloud-metadata pivot
    "lfi": ["lfi"],                        # reach for app config / secrets
    "path_traversal": ["lfi"],
    "open_redirect": ["open_redirect", "host_header"],   # OAuth/token theft
    "redirect": ["open_redirect", "host_header"],
    "idor": ["bola_multi", "idor"],        # enumerate adjacent objects
    "bola": ["bola_multi"],
    "cors": ["cors"],                      # credentialed cross-origin read
    "host_header": ["host_header"],        # cache / reset poisoning
    "sqli": ["sqli"],                      # schema / data enumeration (read-only)
    "ssti": ["ssti", "command_injection"],
    "cloud_exposure": ["cloud_exposure"],
}
# Discovery of a new host -> a full sweep of the new target (recon + vuln).
_NEW_HOST = {"subdomain", "subdomain_alive", "dns_a", "dns_aaaa", "dns_cname", "asset"}
# Terminal findings (escalation needs human action — surfaced, not auto-chained).
_TERMINAL = {"secret", "secrets", "env_exposed", "git_exposed", "js_secret",
             "github_secret", "subdomain_takeover", "cloud_exposure"}


@dataclass
class ExpansionTask:
    target: str
    techniques: List[str]
    reason: str
    new_host: bool = False
    seed: dict = field(default_factory=dict)


def _head(finding: dict) -> str:
    return (str(finding.get("vuln_type") or finding.get("type") or "")
            .lower().split(":")[0])


def _url(finding: dict) -> str:
    return str(finding.get("url") or finding.get("endpoint")
               or finding.get("target") or "").strip()


def expand(finding: dict) -> Optional[ExpansionTask]:
    """Return the targeted follow-up for one finding, or None if nothing to chain."""
    if finding.get("false_positive") or finding.get("skipped"):
        return None
    head = _head(finding)
    url = _url(finding)
    if not url or urlsplit(url).scheme.lower() not in ("http", "https"):
        return None

    if head in _NEW_HOST:
        origin = urlunsplit(urlsplit(url)._replace(path="", query="", fragment=""))
        return ExpansionTask(origin or url, _SURFACE_PROBES,
                             f"new host {head} discovered — full vuln sweep",
                             new_host=True, seed=finding)
    if head in _TERMINAL:
        return None        # high-value but needs a human (use the credential, etc.)
    techs = _ESCALATE.get(head)
    if not techs:
        return None
    return ExpansionTask(url, list(techs),
                         f"escalate {head} via {', '.join(techs[:3])}", seed=finding)


def plan_expansions(findings, *, seen: Optional[set] = None,
                    max_tasks: int = 40) -> List[ExpansionTask]:
    """Targeted expansion tasks across a finding set, deduped by (target, techniques)."""
    seen = seen if seen is not None else set()
    out: List[ExpansionTask] = []
    for f in findings or []:
        task = expand(f)
        if task is None:
            continue
        key = (task.target, tuple(task.techniques))
        if key in seen:
            continue
        seen.add(key)
        out.append(task)
        if len(out) >= max_tasks:
            break
    return out
