"""Tech-fingerprint worker.

Best-effort: prefer `recon.wappalyzer` if present, else parse the
target's HTTP headers + HTML for common signatures.

Output:
    {"type": "technology", "title": "nginx 1.18", "asset": "example.com",
     "url": "https://example.com", "severity": "info"}
"""

from __future__ import annotations

import logging
import re
from typing import List
from urllib.parse import urlparse

from core import tool_gateway as gateway
from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

logger = logging.getLogger("viper.swarm_workers.recon.wappalyzer")

TECHNIQUE = "wappalyzer"


_BANNER_PATTERNS = [
    (re.compile(r"nginx[/ ](\S+)", re.I), "nginx"),
    (re.compile(r"apache[/ ](\S+)", re.I), "apache"),
    (re.compile(r"Microsoft-IIS[/ ](\S+)", re.I), "iis"),
    (re.compile(r"caddy", re.I), "caddy"),
    (re.compile(r"cloudflare", re.I), "cloudflare"),
    (re.compile(r"akamai", re.I), "akamai"),
    (re.compile(r"awselb", re.I), "aws-elb"),
    (re.compile(r"PHP[/ ](\S+)", re.I), "php"),
    (re.compile(r"WordPress (\S+)", re.I), "wordpress"),
    (re.compile(r"<meta[^>]+generator[^>]+wordpress", re.I), "wordpress"),
    (re.compile(r"react", re.I), "react"),
    (re.compile(r"vue\.js", re.I), "vue"),
    (re.compile(r"Next\.js", re.I), "nextjs"),
    (re.compile(r"angular", re.I), "angular"),
    (re.compile(r"Django", re.I), "django"),
    (re.compile(r"Express", re.I), "express"),
    (re.compile(r"Rails", re.I), "rails"),
]


def _http_url(target: str) -> str:
    t = target.strip()
    if "://" in t:
        return t.split("?")[0].rstrip("/")
    return f"https://{t.split(':', 1)[0]}"


async def run(agent: SwarmAgent) -> List[dict]:
    url = _http_url(agent.target)
    asset = urlparse(url).hostname or agent.target

    # Path A — full wappalyzer module.
    # ``recon.wappalyzer.Wappalyzer`` exposes ``fingerprint(url, headers,
    # body, ...)``, NOT ``fingerprint_url``. An earlier version called the
    # non-existent method, which raised AttributeError and silently fell
    # through to Path B — making the 3,920-fingerprint database dead code.
    try:
        from recon.wappalyzer import Wappalyzer  # type: ignore
        wa = Wappalyzer()

        # The HTTP fetch hits the TARGET host (we feed its headers/body to the
        # fingerprint DB) → is_infra=False so the hunt's scope predicate applies.
        resp = await gateway.http(
            "GET", url, is_infra=False,
            timeout=min(agent.timeout_s, 15.0),
            headers={"User-Agent": "viper-swarm/1.0"},
        )
        if resp is None:  # scope-denied or network error
            raise RuntimeError("target fetch denied or failed")
        techs = wa.fingerprint(url, resp.headers, resp.body)
        return [
            {
                "type": "technology",
                "title": (
                    f"{t.get('name')}"
                    + (f" {t['version']}" if isinstance(t, dict)
                       and t.get("version") else "")
                ) if isinstance(t, dict) else str(t),
                "asset": asset,
                "url": url,
                "severity": "info",
                "evidence": "wappalyzer fingerprint match",
                "confidence": (t.get("confidence", 70) / 100.0)
                              if isinstance(t, dict) else 0.7,
                "categories": t.get("categories", []) if isinstance(t, dict) else [],
            }
            for t in (techs or [])
        ]
    except Exception as e:  # noqa: BLE001
        logger.debug("wappalyzer module unavailable: %s", e)

    # Path B — quick header + html signature scan via the egress gateway.
    # This fetch hits the TARGET host → is_infra=False (scope predicate applies).
    resp = await gateway.http(
        "GET", url, is_infra=False,
        timeout=min(agent.timeout_s, 10.0),
        headers={"User-Agent": "viper-swarm/1.0"},
    )
    if resp is None:  # scope-denied or network error
        logger.debug("fingerprint fetch failed for %s (scope-denied or network)", url)
        return []
    body = resp.body
    server = resp.headers.get("server", "")
    powered = resp.headers.get("x-powered-by", "")
    text = " ".join([server, powered, body])

    found: dict[str, str] = {}
    for pat, name in _BANNER_PATTERNS:
        m = pat.search(text)
        if m:
            label = name
            if m.groups():
                label = f"{name} {m.group(1)}"
            found.setdefault(name, label)

    return [
        {
            "type": "technology",
            "title": label,
            "asset": asset,
            "url": url,
            "severity": "info",
            "evidence": "signature match in headers/body",
        }
        for label in found.values()
    ]


register_worker("recon", TECHNIQUE, run)
