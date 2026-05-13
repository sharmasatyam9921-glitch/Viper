"""Tech-fingerprint worker.

Best-effort: prefer `recon.wappalyzer` if present, else parse the
target's HTTP headers + HTML for common signatures.

Output:
    {"type": "technology", "title": "nginx 1.18", "asset": "example.com",
     "url": "https://example.com", "severity": "info"}
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List
from urllib.parse import urlparse

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

    # Path A — full wappalyzer module
    try:
        from recon.wappalyzer import Wappalyzer  # type: ignore
        wa = Wappalyzer()
        techs = await asyncio.wait_for(
            asyncio.to_thread(wa.fingerprint_url, url),
            timeout=min(agent.timeout_s, 15.0),
        )
        return [
            {
                "type": "technology",
                "title": t,
                "asset": asset,
                "url": url,
                "severity": "info",
                "evidence": "wappalyzer signature match",
            }
            for t in techs
        ]
    except Exception as e:  # noqa: BLE001
        logger.debug("wappalyzer module unavailable: %s", e)

    # Path B — quick header + html signature scan via stdlib
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "viper-swarm/1.0"})
        with urllib.request.urlopen(req, timeout=min(agent.timeout_s, 10.0)) as resp:
            body = resp.read(64 * 1024).decode("utf-8", errors="replace")
            server = resp.headers.get("Server", "")
            powered = resp.headers.get("X-Powered-By", "")
            text = " ".join([server, powered, body])
    except Exception as e:  # noqa: BLE001
        logger.debug("fingerprint fetch failed for %s: %s", url, e)
        return []

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
