"""Active hidden-parameter discovery (read-only).

A hardened SPA/API often accepts parameters that appear nowhere in the HTML — the
injection workers have nothing to inject into until those names are known. This worker
GET-probes a capped wordlist of common parameter names with a unique canary value and
keeps a name only when it MEASURABLY affects the response versus a baseline: either the
canary is reflected back (decisive — the value was processed), or the response length
changes by clearly more than the page's own natural jitter (measured from two baseline
fetches, so a dynamic page doesn't produce false hits). Kept names are registered via
``add_discovered_params`` so the confirmed-injection/SSRF/access-control workers probe
the app's REAL parameters. Discovery only — read-only GETs, scope-gated and rate-limited
by the shared fetch path; the validation gate still independently confirms everything.
"""
from __future__ import annotations

import logging
import secrets
from typing import List
from urllib.parse import urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ..vuln._http import add_query, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.recon.param_brute")

TECHNIQUE = "param_brute"

# Common hidden/undocumented parameter names across web apps + APIs.
_WORDLIST = (
    "id", "page", "q", "query", "search", "s", "keyword", "name", "user", "username",
    "user_id", "uid", "account", "email", "url", "uri", "link", "redirect", "redirect_uri",
    "next", "return", "returnurl", "callback", "continue", "dest", "destination", "goto",
    "target", "file", "filename", "path", "dir", "folder", "download", "load", "template",
    "view", "page_id", "cat", "category", "type", "action", "cmd", "exec", "func", "op",
    "method", "sort", "order", "filter", "field", "column", "table", "db", "host", "port",
    "server", "proxy", "image", "img", "src", "ref", "token", "key", "api_key", "format",
    "lang", "locale", "debug", "test", "admin", "role", "status", "state", "data", "json",
    "xml", "callback_url", "webhook", "site", "domain", "feed",
)
_MAX_PROBES = 48        # names probed per URL
_MAX_KEEP = 24          # names registered per URL (also globally capped at 60)


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)

    # Two baselines: measure the page's natural length jitter so a dynamic page
    # (ads, timestamps, CSRF tokens) doesn't produce false "the param changed it" hits.
    b1 = await fetch("GET", url, timeout=timeout)
    if not b1 or not b1.body:
        return []
    base_len = len(b1.body)
    b2 = await fetch("GET", url, timeout=timeout)
    jitter = abs(len(b2.body) - base_len) if (b2 and b2.body) else 0
    len_margin = max(64, jitter * 3)   # a delta must clearly beat the natural jitter

    # Echo-everything guard: if a RANDOM non-wordlist param's canary is reflected, the page
    # echoes any query value — reflection is then not attributable to a real param, so we
    # ignore the reflection signal entirely (avoids registering the whole wordlist as junk).
    ctrl_canary = "viperpb" + secrets.token_hex(3)
    ctrl_resp = await fetch(
        "GET", add_query(url, "viperctl" + secrets.token_hex(2), ctrl_canary),
        timeout=timeout)
    echoes_everything = bool(ctrl_resp and ctrl_resp.body and ctrl_canary in ctrl_resp.body)

    # Names already present in the URL are not "hidden" — skip them.
    present = set(k.lower() for k in _query_keys(url))
    discovered: list[str] = []
    for name in _WORDLIST[:_MAX_PROBES]:
        if name in present:
            continue
        canary = "viperpb" + secrets.token_hex(3)
        resp = await fetch("GET", add_query(url, name, canary), timeout=timeout)
        if not resp or not resp.body:
            continue
        if (not echoes_everything) and canary in resp.body:
            discovered.append(name)                          # decisive: value processed
        elif abs(len(resp.body) - base_len) > len_margin:
            # A length change can be page noise (bimodal/random pages defeat a 2-sample
            # jitter estimate) — require it to REPRODUCE on a fresh probe before keeping.
            r2 = await fetch("GET", add_query(url, name, "viperpb" + secrets.token_hex(3)),
                             timeout=timeout)
            if r2 and r2.body and abs(len(r2.body) - base_len) > len_margin:
                discovered.append(name)
        if len(discovered) >= _MAX_KEEP:
            break

    if discovered:
        try:
            from core.payload_library import add_discovered_params
            add_discovered_params(discovered)
        except Exception:  # noqa: BLE001
            pass

    host = urlsplit(url).netloc
    return [{
        "type": "param_discovered",
        "vuln_type": f"param_discovered:{n}",
        "title": f"Hidden parameter '{n}' affects the response",
        "asset": host,
        "url": url,
        "severity": "info",
        "evidence": ("canary reflected or response length changed beyond baseline jitter "
                     "(active hidden-parameter discovery); fed to the injection workers"),
    } for n in discovered]


def _query_keys(url: str) -> list[str]:
    from urllib.parse import parse_qs
    return list(parse_qs(urlsplit(url).query).keys())


register_worker("recon", TECHNIQUE, run)
