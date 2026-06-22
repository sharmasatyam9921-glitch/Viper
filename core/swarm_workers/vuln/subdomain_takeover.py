"""Subdomain takeover detector (vuln phase, non-destructive, read-only).

A dangling DNS record (CNAME/ALIAS) pointing at a de-provisioned third-party
service (S3 bucket, GitHub Pages, Heroku app, Shopify store, ...) lets an attacker
register that resource and serve content on the victim's subdomain. The reliable,
FP-averse signal is the SERVICE'S OWN "this resource is unclaimed" page — a very
specific string that only appears when the backing resource does not exist.

This worker fetches the target and matches the response body against a curated
list of those service fingerprints. The strings are deliberately specific (not
generic 404s), so a match strongly indicates a claimable subdomain. The gate
re-confirms with an independent fetch.
"""
from __future__ import annotations

import logging
import re
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.subdomain_takeover")

TECHNIQUE = "subdomain_takeover"

# (service, fingerprint regex). Each fingerprint is the third party's OWN
# "unclaimed / no such resource" wording — present only when the backing resource
# is gone, which is exactly the takeover condition. Curated to avoid generic 404s.
FINGERPRINTS = [
    ("AWS S3", re.compile(r"NoSuchBucket|The specified bucket does not exist", re.I)),
    ("GitHub Pages", re.compile(r"There isn't a GitHub Pages site here", re.I)),
    ("Heroku", re.compile(r"no-such-app\.html|herokucdn\.com/error-pages|"
                          r"No such app", re.I)),
    ("Shopify", re.compile(r"Sorry, this shop is currently unavailable", re.I)),
    ("Fastly", re.compile(r"Fastly error: unknown domain", re.I)),
    ("Pantheon", re.compile(r"The gods are wise, but do not know of the site which "
                            r"you seek", re.I)),
    ("Tumblr", re.compile(r"Whatever you were looking for doesn't currently exist "
                          r"at this address", re.I)),
    ("Ghost", re.compile(r"The thing you were looking for is no longer here, or "
                         r"never was", re.I)),
    ("JetBrains", re.compile(r"is not a registered InCloud YouTrack", re.I)),
    ("Read the Docs", re.compile(r"unknown to Read the Docs", re.I)),
    ("Help Scout", re.compile(r"No settings were found for this company", re.I)),
    ("Wordpress", re.compile(r"Do you want to register .*\.wordpress\.com", re.I)),
]
# Generic phrases like "Repository not found" / "project not found" were dropped:
# they appear in normal prose/docs and aren't service-specific enough to flag.


def match_fingerprint(body: str):
    """Return the service whose unclaimed-fingerprint is in `body`, else None."""
    if not body:
        return None
    for service, rx in FINGERPRINTS:
        if rx.search(body):
            return service
    return None


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    resp = await fetch("GET", url, timeout=timeout)
    if not resp or not resp.body:
        return []
    # A genuine unclaimed-resource page returns a 4xx/5xx error. A 2xx page that
    # merely contains the phrase (a doc, a blog, a parked domain) is not a takeover.
    if resp.status < 400:
        return []
    service = match_fingerprint(resp.body)
    if not service:
        return []
    return [{
        "type": "subdomain_takeover",
        "vuln_type": f"subdomain_takeover:{service.lower().replace(' ', '_')}",
        "title": f"Subdomain takeover — dangling {service} resource",
        "severity": "high",
        "url": url,
        "cwe": "CWE-350",
        "confidence": 0.85,
        "needs_manual_verification": True,
        "evidence": (f"The response carries {service}'s 'unclaimed resource' "
                     f"fingerprint — the DNS record points at a de-provisioned "
                     f"{service} resource an attacker can register to serve content "
                     f"on this host."),
        "poc_request": f"GET {url}  (observe the {service} unclaimed-resource page)",
    }]


register_worker("vuln", TECHNIQUE, run)
