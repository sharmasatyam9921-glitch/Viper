"""SSRF probe worker (response-based, non-destructive).

Looks for Server-Side Request Forgery by feeding URL-like parameters a
set of internal / cloud-metadata payloads and checking whether the
response body comes back carrying tell-tale metadata markers (or a clear
internal-service banner) that a benign control value does NOT return.

Only URL-shaped parameters are probed (url, uri, dest, callback, webhook,
image, redirect_uri, ...). Each candidate param is first sent a benign
baseline (``http://example.com/``) to capture what a "normal" fetched
remote page looks like; the metadata payloads must produce markers that
the baseline does not, which keeps false positives low (a page that
happens to mention "instance-id" everywhere won't trip the probe).

NOTE: This is purely RESPONSE-BASED SSRF — the target must reflect the
fetched content back to us. Blind SSRF (where the server makes the
request but returns nothing distinguishing) needs an out-of-band
interaction (OAST/collaborator) capability, which is a SEPARATE build and
intentionally out of scope here.

GET-only, read-only payloads — no writes or data-mutation.
"""

from __future__ import annotations

import logging
import re
from typing import List
from urllib.parse import parse_qs, urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import HttpResp, add_query, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.ssrf")

TECHNIQUE = "ssrf"

# Parameters that commonly carry a URL/host the server will dereference.
_URL_PARAMS = {
    "url", "uri", "u", "path", "dest", "target", "callback", "webhook",
    "image", "imageurl", "src", "source", "proxy", "feed", "host", "port",
    "to", "redirect_uri",
}

# Internal / cloud-metadata endpoints to coax the server into fetching.
_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDS
    "http://metadata.google.internal/",            # GCP metadata
    "http://localhost/",                           # loopback
    "http://127.0.0.1:80/",                        # loopback (explicit port)
]

# Benign control — must be a remote, non-internal URL so its response is a
# stable baseline that metadata markers should NOT appear in.
_BENIGN_PAYLOAD = "http://example.com/"

# Markers that only an internal/metadata SERVICE would EMIT. Matching one of
# these in a fetched-back body (and not in the benign baseline) is strong
# evidence the server proxied our internal URL.
#
# IMPORTANT: every marker here must be content the metadata service produces,
# NEVER a substring of a payload we send. An IP/host literal like
# "169.254.169.254" is part of the AWS-IMDS payload itself, so any endpoint
# that merely REFLECTS the submitted url value (open-redirect validators,
# search pages, "invalid URL" error bodies) would carry it in the probe
# response but not in the example.com baseline — a pure-reflection false
# positive. Reflected payloads are also stripped from the body before matching
# (see ``_markers``) as belt-and-suspenders against the same class of bug.
_METADATA_MARKERS = re.compile(
    r"(ami-id|instance-id|iam/security-credentials|computeMetadata|"
    r"AccessKeyId|local-hostname|instance-action|public-keys/|"
    r"securityCredentials)",
    re.IGNORECASE,
)


def _candidate_params(url: str) -> list[str]:
    """URL-like params already present on the target, else a small default set."""
    qs = parse_qs(urlsplit(url).query)
    present = [k for k in qs if k.lower() in _URL_PARAMS]
    if present:
        return present
    # Nothing url-shaped in the query — try the most common injection points.
    return ["url", "uri", "dest", "redirect_uri", "callback"]


def _markers(resp: HttpResp | None, echo: str = "") -> set[str]:
    """Service-emitted metadata markers in the body.

    `echo` (the URL value we submitted) is removed from the body first so a
    page that merely REFLECTS our payload can never contribute a marker — only
    content the server actually fetched/emitted is matched.
    """
    if not resp or not resp.body:
        return set()
    body = resp.body
    if echo:
        body = body.replace(echo, "")
    return {m.group(0).lower() for m in _METADATA_MARKERS.finditer(body)}


async def _probe_param(url: str, param: str, timeout: float) -> List[dict]:
    findings: list[dict] = []

    # Baseline: what does a benign remote fetch look like? Markers found here
    # are noise (e.g. the page itself documents metadata) and are subtracted.
    baseline = await fetch("GET", add_query(url, param, _BENIGN_PAYLOAD), timeout=timeout)
    base_markers = _markers(baseline, _BENIGN_PAYLOAD)

    for payload in _SSRF_PAYLOADS:
        probe_url = add_query(url, param, payload)
        resp = await fetch("GET", probe_url, timeout=timeout)
        if not resp:
            continue
        # Strip the reflected payload so pure reflection can't fabricate a marker.
        found = _markers(resp, payload) - base_markers
        if found:
            findings.append({
                "type": "ssrf",
                "vuln_type": f"ssrf:{param}",
                "title": f"SSRF: internal/metadata content reflected via ?{param}=",
                "severity": "high",
                "url": probe_url,
                "parameter": param,
                "payload": payload,
                "cwe": "CWE-918",
                "confidence": 0.85,
                "evidence": (
                    f"Cloud-metadata marker(s) {sorted(found)} present for "
                    f"payload {payload} but absent from benign baseline"
                ),
            })
            # One confirmed payload per param is enough — stop probing it.
            break

    return findings


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)

    params = _candidate_params(url)[:5]
    findings: list[dict] = []
    for p in params:
        try:
            findings.extend(await _probe_param(url, p, timeout))
        except Exception as e:  # noqa: BLE001
            logger.debug("ssrf probe %s?%s failed: %s", url, p, e)
    return findings


register_worker("vuln", TECHNIQUE, run)
