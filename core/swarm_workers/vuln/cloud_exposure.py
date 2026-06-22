"""Cloud storage exposure detector (vuln phase, read-only, dependency-free).

Misconfigured cloud object storage — a publicly *listable* S3/GCS bucket or Azure
Blob container — leaks every object name (and often the objects) to anyone. A
dangling storage URL (NoSuchBucket) is a takeover. Detected over plain HTTP (no
boto3 / cloud SDK), so it works against the bucket's own endpoint OR a custom
domain CNAME'd to it.

FP-averse: a finding requires the provider's LISTING root element AND at least
one real object entry on a 2xx response — so a "ListBucketResult" mentioned in
prose, or an empty/again-private bucket, is not flagged.
"""
from __future__ import annotations

import logging
import re
from typing import List, Optional

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import HttpResp, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.cloud_exposure")

TECHNIQUE = "cloud_exposure"

# S3 / GCS XML API: a public listing is <ListBucketResult ...> with object <Key>s.
_S3_LIST = re.compile(r"<ListBucketResult\b", re.I)
_S3_KEY = re.compile(r"<Contents>.*?<Key>\s*\S", re.I | re.S)
# Azure Blob: <EnumerationResults ...> with at least one <Blob>.
_AZ_LIST = re.compile(r"<EnumerationResults\b", re.I)
_AZ_BLOB = re.compile(r"<Blob>\s*<Name>\s*\S", re.I | re.S)
# Dangling bucket -> takeover.
_S3_NOSUCH = re.compile(r"<Code>\s*NoSuchBucket\s*</Code>", re.I)


def classify(resp: Optional[HttpResp]):
    """Return (vuln_type_suffix, severity, what) for an exposed bucket, else None."""
    if resp is None:
        return None
    body = resp.body or ""
    ok = 200 <= resp.status < 300
    if ok and _S3_LIST.search(body) and _S3_KEY.search(body):
        return ("public_bucket_listing", "high",
                "a public, listable cloud bucket (S3/GCS) — every object name "
                "(and often the objects) is exposed to anonymous users")
    if ok and _AZ_LIST.search(body) and _AZ_BLOB.search(body):
        return ("azure_public_container", "high",
                "a public, listable Azure Blob container — every blob name is "
                "exposed to anonymous users")
    if _S3_NOSUCH.search(body):
        return ("bucket_takeover", "high",
                "a storage URL pointing at a non-existent bucket (NoSuchBucket) "
                "an attacker can register to serve content on this host")
    return None


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    resp = await fetch("GET", url, timeout=timeout)
    hit = classify(resp)
    if not hit:
        return []
    suffix, severity, what = hit
    return [{
        "type": "cloud_exposure",
        "vuln_type": f"cloud_exposure:{suffix}",
        "title": f"Cloud storage exposure ({suffix.replace('_', ' ')})",
        "severity": severity,
        "url": url,
        "cwe": "CWE-264" if suffix != "bucket_takeover" else "CWE-350",
        "confidence": 0.85,
        "needs_manual_verification": True,
        "evidence": f"GET {url} returned {what}.",
        "poc_request": f"GET {url}  (anonymous)",
    }]


register_worker("vuln", TECHNIQUE, run)
