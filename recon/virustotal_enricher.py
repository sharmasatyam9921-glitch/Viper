"""
VIPER 5.0 - VirusTotal Enrichment
==================================
Passive enrichment via VirusTotal Public API v3.

Requires a free API key (set ``VIRUSTOTAL_API_KEY`` env var). Free tier:
500 req/day, 4 req/min. The module enforces a self-imposed 4 req/min
ceiling so we never exhaust the quota during a hunt.

Endpoints::

    GET /api/v3/domains/{domain}
    GET /api/v3/ip_addresses/{ip}

Returns reputation, last analysis stats, categories, registrar, WHOIS
preview, related subdomains, and any community-tagged threats.

Stdlib only — no external deps.
"""

import asyncio
import json
import logging
import os
import time
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("viper.recon.virustotal")

VT_BASE = "https://www.virustotal.com/api/v3"
VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
VT_TIMEOUT = 15
_MIN_INTERVAL = 16.0  # 4 req/min = 1 req every 15s; pad to 16
_last_call_ts: float = 0.0


def _vt_get(path: str) -> Optional[dict]:
    """Single VT GET, with self-rate-limit. Returns parsed JSON or None."""
    global _last_call_ts
    if not VT_KEY:
        logger.debug("VIRUSTOTAL_API_KEY not set — skipping VT enrichment")
        return None

    # Throttle to 4 req/min
    elapsed = time.time() - _last_call_ts
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_call_ts = time.time()

    headers = {
        "Accept": "application/json",
        "User-Agent": "VIPER/5.0",
        "x-apikey": VT_KEY,
    }
    try:
        req = Request(f"{VT_BASE}{path}", headers=headers)
        with urlopen(req, timeout=VT_TIMEOUT) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
            return None
    except HTTPError as exc:
        if exc.code in (404, 400):
            return None
        logger.debug("VT HTTP error %s on %s", exc.code, path)
        return None
    except (URLError, json.JSONDecodeError, OSError) as exc:
        logger.debug("VT request failed: %s", exc)
        return None


def enrich_domain_sync(domain: str) -> Dict:
    """
    Pull VT v3 attributes for a domain.

    Returns the most useful fields flattened::

        {
            "domain": "example.com",
            "reputation": 0,
            "categories": {},
            "last_analysis_stats": {"harmless": ..., "malicious": ..., ...},
            "registrar": "",
            "creation_date": 0,
            "last_modification_date": 0,
            "tags": [],
            "total_votes": {"harmless": 0, "malicious": 0},
        }

    Empty dict if VT key not set or domain not found.
    """
    data = _vt_get(f"/domains/{domain}")
    if not data:
        return {"domain": domain}

    attrs = data.get("data", {}).get("attributes", {})
    return {
        "domain": domain,
        "reputation": attrs.get("reputation", 0),
        "categories": attrs.get("categories", {}),
        "last_analysis_stats": attrs.get("last_analysis_stats", {}),
        "registrar": attrs.get("registrar", ""),
        "creation_date": attrs.get("creation_date", 0),
        "last_modification_date": attrs.get("last_modification_date", 0),
        "tags": attrs.get("tags", []),
        "total_votes": attrs.get("total_votes", {}),
    }


def enrich_ip_sync(ip: str) -> Dict:
    """
    Pull VT v3 attributes for an IPv4 address.

    Returns::

        {
            "ip": "1.2.3.4",
            "reputation": 0,
            "country": "",
            "asn": 0,
            "as_owner": "",
            "network": "",
            "last_analysis_stats": {...},
            "tags": [],
        }
    """
    data = _vt_get(f"/ip_addresses/{ip}")
    if not data:
        return {"ip": ip}

    attrs = data.get("data", {}).get("attributes", {})
    return {
        "ip": ip,
        "reputation": attrs.get("reputation", 0),
        "country": attrs.get("country", ""),
        "asn": attrs.get("asn", 0),
        "as_owner": attrs.get("as_owner", ""),
        "network": attrs.get("network", ""),
        "last_analysis_stats": attrs.get("last_analysis_stats", {}),
        "tags": attrs.get("tags", []),
    }


# =============================================================================
# Async wrappers
# =============================================================================

async def enrich_domain(domain: str) -> Dict:
    """Async wrapper for enrich_domain_sync."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, enrich_domain_sync, domain)


async def enrich_ips(ips: List[str], delay: float = 0.0) -> List[Dict]:
    """
    Enrich a list of IPs with VT data. Sequential — VT free tier rate
    limit is too tight for concurrency to help.
    """
    if not VT_KEY:
        return [{"ip": ip} for ip in ips]

    loop = asyncio.get_event_loop()
    results = []
    for ip in ips[:8]:  # Cap at 8 IPs to stay under daily quota
        results.append(await loop.run_in_executor(None, enrich_ip_sync, ip))
    return results


def enrich(domain: str, ips: Optional[List[str]] = None) -> Dict:
    """
    Single-call enrichment combining domain + IP intelligence.

    Returns::

        {
            "domain_report": {...},
            "ip_reports": [...],
        }

    If VIRUSTOTAL_API_KEY is not set, returns an empty stub instead of
    making any HTTP calls.
    """
    if not VT_KEY:
        return {"domain_report": {"domain": domain}, "ip_reports": []}

    return {
        "domain_report": enrich_domain_sync(domain),
        "ip_reports": [enrich_ip_sync(ip) for ip in (ips or [])[:5]],
    }
