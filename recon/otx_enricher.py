"""
VIPER 5.0 - AlienVault OTX Enrichment
======================================
Passive threat-intelligence enrichment via AlienVault OTX (Open Threat Exchange).

OTX is FREE; an API key is optional but raises the rate limit from
~1,000 req/hr (anonymous) to ~10,000 req/hr (authenticated). Set
``OTX_API_KEY`` env var to enable the higher tier.

Endpoints used::

    GET /api/v1/indicators/IPv4/{ip}/general
    GET /api/v1/indicators/IPv4/{ip}/passive_dns
    GET /api/v1/indicators/IPv4/{ip}/malware
    GET /api/v1/indicators/IPv4/{ip}/url_list
    GET /api/v1/indicators/domain/{domain}/general
    GET /api/v1/indicators/domain/{domain}/passive_dns
    GET /api/v1/indicators/domain/{domain}/malware

Stdlib only — no external deps.
"""

import asyncio
import json
import logging
import os
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

logger = logging.getLogger("viper.recon.otx")

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"
OTX_API_KEY = os.environ.get("OTX_API_KEY", "").strip()
OTX_TIMEOUT = 10


def _otx_get(path: str, timeout: int = OTX_TIMEOUT) -> Optional[dict]:
    """Single OTX GET. Returns parsed JSON or None on error."""
    headers = {
        "Accept": "application/json",
        "User-Agent": "VIPER/5.0",
    }
    if OTX_API_KEY:
        headers["X-OTX-API-KEY"] = OTX_API_KEY

    try:
        req = Request(f"{OTX_BASE}{path}", headers=headers)
        with urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
            return None
    except HTTPError as exc:
        if exc.code == 404:
            return None
        logger.debug("OTX HTTP error %s on %s", exc.code, path)
        return None
    except (URLError, json.JSONDecodeError, OSError) as exc:
        logger.debug("OTX request failed: %s", exc)
        return None


def enrich_domain_sync(domain: str) -> Dict:
    """
    Pull all OTX indicators for a domain.

    Returns::

        {
            "domain": "example.com",
            "pulse_count": 0,
            "pulse_names": [],
            "passive_dns": [{"hostname": "...", "address": "..."}, ...],
            "malware_samples": [{"hash": "...", "datetime_int": ...}, ...],
            "url_count": 0,
        }
    """
    result = {
        "domain": domain,
        "pulse_count": 0,
        "pulse_names": [],
        "passive_dns": [],
        "malware_samples": [],
        "url_count": 0,
    }

    enc = quote(domain, safe="")

    general = _otx_get(f"/domain/{enc}/general")
    if general:
        pulse_info = general.get("pulse_info", {})
        result["pulse_count"] = pulse_info.get("count", 0)
        result["pulse_names"] = [
            p.get("name", "")
            for p in pulse_info.get("pulses", [])[:20]
            if p.get("name")
        ]

    pdns = _otx_get(f"/domain/{enc}/passive_dns")
    if pdns:
        result["passive_dns"] = [
            {
                "hostname": e.get("hostname", ""),
                "address": e.get("address", ""),
                "first": e.get("first", ""),
                "last": e.get("last", ""),
            }
            for e in pdns.get("passive_dns", [])[:50]
        ]

    malware = _otx_get(f"/domain/{enc}/malware")
    if malware:
        result["malware_samples"] = [
            {"hash": m.get("hash", ""), "datetime": m.get("datetime", "")}
            for m in malware.get("data", [])[:20]
        ]

    url_list = _otx_get(f"/domain/{enc}/url_list")
    if url_list:
        result["url_count"] = url_list.get("full_size", 0)

    return result


def enrich_ip_sync(ip: str) -> Dict:
    """
    Pull all OTX indicators for an IPv4 address.

    Returns::

        {
            "ip": "1.2.3.4",
            "pulse_count": 0,
            "pulse_names": [],
            "country": "",
            "city": "",
            "asn": "",
            "passive_dns": [],
            "malware_samples": [],
        }
    """
    result = {
        "ip": ip,
        "pulse_count": 0,
        "pulse_names": [],
        "country": "",
        "city": "",
        "asn": "",
        "passive_dns": [],
        "malware_samples": [],
    }

    general = _otx_get(f"/IPv4/{ip}/general")
    if general:
        pulse_info = general.get("pulse_info", {})
        result["pulse_count"] = pulse_info.get("count", 0)
        result["pulse_names"] = [
            p.get("name", "")
            for p in pulse_info.get("pulses", [])[:20]
            if p.get("name")
        ]
        result["country"] = general.get("country_name", "")
        result["city"] = general.get("city", "")
        result["asn"] = general.get("asn", "")

    pdns = _otx_get(f"/IPv4/{ip}/passive_dns")
    if pdns:
        result["passive_dns"] = [
            {
                "hostname": e.get("hostname", ""),
                "first": e.get("first", ""),
                "last": e.get("last", ""),
            }
            for e in pdns.get("passive_dns", [])[:50]
        ]

    malware = _otx_get(f"/IPv4/{ip}/malware")
    if malware:
        result["malware_samples"] = [
            {"hash": m.get("hash", ""), "datetime": m.get("datetime", "")}
            for m in malware.get("data", [])[:20]
        ]

    return result


# =============================================================================
# Async wrappers
# =============================================================================

async def enrich_domain(domain: str) -> Dict:
    """Async wrapper for enrich_domain_sync."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, enrich_domain_sync, domain)


async def enrich_ips(
    ips: List[str], concurrency: int = 5, delay: float = 0.2
) -> List[Dict]:
    """
    Enrich a list of IPs with OTX data, in parallel with bounded concurrency.
    """
    sem = asyncio.Semaphore(concurrency)
    loop = asyncio.get_event_loop()

    async def _one(ip: str) -> Dict:
        async with sem:
            await asyncio.sleep(delay)
            return await loop.run_in_executor(None, enrich_ip_sync, ip)

    return list(await asyncio.gather(*[_one(ip) for ip in ips]))


# Convenience entry point used by recon/pipeline.py GROUP-1
def enrich(domain: str, ips: Optional[List[str]] = None) -> Dict:
    """
    Single-call enrichment combining domain + IP intelligence.

    Returns::

        {
            "domain_report": {...},
            "ip_reports": [...],
        }
    """
    return {
        "domain_report": enrich_domain_sync(domain),
        "ip_reports": [enrich_ip_sync(ip) for ip in (ips or [])[:10]],
    }
