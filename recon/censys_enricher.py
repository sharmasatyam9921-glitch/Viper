"""
VIPER 5.0 - Censys Search Enrichment
=====================================
Passive enrichment via Censys Search API v2.

Requires free credentials (set ``CENSYS_API_ID`` and ``CENSYS_API_SECRET``
env vars). Free tier: 250 queries/month — used sparingly.

Endpoints::

    GET /api/v2/hosts/{ip}                           — host details
    GET /api/v2/hosts/search?q={query}               — host search

Returns: services, certificates, ASN, location, banners, software,
operating system. Especially useful for confirming open ports passively
without sending packets to the target.

Uses HTTP Basic auth (api_id:api_secret). Stdlib only.
"""

import asyncio
import base64
import json
import logging
import os
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("viper.recon.censys")

CENSYS_BASE = "https://search.censys.io/api/v2"
CENSYS_ID = os.environ.get("CENSYS_API_ID", "").strip()
CENSYS_SECRET = os.environ.get("CENSYS_API_SECRET", "").strip()
CENSYS_TIMEOUT = 15


def _auth_header() -> Optional[str]:
    if not (CENSYS_ID and CENSYS_SECRET):
        return None
    creds = f"{CENSYS_ID}:{CENSYS_SECRET}".encode()
    return f"Basic {base64.b64encode(creds).decode()}"


def _censys_get(path: str) -> Optional[dict]:
    """Single Censys GET. Returns parsed JSON or None on error."""
    auth = _auth_header()
    if not auth:
        logger.debug("Censys credentials not set — skipping enrichment")
        return None

    headers = {
        "Accept": "application/json",
        "User-Agent": "VIPER/5.0",
        "Authorization": auth,
    }
    try:
        req = Request(f"{CENSYS_BASE}{path}", headers=headers)
        with urlopen(req, timeout=CENSYS_TIMEOUT) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
            return None
    except HTTPError as exc:
        if exc.code in (404, 400):
            return None
        logger.debug("Censys HTTP error %s on %s", exc.code, path)
        return None
    except (URLError, json.JSONDecodeError, OSError) as exc:
        logger.debug("Censys request failed: %s", exc)
        return None


def enrich_ip_sync(ip: str) -> Dict:
    """
    Pull Censys host record for an IPv4 address.

    Returns the most useful fields flattened::

        {
            "ip": "1.2.3.4",
            "services": [{"port": 80, "service_name": "HTTP", ...}, ...],
            "ports": [80, 443],
            "asn": 13335,
            "as_name": "CLOUDFLARENET",
            "country": "US",
            "operating_system": "",
            "last_updated": "2024-01-01T00:00:00",
        }

    Empty dict {ip: ip} if no creds or no data.
    """
    data = _censys_get(f"/hosts/{ip}")
    if not data:
        return {"ip": ip}

    result = data.get("result", {})
    services = result.get("services", [])

    return {
        "ip": ip,
        "services": [
            {
                "port": s.get("port"),
                "service_name": s.get("service_name", ""),
                "transport_protocol": s.get("transport_protocol", ""),
                "extended_service_name": s.get("extended_service_name", ""),
                "software": [
                    sw.get("product", "") for sw in s.get("software", [])
                ],
            }
            for s in services
        ],
        "ports": sorted({s.get("port") for s in services if s.get("port")}),
        "asn": (result.get("autonomous_system") or {}).get("asn", 0),
        "as_name": (result.get("autonomous_system") or {}).get("name", ""),
        "country": (result.get("location") or {}).get("country", ""),
        "operating_system": (result.get("operating_system") or {}).get(
            "product", ""
        ),
        "last_updated": result.get("last_updated_at", ""),
    }


# =============================================================================
# Async wrappers
# =============================================================================

async def enrich_ips(
    ips: List[str], concurrency: int = 3, delay: float = 0.5
) -> List[Dict]:
    """
    Enrich a list of IPs with Censys data, in parallel with bounded
    concurrency. Free tier is 250 queries/month, so the caller should
    pre-filter the IP list aggressively.
    """
    if not (CENSYS_ID and CENSYS_SECRET):
        return [{"ip": ip} for ip in ips]

    sem = asyncio.Semaphore(concurrency)
    loop = asyncio.get_event_loop()

    async def _one(ip: str) -> Dict:
        async with sem:
            await asyncio.sleep(delay)
            return await loop.run_in_executor(None, enrich_ip_sync, ip)

    return list(await asyncio.gather(*[_one(ip) for ip in ips[:20]]))


def enrich(domain: str, ips: Optional[List[str]] = None) -> Dict:
    """
    Single-call enrichment. Censys is host-only — domain is unused but
    accepted for API consistency with the other enrichers.

    Returns::

        {"ip_reports": [...]}

    If credentials are not set, returns an empty stub.
    """
    if not (CENSYS_ID and CENSYS_SECRET):
        return {"ip_reports": []}

    return {"ip_reports": [enrich_ip_sync(ip) for ip in (ips or [])[:10]]}
