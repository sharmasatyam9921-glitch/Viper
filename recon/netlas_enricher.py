"""
VIPER 5.0 - Netlas Enrichment
==============================
Passive enrichment via Netlas.io API.

Requires ``NETLAS_API_KEY`` env var. Free tier: 50 queries/day.
Returns host services, certificates, banners, and geolocation.

Endpoint::

    GET https://app.netlas.io/api/responses/?q=...

Stdlib only.
"""

import asyncio
import json
import logging
import os
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger("viper.recon.netlas")

NETLAS_BASE = "https://app.netlas.io/api/responses/"
NETLAS_KEY = os.environ.get("NETLAS_API_KEY", "").strip()
NETLAS_TIMEOUT = 15


def _netlas_get(query: str, size: int = 20) -> Optional[dict]:
    if not NETLAS_KEY:
        return None
    params = urlencode({"q": query, "start": "0", "indices": ""})
    try:
        req = Request(f"{NETLAS_BASE}?{params}", headers={
            "X-API-Key": NETLAS_KEY,
            "Accept": "application/json",
            "User-Agent": "VIPER/5.0",
        })
        with urlopen(req, timeout=NETLAS_TIMEOUT) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        return None
    except (HTTPError, URLError, json.JSONDecodeError, OSError) as exc:
        logger.debug("Netlas request failed: %s", exc)
        return None


def enrich_domain_sync(domain: str) -> Dict:
    result = {"domain": domain, "hosts": [], "total": 0}
    data = _netlas_get(f"domain:{domain}")
    if not data:
        return result

    result["total"] = data.get("count", 0)
    for item in data.get("items", [])[:50]:
        d = item.get("data", {})
        host_entry = {
            "ip": d.get("ip", ""),
            "port": d.get("port", 0),
            "protocol": (d.get("protocol", {}) or {}).get("name", ""),
            "host": d.get("host", ""),
            "geo_country": (d.get("geo", {}) or {}).get("country", ""),
            "geo_city": (d.get("geo", {}) or {}).get("city", ""),
            "asn": (d.get("as", {}) or {}).get("number", 0),
            "as_org": (d.get("as", {}) or {}).get("organization", ""),
        }
        cert = d.get("certificate", {})
        if cert:
            host_entry["cert_issuer"] = (cert.get("issuer", {}) or {}).get("organization", "")
            host_entry["cert_subject"] = (cert.get("subject", {}) or {}).get("common_name", "")
        result["hosts"].append(host_entry)
    return result


def enrich_ip_sync(ip: str) -> Dict:
    data = _netlas_get(f"host:{ip}")
    if not data:
        return {"ip": ip, "services": [], "ports": []}

    services = []
    ports = set()
    for item in data.get("items", [])[:20]:
        d = item.get("data", {})
        port = d.get("port", 0)
        services.append({
            "port": port,
            "protocol": (d.get("protocol", {}) or {}).get("name", ""),
            "banner": str(d.get("data", ""))[:200],
        })
        if port:
            ports.add(int(port))
    return {"ip": ip, "services": services, "ports": sorted(ports)}


async def enrich_domain(domain: str) -> Dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, enrich_domain_sync, domain)


async def enrich_ips(ips: List[str], delay: float = 0.5) -> List[Dict]:
    if not NETLAS_KEY:
        return [{"ip": ip} for ip in ips]
    loop = asyncio.get_event_loop()
    results = []
    for ip in ips[:10]:
        results.append(await loop.run_in_executor(None, enrich_ip_sync, ip))
        await asyncio.sleep(delay)
    return results


def enrich(domain: str, ips: Optional[List[str]] = None) -> Dict:
    if not NETLAS_KEY:
        return {"domain_report": {"domain": domain}, "ip_reports": []}
    return {
        "domain_report": enrich_domain_sync(domain),
        "ip_reports": [enrich_ip_sync(ip) for ip in (ips or [])[:5]],
    }
