"""
VIPER 5.0 - ZoomEye Enrichment
================================
Passive enrichment via ZoomEye API.

Requires ``ZOOMEYE_API_KEY`` env var. Free tier: 10,000 results/month.
Returns host services, banners, geolocation, and vulnerability data.

Endpoint::

    GET https://api.zoomeye.ai/host/search?query=...

Stdlib only.
"""

import asyncio
import json
import logging
import os
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger("viper.recon.zoomeye")

ZE_BASE = "https://api.zoomeye.ai"
ZE_KEY = os.environ.get("ZOOMEYE_API_KEY", "").strip()
ZE_TIMEOUT = 15


def _ze_get(path: str, params: dict = None) -> Optional[dict]:
    if not ZE_KEY:
        return None
    url = f"{ZE_BASE}{path}"
    if params:
        url += "?" + urlencode(params)
    try:
        req = Request(url, headers={
            "API-KEY": ZE_KEY,
            "Accept": "application/json",
            "User-Agent": "VIPER/5.0",
        })
        with urlopen(req, timeout=ZE_TIMEOUT) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        return None
    except (HTTPError, URLError, json.JSONDecodeError, OSError) as exc:
        logger.debug("ZoomEye request failed: %s", exc)
        return None


def enrich_domain_sync(domain: str) -> Dict:
    data = _ze_get("/host/search", {"query": f"hostname:{domain}", "page": "1"})
    if not data:
        return {"domain": domain, "hosts": [], "total": 0}

    hosts = []
    for match in data.get("matches", [])[:50]:
        portinfo = match.get("portinfo", {})
        geoinfo = match.get("geoinfo", {})
        hosts.append({
            "ip": match.get("ip", ""),
            "port": portinfo.get("port", 0),
            "service": portinfo.get("service", ""),
            "product": portinfo.get("product", ""),
            "version": portinfo.get("version", ""),
            "banner": str(portinfo.get("banner", ""))[:200],
            "country": geoinfo.get("country", {}).get("names", {}).get("en", ""),
            "city": geoinfo.get("city", {}).get("names", {}).get("en", ""),
            "os": portinfo.get("os", ""),
        })
    return {
        "domain": domain,
        "hosts": hosts,
        "total": data.get("total", 0),
        "ips": sorted({h["ip"] for h in hosts if h["ip"]}),
        "ports": sorted({h["port"] for h in hosts if h["port"]}),
    }


def enrich_ip_sync(ip: str) -> Dict:
    data = _ze_get("/host/search", {"query": f"ip:{ip}", "page": "1"})
    if not data:
        return {"ip": ip, "services": [], "ports": []}

    services = []
    ports = set()
    for match in data.get("matches", [])[:20]:
        portinfo = match.get("portinfo", {})
        port = portinfo.get("port", 0)
        services.append({
            "port": port,
            "service": portinfo.get("service", ""),
            "product": portinfo.get("product", ""),
            "version": portinfo.get("version", ""),
            "os": portinfo.get("os", ""),
        })
        if port:
            ports.add(int(port))
    return {"ip": ip, "services": services, "ports": sorted(ports)}


async def enrich_domain(domain: str) -> Dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, enrich_domain_sync, domain)


async def enrich_ips(ips: List[str], delay: float = 0.3) -> List[Dict]:
    if not ZE_KEY:
        return [{"ip": ip} for ip in ips]
    loop = asyncio.get_event_loop()
    results = []
    for ip in ips[:15]:
        results.append(await loop.run_in_executor(None, enrich_ip_sync, ip))
        await asyncio.sleep(delay)
    return results


def enrich(domain: str, ips: Optional[List[str]] = None) -> Dict:
    if not ZE_KEY:
        return {"domain_report": {"domain": domain}, "ip_reports": []}
    return {
        "domain_report": enrich_domain_sync(domain),
        "ip_reports": [enrich_ip_sync(ip) for ip in (ips or [])[:5]],
    }
