"""
VIPER 5.0 - FOFA Enrichment
============================
Passive infrastructure search via FOFA (fofa.info).

Requires ``FOFA_EMAIL`` and ``FOFA_API_KEY`` env vars. Free tier: 100
queries/month. Returns host IPs, ports, protocols, banners, and
geographic data for a target domain.

Endpoint::

    GET https://fofa.info/api/v1/search/all?email=...&key=...&qbase64=...

Stdlib only.
"""

import asyncio
import base64
import json
import logging
import os
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger("viper.recon.fofa")

FOFA_BASE = "https://fofa.info/api/v1/search/all"
FOFA_EMAIL = os.environ.get("FOFA_EMAIL", "").strip()
FOFA_KEY = os.environ.get("FOFA_API_KEY", "").strip()
FOFA_TIMEOUT = 15


def _fofa_search(query: str, size: int = 100) -> Optional[dict]:
    if not (FOFA_EMAIL and FOFA_KEY):
        return None
    qb64 = base64.b64encode(query.encode()).decode()
    params = urlencode({
        "email": FOFA_EMAIL,
        "key": FOFA_KEY,
        "qbase64": qb64,
        "size": str(size),
        "fields": "ip,port,protocol,host,title,server,banner,country,city,as_organization",
    })
    try:
        req = Request(f"{FOFA_BASE}?{params}", headers={
            "User-Agent": "VIPER/5.0",
        })
        with urlopen(req, timeout=FOFA_TIMEOUT) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        return None
    except (HTTPError, URLError, json.JSONDecodeError, OSError) as exc:
        logger.debug("FOFA request failed: %s", exc)
        return None


def enrich_domain_sync(domain: str) -> Dict:
    result = {
        "domain": domain,
        "hosts": [],
        "ips": set(),
        "ports": set(),
        "total": 0,
    }
    data = _fofa_search(f'domain="{domain}"')
    if not data or not data.get("results"):
        result["ips"] = []
        result["ports"] = []
        return result

    result["total"] = data.get("size", 0)
    for row in data.get("results", []):
        if len(row) >= 10:
            ip, port, proto, host, title, server, banner, country, city, asn = row[:10]
            result["hosts"].append({
                "ip": ip, "port": port, "protocol": proto,
                "host": host, "title": title, "server": server,
                "country": country, "city": city, "as_org": asn,
            })
            if ip:
                result["ips"].add(ip)
            if port:
                result["ports"].add(int(port) if str(port).isdigit() else port)

    result["ips"] = sorted(result["ips"])
    result["ports"] = sorted(result["ports"])
    return result


def enrich_ip_sync(ip: str) -> Dict:
    data = _fofa_search(f'ip="{ip}"')
    if not data or not data.get("results"):
        return {"ip": ip, "services": [], "ports": []}

    services = []
    ports = set()
    for row in data.get("results", []):
        if len(row) >= 6:
            _, port, proto, host, title, server = row[:6]
            services.append({
                "port": port, "protocol": proto,
                "host": host, "title": title, "server": server,
            })
            if port and str(port).isdigit():
                ports.add(int(port))
    return {"ip": ip, "services": services, "ports": sorted(ports)}


async def enrich_domain(domain: str) -> Dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, enrich_domain_sync, domain)


async def enrich_ips(ips: List[str], delay: float = 1.0) -> List[Dict]:
    if not (FOFA_EMAIL and FOFA_KEY):
        return [{"ip": ip} for ip in ips]
    loop = asyncio.get_event_loop()
    results = []
    for ip in ips[:10]:
        results.append(await loop.run_in_executor(None, enrich_ip_sync, ip))
        await asyncio.sleep(delay)
    return results


def enrich(domain: str, ips: Optional[List[str]] = None) -> Dict:
    if not (FOFA_EMAIL and FOFA_KEY):
        return {"domain_report": {"domain": domain}, "ip_reports": []}
    return {
        "domain_report": enrich_domain_sync(domain),
        "ip_reports": [enrich_ip_sync(ip) for ip in (ips or [])[:5]],
    }
