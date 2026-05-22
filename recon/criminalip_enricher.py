"""
VIPER 5.0 - CriminalIP Enrichment
===================================
Passive enrichment via CriminalIP API.

Requires ``CRIMINALIP_API_KEY`` env var. Free tier: 50 credits/month.

Endpoints::

    GET https://api.criminalip.io/v1/ip/data?ip=...
    GET https://api.criminalip.io/v1/domain/report?query=...

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

logger = logging.getLogger("viper.recon.criminalip")

CIP_BASE = "https://api.criminalip.io/v1"
CIP_KEY = os.environ.get("CRIMINALIP_API_KEY", "").strip()
CIP_TIMEOUT = 15


def _cip_get(path: str, params: dict = None) -> Optional[dict]:
    if not CIP_KEY:
        return None
    url = f"{CIP_BASE}{path}"
    if params:
        url += "?" + urlencode(params)
    try:
        req = Request(url, headers={
            "x-api-key": CIP_KEY,
            "Accept": "application/json",
            "User-Agent": "VIPER/5.0",
        })
        with urlopen(req, timeout=CIP_TIMEOUT) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        return None
    except (HTTPError, URLError, json.JSONDecodeError, OSError) as exc:
        logger.debug("CriminalIP request failed: %s", exc)
        return None


def enrich_domain_sync(domain: str) -> Dict:
    data = _cip_get("/domain/report", {"query": domain})
    if not data or data.get("status") != 200:
        return {"domain": domain}
    report = data.get("data", {})
    return {
        "domain": domain,
        "score": report.get("score", {}),
        "whois": report.get("whois", {}),
        "dns": report.get("dns", {}),
        "connected_ips": [
            ip.get("ip", "") for ip in report.get("connected_ip", [])[:20]
        ],
        "technologies": [
            t.get("tech_name", "") for t in report.get("technologies", [])[:20]
        ],
    }


def enrich_ip_sync(ip: str) -> Dict:
    data = _cip_get("/ip/data", {"ip": ip})
    if not data or data.get("status") != 200:
        return {"ip": ip}
    report = data.get("data", {})
    ports = []
    for p in report.get("port", [])[:30]:
        ports.append({
            "port": p.get("open_port_no", 0),
            "protocol": p.get("protocol", ""),
            "service": p.get("app_name", ""),
            "banner": str(p.get("banner", ""))[:200],
        })
    return {
        "ip": ip,
        "score": report.get("score", {}),
        "country": (report.get("ip_scoring", {}) or {}).get("country", ""),
        "as_name": report.get("as_name", ""),
        "ports": ports,
        "port_numbers": sorted({p["port"] for p in ports if p["port"]}),
        "vulnerabilities": [
            {"cve": v.get("cve_id", ""), "cvss": v.get("cvss_score", 0)}
            for v in report.get("vulnerability", [])[:20]
        ],
    }


async def enrich_domain(domain: str) -> Dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, enrich_domain_sync, domain)


async def enrich_ips(ips: List[str], delay: float = 1.0) -> List[Dict]:
    if not CIP_KEY:
        return [{"ip": ip} for ip in ips]
    loop = asyncio.get_event_loop()
    results = []
    for ip in ips[:10]:
        results.append(await loop.run_in_executor(None, enrich_ip_sync, ip))
        await asyncio.sleep(delay)
    return results


def enrich(domain: str, ips: Optional[List[str]] = None) -> Dict:
    if not CIP_KEY:
        return {"domain_report": {"domain": domain}, "ip_reports": []}
    return {
        "domain_report": enrich_domain_sync(domain),
        "ip_reports": [enrich_ip_sync(ip) for ip in (ips or [])[:5]],
    }
