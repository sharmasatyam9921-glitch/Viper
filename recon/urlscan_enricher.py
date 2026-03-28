"""
VIPER 4.0 - URLScan.io Passive Enrichment
===========================================
Passive OSINT via URLScan.io Search API. Discovers subdomains, IPs,
technologies, TLS info, and page titles from historical scans --
without touching the target.

Free tier: no API key needed (public results only, rate-limited).
With URLSCAN_API_KEY env var: higher rate limits + private scans.

Stdlib only (urllib). No external dependencies.
"""

import json
import logging
import os
import time
from typing import Dict, List, Optional, Set
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

logger = logging.getLogger("viper.recon.urlscan")

URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"


# =============================================================================
# Core API
# =============================================================================

def search(domain: str, max_results: int = 200, api_key: str = None,
           timeout: int = 30) -> dict:
    """
    Query URLScan.io search API for passive domain intelligence.

    Args:
        domain: Root domain to search (e.g. "example.com")
        max_results: Max results to fetch (capped at 10000)
        api_key: Optional API key for higher rate limits
        timeout: HTTP request timeout in seconds

    Returns:
        {
            "results_count": int,
            "subdomains": ["sub.example.com", ...],
            "ips": ["1.2.3.4", ...],
            "technologies": {"nginx": 5, "cloudflare": 3, ...},
            "tls_issuers": {"Let's Encrypt": 10, ...},
            "page_titles": {"Example - Home": "https://example.com", ...},
            "urls_with_paths": [{"url": "...", "path": "...", "status": 200}, ...],
            "asns": {"AS13335": "Cloudflare", ...},
            "countries": {"US": 5, ...},
            "entries": [raw entries list]
        }
    """
    if not api_key:
        api_key = os.environ.get("URLSCAN_API_KEY", "")

    query = quote(f"domain:{domain}")
    size = min(max_results, 10000)
    url = f"{URLSCAN_SEARCH_URL}?q={query}&size={size}"

    headers = {
        "Accept": "application/json",
        "User-Agent": "VIPER/4.0",
    }
    if api_key:
        headers["API-Key"] = api_key

    raw_results = _fetch_results(url, headers, timeout)
    if raw_results is None:
        return _empty_result()

    return _parse_results(raw_results, domain)


def _fetch_results(url: str, headers: dict, timeout: int,
                   retries: int = 2) -> Optional[list]:
    """Fetch search results with retry on rate limit."""
    for attempt in range(retries + 1):
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())
                results = data.get("results", [])
                logger.info("URLScan returned %d results", len(results))
                return results

        except HTTPError as e:
            if e.code == 429:
                wait = min(2 ** attempt * 5, 30)
                logger.warning("URLScan rate limit, waiting %ds (attempt %d/%d)",
                               wait, attempt + 1, retries + 1)
                if attempt < retries:
                    time.sleep(wait)
                    continue
                return None
            logger.warning("URLScan HTTP %d: %s", e.code,
                           e.read().decode()[:200] if hasattr(e, 'read') else "")
            return None
        except URLError as e:
            logger.warning("URLScan connection error: %s", e.reason)
            return None
        except Exception as e:
            logger.warning("URLScan request failed: %s", e)
            return None
    return None


def _parse_results(results: list, root_domain: str) -> dict:
    """Parse raw URLScan results into structured intelligence."""
    subdomains: Set[str] = set()
    ips: Set[str] = set()
    technologies: Dict[str, int] = {}
    tls_issuers: Dict[str, int] = {}
    page_titles: Dict[str, str] = {}
    urls_with_paths: List[dict] = []
    asns: Dict[str, str] = {}
    countries: Dict[str, int] = {}

    seen_paths: Set[str] = set()

    for entry in results:
        page = entry.get("page", {})
        task = entry.get("task", {})

        # -- Subdomains --
        page_domain = page.get("domain", "")
        if page_domain and _belongs_to(page_domain, root_domain):
            subdomains.add(page_domain.lower())

        task_domain = task.get("domain", "")
        if task_domain and _belongs_to(task_domain, root_domain):
            subdomains.add(task_domain.lower())

        # -- IPs --
        ip = page.get("ip", "")
        if ip and not ip.startswith(("10.", "192.168.", "127.")):
            ips.add(ip)

        # -- Technologies --
        # URLScan stores tech in page.server and various headers
        server = page.get("server", "")
        if server:
            technologies[server] = technologies.get(server, 0) + 1

        # -- TLS --
        tls_issuer = page.get("tlsIssuer", "")
        if tls_issuer:
            tls_issuers[tls_issuer] = tls_issuers.get(tls_issuer, 0) + 1

        # -- Page titles --
        title = page.get("title", "")
        page_url = page.get("url", task.get("url", ""))
        if title and page_url:
            page_titles[title] = page_url

        # -- URL paths --
        if page_url:
            parsed = urlparse(page_url)
            path = parsed.path or "/"
            if path != "/" and path not in seen_paths:
                seen_paths.add(path)
                urls_with_paths.append({
                    "url": page_url,
                    "path": path,
                    "status": page.get("status"),
                })

        # -- ASN / Country --
        asn = page.get("asn", "")
        asnname = page.get("asnname", "")
        if asn:
            asns[asn] = asnname

        country = page.get("country", "")
        if country:
            countries[country] = countries.get(country, 0) + 1

    return {
        "results_count": len(results),
        "subdomains": sorted(subdomains),
        "ips": sorted(ips),
        "technologies": dict(sorted(technologies.items(),
                                    key=lambda x: x[1], reverse=True)),
        "tls_issuers": dict(sorted(tls_issuers.items(),
                                   key=lambda x: x[1], reverse=True)),
        "page_titles": page_titles,
        "urls_with_paths": urls_with_paths[:100],  # cap
        "asns": asns,
        "countries": dict(sorted(countries.items(),
                                 key=lambda x: x[1], reverse=True)),
        "entries": results[:50],  # keep raw sample
    }


# =============================================================================
# Helpers
# =============================================================================

def _belongs_to(hostname: str, root_domain: str) -> bool:
    """Check if hostname belongs to root domain."""
    hostname = hostname.lower()
    root_domain = root_domain.lower()
    return hostname == root_domain or hostname.endswith("." + root_domain)


def _empty_result() -> dict:
    return {
        "results_count": 0,
        "subdomains": [],
        "ips": [],
        "technologies": {},
        "tls_issuers": {},
        "page_titles": {},
        "urls_with_paths": [],
        "asns": {},
        "countries": {},
        "entries": [],
    }


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python urlscan_enricher.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    print(f"[*] Querying URLScan.io for: {domain}\n")
    result = search(domain)

    print(f"  Results:      {result['results_count']}")
    print(f"  Subdomains:   {len(result['subdomains'])}")
    if result["subdomains"]:
        for s in result["subdomains"][:15]:
            print(f"    - {s}")
    print(f"  IPs:          {len(result['ips'])}")
    print(f"  Technologies: {result['technologies']}")
    print(f"  TLS Issuers:  {result['tls_issuers']}")
    print(f"  ASNs:         {result['asns']}")
    print(f"  Countries:    {result['countries']}")
    print(f"  URL Paths:    {len(result['urls_with_paths'])}")
