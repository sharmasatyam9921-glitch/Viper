"""
VIPER 4.0 - Shodan InternetDB Enrichment
==========================================
Free IP enrichment via Shodan's InternetDB API (no API key required).

InternetDB (https://internetdb.shodan.io/) provides:
    - Open ports
    - Hostnames (reverse DNS)
    - CPEs (Common Platform Enumeration)
    - Known vulnerabilities (CVE IDs)
    - Tags (e.g., "cloud", "vpn", "self-signed")

Rate limits are generous for the free tier. No auth needed.

No external dependencies. Stdlib only (urllib, asyncio, json, socket).
"""

import asyncio
import json
import socket
import time
from typing import Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


INTERNETDB_URL = "https://internetdb.shodan.io/"


# =============================================================================
# Synchronous API
# =============================================================================

def enrich_ip_sync(ip: str, timeout: int = 10) -> dict:
    """
    Query Shodan InternetDB for IP enrichment. Free, no API key.

    Args:
        ip: IPv4 address to query
        timeout: Request timeout in seconds

    Returns:
        {
            "ip": "1.2.3.4",
            "ports": [80, 443, 8080],
            "hostnames": ["example.com"],
            "cpes": ["cpe:/a:apache:http_server:2.4.41"],
            "vulns": ["CVE-2021-41773"],
            "tags": ["cloud"]
        }
        On error, returns {"ip": ip, "error": "message", ...} with empty lists.
    """
    ip = ip.strip()

    # Validate IP format
    try:
        socket.inet_aton(ip)
    except socket.error:
        return _empty_result(ip, error="Invalid IPv4 address")

    # Skip private/reserved IPs
    if _is_private_ip(ip):
        return _empty_result(ip, error="Private/reserved IP")

    url = f"{INTERNETDB_URL}{ip}"
    try:
        req = Request(url, headers={
            "Accept": "application/json",
            "User-Agent": "VIPER/4.0"
        })
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())

        return {
            "ip": data.get("ip", ip),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "cpes": data.get("cpes", []),
            "vulns": data.get("vulns", []),
            "tags": data.get("tags", []),
        }

    except HTTPError as e:
        if e.code == 404:
            # IP not found in InternetDB = no open ports observed
            return _empty_result(ip, error=None)
        return _empty_result(ip, error=f"HTTP {e.code}")
    except URLError as e:
        return _empty_result(ip, error=f"Connection error: {e.reason}")
    except Exception as e:
        return _empty_result(ip, error=str(e))


def enrich_ips_sync(ips: list, delay: float = 0.5,
                    timeout: int = 10) -> List[dict]:
    """
    Bulk IP enrichment (synchronous) with rate limiting.

    Args:
        ips: List of IPv4 addresses
        delay: Delay between requests in seconds
        timeout: Per-request timeout

    Returns:
        List of enrichment dicts (same order as input).
    """
    results = []
    for i, ip in enumerate(ips):
        result = enrich_ip_sync(ip, timeout=timeout)
        results.append(result)
        if i < len(ips) - 1 and delay > 0:
            time.sleep(delay)
    return results


# =============================================================================
# Async API
# =============================================================================

async def enrich_ip(ip: str, timeout: int = 10) -> dict:
    """
    Async version of enrich_ip_sync. Runs the sync call in a thread executor.

    Args:
        ip: IPv4 address to query
        timeout: Request timeout in seconds

    Returns:
        Same dict format as enrich_ip_sync.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, enrich_ip_sync, ip, timeout)


async def enrich_ips(ips: list, concurrency: int = 5,
                     delay: float = 0.3) -> List[dict]:
    """
    Bulk async IP enrichment with concurrency control and rate limiting.

    Args:
        ips: List of IPv4 addresses
        concurrency: Max concurrent requests
        delay: Delay between request batches in seconds

    Returns:
        List of enrichment dicts (same order as input).
    """
    semaphore = asyncio.Semaphore(concurrency)
    results = [None] * len(ips)

    async def _enrich(idx: int, ip: str):
        async with semaphore:
            results[idx] = await enrich_ip(ip)
            if delay > 0:
                await asyncio.sleep(delay)

    tasks = [_enrich(i, ip) for i, ip in enumerate(ips)]
    await asyncio.gather(*tasks)
    return results


# =============================================================================
# Analysis Helpers
# =============================================================================

def summarize_enrichments(results: list) -> dict:
    """
    Summarize bulk enrichment results.

    Returns:
        {
            "total_ips": N,
            "ips_with_ports": N,
            "ips_with_vulns": N,
            "all_ports": {port: count},
            "all_vulns": {cve: count},
            "all_cpes": {cpe: count},
            "all_tags": {tag: count},
            "all_hostnames": [...]
        }
    """
    all_ports: Dict[int, int] = {}
    all_vulns: Dict[str, int] = {}
    all_cpes: Dict[str, int] = {}
    all_tags: Dict[str, int] = {}
    all_hostnames: List[str] = []
    ips_with_ports = 0
    ips_with_vulns = 0

    for r in results:
        if r.get("error"):
            continue

        ports = r.get("ports", [])
        if ports:
            ips_with_ports += 1
        for p in ports:
            all_ports[p] = all_ports.get(p, 0) + 1

        vulns = r.get("vulns", [])
        if vulns:
            ips_with_vulns += 1
        for v in vulns:
            all_vulns[v] = all_vulns.get(v, 0) + 1

        for c in r.get("cpes", []):
            all_cpes[c] = all_cpes.get(c, 0) + 1

        for t in r.get("tags", []):
            all_tags[t] = all_tags.get(t, 0) + 1

        all_hostnames.extend(r.get("hostnames", []))

    return {
        "total_ips": len(results),
        "ips_with_ports": ips_with_ports,
        "ips_with_vulns": ips_with_vulns,
        "all_ports": dict(sorted(all_ports.items(), key=lambda x: x[1], reverse=True)),
        "all_vulns": dict(sorted(all_vulns.items(), key=lambda x: x[1], reverse=True)),
        "all_cpes": dict(sorted(all_cpes.items(), key=lambda x: x[1], reverse=True)),
        "all_tags": dict(sorted(all_tags.items(), key=lambda x: x[1], reverse=True)),
        "all_hostnames": sorted(set(all_hostnames)),
        "top_ports": sorted(all_ports.keys())[:20],
        "top_vulns": list(all_vulns.keys())[:20],
    }


def extract_cves(results: list) -> List[str]:
    """Extract unique CVE IDs from enrichment results."""
    cves = set()
    for r in results:
        for v in r.get("vulns", []):
            if v.upper().startswith("CVE-"):
                cves.add(v.upper())
    return sorted(cves)


# =============================================================================
# Private Helpers
# =============================================================================

def _empty_result(ip: str, error: Optional[str] = None) -> dict:
    """Return an empty enrichment result."""
    result = {
        "ip": ip,
        "ports": [],
        "hostnames": [],
        "cpes": [],
        "vulns": [],
        "tags": [],
    }
    if error:
        result["error"] = error
    return result


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return True

    # 10.0.0.0/8
    if octets[0] == 10:
        return True
    # 172.16.0.0/12
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    # 192.168.0.0/16
    if octets[0] == 192 and octets[1] == 168:
        return True
    # 127.0.0.0/8
    if octets[0] == 127:
        return True
    # 0.0.0.0
    if all(o == 0 for o in octets):
        return True
    # 169.254.0.0/16 (link-local)
    if octets[0] == 169 and octets[1] == 254:
        return True

    return False


# =============================================================================
# CLI Entry Point
# =============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python shodan_enricher.py <ip> [ip2] [ip3] ...")
        print("Example: python shodan_enricher.py 8.8.8.8 1.1.1.1")
        sys.exit(1)

    ips = sys.argv[1:]
    print(f"[*] Querying Shodan InternetDB for {len(ips)} IP(s)...\n")

    for ip in ips:
        result = enrich_ip_sync(ip)
        print(f"  IP: {result['ip']}")

        if result.get("error"):
            print(f"    Error: {result['error']}")
        else:
            if result["ports"]:
                print(f"    Ports:     {result['ports']}")
            if result["hostnames"]:
                print(f"    Hostnames: {result['hostnames']}")
            if result["cpes"]:
                print(f"    CPEs:      {result['cpes'][:5]}")
            if result["vulns"]:
                print(f"    Vulns:     {result['vulns'][:10]}")
            if result["tags"]:
                print(f"    Tags:      {result['tags']}")
            if not any([result["ports"], result["hostnames"], result["vulns"]]):
                print(f"    (no data in InternetDB)")
        print()

    if len(ips) > 1:
        results = [enrich_ip_sync(ip) for ip in ips]
        summary = summarize_enrichments(results)
        print(f"[*] Summary:")
        print(f"    IPs with open ports: {summary['ips_with_ports']}/{summary['total_ips']}")
        print(f"    IPs with vulns:      {summary['ips_with_vulns']}/{summary['total_ips']}")
        print(f"    Unique CVEs:         {len(summary['all_vulns'])}")
        print(f"    Top ports:           {summary['top_ports'][:10]}")
