"""
VIPER 5.0 - Unified OSINT Enrichment
======================================
Parallel OSINT enrichment from multiple threat intelligence sources.

Queries Shodan InternetDB, Censys, AlienVault OTX, VirusTotal, and FOFA
in parallel using ThreadPoolExecutor with isolated sessions per source.

All sources degrade gracefully: missing API keys skip paid endpoints,
network errors are caught per-source, and the pipeline never fails.

Stdlib + requests only.
"""

import base64
import json
import logging
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

import requests

logger = logging.getLogger("viper.recon.osint")

# ── Rate limiter for VirusTotal (4 req/min) ─────────────────────────────
_vt_lock = threading.Lock()
_vt_timestamps: List[float] = []
VT_RATE_LIMIT = 4       # requests per window
VT_RATE_WINDOW = 60.0   # seconds


def _vt_rate_wait():
    """Block until a VirusTotal request slot is available (4 req/min)."""
    with _vt_lock:
        now = time.monotonic()
        # Prune old timestamps outside the window
        while _vt_timestamps and _vt_timestamps[0] < now - VT_RATE_WINDOW:
            _vt_timestamps.pop(0)
        if len(_vt_timestamps) >= VT_RATE_LIMIT:
            sleep_for = VT_RATE_WINDOW - (now - _vt_timestamps[0]) + 0.1
            if sleep_for > 0:
                logger.debug("VirusTotal rate limit: sleeping %.1fs", sleep_for)
                time.sleep(sleep_for)
        _vt_timestamps.append(time.monotonic())


# ── Private IP check (shared with shodan_enricher) ──────────────────────

def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return True
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    if all(o == 0 for o in octets):
        return True
    if octets[0] == 169 and octets[1] == 254:
        return True
    return False


def _validate_ip(ip: str) -> bool:
    """Return True if ip is a valid, public IPv4 address."""
    try:
        socket.inet_aton(ip)
    except socket.error:
        return False
    return not _is_private_ip(ip)


# =============================================================================
# OSINTEnricher
# =============================================================================

class OSINTEnricher:
    """Parallel OSINT enrichment from multiple sources.

    Queries Shodan, Censys, OTX, VirusTotal, FOFA in parallel
    using ThreadPoolExecutor with isolated sessions per source.
    """

    def __init__(self, max_workers: int = 5, timeout: int = 15):
        """
        Args:
            max_workers: ThreadPoolExecutor concurrency (one thread per source).
            timeout: Per-source HTTP request timeout in seconds.
        """
        self.max_workers = max_workers
        self.timeout = timeout

        # API keys from environment (all optional)
        self.censys_app_id = os.environ.get("CENSYS_API_ID", "")
        self.censys_secret = os.environ.get("CENSYS_API_SECRET", "")
        self.otx_key = os.environ.get("OTX_API_KEY", "")
        self.vt_key = os.environ.get("VIRUSTOTAL_API_KEY",
                                     os.environ.get("VT_API_KEY", ""))
        self.fofa_email = os.environ.get("FOFA_EMAIL", "")
        self.fofa_key = os.environ.get("FOFA_API_KEY", "")

    # ── Public API ──────────────────────────────────────────────────────

    def enrich_ip(self, ip: str) -> dict:
        """Query all sources for an IP address in parallel.

        Returns:
            {
                "target": ip,
                "type": "ip",
                "sources": {
                    "shodan": {...},
                    "censys": {...},
                    "otx": {...},
                    "virustotal": {...},
                    "fofa": {...},
                },
                "errors": {"source_name": "error message", ...},
                "meta": {"duration_s": float, "sources_ok": int, "sources_err": int}
            }
        """
        ip = ip.strip()
        if not _validate_ip(ip):
            return {
                "target": ip,
                "type": "ip",
                "sources": {},
                "errors": {"validation": "Invalid or private IPv4 address"},
                "meta": {"duration_s": 0, "sources_ok": 0, "sources_err": 1},
            }

        queries: Dict[str, Callable] = {
            "shodan": lambda s: self._query_shodan(s, ip),
            "censys": lambda s: self._query_censys(s, ip),
            "otx": lambda s: self._query_otx(s, ip, indicator_type="IPv4"),
            "virustotal": lambda s: self._query_virustotal(s, ip, vt_type="ip-addresses"),
            "fofa": lambda s: self._query_fofa(s, f'ip="{ip}"'),
        }
        return self._fan_out(ip, "ip", queries)

    def enrich_domain(self, domain: str) -> dict:
        """Query all sources for a domain in parallel.

        Returns same structure as enrich_ip but with domain-relevant data.
        """
        domain = domain.strip().lower()

        queries: Dict[str, Callable] = {
            "shodan": lambda s: self._query_shodan_domain(s, domain),
            "censys": lambda s: self._query_censys_domain(s, domain),
            "otx": lambda s: self._query_otx(s, domain, indicator_type="domain"),
            "virustotal": lambda s: self._query_virustotal(s, domain, vt_type="domains"),
            "fofa": lambda s: self._query_fofa(s, f'domain="{domain}"'),
        }
        return self._fan_out(domain, "domain", queries)

    # ── Fan-out / Fan-in ────────────────────────────────────────────────

    def _fan_out(self, target: str, target_type: str,
                 queries: Dict[str, Callable]) -> dict:
        """Execute all source queries in parallel, collect results."""
        sources: Dict[str, Any] = {}
        errors: Dict[str, str] = {}
        t0 = time.monotonic()

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map = {}
            for name, fn in queries.items():
                # Each source gets its own requests.Session for thread safety
                session = requests.Session()
                session.headers.update({
                    "User-Agent": "VIPER/5.0",
                    "Accept": "application/json",
                })
                future = pool.submit(self._safe_call, name, fn, session)
                future_map[future] = name

            for future in as_completed(future_map):
                name = future_map[future]
                result = future.result()  # _safe_call never raises
                if result.get("_error"):
                    errors[name] = result["_error"]
                    logger.debug("OSINT %s failed for %s: %s",
                                 name, target, result["_error"])
                else:
                    sources[name] = result
                    logger.debug("OSINT %s OK for %s", name, target)

        duration = round(time.monotonic() - t0, 2)
        return {
            "target": target,
            "type": target_type,
            "sources": sources,
            "errors": errors,
            "meta": {
                "duration_s": duration,
                "sources_ok": len(sources),
                "sources_err": len(errors),
            },
        }

    def _safe_call(self, name: str, fn: Callable, session: requests.Session) -> dict:
        """Call a query function, catching ALL exceptions."""
        try:
            return fn(session)
        except requests.Timeout:
            return {"_error": f"Timeout ({self.timeout}s)"}
        except requests.ConnectionError as e:
            return {"_error": f"Connection error: {e}"}
        except Exception as e:
            return {"_error": f"{type(e).__name__}: {e}"}

    # ── Shodan InternetDB (free, no key) ────────────────────────────────

    def _query_shodan(self, session: requests.Session, ip: str) -> dict:
        """Shodan InternetDB (free, no key required)."""
        url = f"https://internetdb.shodan.io/{ip}"
        resp = session.get(url, timeout=self.timeout)

        if resp.status_code == 404:
            return {"ports": [], "hostnames": [], "cpes": [], "vulns": [], "tags": []}
        resp.raise_for_status()

        data = resp.json()
        return {
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "cpes": data.get("cpes", []),
            "vulns": data.get("vulns", []),
            "tags": data.get("tags", []),
        }

    def _query_shodan_domain(self, session: requests.Session, domain: str) -> dict:
        """Shodan InternetDB for domain — resolve to IP first."""
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return {"_error": f"DNS resolution failed for {domain}"}
        return self._query_shodan(session, ip)

    # ── Censys (free tier: 250 queries/month) ───────────────────────────

    def _query_censys(self, session: requests.Session, ip: str) -> dict:
        """Censys host lookup (requires CENSYS_API_ID + CENSYS_API_SECRET)."""
        if not self.censys_app_id or not self.censys_secret:
            return {"_error": "No Censys credentials (CENSYS_API_ID / CENSYS_API_SECRET)"}

        session.auth = (self.censys_app_id, self.censys_secret)
        url = f"https://search.censys.io/api/v2/hosts/{ip}"
        resp = session.get(url, timeout=self.timeout)
        resp.raise_for_status()

        data = resp.json().get("result", {})
        services = []
        for svc in data.get("services", []):
            services.append({
                "port": svc.get("port"),
                "service_name": svc.get("service_name", ""),
                "transport_protocol": svc.get("transport_protocol", ""),
                "software": [s.get("product", "") for s in svc.get("software", [])],
            })

        return {
            "ip": data.get("ip", ip),
            "services": services,
            "operating_system": data.get("operating_system", {}).get("product", ""),
            "autonomous_system": {
                "asn": data.get("autonomous_system", {}).get("asn"),
                "name": data.get("autonomous_system", {}).get("name", ""),
                "bgp_prefix": data.get("autonomous_system", {}).get("bgp_prefix", ""),
            },
            "location": {
                "country": data.get("location", {}).get("country", ""),
                "city": data.get("location", {}).get("city", ""),
            },
            "last_updated": data.get("last_updated_at", ""),
        }

    def _query_censys_domain(self, session: requests.Session, domain: str) -> dict:
        """Censys search for a domain — uses the search endpoint."""
        if not self.censys_app_id or not self.censys_secret:
            return {"_error": "No Censys credentials (CENSYS_API_ID / CENSYS_API_SECRET)"}

        session.auth = (self.censys_app_id, self.censys_secret)
        url = "https://search.censys.io/api/v2/hosts/search"
        params = {"q": f"services.tls.certificates.leaf.names: {domain}", "per_page": 25}
        resp = session.get(url, params=params, timeout=self.timeout)
        resp.raise_for_status()

        data = resp.json().get("result", {})
        hosts = []
        for hit in data.get("hits", []):
            hosts.append({
                "ip": hit.get("ip", ""),
                "services": [
                    {"port": s.get("port"), "service_name": s.get("service_name", "")}
                    for s in hit.get("services", [])
                ],
                "autonomous_system": hit.get("autonomous_system", {}).get("name", ""),
                "location_country": hit.get("location", {}).get("country", ""),
            })
        return {
            "total": data.get("total", 0),
            "hosts": hosts,
        }

    # ── AlienVault OTX (free, no key required for basic) ────────────────

    def _query_otx(self, session: requests.Session, target: str,
                   indicator_type: str = "IPv4") -> dict:
        """AlienVault OTX (free, no key required for basic lookups)."""
        base = "https://otx.alienvault.com/api/v1/indicators"

        if self.otx_key:
            session.headers["X-OTX-API-KEY"] = self.otx_key

        # Fetch general info + reputation
        if indicator_type == "IPv4":
            sections = ["general", "reputation", "malware", "passive_dns"]
        else:
            sections = ["general", "malware", "passive_dns", "whois"]

        result: Dict[str, Any] = {}
        for section in sections:
            url = f"{base}/{indicator_type}/{target}/{section}"
            try:
                resp = session.get(url, timeout=self.timeout)
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                data = resp.json()
            except Exception:
                continue

            if section == "general":
                result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
                result["reputation"] = data.get("reputation", 0)
                result["country"] = data.get("country_name", data.get("country_code", ""))
                result["asn"] = data.get("asn", "")
                # Collect tags from pulses
                pulses = data.get("pulse_info", {}).get("pulses", [])
                tags = set()
                for p in pulses[:20]:
                    tags.update(p.get("tags", []))
                result["pulse_tags"] = sorted(tags)[:30]

            elif section == "reputation":
                rep = data.get("reputation", {})
                if isinstance(rep, dict):
                    result["threat_score"] = rep.get("threat_score", 0)
                    result["activities"] = [
                        a.get("name", "") for a in rep.get("activities", [])
                    ][:10]

            elif section == "malware":
                samples = data.get("data", [])
                result["malware_samples"] = len(samples)
                result["malware_hashes"] = [
                    s.get("hash", "")[:16] + "..." for s in samples[:5]
                ]

            elif section == "passive_dns":
                records = data.get("passive_dns", [])
                result["passive_dns_count"] = len(records)
                result["passive_dns"] = [
                    {
                        "hostname": r.get("hostname", ""),
                        "address": r.get("address", ""),
                        "record_type": r.get("record_type", ""),
                        "first_seen": r.get("first", ""),
                        "last_seen": r.get("last", ""),
                    }
                    for r in records[:20]
                ]

            elif section == "whois":
                result["whois"] = {
                    "registrar": data.get("data", [{}])[0].get("value", "")
                    if data.get("data") else "",
                }

        return result

    # ── VirusTotal (free tier: 4 req/min) ───────────────────────────────

    def _query_virustotal(self, session: requests.Session, target: str,
                          vt_type: str = "ip-addresses") -> dict:
        """VirusTotal lookup (requires VIRUSTOTAL_API_KEY or VT_API_KEY)."""
        if not self.vt_key:
            return {"_error": "No VirusTotal API key (VIRUSTOTAL_API_KEY)"}

        _vt_rate_wait()

        session.headers["x-apikey"] = self.vt_key
        url = f"https://www.virustotal.com/api/v3/{vt_type}/{target}"
        resp = session.get(url, timeout=self.timeout)
        resp.raise_for_status()

        data = resp.json().get("data", {}).get("attributes", {})

        result: Dict[str, Any] = {}

        if vt_type == "ip-addresses":
            result["as_owner"] = data.get("as_owner", "")
            result["asn"] = data.get("asn", 0)
            result["country"] = data.get("country", "")
            result["network"] = data.get("network", "")
            stats = data.get("last_analysis_stats", {})
            result["analysis_stats"] = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
            result["reputation"] = data.get("reputation", 0)

        elif vt_type == "domains":
            result["registrar"] = data.get("registrar", "")
            result["creation_date"] = data.get("creation_date", 0)
            result["last_dns_records"] = [
                {"type": r.get("type", ""), "value": r.get("value", "")}
                for r in data.get("last_dns_records", [])[:10]
            ]
            stats = data.get("last_analysis_stats", {})
            result["analysis_stats"] = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
            result["reputation"] = data.get("reputation", 0)
            result["categories"] = data.get("categories", {})

        return result

    # ── FOFA (free tier) ────────────────────────────────────────────────

    def _query_fofa(self, session: requests.Session, query: str) -> dict:
        """FOFA search (requires FOFA_EMAIL + FOFA_API_KEY)."""
        if not self.fofa_email or not self.fofa_key:
            return {"_error": "No FOFA credentials (FOFA_EMAIL / FOFA_API_KEY)"}

        b64_query = base64.b64encode(query.encode()).decode()
        url = "https://fofa.info/api/v1/search/all"
        params = {
            "email": self.fofa_email,
            "key": self.fofa_key,
            "qbase64": b64_query,
            "size": 50,
            "fields": "ip,port,protocol,host,title,server,banner",
        }
        resp = session.get(url, params=params, timeout=self.timeout)
        resp.raise_for_status()

        data = resp.json()
        if data.get("error"):
            return {"_error": f"FOFA error: {data.get('errmsg', 'unknown')}"}

        results = data.get("results", [])
        field_names = ["ip", "port", "protocol", "host", "title", "server", "banner"]

        hosts = []
        for row in results[:50]:
            entry = {}
            for i, field in enumerate(field_names):
                if i < len(row):
                    entry[field] = row[i]
            hosts.append(entry)

        return {
            "total": data.get("size", 0),
            "hosts": hosts,
        }


# =============================================================================
# Convenience functions
# =============================================================================

_default_enricher: Optional[OSINTEnricher] = None


def get_enricher(**kwargs) -> OSINTEnricher:
    """Get or create a module-level OSINTEnricher singleton."""
    global _default_enricher
    if _default_enricher is None:
        _default_enricher = OSINTEnricher(**kwargs)
    return _default_enricher


def enrich_ip(ip: str, **kwargs) -> dict:
    """Convenience: enrich an IP using the default enricher."""
    return get_enricher(**kwargs).enrich_ip(ip)


def enrich_domain(domain: str, **kwargs) -> dict:
    """Convenience: enrich a domain using the default enricher."""
    return get_enricher(**kwargs).enrich_domain(domain)


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python osint_enricher.py <ip_or_domain> [ip2] [domain2] ...")
        print("Example: python osint_enricher.py 8.8.8.8 example.com")
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s")

    enricher = OSINTEnricher()
    for target in sys.argv[1:]:
        # Detect IP vs domain
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            is_ip = False

        if is_ip:
            print(f"\n[*] Enriching IP: {target}")
            result = enricher.enrich_ip(target)
        else:
            print(f"\n[*] Enriching domain: {target}")
            result = enricher.enrich_domain(target)

        print(f"    Duration: {result['meta']['duration_s']}s")
        print(f"    Sources OK: {result['meta']['sources_ok']}  "
              f"Errors: {result['meta']['sources_err']}")

        for name, data in result["sources"].items():
            print(f"\n  [{name}]")
            for k, v in data.items():
                val = str(v)
                if len(val) > 120:
                    val = val[:120] + "..."
                print(f"    {k}: {val}")

        if result["errors"]:
            print(f"\n  [errors]")
            for name, msg in result["errors"].items():
                print(f"    {name}: {msg}")
