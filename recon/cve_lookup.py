"""
VIPER 4.0 - CVE Lookup (NVD + Vulners)
========================================
Passive CVE intelligence from public databases.

Sources:
  - NVD API 2.0 (free, rate-limited: 5 req/30s without key, 50/30s with key)
  - Vulners API (optional, needs VULNERS_API_KEY env var)

CPE string builder from technology + version for precise NVD queries.
Stdlib only (urllib). No external dependencies.
"""

import json
import logging
import os
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from core.key_rotation import KeyRotator

logger = logging.getLogger("viper.recon.cve")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VULNERS_API_URL = "https://vulners.com/api/v3/burp/software/"

# Rate-limit state for NVD
_nvd_last_call = 0.0
_NVD_DELAY_NO_KEY = 6.5   # 5 req / 30s = ~6s between calls
_NVD_DELAY_WITH_KEY = 0.7  # 50 req / 30s

# ── NVD API Key Rotation ─────────────────────────────────────────────────
# Set NVD_API_KEY to a single key or comma-separated list for rotation.
_nvd_keys = [k for k in os.environ.get("NVD_API_KEY", "").split(",") if k.strip()]
_nvd_rotator = KeyRotator(_nvd_keys, rotate_every_n=15) if len(_nvd_keys) > 1 else None


# =============================================================================
# CPE Mappings (subset — common web stack)
# =============================================================================

CPE_MAPPINGS = {
    # Web Servers
    "nginx": ("f5", "nginx"),
    "apache": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_services"),
    "tomcat": ("apache", "tomcat"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "caddy": ("caddyserver", "caddy"),
    "litespeed": ("litespeedtech", "litespeed_web_server"),
    "gunicorn": ("gunicorn", "gunicorn"),
    "traefik": ("traefik", "traefik"),
    "openresty": ("openresty", "openresty"),
    # Languages / Runtimes
    "php": ("php", "php"),
    "python": ("python", "python"),
    "node.js": ("nodejs", "node.js"),
    "ruby": ("ruby-lang", "ruby"),
    "go": ("golang", "go"),
    # Databases
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "memcached": ("memcached", "memcached"),
    # CMS
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "ghost": ("ghost", "ghost"),
    # Frameworks
    "django": ("djangoproject", "django"),
    "laravel": ("laravel", "laravel"),
    "spring": ("vmware", "spring_framework"),
    "flask": ("palletsprojects", "flask"),
    "express": ("expressjs", "express"),
    "rails": ("rubyonrails", "rails"),
    "next.js": ("vercel", "next.js"),
    # JS Libraries
    "jquery": ("jquery", "jquery"),
    "angular": ("angular", "angular"),
    "react": ("facebook", "react"),
    "vue": ("vuejs", "vue.js"),
    "bootstrap": ("getbootstrap", "bootstrap"),
    # Security / Proxy
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "haproxy": ("haproxy", "haproxy"),
    "varnish": ("varnish-software", "varnish_cache"),
    # DevOps
    "grafana": ("grafana", "grafana"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "sonarqube": ("sonarsource", "sonarqube"),
    # Mail
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),
    # CMS (extended)
    "magento": ("adobe", "magento"),
    "typo3": ("typo3", "typo3"),
    "concrete cms": ("concretecms", "concrete_cms"),
    "craft cms": ("craftcms", "craft_cms"),
    "strapi": ("strapi", "strapi"),
    "umbraco": ("umbraco", "umbraco_cms"),
    "adobe experience manager": ("adobe", "experience_manager"),
    "sitecore": ("sitecore", "experience_platform"),
    "dnn": ("dnnsoftware", "dotnetnuke"),
    "kentico": ("kentico", "kentico"),
    "contentful": ("contentful", "contentful"),
    "sanity": ("sanity", "sanity"),
    # Web Servers (extended)
    "cherokee": ("cherokee-project", "cherokee"),
    "uvicorn": ("encode", "uvicorn"),
    "envoy": ("envoyproxy", "envoy"),
    "deno": ("deno", "deno"),
    "tengine": ("alibaba", "tengine"),
    # Languages / Runtimes (extended)
    "perl": ("perl", "perl"),
    # Databases (extended)
    "couchdb": ("apache", "couchdb"),
    "sqlite": ("sqlite", "sqlite"),
    "solr": ("apache", "solr"),
    "adminer": ("adminer", "adminer"),
    "cassandra": ("apache", "cassandra"),
    "neo4j": ("neo4j", "neo4j"),
    "influxdb": ("influxdata", "influxdb"),
    # Frameworks (extended)
    "codeigniter": ("codeigniter", "codeigniter"),
    "symfony": ("sensiolabs", "symfony"),
    "cakephp": ("cakephp", "cakephp"),
    "yii": ("yiiframework", "yii"),
    "nuxt.js": ("nuxt", "nuxt.js"),
    "struts": ("apache", "struts"),
    "coldfusion": ("adobe", "coldfusion"),
    # JS Libraries (extended)
    "moment.js": ("momentjs", "moment"),
    "lodash": ("lodash", "lodash"),
    "handlebars": ("handlebarsjs", "handlebars"),
    "ember.js": ("emberjs", "ember.js"),
    "backbone.js": ("backbonejs", "backbone.js"),
    "dojo": ("dojotoolkit", "dojo"),
    "ckeditor": ("ckeditor", "ckeditor"),
    "tinymce": ("tiny", "tinymce"),
    "prototype": ("prototypejs", "prototype"),
    # E-commerce
    "prestashop": ("prestashop", "prestashop"),
    "opencart": ("opencart", "opencart"),
    "oscommerce": ("oscommerce", "oscommerce"),
    "zen cart": ("zen-cart", "zen_cart"),
    "woocommerce": ("automattic", "woocommerce"),
    "shopify": ("shopify", "shopify"),
    "bigcommerce": ("bigcommerce", "bigcommerce"),
    # Forums / Community
    "discourse": ("discourse", "discourse"),
    "phpbb": ("phpbb", "phpbb"),
    "vbulletin": ("vbulletin", "vbulletin"),
    "mybb": ("mybb", "mybb"),
    "flarum": ("flarum", "flarum"),
    "nodebb": ("nodebb", "nodebb"),
    "mastodon": ("joinmastodon", "mastodon"),
    "mattermost": ("mattermost", "mattermost_server"),
    "vanilla forums": ("vanillaforums", "vanilla_forums"),
    # Wikis
    "mediawiki": ("mediawiki", "mediawiki"),
    "confluence": ("atlassian", "confluence_server"),
    "dokuwiki": ("dokuwiki", "dokuwiki"),
    "xwiki": ("xwiki", "xwiki"),
    "bookstack": ("bookstackapp", "bookstack"),
    # Mail (extended)
    "zimbra": ("synacor", "zimbra_collaboration_suite"),
    "squirrelmail": ("squirrelmail", "squirrelmail"),
    "roundcube": ("roundcube", "webmail"),
    "exchange": ("microsoft", "exchange_server"),
    # DNS
    "bind": ("isc", "bind"),
    "powerdns": ("powerdns", "authoritative_server"),
    "unbound": ("nlnetlabs", "unbound"),
    # FTP
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "pureftpd": ("pureftpd", "pure-ftpd"),
    # Security / Proxies (extended)
    "squid": ("squid-cache", "squid"),
    "kong": ("konghq", "kong_gateway"),
    "f5 big-ip": ("f5", "big-ip_access_policy_manager"),
    "pulse secure": ("pulsesecure", "pulse_connect_secure"),
    # CI/CD & DevOps (extended)
    "nexus": ("sonatype", "nexus_repository_manager"),
    "rabbitmq": ("vmware", "rabbitmq"),
    "kafka": ("apache", "kafka"),
    "zookeeper": ("apache", "zookeeper"),
    "jira": ("atlassian", "jira"),
    "bitbucket": ("atlassian", "bitbucket"),
    "bugzilla": ("mozilla", "bugzilla"),
    "redmine": ("redmine", "redmine"),
    "gitea": ("gitea", "gitea"),
    "teamcity": ("jetbrains", "teamcity"),
    "bamboo": ("atlassian", "bamboo"),
    "artifactory": ("jfrog", "artifactory"),
    # Java Application Servers
    "jetty": ("eclipse", "jetty"),
    "wildfly": ("redhat", "wildfly"),
    "jboss": ("redhat", "jboss_enterprise_application_platform"),
    "glassfish": ("eclipse", "glassfish"),
    "weblogic": ("oracle", "weblogic_server"),
    "websphere": ("ibm", "websphere_application_server"),
    "passenger": ("phusion", "passenger"),
    # Hosting Panels
    "cpanel": ("cpanel", "cpanel"),
    "plesk": ("plesk", "plesk"),
    "directadmin": ("directadmin", "directadmin"),
    "ispconfig": ("ispconfig", "ispconfig"),
    # Monitoring
    "nagios": ("nagios", "nagios"),
    "zabbix": ("zabbix", "zabbix"),
    "prometheus": ("prometheus", "prometheus"),
    # Other
    "phpmyadmin": ("phpmyadmin", "phpmyadmin"),
    "webmin": ("webmin", "webmin"),
    "minio": ("minio", "minio"),
}

# Name normalization aliases
_ALIASES = {
    "apache httpd": "apache", "apache http server": "apache",
    "apache2": "apache", "httpd": "apache",
    "apache tomcat": "tomcat", "apache-coyote": "tomcat",
    "microsoft-iis": "iis", "microsoft iis": "iis",
    "node": "node.js", "nodejs": "node.js",
    "postgres": "postgresql", "mongo": "mongodb",
    "wp": "wordpress",
    "ruby on rails": "rails",
    # Extended aliases
    "apache couchdb": "couchdb", "apache cassandra": "cassandra",
    "apache solr": "solr", "apache kafka": "kafka",
    "apache zookeeper": "zookeeper", "apache struts": "struts",
    "jboss eap": "jboss", "jboss as": "jboss",
    "oracle weblogic": "weblogic", "ibm websphere": "websphere",
    "eclipse jetty": "jetty", "eclipse glassfish": "glassfish",
    "red hat wildfly": "wildfly",
    "dotnetnuke": "dnn",
    "ms exchange": "exchange", "microsoft exchange": "exchange",
    "isc bind": "bind", "named": "bind",
    "nlnetlabs unbound": "unbound",
    "roundcube webmail": "roundcube",
    "zimbra collaboration": "zimbra",
    "jetbrains teamcity": "teamcity",
    "atlassian jira": "jira", "atlassian confluence": "confluence",
    "atlassian bitbucket": "bitbucket", "atlassian bamboo": "bamboo",
    "sonatype nexus": "nexus", "jfrog artifactory": "artifactory",
}


# =============================================================================
# Public API
# =============================================================================

def build_cpe(tech: str, version: str = None) -> Optional[str]:
    """
    Build a CPE 2.3 string from technology name + version.

    Args:
        tech: Technology name (e.g. "nginx", "Apache", "PHP")
        version: Version string (e.g. "1.21.0", "8.1.2")

    Returns:
        CPE string like "cpe:2.3:a:f5:nginx:1.21.0:*:*:*:*:*:*:*"
        or None if technology not recognized.
    """
    name = tech.strip().lower()
    name = _ALIASES.get(name, name)

    if name not in CPE_MAPPINGS:
        return None

    vendor, product = CPE_MAPPINGS[name]
    ver = _extract_semver(version) if version else "*"
    if not ver:
        ver = "*"

    return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"


def lookup_cves(cpe_or_tech: str, version: str = None,
                max_results: int = 20, api_key: str = None) -> List[dict]:
    """
    Look up CVEs from NVD for a given CPE string or technology+version.

    Args:
        cpe_or_tech: Full CPE 2.3 string or technology name
        version: Version (only used if cpe_or_tech is a tech name)
        max_results: Maximum CVEs to return
        api_key: NVD API key (env NVD_API_KEY used if not provided)

    Returns:
        List of {
            "id": "CVE-2021-44228",
            "description": "...",
            "cvss": 10.0,
            "cvss_vector": "...",
            "severity": "CRITICAL",
            "published": "2021-12-10",
            "references": ["https://..."],
            "cpe_match": "cpe:2.3:a:..."
        }
    """
    if not api_key:
        if _nvd_rotator and _nvd_rotator.has_keys:
            api_key = _nvd_rotator.current_key
        else:
            api_key = os.environ.get("NVD_API_KEY", "")

    # Build CPE if tech name given
    if not cpe_or_tech.startswith("cpe:"):
        cpe = build_cpe(cpe_or_tech, version)
        if not cpe:
            logger.debug("No CPE mapping for '%s'", cpe_or_tech)
            return []
    else:
        cpe = cpe_or_tech

    # Rate limit
    _nvd_rate_limit(api_key)

    # Query NVD
    params = f"cpeName={quote(cpe)}&resultsPerPage={max_results}"
    url = f"{NVD_API_URL}?{params}"

    headers = {"User-Agent": "VIPER/4.0"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())

        vulnerabilities = data.get("vulnerabilities", [])
        if _nvd_rotator:
            _nvd_rotator.tick()
        return [_parse_nvd_cve(v, cpe) for v in vulnerabilities[:max_results]]

    except HTTPError as e:
        if e.code == 403:
            logger.warning("NVD API rate limit or key issue (403)")
        elif e.code == 404:
            logger.debug("NVD: no CVEs for %s", cpe)
        else:
            logger.warning("NVD HTTP %d for %s", e.code, cpe)
        return []
    except (URLError, Exception) as e:
        logger.warning("NVD request failed: %s", e)
        return []


def lookup_vulners(query: str, api_key: str = None,
                   max_results: int = 20) -> List[dict]:
    """
    Look up vulnerabilities from Vulners API.

    Args:
        query: Software query (e.g. "nginx 1.21.0")
        api_key: Vulners API key (env VULNERS_API_KEY used if not provided)
        max_results: Maximum results

    Returns:
        List of {
            "id": "CVE-...",
            "title": "...",
            "description": "...",
            "cvss": float,
            "source": "vulners",
            "href": "https://..."
        }
    """
    if not api_key:
        api_key = os.environ.get("VULNERS_API_KEY", "")
    if not api_key:
        logger.debug("No Vulners API key, skipping")
        return []

    payload = json.dumps({
        "software": query,
        "version": "",
        "type": "software",
        "maxVulnerabilities": max_results,
        "apiKey": api_key,
    }).encode()

    try:
        req = Request(
            VULNERS_API_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "VIPER/4.0",
            },
        )
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())

        if data.get("result") != "OK":
            logger.warning("Vulners API error: %s", data.get("data", {}).get("error"))
            return []

        vulns = data.get("data", {}).get("search", [])
        results = []
        for v in vulns[:max_results]:
            source = v.get("_source", {})
            results.append({
                "id": source.get("id", v.get("_id", "")),
                "title": source.get("title", ""),
                "description": source.get("description", "")[:500],
                "cvss": source.get("cvss", {}).get("score", 0),
                "source": "vulners",
                "href": source.get("href", ""),
            })
        return results

    except Exception as e:
        logger.warning("Vulners request failed: %s", e)
        return []


def lookup_cves_for_cpes(cpes: List[str], api_key: str = None) -> Dict[str, List[dict]]:
    """
    Batch CVE lookup for a list of CPE strings (e.g. from Shodan InternetDB).

    Args:
        cpes: List of CPE strings
        api_key: Optional NVD API key

    Returns:
        {cpe_string: [cve_dicts]}
    """
    results = {}
    for cpe in cpes:
        cves = lookup_cves(cpe, api_key=api_key)
        if cves:
            results[cpe] = cves
    return results


# =============================================================================
# Internal helpers
# =============================================================================

def _nvd_rate_limit(api_key: str):
    """Enforce NVD rate limits."""
    global _nvd_last_call
    delay = _NVD_DELAY_WITH_KEY if api_key else _NVD_DELAY_NO_KEY
    elapsed = time.time() - _nvd_last_call
    if elapsed < delay:
        time.sleep(delay - elapsed)
    _nvd_last_call = time.time()


def _parse_nvd_cve(vuln_entry: dict, cpe_match: str) -> dict:
    """Parse a single NVD vulnerability entry."""
    cve = vuln_entry.get("cve", {})
    cve_id = cve.get("id", "")

    # Description
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    # CVSS — prefer v3.1, then v3.0, then v2
    cvss_score = 0.0
    cvss_vector = ""
    severity = "UNKNOWN"
    metrics = cve.get("metrics", {})

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")
            severity = cvss_data.get("baseSeverity",
                                     metric_list[0].get("baseSeverity", "UNKNOWN"))
            break

    # References
    refs = [r.get("url", "") for r in cve.get("references", [])[:5]]

    # Published date
    published = cve.get("published", "")[:10]

    return {
        "id": cve_id,
        "description": desc[:500],
        "cvss": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity.upper(),
        "published": published,
        "references": refs,
        "cpe_match": cpe_match,
    }


def _extract_semver(version: str) -> Optional[str]:
    """Extract clean semantic version from a version string."""
    if not version:
        return None
    version = re.sub(r'^[vV]', '', version.strip())
    match = re.match(r'(\d+(?:\.\d+)+)', version)
    if match:
        return match.group(1)
    match = re.match(r'(\d+)', version)
    return match.group(1) if match else None


# =============================================================================
# Async Vulners API (Lucene search — free tier: 100 req/day)
# =============================================================================

VULNERS_LUCENE_URL = "https://vulners.com/api/v3/search/lucene/"


async def lookup_cves_vulners(query: str, api_key: str = None,
                               max_results: int = 20) -> List[dict]:
    """
    Look up CVEs via the Vulners Lucene search API (async, stdlib-only).

    Uses asyncio.to_thread to avoid blocking the event loop while keeping
    urllib (no aiohttp dependency).

    Args:
        query: Free-text search (e.g. "nginx 1.21.0", "CVE-2021-44228").
        api_key: Vulners API key. Falls back to VULNERS_API_KEY env var.
        max_results: Maximum number of results.

    Returns:
        List of {
            "id": "CVE-...",
            "title": "...",
            "description": "...",
            "cvss": float,
            "severity": "HIGH",
            "source": "vulners",
            "href": "https://...",
            "published": "2021-12-10",
        }
    """
    import asyncio

    if not api_key:
        api_key = os.environ.get("VULNERS_API_KEY", "")
    if not api_key:
        logger.debug("No Vulners API key (set VULNERS_API_KEY), skipping Lucene search")
        return []

    def _sync_fetch():
        params = f"query={quote(query)}&skip=0&size={max_results}&apiKey={quote(api_key)}"
        url = f"{VULNERS_LUCENE_URL}?{params}"
        try:
            req = Request(url, headers={"User-Agent": "VIPER/4.0"})
            with urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            if e.code == 429:
                logger.warning("Vulners rate limit hit (429)")
            else:
                logger.warning("Vulners HTTP %d for query '%s'", e.code, query)
            return None
        except Exception as e:
            logger.warning("Vulners Lucene request failed: %s", e)
            return None

    data = await asyncio.to_thread(_sync_fetch)
    if not data or data.get("result") != "OK":
        if data:
            logger.debug("Vulners non-OK response: %s", data.get("data", {}).get("error", ""))
        return []

    search_results = data.get("data", {}).get("search", [])
    results = []
    for item in search_results[:max_results]:
        src = item.get("_source", {})
        cve_id = src.get("id", item.get("_id", ""))

        # Extract CVSS score
        cvss_obj = src.get("cvss", {})
        if isinstance(cvss_obj, dict):
            cvss_score = cvss_obj.get("score", 0.0)
        elif isinstance(cvss_obj, (int, float)):
            cvss_score = float(cvss_obj)
        else:
            cvss_score = 0.0

        # Derive severity from score
        severity = _cvss_to_severity(cvss_score)

        results.append({
            "id": cve_id,
            "title": src.get("title", ""),
            "description": src.get("description", "")[:500],
            "cvss": cvss_score,
            "severity": severity,
            "source": "vulners",
            "href": src.get("href", f"https://vulners.com/{cve_id}"),
            "published": src.get("published", "")[:10],
        })

    return results


async def lookup_cves_combined(tech: str, version: str = "",
                                max_results: int = 30) -> List[dict]:
    """
    Query both NVD and Vulners, deduplicate by CVE ID, merge CVSS scores.

    NVD is queried synchronously (rate-limited), Vulners via async Lucene.
    Results are merged: if both sources have the same CVE ID, the higher CVSS
    score wins and the entry is tagged with both sources.

    Args:
        tech: Technology name (e.g. "nginx").
        version: Version string (e.g. "1.21.0").
        max_results: Maximum total results after dedup.

    Returns:
        Deduplicated list of CVE dicts, sorted by CVSS descending.
    """
    import asyncio

    # NVD lookup (sync, wrapped in thread to not block)
    async def _nvd():
        return await asyncio.to_thread(lookup_cves, tech, version, max_results)

    # Vulners lookup (already async)
    query = f"{tech} {version}".strip()
    nvd_task = asyncio.ensure_future(_nvd())
    vulners_task = asyncio.ensure_future(lookup_cves_vulners(query, max_results=max_results))

    nvd_results, vulners_results = await asyncio.gather(
        nvd_task, vulners_task, return_exceptions=True
    )

    # Handle exceptions gracefully
    if isinstance(nvd_results, Exception):
        logger.warning("NVD combined lookup failed: %s", nvd_results)
        nvd_results = []
    if isinstance(vulners_results, Exception):
        logger.warning("Vulners combined lookup failed: %s", vulners_results)
        vulners_results = []

    # Merge into a dict keyed by CVE ID
    merged: Dict[str, dict] = {}

    for cve in nvd_results:
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        cve["sources"] = ["nvd"]
        merged[cve_id] = cve

    for cve in vulners_results:
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        # Only merge entries that look like CVE IDs for dedup
        if cve_id in merged:
            existing = merged[cve_id]
            # Keep the higher CVSS score
            if cve.get("cvss", 0) > existing.get("cvss", 0):
                existing["cvss"] = cve["cvss"]
                existing["severity"] = cve.get("severity", existing.get("severity", "UNKNOWN"))
            existing.setdefault("sources", [])
            if "vulners" not in existing["sources"]:
                existing["sources"].append("vulners")
            # Add Vulners href if missing
            if cve.get("href") and not existing.get("href"):
                existing["href"] = cve["href"]
        else:
            cve["sources"] = ["vulners"]
            merged[cve_id] = cve

    # Sort by CVSS descending, take top N
    sorted_cves = sorted(merged.values(), key=lambda c: c.get("cvss", 0), reverse=True)
    return sorted_cves[:max_results]


def _cvss_to_severity(score: float) -> str:
    """Convert a CVSS score to a severity label."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "UNKNOWN"


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cve_lookup.py <technology> [version]")
        print("       python cve_lookup.py cpe:2.3:a:f5:nginx:1.21.0:*:*:*:*:*:*:*")
        sys.exit(1)

    tech = sys.argv[1]
    ver = sys.argv[2] if len(sys.argv) > 2 else None

    if tech.startswith("cpe:"):
        cpe = tech
        print(f"[*] Looking up CVEs for CPE: {cpe}\n")
    else:
        cpe = build_cpe(tech, ver)
        print(f"[*] Technology: {tech} {ver or ''}")
        print(f"[*] CPE: {cpe or '(no mapping)'}\n")

    cves = lookup_cves(tech, ver)
    if not cves:
        print("[-] No CVEs found")
    else:
        print(f"[+] Found {len(cves)} CVEs:\n")
        for c in cves:
            sev = c["severity"]
            print(f"  {c['id']}  CVSS={c['cvss']:<4}  {sev:10s}  {c['description'][:80]}")
