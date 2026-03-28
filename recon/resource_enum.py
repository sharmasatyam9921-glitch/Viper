#!/usr/bin/env python3
"""
VIPER 4.0 Resource Enumerator — Parallel endpoint discovery using multiple tools.

Runs Katana, GAU, Wayback CDX, and JS analysis concurrently via ThreadPoolExecutor,
then deduplicates and classifies all discovered endpoints.

Tools (graceful fallback if not installed):
  - Katana: active crawling with JS rendering
  - GAU: passive URL harvesting from archives
  - Wayback CDX API: direct archive query
  - JS Analysis: regex-based endpoint/secret extraction from JS files

Usage:
    results = await run_resource_enum("https://target.com")
    # or synchronously:
    results = run_resource_enum_sync("https://target.com")
"""

import asyncio
import json
import logging
import re
import shutil
import subprocess
import ssl
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

import aiohttp

logger = logging.getLogger("viper.resource_enum")

HACKAGENT_DIR = Path(__file__).parent.parent
DATA_DIR = HACKAGENT_DIR / "data" / "resource_enum"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Timeout for external tool subprocesses (seconds)
TOOL_TIMEOUT = 300
# Max concurrent JS file downloads
JS_DOWNLOAD_CONCURRENCY = 10


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ResourceEnumResults:
    """Structured results from resource enumeration."""
    urls: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    auth_endpoints: List[str] = field(default_factory=list)
    file_endpoints: List[str] = field(default_factory=list)
    admin_endpoints: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    js_secrets: List[Dict] = field(default_factory=list)       # {type, value, file}
    parameters: List[Dict] = field(default_factory=list)       # {name, url, type}
    forms: List[Dict] = field(default_factory=list)            # {action, method, inputs}
    total_unique: int = 0

    def to_dict(self) -> dict:
        return {
            "urls": self.urls,
            "api_endpoints": self.api_endpoints,
            "auth_endpoints": self.auth_endpoints,
            "file_endpoints": self.file_endpoints,
            "admin_endpoints": self.admin_endpoints,
            "js_files": self.js_files,
            "js_secrets": self.js_secrets,
            "parameters": self.parameters,
            "forms": self.forms,
            "total_unique": self.total_unique,
        }


# ---------------------------------------------------------------------------
# Classification patterns
# ---------------------------------------------------------------------------

_API_PATTERNS = re.compile(
    r'/(?:api|v[0-9]+|graphql|rest|rpc|jsonrpc|grpc|ws)(?:/|$|\?)', re.I
)
_AUTH_PATTERNS = re.compile(
    r'/(?:login|logout|signin|signup|register|auth|oauth|sso|saml|'
    r'forgot|reset[-_]?password|token|session|2fa|mfa|verify)(?:/|$|\?)', re.I
)
_FILE_PATTERNS = re.compile(
    r'/(?:upload|download|file|attachment|media|import|export|'
    r'multipart|document|blob|asset)(?:/|$|\?)', re.I
)
_ADMIN_PATTERNS = re.compile(
    r'/(?:admin|dashboard|panel|console|manage|cms|backend|'
    r'control|settings|config|debug|phpinfo|phpmyadmin|'
    r'wp-admin|wp-login|administrator)(?:/|$|\?)', re.I
)

_INTERESTING_PARAMS = {
    "id", "user", "uid", "user_id", "username", "email",
    "file", "filename", "path", "filepath", "dir", "folder",
    "url", "uri", "link", "href", "redirect", "return", "next", "goto", "redir",
    "callback", "cb", "jsonp",
    "token", "key", "api_key", "apikey", "secret", "access_token",
    "search", "query", "q", "s", "keyword",
    "page", "limit", "offset", "sort", "order",
    "cmd", "exec", "command", "run",
    "template", "tpl", "view", "layout",
    "lang", "locale", "debug", "test",
}

# JS secret patterns (reuse from web_crawler)
_SECRET_PATTERNS = [
    ("aws_key", r'(?:AKIA|ASIA)[A-Z0-9]{16}'),
    ("aws_secret", r'(?:aws_secret|secret_key|secretAccessKey)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']'),
    ("google_api_key", r'AIza[A-Za-z0-9_-]{35}'),
    ("github_token", r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'),
    ("slack_token", r'xox[bporas]-[A-Za-z0-9-]+'),
    ("jwt_token", r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    ("private_key", r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    ("generic_secret", r'(?:secret|token|password|passwd|api_key|apikey|access_key)\s*[:=]\s*["\']([^"\']{8,})["\']'),
    ("firebase_url", r'https://[a-z0-9-]+\.firebaseio\.com'),
    ("stripe_key", r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}'),
    ("sendgrid_key", r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
]

_JS_ENDPOINT_PATTERNS = [
    r'["\'](/api/[^"\'\s]+)["\']',
    r'["\'](/v[0-9]+/[^"\'\s]+)["\']',
    r'fetch\s*\(\s*["\']([^"\']+)["\']',
    r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
    r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
    r'XMLHttpRequest[^;]*\.open\s*\(\s*["\'][^"\']*["\']\s*,\s*["\']([^"\']+)["\']',
    r'["\'](/graphql[^"\'\s]*)["\']',
    r'["\'](/admin[^"\'\s]*)["\']',
    r'["\'](/auth[^"\'\s]*)["\']',
    r'["\'](/upload[^"\'\s]*)["\']',
    r'["\'](/webhook[^"\'\s]*)["\']',
    r'(?:endpoint|baseUrl|base_url|apiUrl|api_url)\s*[:=]\s*["\']([^"\']+)["\']',
]


# ---------------------------------------------------------------------------
# Tool check
# ---------------------------------------------------------------------------

def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run_subprocess(cmd: List[str], timeout: int = TOOL_TIMEOUT) -> Tuple[bool, str]:
    """Run a subprocess, return (success, stdout). Graceful on missing tool."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return (result.returncode == 0, result.stdout)
    except FileNotFoundError:
        logger.warning(f"Tool not found: {cmd[0]}")
        return (False, "")
    except subprocess.TimeoutExpired:
        logger.warning(f"Tool timed out after {timeout}s: {cmd[0]}")
        return (False, "")
    except Exception as e:
        logger.warning(f"Tool error ({cmd[0]}): {e}")
        return (False, "")


# ---------------------------------------------------------------------------
# Katana — active crawling
# ---------------------------------------------------------------------------

def _run_katana(url: str, depth: int = 3, timeout: int = TOOL_TIMEOUT) -> Set[str]:
    """Run katana crawler and return discovered URLs."""
    if not _tool_available("katana"):
        logger.info("[Katana] Not installed, skipping active crawl")
        return set()

    logger.info(f"[Katana] Crawling {url} (depth={depth})")
    cmd = [
        "katana", "-u", url, "-d", str(depth),
        "-jc",                       # JavaScript crawling
        "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
        "-silent",
        "-no-color",
        "-timeout", str(min(timeout, 30)),
        "-rate-limit", "50",
    ]

    ok, stdout = _run_subprocess(cmd, timeout=timeout)
    if not ok:
        logger.warning("[Katana] Crawl failed or returned no results")
        return set()

    urls = set()
    for line in stdout.strip().splitlines():
        line = line.strip()
        if line and line.startswith(("http://", "https://")):
            urls.add(line)

    logger.info(f"[Katana] Discovered {len(urls)} URLs")
    return urls


# ---------------------------------------------------------------------------
# GAU — passive URL harvesting
# ---------------------------------------------------------------------------

def _run_gau(domain: str, timeout: int = TOOL_TIMEOUT) -> Set[str]:
    """Run gau to fetch historical URLs from archives."""
    if not _tool_available("gau"):
        logger.info("[GAU] Not installed, skipping passive discovery")
        return set()

    logger.info(f"[GAU] Fetching archived URLs for {domain}")
    cmd = [
        "gau", domain,
        "--threads", "5",
        "--providers", "wayback,commoncrawl,otx,urlscan",
    ]

    ok, stdout = _run_subprocess(cmd, timeout=timeout)
    if not ok:
        logger.warning("[GAU] Discovery failed or returned no results")
        return set()

    # Filter out static assets
    blacklist_ext = {".png", ".jpg", ".jpeg", ".gif", ".css", ".svg",
                     ".ico", ".woff", ".woff2", ".ttf", ".eot"}
    urls = set()
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        path_lower = urlparse(line).path.lower()
        if not any(path_lower.endswith(ext) for ext in blacklist_ext):
            urls.add(line)

    logger.info(f"[GAU] Discovered {len(urls)} URLs")
    return urls


# ---------------------------------------------------------------------------
# Wayback CDX API — direct archive query
# ---------------------------------------------------------------------------

def _run_wayback_cdx(domain: str, timeout: int = 60) -> Set[str]:
    """Query Wayback Machine CDX API for archived URLs."""
    logger.info(f"[Wayback] Querying CDX API for *.{domain}")
    cdx_url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=5000"
    )

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        import urllib.request
        req = urllib.request.Request(cdx_url, headers={"User-Agent": "VIPER/4.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())

        # First row is header ["original"], rest are values
        urls = set()
        blacklist_ext = {".png", ".jpg", ".jpeg", ".gif", ".css", ".svg",
                         ".ico", ".woff", ".woff2", ".ttf", ".eot"}
        for row in data[1:]:  # skip header
            if row and isinstance(row, list):
                url = row[0]
                path_lower = urlparse(url).path.lower()
                if not any(path_lower.endswith(ext) for ext in blacklist_ext):
                    urls.add(url)

        logger.info(f"[Wayback] Discovered {len(urls)} URLs")
        return urls

    except Exception as e:
        logger.warning(f"[Wayback] CDX query failed: {e}")
        return set()


# ---------------------------------------------------------------------------
# JS Analysis — download JS files and extract endpoints/secrets
# ---------------------------------------------------------------------------

def _download_js(url: str, session: aiohttp.ClientSession) -> Optional[Tuple[str, str]]:
    """Download a single JS file. Returns (url, content) or None."""
    # This is a sync wrapper — actual async download happens in _analyze_js_files
    pass


async def _fetch_js_content(url: str, session: aiohttp.ClientSession) -> Optional[Tuple[str, str]]:
    """Async fetch of a JS file."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15),
                               ssl=False) as resp:
            if resp.status == 200:
                content = await resp.text(errors="replace")
                return (url, content)
    except Exception:
        pass
    return None


def _extract_from_js(content: str, source_url: str, base_url: str) -> Tuple[Set[str], List[Dict]]:
    """Extract endpoints and secrets from JS content."""
    endpoints = set()
    secrets = []

    # Extract endpoints
    for pattern in _JS_ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, content):
            ep = match.group(1)
            if ep.startswith("/"):
                ep = urljoin(base_url, ep)
            if ep.startswith(("http://", "https://", "/")):
                endpoints.add(ep)

    # Extract secrets
    for secret_type, pattern in _SECRET_PATTERNS:
        for match in re.finditer(pattern, content):
            value = match.group(1) if match.lastindex else match.group(0)
            # Skip common false positives
            if len(value) < 8 or value in ("password", "username", "changeme"):
                continue
            secrets.append({
                "type": secret_type,
                "value": value[:80],  # truncate long matches
                "file": source_url,
            })

    return endpoints, secrets


async def _analyze_js_files(
    js_urls: List[str], base_url: str
) -> Tuple[Set[str], List[Dict]]:
    """Download and analyze JS files for endpoints and secrets."""
    if not js_urls:
        return set(), []

    js_urls = js_urls[:100]  # cap at 100 files
    logger.info(f"[JS] Analyzing {len(js_urls)} JavaScript files")

    all_endpoints: Set[str] = set()
    all_secrets: List[Dict] = []

    connector = aiohttp.TCPConnector(limit=JS_DOWNLOAD_CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(
        connector=connector,
        headers={"User-Agent": "Mozilla/5.0 VIPER/4.0"}
    ) as session:
        tasks = [_fetch_js_content(url, session) for url in js_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        downloaded = 0
        for result in results:
            if isinstance(result, Exception) or result is None:
                continue
            url, content = result
            downloaded += 1
            endpoints, secrets = _extract_from_js(content, url, base_url)
            all_endpoints.update(endpoints)
            all_secrets.extend(secrets)

        logger.info(f"[JS] Downloaded {downloaded}/{len(js_urls)} files, "
                     f"found {len(all_endpoints)} endpoints, {len(all_secrets)} secrets")

    return all_endpoints, all_secrets


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

def _classify_url(url: str) -> Optional[str]:
    """Classify a URL into a category. Returns category name or None."""
    if _API_PATTERNS.search(url):
        return "api"
    if _AUTH_PATTERNS.search(url):
        return "auth"
    if _FILE_PATTERNS.search(url):
        return "file"
    if _ADMIN_PATTERNS.search(url):
        return "admin"
    return None


def _extract_parameters(url: str) -> List[Dict]:
    """Extract query parameters from a URL and classify them."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    results = []
    for name in params:
        param_type = "interesting" if name.lower() in _INTERESTING_PARAMS else "standard"
        results.append({"name": name, "url": url, "type": param_type})
    return results


def _is_js_url(url: str) -> bool:
    """Check if URL points to a JavaScript file."""
    path = urlparse(url).path.lower()
    return path.endswith(".js") or path.endswith(".mjs") or ".js?" in path


# ---------------------------------------------------------------------------
# ParamSpider — passive URL parameter mining
# ---------------------------------------------------------------------------

def _run_paramspider_phase(
    domain: str, placeholder: str = "FUZZ", timeout: int = TOOL_TIMEOUT
) -> Dict:
    """Run ParamSpider passive discovery (called from ThreadPoolExecutor)."""
    try:
        from recon.paramspider_discovery import (
            paramspider_available,
            run_paramspider_discovery,
        )
        if not paramspider_available():
            logger.info("[ParamSpider] Not installed, skipping passive param mining")
            return {"urls": [], "params": [], "stats": {"skipped": True}}

        return run_paramspider_discovery(
            target_domains={domain},
            placeholder=placeholder,
            timeout_per_domain=min(timeout, 120),
        )
    except ImportError:
        logger.warning("[ParamSpider] Module not available — skipping")
        return {"urls": [], "params": [], "stats": {"skipped": True}}
    except Exception as e:
        logger.warning(f"[ParamSpider] Error: {e}")
        return {"urls": [], "params": [], "stats": {"skipped": True, "error": str(e)}}


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

async def run_resource_enum(
    target: str,
    depth: int = 3,
    timeout: int = TOOL_TIMEOUT,
    enable_katana: bool = True,
    enable_gau: bool = True,
    enable_wayback: bool = True,
    enable_js_analysis: bool = True,
    enable_arjun: bool = True,
    enable_paramspider: bool = True,
    paramspider_placeholder: str = "FUZZ",
    arjun_max_endpoints: int = 20,
    arjun_rate_limit: int = 0,
    arjun_proxy: Optional[str] = None,
    arjun_methods: Optional[List[str]] = None,
    enable_kiterunner: bool = True,
    enable_ffuf: bool = True,
    ffuf_wordlist: Optional[str] = None,
    ffuf_extensions: Optional[List[str]] = None,
    ffuf_proxy: Optional[str] = None,
    ffuf_rate_limit: int = 0,
    kiterunner_proxy: Optional[str] = None,
) -> ResourceEnumResults:
    """
    Run parallel endpoint discovery and classification.

    Args:
        target: Target URL (e.g., https://example.com)
        depth: Katana crawl depth
        timeout: Per-tool timeout in seconds
        enable_katana: Run katana active crawl
        enable_gau: Run GAU passive discovery
        enable_wayback: Query Wayback CDX API
        enable_js_analysis: Analyze discovered JS files
        enable_arjun: Run Arjun parameter discovery on param-less endpoints
        enable_paramspider: Run ParamSpider passive param mining via Wayback Machine
        paramspider_placeholder: Placeholder for ParamSpider param values (default "FUZZ")
        arjun_max_endpoints: Max endpoints to scan with Arjun (default 20)
        arjun_rate_limit: Arjun rate limit (0 = unlimited)
        arjun_proxy: Proxy URL for Arjun (e.g. socks5://127.0.0.1:9050)
        arjun_methods: HTTP methods for Arjun (default: ["GET", "POST", "JSON"])
        enable_kiterunner: Run Kiterunner API discovery (post-crawl)
        enable_ffuf: Run ffuf directory fuzzing (post-crawl)
        ffuf_wordlist: Path to wordlist for ffuf (auto-detected if None)
        ffuf_extensions: File extensions for ffuf (e.g. [".php", ".bak"])
        ffuf_proxy: Proxy URL for ffuf
        ffuf_rate_limit: ffuf rate limit (0 = unlimited)
        kiterunner_proxy: Proxy URL for Kiterunner

    Returns:
        ResourceEnumResults with classified endpoints
    """
    start = time.time()
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    logger.info(f"{'='*60}")
    logger.info(f"[ResourceEnum] Starting parallel endpoint discovery")
    logger.info(f"[ResourceEnum] Target: {target}")
    logger.info(f"[ResourceEnum] Domain: {domain}")
    logger.info(f"{'='*60}")

    # Phase 1: Run discovery tools in parallel via ThreadPoolExecutor
    all_urls: Set[str] = set()
    paramspider_result: Optional[Dict] = None

    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="recon") as pool:
        futures = {}

        if enable_katana:
            futures["katana"] = pool.submit(_run_katana, target, depth, timeout)
        if enable_gau:
            futures["gau"] = pool.submit(_run_gau, domain, timeout)
        if enable_wayback:
            futures["wayback"] = pool.submit(_run_wayback_cdx, domain, min(timeout, 60))
        if enable_paramspider:
            futures["paramspider"] = pool.submit(
                _run_paramspider_phase, domain, paramspider_placeholder, timeout
            )

        for name, future in futures.items():
            try:
                result = future.result(timeout=timeout + 30)
                if name == "paramspider":
                    # ParamSpider returns a dict, not a set
                    paramspider_result = result
                    ps_urls = set(result.get("urls", []))
                    logger.info(f"[ResourceEnum] {name}: {len(ps_urls)} URLs")
                    all_urls.update(ps_urls)
                else:
                    logger.info(f"[ResourceEnum] {name}: {len(result)} URLs")
                    all_urls.update(result)
            except Exception as e:
                logger.warning(f"[ResourceEnum] {name} failed: {e}")

    logger.info(f"[ResourceEnum] Total raw URLs: {len(all_urls)}")

    # Phase 2: JS analysis on discovered JS files
    js_urls = sorted(u for u in all_urls if _is_js_url(u))
    js_endpoints: Set[str] = set()
    js_secrets: List[Dict] = []

    if enable_js_analysis and js_urls:
        js_endpoints, js_secrets = await _analyze_js_files(js_urls, base_url)
        all_urls.update(js_endpoints)

    # Phase 3: Deduplicate and classify
    unique_urls = sorted(all_urls)
    api_eps: List[str] = []
    auth_eps: List[str] = []
    file_eps: List[str] = []
    admin_eps: List[str] = []
    all_params: List[Dict] = []
    seen_params: Set[str] = set()

    for url in unique_urls:
        cat = _classify_url(url)
        if cat == "api":
            api_eps.append(url)
        elif cat == "auth":
            auth_eps.append(url)
        elif cat == "file":
            file_eps.append(url)
        elif cat == "admin":
            admin_eps.append(url)

        # Extract parameters
        for param in _extract_parameters(url):
            key = f"{param['name']}:{param['url']}"
            if key not in seen_params:
                seen_params.add(key)
                all_params.append(param)

    # Phase 3b: Merge ParamSpider classified params
    paramspider_new_params = 0
    if paramspider_result and paramspider_result.get("params"):
        for p in paramspider_result["params"]:
            key = f"{p['name']}:{p['url']}"
            if key not in seen_params:
                seen_params.add(key)
                all_params.append({
                    "name": p["name"],
                    "url": p["url"],
                    "type": p.get("category", "standard"),
                    "source": "paramspider",
                })
                paramspider_new_params += 1
        logger.info(f"[ResourceEnum] ParamSpider: merged {paramspider_new_params} new params")

    # Phase 4: Arjun parameter discovery (post-crawl)
    # Only run on endpoints that have no discovered parameters yet.
    arjun_params: List[Dict] = []
    if enable_arjun:
        try:
            from recon.arjun_discovery import (
                arjun_available as _arjun_ok,
                urls_needing_param_discovery,
                run_arjun_discovery as _run_arjun,
                merge_arjun_into_resource_results,
            )
            if _arjun_ok():
                arjun_targets = urls_needing_param_discovery(
                    unique_urls, seen_params, max_endpoints=arjun_max_endpoints,
                )
                if arjun_targets:
                    logger.info(f"[ResourceEnum] Arjun: probing {len(arjun_targets)} param-less endpoints")
                    arjun_disc = await _run_arjun(
                        arjun_targets,
                        methods=arjun_methods,
                        rate_limit=arjun_rate_limit,
                        proxy=arjun_proxy,
                        max_endpoints=arjun_max_endpoints,
                    )
                    # Collect arjun params into all_params + seen_params
                    for r in arjun_disc.results:
                        for p in r.params:
                            key = f"{p['name']}:{r.url}"
                            if key not in seen_params:
                                seen_params.add(key)
                                entry = {
                                    "name": p["name"],
                                    "url": r.url,
                                    "type": p["classification"],
                                    "method": r.method,
                                    "source": "arjun",
                                }
                                all_params.append(entry)
                                arjun_params.append(entry)
                    logger.info(f"[ResourceEnum] Arjun: discovered {len(arjun_params)} new parameters")
                else:
                    logger.info("[ResourceEnum] Arjun: no param-less endpoints to probe")
            else:
                logger.info("[ResourceEnum] Arjun: binary not installed — skipping")
        except ImportError:
            logger.warning("[ResourceEnum] Arjun: module not available — skipping")
        except Exception as exc:
            logger.warning(f"[ResourceEnum] Arjun: error — {exc}")

    # Phase 5: Kiterunner API discovery (post-crawl)
    kr_routes_count = 0
    if enable_kiterunner:
        try:
            from recon.kiterunner_discovery import kiterunner_available, run_kiterunner
            if kiterunner_available():
                logger.info("[ResourceEnum] Kiterunner: starting API discovery")
                kr_disc = run_kiterunner(
                    target, max_time=min(timeout, 300), proxy=kiterunner_proxy,
                )
                for route in kr_disc.routes:
                    if route.url not in all_urls:
                        all_urls.add(route.url)
                        unique_urls.append(route.url)
                        cat = _classify_url(route.url)
                        if cat == "api":
                            api_eps.append(route.url)
                        elif cat == "auth":
                            auth_eps.append(route.url)
                        elif cat == "file":
                            file_eps.append(route.url)
                        elif cat == "admin":
                            admin_eps.append(route.url)
                        kr_routes_count += 1
                logger.info(f"[ResourceEnum] Kiterunner: {kr_routes_count} new routes")
            else:
                logger.info("[ResourceEnum] Kiterunner: binary not installed — skipping")
        except ImportError:
            logger.warning("[ResourceEnum] Kiterunner: module not available — skipping")
        except Exception as exc:
            logger.warning(f"[ResourceEnum] Kiterunner: error — {exc}")

    # Phase 6: FFuf directory fuzzing (post-crawl)
    ffuf_paths_count = 0
    if enable_ffuf:
        try:
            from recon.ffuf_fuzzer import ffuf_available, run_ffuf
            if ffuf_available():
                # Collect discovered base paths for recursive fuzzing
                discovered_bases = list(set(
                    "/" + urlparse(u).path.strip("/").split("/")[0]
                    for u in api_eps + admin_eps
                    if urlparse(u).path.strip("/")
                ))[:10]
                logger.info(f"[ResourceEnum] FFuf: starting directory fuzzing "
                           f"(root + {len(discovered_bases)} base paths)")
                ffuf_disc = run_ffuf(
                    target,
                    wordlist=ffuf_wordlist,
                    rate_limit=ffuf_rate_limit,
                    extensions=ffuf_extensions,
                    proxy=ffuf_proxy,
                    max_time=min(timeout, 300),
                    discovered_base_paths=discovered_bases if discovered_bases else None,
                )
                for r in ffuf_disc.results:
                    if r.url not in all_urls:
                        all_urls.add(r.url)
                        unique_urls.append(r.url)
                        cat = _classify_url(r.url)
                        if cat == "api":
                            api_eps.append(r.url)
                        elif cat == "auth":
                            auth_eps.append(r.url)
                        elif cat == "file":
                            file_eps.append(r.url)
                        elif cat == "admin":
                            admin_eps.append(r.url)
                        ffuf_paths_count += 1
                logger.info(f"[ResourceEnum] FFuf: {ffuf_paths_count} new paths")
            else:
                logger.info("[ResourceEnum] FFuf: binary not installed — skipping")
        except ImportError:
            logger.warning("[ResourceEnum] FFuf: module not available — skipping")
        except Exception as exc:
            logger.warning(f"[ResourceEnum] FFuf: error — {exc}")

    # Deduplicate secrets by value
    seen_secrets: Set[str] = set()
    deduped_secrets = []
    for s in js_secrets:
        if s["value"] not in seen_secrets:
            seen_secrets.add(s["value"])
            deduped_secrets.append(s)

    elapsed = time.time() - start

    # Re-sort after kiterunner/ffuf additions
    unique_urls = sorted(all_urls)

    results = ResourceEnumResults(
        urls=unique_urls,
        api_endpoints=sorted(api_eps),
        auth_endpoints=sorted(auth_eps),
        file_endpoints=sorted(file_eps),
        admin_endpoints=sorted(admin_eps),
        js_files=sorted(js_urls),
        js_secrets=deduped_secrets,
        parameters=all_params,
        forms=[],  # forms populated by web_crawler, not duplicated here
        total_unique=len(unique_urls),
    )

    # Log summary
    logger.info(f"[ResourceEnum] Completed in {elapsed:.1f}s")
    logger.info(f"[ResourceEnum] Unique URLs:    {results.total_unique}")
    logger.info(f"[ResourceEnum] API endpoints:  {len(results.api_endpoints)}")
    logger.info(f"[ResourceEnum] Auth endpoints: {len(results.auth_endpoints)}")
    logger.info(f"[ResourceEnum] File endpoints: {len(results.file_endpoints)}")
    logger.info(f"[ResourceEnum] Admin panels:   {len(results.admin_endpoints)}")
    logger.info(f"[ResourceEnum] JS files:       {len(results.js_files)}")
    logger.info(f"[ResourceEnum] JS secrets:     {len(results.js_secrets)}")
    logger.info(f"[ResourceEnum] Parameters:     {len(results.parameters)}")
    if arjun_params:
        logger.info(f"[ResourceEnum] Arjun params:   {len(arjun_params)}")
    if paramspider_new_params:
        logger.info(f"[ResourceEnum] ParamSpider:    {paramspider_new_params} params")
    if kr_routes_count:
        logger.info(f"[ResourceEnum] Kiterunner:     {kr_routes_count} routes")
    if ffuf_paths_count:
        logger.info(f"[ResourceEnum] FFuf:           {ffuf_paths_count} paths")

    # Save results to disk
    out_path = DATA_DIR / f"resource_enum_{domain.replace(':', '_')}.json"
    try:
        out_path.write_text(json.dumps(results.to_dict(), indent=2))
        logger.info(f"[ResourceEnum] Results saved to {out_path}")
    except Exception as e:
        logger.warning(f"[ResourceEnum] Failed to save results: {e}")

    return results


def run_resource_enum_sync(
    target: str, **kwargs
) -> ResourceEnumResults:
    """Synchronous wrapper for run_resource_enum."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already in an async context — create a new thread to run it
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            return pool.submit(
                lambda: asyncio.run(run_resource_enum(target, **kwargs))
            ).result()
    else:
        return asyncio.run(run_resource_enum(target, **kwargs))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    if len(sys.argv) < 2:
        print("Usage: python resource_enum.py <target_url>")
        sys.exit(1)
    target_url = sys.argv[1]
    result = run_resource_enum_sync(target_url)
    print(f"\n{'='*60}")
    print(f"Total unique URLs: {result.total_unique}")
    print(f"API endpoints:     {len(result.api_endpoints)}")
    print(f"Auth endpoints:    {len(result.auth_endpoints)}")
    print(f"File endpoints:    {len(result.file_endpoints)}")
    print(f"Admin panels:      {len(result.admin_endpoints)}")
    print(f"JS files:          {len(result.js_files)}")
    print(f"JS secrets:        {len(result.js_secrets)}")
    print(f"Parameters:        {len(result.parameters)}")
