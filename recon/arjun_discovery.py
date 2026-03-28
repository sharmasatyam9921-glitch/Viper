#!/usr/bin/env python3
"""
VIPER 4.0 — Arjun Parameter Discovery Module (F2)
===================================================
Active HTTP parameter discovery using Arjun. Tests common parameter names
against endpoints to find hidden query/body parameters (debug params, admin
functionality, hidden API inputs).

Inspired by RedAmon's arjun_helpers.py. Runs arjun as a subprocess with:
  - GET, POST, JSON body parameter discovery
  - Rate limiting & proxy (Tor/SOCKS) support
  - Timeout handling with partial result recovery
  - Parameter classification (injectable, auth, API)

Graceful fallback when arjun binary is not installed.

Usage:
    results = await run_arjun_discovery(["https://target.com/api/users"])
    # or synchronously:
    results = run_arjun_discovery_sync(["https://target.com/api/users"])
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("viper.arjun_discovery")

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

ARJUN_TIMEOUT = 300          # Per-method scan timeout (seconds)
ARJUN_REQ_TIMEOUT = 15       # Per-request timeout (seconds)
ARJUN_THREADS = 5            # Concurrent threads inside arjun
ARJUN_CHUNK_SIZE = 250       # Parameters per request batch
ARJUN_RATE_LIMIT = 0         # 0 = unlimited
ARJUN_MAX_ENDPOINTS = 20     # Max endpoints to scan (configurable)

# ---------------------------------------------------------------------------
# Parameter classification
# ---------------------------------------------------------------------------

_INJECTABLE_PARAMS = {
    "id", "user", "uid", "user_id", "username", "account",
    "file", "filename", "path", "filepath", "dir", "folder", "document",
    "url", "uri", "link", "href", "redirect", "return", "next", "goto",
    "redir", "redirect_uri", "return_url", "continue",
    "query", "q", "s", "search", "keyword", "term", "filter",
    "cmd", "exec", "command", "run", "ping", "process",
    "template", "tpl", "view", "layout", "page", "include",
    "host", "ip", "domain", "port",
}

_AUTH_PARAMS = {
    "token", "key", "password", "passwd", "pass", "pwd",
    "session", "session_id", "sessionid", "sid",
    "auth", "authorization", "bearer",
    "cookie", "csrf", "csrf_token", "xsrf",
    "otp", "code", "pin", "2fa", "mfa",
    "secret", "access_token", "refresh_token",
    "api_token", "auth_token",
}

_API_PARAMS = {
    "api_key", "apikey", "api_secret", "app_key", "app_id",
    "version", "v", "format", "output",
    "callback", "cb", "jsonp", "jsonpcallback",
    "fields", "select", "expand", "include",
    "limit", "offset", "page", "per_page", "page_size",
    "sort", "order", "orderby", "sort_by",
    "locale", "lang", "language",
}


def classify_param(name: str) -> str:
    """Classify a parameter name into injectable/auth/api/standard."""
    lower = name.lower().strip()
    if lower in _INJECTABLE_PARAMS:
        return "injectable"
    if lower in _AUTH_PARAMS:
        return "auth"
    if lower in _API_PARAMS:
        return "api"
    return "standard"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ArjunResult:
    """Result from Arjun parameter discovery on a single URL."""
    url: str
    method: str
    params: List[Dict] = field(default_factory=list)  # [{name, classification}]

    def to_dict(self) -> dict:
        return {"url": self.url, "method": self.method, "params": self.params}


@dataclass
class ArjunDiscoveryResults:
    """Aggregated results from full Arjun discovery run."""
    results: List[ArjunResult] = field(default_factory=list)
    total_params: int = 0
    total_urls_scanned: int = 0
    total_urls_with_params: int = 0
    injectable_params: List[Dict] = field(default_factory=list)
    auth_params: List[Dict] = field(default_factory=list)
    api_params: List[Dict] = field(default_factory=list)
    timed_out: bool = False
    elapsed: float = 0.0
    arjun_available: bool = True

    def to_dict(self) -> dict:
        return {
            "results": [r.to_dict() for r in self.results],
            "total_params": self.total_params,
            "total_urls_scanned": self.total_urls_scanned,
            "total_urls_with_params": self.total_urls_with_params,
            "injectable_params": self.injectable_params,
            "auth_params": self.auth_params,
            "api_params": self.api_params,
            "timed_out": self.timed_out,
            "elapsed": self.elapsed,
            "arjun_available": self.arjun_available,
        }


# ---------------------------------------------------------------------------
# Binary check
# ---------------------------------------------------------------------------

def arjun_available() -> bool:
    """Check if arjun binary is on PATH."""
    return shutil.which("arjun") is not None


# ---------------------------------------------------------------------------
# Truncated JSON recovery (from RedAmon)
# ---------------------------------------------------------------------------

def _recover_truncated_json(content: str):
    """Attempt to recover valid JSON from a truncated arjun output file."""
    stack = []
    in_string = False
    escape_next = False
    for ch in content:
        if escape_next:
            escape_next = False
            continue
        if ch == '\\' and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch in ('{', '['):
            stack.append('}' if ch == '{' else ']')
        elif ch in ('}', ']') and stack:
            stack.pop()

    salvaged = content
    if in_string:
        salvaged += '"'
    salvaged = salvaged.rstrip().rstrip(',')
    salvaged += ''.join(reversed(stack))
    return json.loads(salvaged)


# ---------------------------------------------------------------------------
# Single-method scan
# ---------------------------------------------------------------------------

def _run_arjun_method(
    urls: List[str],
    method: str = "GET",
    threads: int = ARJUN_THREADS,
    req_timeout: int = ARJUN_REQ_TIMEOUT,
    scan_timeout: int = ARJUN_TIMEOUT,
    chunk_size: int = ARJUN_CHUNK_SIZE,
    rate_limit: int = ARJUN_RATE_LIMIT,
    stable: bool = False,
    proxy: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[List[ArjunResult], bool]:
    """
    Run arjun for a single HTTP method. Returns (results, timed_out).
    """
    tmp_dir = tempfile.mkdtemp(prefix="viper_arjun_")
    results: List[ArjunResult] = []
    timed_out = False

    try:
        urls_file = os.path.join(tmp_dir, "urls.txt")
        output_file = os.path.join(tmp_dir, "results.json")

        with open(urls_file, 'w') as f:
            for url in urls:
                f.write(url + '\n')

        cmd = [
            'arjun',
            '-i', urls_file,
            '-oJ', output_file,
            '-m', method,
            '-t', str(threads),
            '-T', str(req_timeout),
            '-c', str(chunk_size),
        ]

        if rate_limit > 0:
            cmd.extend(['--rate-limit', str(rate_limit)])
        if stable:
            cmd.append('--stable')

        if headers:
            hdr_str = '\n'.join(f"{k}: {v}" for k, v in headers.items())
            cmd.extend(['--headers', hdr_str])

        logger.info(f"[Arjun/{method}] Scanning {len(urls)} URLs")

        env = os.environ.copy()
        if proxy:
            env['HTTP_PROXY'] = proxy
            env['HTTPS_PROXY'] = proxy

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env,
        )

        try:
            stdout, stderr = proc.communicate(timeout=scan_timeout + 60)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                proc.terminate()
                proc.communicate(timeout=10)
            except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
                try:
                    proc.kill()
                except (ProcessLookupError, OSError):
                    pass
                proc.communicate()
            logger.warning(f"[Arjun/{method}] Timed out after {scan_timeout}s — collecting partial results")
        else:
            if proc.returncode != 0 and stderr:
                for line in stderr.strip().split('\n')[-3:]:
                    logger.warning(f"[Arjun/{method}] {line}")

        # Parse output
        if not os.path.exists(output_file):
            logger.info(f"[Arjun/{method}] No output file — {'timeout' if timed_out else 'no params found'}")
            return [], timed_out

        content = Path(output_file).read_text().strip()
        if not content:
            logger.info(f"[Arjun/{method}] Empty output — {'timeout' if timed_out else 'no params found'}")
            return [], timed_out

        # Parse JSON (with truncation recovery)
        try:
            arjun_output = json.loads(content)
        except json.JSONDecodeError:
            if not timed_out:
                logger.warning(f"[Arjun/{method}] Failed to parse JSON output")
                return [], False
            try:
                arjun_output = _recover_truncated_json(content)
                logger.info(f"[Arjun/{method}] Recovered partial JSON output")
            except Exception as e:
                logger.warning(f"[Arjun/{method}] Failed to recover partial JSON: {e}")
                return [], True

        # Build results
        for url, url_data in arjun_output.items():
            params_raw = url_data.get('params', [])
            disc_method = url_data.get('method', method)
            if not params_raw:
                continue

            classified = []
            for p in params_raw:
                cls = classify_param(p)
                classified.append({"name": p, "classification": cls})

            results.append(ArjunResult(
                url=url,
                method=disc_method,
                params=classified,
            ))

        total_p = sum(len(r.params) for r in results)
        if timed_out and total_p > 0:
            logger.info(f"[Arjun/{method}] Recovered {len(results)} URLs, {total_p} params from partial scan")
        elif not timed_out:
            logger.info(f"[Arjun/{method}] {len(results)} URLs, {total_p} params discovered")

    except Exception as e:
        logger.error(f"[Arjun/{method}] Error: {e}")
    finally:
        try:
            shutil.rmtree(tmp_dir)
        except Exception:
            pass

    return results, timed_out


# ---------------------------------------------------------------------------
# Multi-method orchestrator
# ---------------------------------------------------------------------------

async def run_arjun_discovery(
    target_urls: List[str],
    methods: Optional[List[str]] = None,
    threads: int = ARJUN_THREADS,
    req_timeout: int = ARJUN_REQ_TIMEOUT,
    scan_timeout: int = ARJUN_TIMEOUT,
    chunk_size: int = ARJUN_CHUNK_SIZE,
    rate_limit: int = ARJUN_RATE_LIMIT,
    stable: bool = False,
    proxy: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    max_endpoints: int = ARJUN_MAX_ENDPOINTS,
) -> ArjunDiscoveryResults:
    """
    Run Arjun parameter discovery across multiple HTTP methods.

    Args:
        target_urls: Endpoint URLs to probe for hidden parameters.
        methods: HTTP methods to test (default: ["GET", "POST", "JSON"]).
        threads: Arjun internal concurrency.
        req_timeout: Per-request timeout.
        scan_timeout: Overall timeout per method.
        chunk_size: Params per request batch.
        rate_limit: Max req/s (0 = unlimited).
        stable: Enable WAF-evasion random delays.
        proxy: Proxy URL (e.g. socks5://127.0.0.1:9050).
        headers: Custom HTTP headers dict.
        max_endpoints: Cap on endpoints to scan (avoid noise).

    Returns:
        ArjunDiscoveryResults with classified parameters.
    """
    start = time.time()

    if not arjun_available():
        logger.warning("[Arjun] Binary not found — skipping parameter discovery")
        return ArjunDiscoveryResults(arjun_available=False)

    if not target_urls:
        logger.info("[Arjun] No target URLs provided")
        return ArjunDiscoveryResults()

    if methods is None:
        methods = ["GET", "POST", "JSON"]

    # Cap endpoints
    if len(target_urls) > max_endpoints:
        logger.info(f"[Arjun] Capping from {len(target_urls)} to {max_endpoints} endpoints")
        target_urls = target_urls[:max_endpoints]

    logger.info(f"[Arjun] Starting parameter discovery on {len(target_urls)} endpoints")
    logger.info(f"[Arjun] Methods: {', '.join(methods)}")
    if proxy:
        logger.info(f"[Arjun] Using proxy: {proxy}")

    all_results: List[ArjunResult] = []
    any_timeout = False

    loop = asyncio.get_event_loop()

    # Run each method in a thread (arjun is subprocess-based, safe in threads)
    with ThreadPoolExecutor(max_workers=len(methods), thread_name_prefix="arjun") as pool:
        futures = {}
        for method in methods:
            futures[method] = loop.run_in_executor(
                pool,
                _run_arjun_method,
                target_urls, method, threads, req_timeout, scan_timeout,
                chunk_size, rate_limit, stable, proxy, headers,
            )

        for method in methods:
            try:
                method_results, method_timed_out = await futures[method]
                all_results.extend(method_results)
                if method_timed_out:
                    any_timeout = True
            except Exception as e:
                logger.error(f"[Arjun/{method}] Failed: {e}")

    # Aggregate and classify
    injectable: List[Dict] = []
    auth: List[Dict] = []
    api: List[Dict] = []
    total_params = 0

    for r in all_results:
        for p in r.params:
            total_params += 1
            entry = {"name": p["name"], "url": r.url, "method": r.method,
                     "classification": p["classification"]}
            if p["classification"] == "injectable":
                injectable.append(entry)
            elif p["classification"] == "auth":
                auth.append(entry)
            elif p["classification"] == "api":
                api.append(entry)

    elapsed = time.time() - start

    disc = ArjunDiscoveryResults(
        results=all_results,
        total_params=total_params,
        total_urls_scanned=len(target_urls),
        total_urls_with_params=len(all_results),
        injectable_params=injectable,
        auth_params=auth,
        api_params=api,
        timed_out=any_timeout,
        elapsed=elapsed,
        arjun_available=True,
    )

    logger.info(f"[Arjun] Completed in {elapsed:.1f}s")
    logger.info(f"[Arjun] {len(all_results)} URLs with params, {total_params} total params")
    logger.info(f"[Arjun] Injectable: {len(injectable)}, Auth: {len(auth)}, API: {len(api)}")

    return disc


def run_arjun_discovery_sync(
    target_urls: List[str], **kwargs
) -> ArjunDiscoveryResults:
    """Synchronous wrapper for run_arjun_discovery."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            return pool.submit(
                lambda: asyncio.run(run_arjun_discovery(target_urls, **kwargs))
            ).result()
    else:
        return asyncio.run(run_arjun_discovery(target_urls, **kwargs))


# ---------------------------------------------------------------------------
# Helpers for integration with resource_enum
# ---------------------------------------------------------------------------

def urls_needing_param_discovery(
    all_urls: List[str],
    known_params: Set[str],
    max_endpoints: int = ARJUN_MAX_ENDPOINTS,
) -> List[str]:
    """
    Filter URLs to those with no discovered query parameters.
    Used as post-crawl filter before running Arjun.

    Args:
        all_urls: All discovered endpoint URLs.
        known_params: Set of "param_name:url" keys already discovered.
        max_endpoints: Max URLs to return.

    Returns:
        List of URLs that have no known parameters (capped).
    """
    no_params = []
    for url in all_urls:
        parsed = urlparse(url)
        # Skip URLs that already have query params in the URL itself
        if parsed.query:
            continue
        # Skip JS/CSS/image files
        path_lower = parsed.path.lower()
        if any(path_lower.endswith(ext) for ext in (
            '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
            '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map',
            '.pdf', '.zip', '.gz', '.tar',
        )):
            continue
        # Check if any params already known for this URL
        has_known = any(k.endswith(f":{url}") for k in known_params)
        if not has_known:
            no_params.append(url)

    # Deduplicate by path (strip fragment/query variations)
    seen_paths: Set[str] = set()
    deduped = []
    for url in no_params:
        parsed = urlparse(url)
        key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if key not in seen_paths:
            seen_paths.add(key)
            deduped.append(url)

    if len(deduped) > max_endpoints:
        logger.info(f"[Arjun] Capping param discovery from {len(deduped)} to {max_endpoints} endpoints")
        deduped = deduped[:max_endpoints]

    return deduped


def merge_arjun_into_resource_results(
    arjun_results: ArjunDiscoveryResults,
    resource_results,  # ResourceEnumResults
) -> None:
    """
    Merge Arjun discovered parameters into existing ResourceEnumResults in-place.
    """
    if not arjun_results.results:
        return

    existing_keys = {f"{p['name']}:{p['url']}" for p in resource_results.parameters}

    for r in arjun_results.results:
        for p in r.params:
            key = f"{p['name']}:{r.url}"
            if key not in existing_keys:
                existing_keys.add(key)
                resource_results.parameters.append({
                    "name": p["name"],
                    "url": r.url,
                    "type": p["classification"],
                    "method": r.method,
                    "source": "arjun",
                })


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(message)s",
    )

    if len(sys.argv) < 2:
        print("Usage: python arjun_discovery.py <url1> [url2] ...")
        sys.exit(1)

    urls = sys.argv[1:]
    results = run_arjun_discovery_sync(urls)
    print(json.dumps(results.to_dict(), indent=2))
