#!/usr/bin/env python3
"""
VIPER 4.0 Kiterunner API Discovery — OpenAPI-aware endpoint brute forcing.

Uses Kiterunner (kr) binary for content-aware API route discovery that goes
beyond simple status-code matching. Discovers routes by analyzing response
bodies, content types, and content lengths.

Graceful fallback if kr is not installed.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("viper.kiterunner")

# Default wordlists shipped with kr or from Assetnote
DEFAULT_WORDLISTS = [
    "routes-large.kite",
    "routes-small.kite",
]

# Built-in API routes wordlist (used when no .kite file available)
BUILTIN_API_ROUTES = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/api/health", "/api/status", "/api/info", "/api/version",
    "/api/docs", "/api/swagger", "/api/openapi",
    "/api/graphql", "/api/graphiql",
    "/api/users", "/api/user", "/api/me", "/api/profile",
    "/api/auth", "/api/login", "/api/register", "/api/token",
    "/api/admin", "/api/config", "/api/settings",
    "/api/search", "/api/upload", "/api/download", "/api/export",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/api", "/rest/v1",
    "/graphql", "/graphiql",
    "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
    "/openapi", "/openapi.json", "/openapi.yaml",
    "/docs", "/redoc", "/api-docs",
    "/.well-known/openid-configuration",
    "/.well-known/security.txt",
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/healthz", "/readyz", "/livez",
    "/metrics", "/prometheus",
    "/_debug", "/_status", "/_health",
    "/wp-json", "/wp-json/wp/v2",
    "/xmlrpc.php", "/robots.txt", "/sitemap.xml",
]


@dataclass
class KiterunnerResult:
    """A single API route discovered by Kiterunner."""
    url: str
    method: str
    status_code: int
    content_length: int
    content_type: str = ""
    words: int = 0
    lines: int = 0
    source: str = "kiterunner"


@dataclass
class KiterunnerDiscovery:
    """Aggregated results from a Kiterunner scan."""
    routes: List[KiterunnerResult] = field(default_factory=list)
    target: str = ""
    tool_available: bool = False
    scan_completed: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "routes": [
                {
                    "url": r.url,
                    "method": r.method,
                    "status_code": r.status_code,
                    "content_length": r.content_length,
                    "content_type": r.content_type,
                    "words": r.words,
                    "lines": r.lines,
                }
                for r in self.routes
            ],
            "target": self.target,
            "tool_available": self.tool_available,
            "scan_completed": self.scan_completed,
            "error": self.error,
        }


def kiterunner_available() -> bool:
    """Check if the kr binary is installed and accessible."""
    return shutil.which("kr") is not None


def _find_wordlist() -> Optional[str]:
    """Find a .kite wordlist on disk. Returns path or None."""
    # Check common locations
    search_paths = [
        os.path.expanduser("~/.kiterunner"),
        os.path.expanduser("~/kiterunner"),
        os.path.expanduser("~/.viper/tools/kiterunner"),
        "/usr/share/kiterunner",
        "/opt/kiterunner",
    ]
    for base in search_paths:
        for wl in DEFAULT_WORDLISTS:
            path = os.path.join(base, wl)
            if os.path.isfile(path):
                return path
    return None


def _parse_kr_text_output(stdout: str, target: str) -> List[KiterunnerResult]:
    """
    Parse Kiterunner text output lines.

    Kiterunner output format (text mode):
        GET     200 [  1234,   56,   7] https://target.com/api/v1/users
    """
    results = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("="):
            continue
        try:
            parts = line.split()
            if len(parts) < 4:
                continue
            method = parts[0].upper()
            if method not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
                continue
            status = int(parts[1])
            # Parse content metrics [length, words, lines]
            content_length = 0
            words = 0
            lines_count = 0
            bracket_start = line.find("[")
            bracket_end = line.find("]")
            if bracket_start != -1 and bracket_end != -1:
                metrics = line[bracket_start + 1:bracket_end].split(",")
                if len(metrics) >= 1:
                    content_length = int(metrics[0].strip())
                if len(metrics) >= 2:
                    words = int(metrics[1].strip())
                if len(metrics) >= 3:
                    lines_count = int(metrics[2].strip())
            # URL is the last token
            url = parts[-1]
            if not url.startswith(("http://", "https://")):
                url = target.rstrip("/") + "/" + url.lstrip("/")
            results.append(KiterunnerResult(
                url=url,
                method=method,
                status_code=status,
                content_length=content_length,
                words=words,
                lines=lines_count,
            ))
        except (ValueError, IndexError):
            continue
    return results


def _parse_kr_json_output(json_path: str, target: str) -> List[KiterunnerResult]:
    """Parse Kiterunner JSON output file."""
    results = []
    try:
        with open(json_path, "r") as f:
            data = json.load(f)

        # kr JSON output can be a list of results or nested
        items = data if isinstance(data, list) else data.get("results", [])
        for item in items:
            results.append(KiterunnerResult(
                url=item.get("url", item.get("path", "")),
                method=item.get("method", "GET").upper(),
                status_code=item.get("status_code", item.get("status", 0)),
                content_length=item.get("content_length", item.get("length", 0)),
                content_type=item.get("content_type", ""),
                words=item.get("words", 0),
                lines=item.get("lines", 0),
            ))
    except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
        logger.warning(f"[Kiterunner] Failed to parse JSON output: {e}")
    return results


def run_kiterunner(
    target: str,
    wordlist: Optional[str] = None,
    max_time: int = 300,
    threads: int = 20,
    delay_ms: int = 0,
    methods: Optional[List[str]] = None,
    headers: Optional[Dict[str, str]] = None,
    proxy: Optional[str] = None,
    filter_status: Optional[List[int]] = None,
    use_assetnote_wordlist: bool = False,
) -> KiterunnerDiscovery:
    """
    Run Kiterunner API endpoint discovery.

    Args:
        target: Base URL to scan (e.g. https://example.com)
        wordlist: Path to .kite or .txt wordlist. Auto-detected if None.
        max_time: Max scan time in seconds.
        threads: Concurrent connection count.
        delay_ms: Delay between requests in milliseconds.
        methods: HTTP methods to test (default: all).
        headers: Custom HTTP headers.
        proxy: Proxy URL (e.g. http://127.0.0.1:8080).
        filter_status: Status codes to exclude from results.
        use_assetnote_wordlist: Use -A flag for built-in Assetnote wordlist.

    Returns:
        KiterunnerDiscovery with discovered routes.
    """
    discovery = KiterunnerDiscovery(target=target)

    if not kiterunner_available():
        logger.info("[Kiterunner] Binary 'kr' not found — skipping API discovery")
        discovery.error = "kr binary not installed"
        return discovery

    discovery.tool_available = True
    logger.info(f"[Kiterunner] Starting API discovery on {target}")

    # Resolve wordlist
    wl_path = wordlist or _find_wordlist()
    if not wl_path and not use_assetnote_wordlist:
        logger.info("[Kiterunner] No .kite wordlist found, using -A (Assetnote built-in)")
        use_assetnote_wordlist = True

    # Build command
    output_dir = tempfile.mkdtemp(prefix="viper_kr_")
    output_file = os.path.join(output_dir, "kr_output.json")

    cmd = ["kr", "scan", target]

    if use_assetnote_wordlist:
        cmd.append("-A")
    elif wl_path:
        cmd.extend(["-w", wl_path])

    cmd.extend(["--max-connection-per-host", str(threads)])

    if delay_ms > 0:
        cmd.extend(["--delay", f"{delay_ms}ms"])

    if proxy:
        cmd.extend(["--proxy", proxy])

    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

    if filter_status:
        for code in filter_status:
            cmd.extend(["--ignore-status-code", str(code)])

    # JSON output
    cmd.extend(["-o", "json", "--output-file", output_file])

    logger.info(f"[Kiterunner] Command: {' '.join(cmd[:6])}...")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max_time + 60,
        )

        # Try JSON output first
        if os.path.isfile(output_file) and os.path.getsize(output_file) > 0:
            discovery.routes = _parse_kr_json_output(output_file, target)
        elif result.stdout:
            # Fall back to parsing text output
            discovery.routes = _parse_kr_text_output(result.stdout, target)

        if result.stderr and "error" in result.stderr.lower():
            logger.warning(f"[Kiterunner] Stderr: {result.stderr[:500]}")

        discovery.scan_completed = True
        logger.info(f"[Kiterunner] Discovered {len(discovery.routes)} API routes")

    except subprocess.TimeoutExpired:
        discovery.error = f"Scan timed out after {max_time}s"
        logger.warning(f"[Kiterunner] {discovery.error}")
    except FileNotFoundError:
        discovery.error = "kr binary disappeared during scan"
        logger.error(f"[Kiterunner] {discovery.error}")
    except Exception as e:
        discovery.error = str(e)
        logger.error(f"[Kiterunner] Scan error: {e}")
    finally:
        # Cleanup
        try:
            import shutil as _shutil
            _shutil.rmtree(output_dir, ignore_errors=True)
        except Exception:
            pass

    return discovery


async def run_kiterunner_async(target: str, **kwargs) -> KiterunnerDiscovery:
    """Async wrapper — runs kr in a thread to avoid blocking the event loop."""
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: run_kiterunner(target, **kwargs))
