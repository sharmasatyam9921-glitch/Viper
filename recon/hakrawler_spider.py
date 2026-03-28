#!/usr/bin/env python3
"""
VIPER 5.0 — Hakrawler + jsluice Integration

Hakrawler: Fast web crawler for endpoint/URL discovery.
jsluice: JavaScript analysis for extracting URLs, secrets, and endpoints from JS files.
"""

import asyncio
import json
import logging
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger("viper.recon.hakrawler")


@dataclass
class CrawlResult:
    """Result from hakrawler crawling."""
    urls: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    forms: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    total: int = 0


@dataclass
class JSAnalysisResult:
    """Result from jsluice JS analysis."""
    urls: List[Dict] = field(default_factory=list)
    secrets: List[Dict] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)


class HakrawlerSpider:
    """Hakrawler subprocess wrapper for web crawling.

    Args:
        depth: Crawl depth (default 2).
        threads: Concurrent threads (default 5).
        timeout: Request timeout in seconds.
        scope: Restrict to same domain (default True).
    """

    def __init__(
        self,
        depth: int = 2,
        threads: int = 5,
        timeout: int = 10,
        scope: bool = True,
    ):
        self.binary = shutil.which("hakrawler")
        self.available = self.binary is not None
        self.depth = depth
        self.threads = threads
        self.timeout = timeout
        self.scope = scope

    async def crawl(self, target: str) -> CrawlResult:
        """Crawl a target URL and extract all discovered URLs.

        Args:
            target: Base URL to crawl (e.g., "https://example.com").

        Returns:
            CrawlResult with discovered URLs, JS files, forms, endpoints.
        """
        if not self.available:
            logger.warning("hakrawler not installed, skipping")
            return CrawlResult()

        result = CrawlResult()

        try:
            cmd = [
                self.binary,
                "-d", str(self.depth),
                "-t", str(self.threads),
                "-timeout", str(self.timeout),
            ]
            if self.scope:
                cmd.append("-subs")  # Include subdomains

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=target.encode()),
                timeout=120,
            )

            seen: Set[str] = set()
            for line in stdout.decode(errors="ignore").splitlines():
                url = line.strip()
                if not url or url in seen:
                    continue
                seen.add(url)

                result.urls.append(url)

                # Classify
                url_lower = url.lower()
                if url_lower.endswith(".js") or ".js?" in url_lower:
                    result.js_files.append(url)
                elif "form" in url_lower or "action=" in url_lower:
                    result.forms.append(url)
                elif "/api/" in url_lower or "/v1/" in url_lower or "/v2/" in url_lower:
                    result.endpoints.append(url)

            result.total = len(result.urls)
            logger.info("hakrawler: %d URLs, %d JS, %d endpoints from %s",
                        result.total, len(result.js_files), len(result.endpoints), target[:60])

        except asyncio.TimeoutError:
            logger.warning("hakrawler timed out for %s", target[:60])
        except Exception as e:
            logger.error("hakrawler error: %s", e)

        return result

    async def crawl_batch(self, targets: List[str]) -> CrawlResult:
        """Crawl multiple targets and merge results."""
        merged = CrawlResult()
        for target in targets:
            r = await self.crawl(target)
            merged.urls.extend(r.urls)
            merged.js_files.extend(r.js_files)
            merged.forms.extend(r.forms)
            merged.endpoints.extend(r.endpoints)
        merged.total = len(merged.urls)
        return merged


class JSluiceAnalyzer:
    """jsluice subprocess wrapper for JavaScript analysis.

    Extracts URLs, secrets, and API endpoints from JavaScript files.
    """

    def __init__(self):
        self.binary = shutil.which("jsluice")
        self.available = self.binary is not None

    async def analyze_urls(self, js_content: str) -> List[Dict]:
        """Extract URLs from JavaScript content."""
        if not self.available:
            return self._fallback_extract_urls(js_content)

        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary, "urls",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=js_content.encode()),
                timeout=30,
            )

            results = []
            for line in stdout.decode(errors="ignore").splitlines():
                try:
                    data = json.loads(line)
                    results.append(data)
                except json.JSONDecodeError:
                    if line.strip().startswith("http"):
                        results.append({"url": line.strip()})

            return results

        except Exception as e:
            logger.debug("jsluice error: %s, using fallback", e)
            return self._fallback_extract_urls(js_content)

    async def analyze_secrets(self, js_content: str) -> List[Dict]:
        """Extract secrets from JavaScript content."""
        if not self.available:
            return self._fallback_extract_secrets(js_content)

        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary, "secrets",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=js_content.encode()),
                timeout=30,
            )

            results = []
            for line in stdout.decode(errors="ignore").splitlines():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            return results

        except Exception as e:
            logger.debug("jsluice secrets error: %s, using fallback", e)
            return self._fallback_extract_secrets(js_content)

    async def analyze_file(self, js_url: str) -> JSAnalysisResult:
        """Download and analyze a JavaScript file."""
        result = JSAnalysisResult()

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        result.urls = await self.analyze_urls(content)
                        result.secrets = await self.analyze_secrets(content)
                        result.endpoints = [u.get("url", "") for u in result.urls
                                            if "/api/" in u.get("url", "").lower()]
        except Exception as e:
            logger.debug("JS file analysis failed for %s: %s", js_url[:60], e)

        return result

    def _fallback_extract_urls(self, content: str) -> List[Dict]:
        """Python fallback for URL extraction from JS."""
        patterns = [
            r'(?:"|\'|`)(https?://[^\s"\'`<>{}|\\^]+?)(?:"|\'|`)',
            r'(?:"|\'|`)(\/api\/[^\s"\'`<>{}|\\^]+?)(?:"|\'|`)',
            r'(?:"|\'|`)(\/v[12]\/[^\s"\'`<>{}|\\^]+?)(?:"|\'|`)',
            r'fetch\s*\(\s*["\']([^"\']+)',
            r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)',
            r'XMLHttpRequest.*?open\s*\([^,]+,\s*["\']([^"\']+)',
        ]
        results = []
        seen = set()
        for pattern in patterns:
            for match in re.findall(pattern, content):
                if match not in seen and len(match) > 3:
                    seen.add(match)
                    results.append({"url": match, "source": "regex_fallback"})
        return results[:200]

    def _fallback_extract_secrets(self, content: str) -> List[Dict]:
        """Python fallback for secret extraction from JS."""
        secret_patterns = [
            (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "api_key"),
            (r'(?:secret|token|password|passwd)\s*[:=]\s*["\']([^\s"\']{8,})["\']', "secret"),
            (r'(?:aws_access_key_id)\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})["\']?', "aws_key"),
            (r'(?:GITHUB_TOKEN|github_token|gh_token)\s*[:=]\s*["\']?(gh[ps]_[a-zA-Z0-9]{36,})["\']?', "github_token"),
            (r'(?:Bearer|bearer)\s+([a-zA-Z0-9_\-.]{20,})', "bearer_token"),
            (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "private_key"),
            (r'(?:sk-[a-zA-Z0-9]{20,})', "openai_key"),
            (r'(?:SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})', "sendgrid_key"),
            (r'(?:xox[bpoas]-[0-9]{10,}-[a-zA-Z0-9-]+)', "slack_token"),
        ]
        results = []
        for pattern, stype in secret_patterns:
            for match in re.findall(pattern, content):
                results.append({"type": stype, "value": match[:20] + "...", "severity": "high"})
        return results


__all__ = ["HakrawlerSpider", "JSluiceAnalyzer", "CrawlResult", "JSAnalysisResult"]
