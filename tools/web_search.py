#!/usr/bin/env python3
"""
VIPER 4.0 Web Search Tool (G3)

Web search for CVE details, exploit PoCs, and security research.
Uses stdlib urllib.request — supports SerpAPI and Tavily backends.
Graceful fallback if no API keys are configured.
"""

import json
import logging
import os
import asyncio
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.web_search")

# ── Constants ─────────────────────────────────────────────────────────────

_SERPAPI_BASE = "https://serpapi.com/search.json"
_TAVILY_BASE = "https://api.tavily.com/search"

_DEFAULT_TIMEOUT = 15  # seconds
_USER_AGENT = "VIPER/4.0 Security Research Bot"


# ── Result dataclass ──────────────────────────────────────────────────────

@dataclass
class SearchResult:
    """Single web search result."""
    title: str = ""
    url: str = ""
    snippet: str = ""
    source: str = ""  # "serpapi" | "tavily" | "fallback"

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "url": self.url,
            "snippet": self.snippet,
            "source": self.source,
        }


# ── Internal HTTP helpers ─────────────────────────────────────────────────

def _http_get(url: str, timeout: int = _DEFAULT_TIMEOUT) -> Optional[dict]:
    """Perform a GET request and parse JSON response. Returns None on error."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            OSError, ValueError) as e:
        logger.warning("HTTP GET failed for %s: %s", url[:80], e)
        return None


def _http_post_json(url: str, payload: dict, timeout: int = _DEFAULT_TIMEOUT) -> Optional[dict]:
    """Perform a POST request with JSON body and parse JSON response."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "User-Agent": _USER_AGENT,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            OSError, ValueError) as e:
        logger.warning("HTTP POST failed for %s: %s", url[:80], e)
        return None


# ── Provider implementations ──────────────────────────────────────────────

def _search_serpapi(query: str, api_key: str, num_results: int = 5) -> List[SearchResult]:
    """Search using SerpAPI (Google results)."""
    params = urllib.parse.urlencode({
        "q": query,
        "api_key": api_key,
        "num": num_results,
        "engine": "google",
    })
    url = f"{_SERPAPI_BASE}?{params}"
    data = _http_get(url)
    if not data:
        return []

    results = []
    for item in data.get("organic_results", [])[:num_results]:
        results.append(SearchResult(
            title=item.get("title", ""),
            url=item.get("link", ""),
            snippet=item.get("snippet", ""),
            source="serpapi",
        ))
    return results


def _search_tavily(query: str, api_key: str, num_results: int = 5) -> List[SearchResult]:
    """Search using Tavily API."""
    payload = {
        "api_key": api_key,
        "query": query,
        "max_results": num_results,
        "search_depth": "advanced",
        "include_answer": False,
    }
    data = _http_post_json(_TAVILY_BASE, payload)
    if not data:
        return []

    results = []
    for item in data.get("results", [])[:num_results]:
        results.append(SearchResult(
            title=item.get("title", ""),
            url=item.get("url", ""),
            snippet=item.get("content", ""),
            source="tavily",
        ))
    return results


def _search_duckduckgo(query: str, num_results: int = 5) -> List[SearchResult]:
    """DuckDuckGo HTML search — free, no API key required."""
    results = []
    try:
        data = urllib.parse.urlencode({"q": query, "kl": "us-en"}).encode()
        req = urllib.request.Request(
            "https://html.duckduckgo.com/html/",
            data=data,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")

        import re
        # Parse result blocks from DDG HTML
        blocks = re.findall(
            r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>'
            r'.*?<a[^>]*class="result__snippet"[^>]*>(.*?)</a>',
            html, re.DOTALL,
        )
        for url, title, snippet in blocks[:num_results]:
            # DDG wraps URLs in redirect — extract actual URL
            actual = re.search(r'uddg=([^&]+)', url)
            clean_url = urllib.parse.unquote(actual.group(1)) if actual else url
            clean_title = re.sub(r'<[^>]+>', '', title).strip()
            clean_snippet = re.sub(r'<[^>]+>', '', snippet).strip()
            if clean_url and clean_title:
                results.append(SearchResult(
                    title=clean_title,
                    url=clean_url,
                    snippet=clean_snippet,
                    source="duckduckgo",
                ))
    except Exception as e:
        logger.debug("DuckDuckGo search failed: %s", e)
    return results


def _search_searxng(query: str, base_url: str, num_results: int = 5) -> List[SearchResult]:
    """SearXNG self-hosted search engine."""
    results = []
    if not base_url:
        return results
    try:
        params = urllib.parse.urlencode({
            "q": query,
            "format": "json",
            "categories": "general",
            "language": "en",
        })
        url = f"{base_url.rstrip('/')}/search?{params}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())

        for item in data.get("results", [])[:num_results]:
            results.append(SearchResult(
                title=item.get("title", ""),
                url=item.get("url", ""),
                snippet=item.get("content", ""),
                source="searxng",
            ))
    except Exception as e:
        logger.debug("SearXNG search failed: %s", e)
    return results


# ── Main WebSearchTool class ──────────────────────────────────────────────

class WebSearchTool:
    """
    Web search for CVE details, exploit PoCs, and security research.

    Supports SerpAPI (env: SERPAPI_KEY) and Tavily (env: TAVILY_API_KEY).
    Falls back gracefully if no API keys are configured — returns empty results
    with a warning instead of crashing.

    Usage::

        tool = WebSearchTool()
        results = await tool.search("CVE-2021-44228 exploit PoC")
        cve_info = await tool.search_cve("CVE-2021-44228")
        exploits = await tool.search_exploit("Apache Log4j", "2.14.1")
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        provider: str = "serpapi",
    ):
        """
        Initialize the web search tool.

        Args:
            api_key: API key for the chosen provider. If None, reads from
                     environment (SERPAPI_KEY or TAVILY_API_KEY).
            provider: "serpapi" or "tavily". Falls back to the other if the
                      primary key is missing.
        """
        self.provider = provider.lower()
        self._serpapi_key = ""
        self._tavily_key = ""

        if api_key:
            if self.provider == "tavily":
                self._tavily_key = api_key
            else:
                self._serpapi_key = api_key
        else:
            self._serpapi_key = os.environ.get("SERPAPI_KEY", "")
            self._tavily_key = os.environ.get("TAVILY_API_KEY", "")

        # Determine effective provider order
        self._providers: List[str] = []
        if self.provider == "tavily" and self._tavily_key:
            self._providers.append("tavily")
        if self._serpapi_key:
            self._providers.append("serpapi")
        if "tavily" not in self._providers and self._tavily_key:
            self._providers.append("tavily")

        # DuckDuckGo — always available (free, no key)
        self._providers.append("duckduckgo")

        # SearXNG — self-hosted, available if URL configured
        self._searxng_url = os.environ.get("SEARXNG_URL", "")
        if self._searxng_url:
            self._providers.append("searxng")

        if not self._providers:
            logger.warning(
                "WebSearchTool: no search providers available. "
                "Set SERPAPI_KEY or TAVILY_API_KEY for premium search, "
                "or SEARXNG_URL for self-hosted. DuckDuckGo is always available."
            )

    @property
    def is_available(self) -> bool:
        """True if at least one search provider is configured."""
        return len(self._providers) > 0

    async def search(self, query: str, num_results: int = 5) -> List[dict]:
        """
        Search the web for security research information.

        Args:
            query: Search query string (e.g., "CVE-2021-41773 exploit PoC").
            num_results: Maximum results to return (default 5).

        Returns:
            List of dicts with keys: title, url, snippet, source.
        """
        if not self._providers:
            logger.warning("WebSearchTool: search called but no providers configured")
            return []

        # Run synchronous HTTP calls in a thread to avoid blocking
        loop = asyncio.get_running_loop()

        for provider in self._providers:
            try:
                if provider == "serpapi":
                    results = await loop.run_in_executor(
                        None, _search_serpapi, query, self._serpapi_key, num_results
                    )
                elif provider == "tavily":
                    results = await loop.run_in_executor(
                        None, _search_tavily, query, self._tavily_key, num_results
                    )
                elif provider == "duckduckgo":
                    results = await loop.run_in_executor(
                        None, _search_duckduckgo, query, num_results
                    )
                elif provider == "searxng":
                    results = await loop.run_in_executor(
                        None, _search_searxng, query, self._searxng_url, num_results
                    )
                else:
                    continue

                if results:
                    logger.info("WebSearchTool: %d results from %s for '%s'",
                                len(results), provider, query[:60])
                    return [r.to_dict() for r in results]

            except Exception as e:
                logger.warning("WebSearchTool: %s failed for '%s': %s",
                               provider, query[:60], e)
                continue

        logger.warning("WebSearchTool: all providers failed for '%s'", query[:60])
        return []

    async def search_cve(self, cve_id: str) -> dict:
        """
        Focused CVE lookup — searches for details, severity, affected versions, and patches.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228").

        Returns:
            Dict with keys: cve_id, results (list of search results), summary.
        """
        queries = [
            f"{cve_id} vulnerability details severity CVSS",
            f"{cve_id} exploit PoC proof of concept",
        ]

        all_results = []
        for q in queries:
            results = await self.search(q, num_results=3)
            all_results.extend(results)

        # Deduplicate by URL
        seen_urls = set()
        unique_results = []
        for r in all_results:
            if r["url"] not in seen_urls:
                seen_urls.add(r["url"])
                unique_results.append(r)

        return {
            "cve_id": cve_id,
            "results": unique_results[:6],
            "summary": f"Found {len(unique_results)} results for {cve_id}",
        }

    async def search_exploit(self, tech: str, version: str = "") -> List[dict]:
        """
        Search for known exploits and PoCs for a specific technology/version.

        Args:
            tech: Technology name (e.g., "Apache Log4j", "OpenSSH").
            version: Version string (e.g., "2.14.1"). Optional.

        Returns:
            List of search result dicts.
        """
        version_str = f" {version}" if version else ""
        queries = [
            f"{tech}{version_str} exploit PoC vulnerability",
            f"{tech}{version_str} CVE security advisory",
        ]

        all_results = []
        for q in queries:
            results = await self.search(q, num_results=3)
            all_results.extend(results)

        # Deduplicate by URL
        seen_urls = set()
        unique_results = []
        for r in all_results:
            if r["url"] not in seen_urls:
                seen_urls.add(r["url"])
                unique_results.append(r)

        return unique_results[:6]

    def format_results(self, results: List[dict]) -> str:
        """Format search results as a readable string for LLM context injection."""
        if not results:
            return "No web search results available."

        lines = []
        for i, r in enumerate(results, 1):
            lines.append(f"[{i}] {r.get('title', 'No title')}")
            lines.append(f"    URL: {r.get('url', '')}")
            snippet = r.get("snippet", "")
            if snippet:
                lines.append(f"    {snippet[:300]}")
            lines.append("")
        return "\n".join(lines).strip()
