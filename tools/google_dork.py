#!/usr/bin/env python3
"""
VIPER 4.0 Feature F7 — Google Dork Tool.

Passive OSINT via Google dork queries through SerpAPI.
Stdlib only (urllib.request). No external dependencies.
"""

import json
import logging
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.tools.google_dork")

SERPAPI_BASE = "https://serpapi.com/search"


class GoogleDorkTool:
    """Passive OSINT via Google dork queries through SerpAPI."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("SERPAPI_KEY", "")
        self.available = bool(self.api_key)

    # ------------------------------------------------------------------
    # Core search
    # ------------------------------------------------------------------

    async def search(self, query: str, num_results: int = 10) -> Dict[str, Any]:
        """
        Run a Google dork query via SerpAPI.

        Args:
            query: Google dork query string (e.g. "site:example.com filetype:sql").
            num_results: Number of results to request (max 100).

        Returns:
            Dict with keys:
                ok: bool — whether the search succeeded.
                query: str — the query that was run.
                total_results: str — estimated total results from Google.
                results: list of dicts with title, url, snippet, displayed_link, position.
                error: str — error message if ok is False.
        """
        if not self.available:
            return {
                "ok": False,
                "query": query,
                "total_results": "0",
                "results": [],
                "error": (
                    "SerpAPI key not configured. Set SERPAPI_KEY environment variable "
                    "or pass api_key to GoogleDorkTool()."
                ),
            }

        params = urllib.parse.urlencode({
            "engine": "google",
            "api_key": self.api_key,
            "q": query,
            "num": min(num_results, 100),
            "nfpr": 1,      # Disable auto-correct to preserve dork syntax
            "filter": 0,    # Disable similar results filter
        })
        url = f"{SERPAPI_BASE}?{params}"

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VIPER/4.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if "error" in data:
                return {
                    "ok": False,
                    "query": query,
                    "total_results": "0",
                    "results": [],
                    "error": data["error"],
                }

            items = data.get("organic_results", [])
            search_info = data.get("search_information", {})
            total = search_info.get("total_results", "?")

            results = []
            for item in items:
                results.append({
                    "position": item.get("position", 0),
                    "title": item.get("title", ""),
                    "url": item.get("link", ""),
                    "snippet": item.get("snippet", ""),
                    "displayed_link": item.get("displayed_link", ""),
                })

            return {
                "ok": True,
                "query": query,
                "total_results": str(total),
                "results": results,
                "error": "",
            }

        except urllib.error.HTTPError as e:
            status = e.code
            if status == 401:
                msg = "SerpAPI error: Invalid API key."
            elif status == 429:
                msg = "SerpAPI error: Rate limit exceeded (free tier: 250/month, 50/hour)."
            else:
                msg = f"SerpAPI error: HTTP {status}"
            logger.error(msg)
            return {
                "ok": False,
                "query": query,
                "total_results": "0",
                "results": [],
                "error": msg,
            }
        except Exception as e:
            # Sanitize error to prevent API key leakage in exception messages
            err_msg = str(e)
            if self.api_key and self.api_key in err_msg:
                err_msg = err_msg.replace(self.api_key, "***API_KEY***")
            logger.error(f"Google dork search failed: {err_msg}")
            return {
                "ok": False,
                "query": query,
                "total_results": "0",
                "results": [],
                "error": err_msg,
            }

    # ------------------------------------------------------------------
    # Dork battery against a target
    # ------------------------------------------------------------------

    def generate_dorks(self, domain: str) -> List[str]:
        """
        Generate common Google dork queries for a domain.

        Returns a list of dork query strings covering file exposure,
        admin panels, directory listings, sensitive data, and code leaks.
        """
        return [
            f'site:{domain} filetype:sql',
            f'site:{domain} filetype:env',
            f'site:{domain} filetype:log',
            f'site:{domain} filetype:bak',
            f'site:{domain} filetype:conf',
            f'site:{domain} filetype:cfg',
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login | inurl:signin',
            f'site:{domain} intitle:"index of"',
            f'site:{domain} filetype:pdf confidential',
            f'site:{domain} ext:xml | ext:json | ext:yaml',
            f'site:{domain} inurl:api',
            f'site:{domain} inurl:wp-content | inurl:wp-admin',
            f'site:{domain} intext:"sql syntax" | intext:"mysql_fetch"',
            f'"{domain}" password | secret | token | api_key',
            f'site:github.com "{domain}"',
            f'site:pastebin.com "{domain}"',
            f'site:trello.com "{domain}"',
        ]

    async def dork_target(self, domain: str) -> Dict[str, Any]:
        """
        Run a battery of common dorks against a target domain.

        Args:
            domain: Target domain (e.g. "example.com").

        Returns:
            Dict with keys:
                domain: str — the target domain.
                total_dorks: int — number of dork queries executed.
                total_results_found: int — total result items across all queries.
                dork_results: list of per-query result dicts.
                errors: list of error messages for failed queries.
        """
        dorks = self.generate_dorks(domain)
        all_results: List[Dict[str, Any]] = []
        errors: List[str] = []
        total_found = 0

        for query in dorks:
            result = await self.search(query, num_results=10)
            entry = {
                "query": query,
                "ok": result["ok"],
                "total_results": result["total_results"],
                "results": result["results"],
            }
            all_results.append(entry)

            if result["ok"]:
                total_found += len(result["results"])
            else:
                errors.append(f"{query}: {result['error']}")

        return {
            "domain": domain,
            "total_dorks": len(dorks),
            "total_results_found": total_found,
            "dork_results": all_results,
            "errors": errors,
        }

    # ------------------------------------------------------------------
    # Convenience: formatted text output
    # ------------------------------------------------------------------

    def format_results(self, search_result: Dict[str, Any]) -> str:
        """Format a search result dict into readable text output."""
        if not search_result.get("ok"):
            return f"Error: {search_result.get('error', 'Unknown error')}"

        results = search_result.get("results", [])
        if not results:
            return f"No results found for: {search_result.get('query', '?')}"

        total = search_result.get("total_results", "?")
        lines = [f"Google dork results ({total} total, showing {len(results)}):"]
        for r in results:
            pos = r.get("position", "?")
            title = r.get("title", "No title")
            url = r.get("url", "")
            snippet = r.get("snippet", "")
            entry = f"\n[{pos}] {title}\n    URL: {url}"
            if snippet:
                entry += f"\n    {snippet}"
            lines.append(entry)

        return "\n".join(lines)

    def format_dork_report(self, dork_result: Dict[str, Any]) -> str:
        """Format a full dork_target result into a readable report."""
        domain = dork_result.get("domain", "?")
        total_dorks = dork_result.get("total_dorks", 0)
        total_found = dork_result.get("total_results_found", 0)
        errors = dork_result.get("errors", [])

        lines = [
            f"Google Dork OSINT Report for {domain}",
            f"{'=' * 50}",
            f"Dork queries executed: {total_dorks}",
            f"Total results found: {total_found}",
            f"Errors: {len(errors)}",
            "",
        ]

        for dr in dork_result.get("dork_results", []):
            query = dr.get("query", "")
            results = dr.get("results", [])
            total = dr.get("total_results", "0")

            if not dr.get("ok"):
                lines.append(f"[FAIL] {query}")
                continue

            if not results:
                lines.append(f"[  0] {query}")
                continue

            lines.append(f"[{len(results):3d}] {query} ({total} total)")
            for r in results[:3]:  # Show top 3 per dork
                lines.append(f"      - {r.get('title', '')} | {r.get('url', '')}")

        if errors:
            lines.append(f"\nErrors encountered:")
            for err in errors:
                lines.append(f"  - {err}")

        return "\n".join(lines)
