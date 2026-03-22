#!/usr/bin/env python3
"""
VIPER Web Crawler + JS Analysis Engine — Async recursive web crawler with
JavaScript analysis, form extraction, and parameter discovery.

Features:
  - BFS async crawling with configurable depth and page limits
  - robots.txt parsing and enforcement
  - Scope-aware (same-domain only)
  - JavaScript endpoint extraction and secret detection
  - Form detection (login, file upload, search)
  - Parameter discovery from URLs, forms, and JS
  - Rate limiting (configurable RPS)
  - Deduplication of visited URLs
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from html.parser import HTMLParser

import aiohttp

logger = logging.getLogger("viper.web_crawler")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FormInfo:
    """Extracted HTML form details."""
    url: str
    action: str
    method: str
    inputs: List[Dict]  # [{name, type, value}]
    form_type: str  # "login", "upload", "search", "generic"

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
            "form_type": self.form_type,
        }


@dataclass
class JSAnalysisResult:
    """Results from JavaScript analysis."""
    endpoints: List[str] = field(default_factory=list)
    secrets: List[Dict] = field(default_factory=list)
    source_maps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "endpoints": self.endpoints,
            "secrets": self.secrets,
            "source_maps": self.source_maps,
        }


@dataclass
class CrawlResult:
    """Results from a web crawl."""
    target: str
    pages_crawled: int = 0
    urls: Set[str] = field(default_factory=set)
    forms: List[FormInfo] = field(default_factory=list)
    parameters: Set[str] = field(default_factory=set)
    js_endpoints: List[str] = field(default_factory=list)
    js_secrets: List[Dict] = field(default_factory=list)
    comments: List[Dict] = field(default_factory=list)  # [{url, comment}]
    emails: Set[str] = field(default_factory=set)
    technologies: List[str] = field(default_factory=list)
    js_files: Set[str] = field(default_factory=set)
    source_maps: List[str] = field(default_factory=list)
    duration: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "pages_crawled": self.pages_crawled,
            "urls": list(self.urls),
            "forms": [f.to_dict() for f in self.forms],
            "parameters": list(self.parameters),
            "js_endpoints": self.js_endpoints,
            "js_secrets": self.js_secrets,
            "comments": self.comments,
            "emails": list(self.emails),
            "technologies": self.technologies,
            "js_files": list(self.js_files),
            "source_maps": self.source_maps,
            "duration": round(self.duration, 2),
        }


# ---------------------------------------------------------------------------
# HTML Form Parser
# ---------------------------------------------------------------------------

class _FormExtractor(HTMLParser):
    """HTML parser that extracts forms and their inputs."""

    def __init__(self):
        super().__init__()
        self.forms: List[Dict] = []
        self._current_form: Optional[Dict] = None

    def handle_starttag(self, tag: str, attrs):
        attr_dict = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": (attr_dict.get("method", "GET")).upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attr_dict.get("name", ""),
                "type": attr_dict.get("type", "text"),
                "value": attr_dict.get("value", ""),
            })
        elif tag == "textarea" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attr_dict.get("name", ""),
                "type": "textarea",
                "value": "",
            })
        elif tag == "select" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attr_dict.get("name", ""),
                "type": "select",
                "value": "",
            })

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


# ---------------------------------------------------------------------------
# Secret patterns for JS analysis
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    ("aws_key", r'''(?:AKIA|ASIA)[A-Z0-9]{16}'''),
    ("aws_secret", r'''(?:aws_secret|secret_key|secretAccessKey)\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']'''),
    ("google_api_key", r'''AIza[A-Za-z0-9_-]{35}'''),
    ("github_token", r'''(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'''),
    ("slack_token", r'''xox[bporas]-[A-Za-z0-9-]+'''),
    ("jwt_token", r'''eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'''),
    ("private_key", r'''-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'''),
    ("generic_secret", r'''(?:secret|token|password|passwd|api_key|apikey|access_key)\s*[:=]\s*["']([^"']{8,})["']'''),
    ("firebase_url", r'''https://[a-z0-9-]+\.firebaseio\.com'''),
    ("sendgrid_key", r'''SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'''),
    ("stripe_key", r'''(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}'''),
    ("twilio_sid", r'''AC[a-f0-9]{32}'''),
    ("mailgun_key", r'''key-[A-Za-z0-9]{32}'''),
    ("heroku_api", r'''[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'''),
]

# Endpoint extraction patterns for JS
_ENDPOINT_PATTERNS = [
    r'''["'](/api/[^"'\s]+)["']''',
    r'''["'](/v[0-9]+/[^"'\s]+)["']''',
    r'''fetch\s*\(\s*["']([^"']+)["']''',
    r'''axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']''',
    r'''\.ajax\s*\(\s*\{[^}]*url\s*:\s*["']([^"']+)["']''',
    r'''XMLHttpRequest[^;]*\.open\s*\(\s*["'][^"']*["']\s*,\s*["']([^"']+)["']''',
    r'''["'](https?://[^"'\s]+/api[^"'\s]*)["']''',
    r'''["'](/graphql[^"'\s]*)["']''',
    r'''["'](/admin[^"'\s]*)["']''',
    r'''["'](/internal[^"'\s]*)["']''',
    r'''\.get\s*\(\s*["'](/[^"'\s]+)["']''',
    r'''\.post\s*\(\s*["'](/[^"'\s]+)["']''',
    r'''(?:endpoint|baseUrl|base_url|apiUrl|api_url)\s*[:=]\s*["']([^"']+)["']''',
    r'''["'](/auth[^"'\s]*)["']''',
    r'''["'](/login[^"'\s]*)["']''',
    r'''["'](/register[^"'\s]*)["']''',
    r'''["'](/upload[^"'\s]*)["']''',
    r'''["'](/download[^"'\s]*)["']''',
    r'''["'](/webhook[^"'\s]*)["']''',
]


# ---------------------------------------------------------------------------
# WebCrawler
# ---------------------------------------------------------------------------

class WebCrawler:
    """Async recursive web crawler with JS analysis.

    Crawls a website using BFS, extracts forms, parameters, JS files,
    comments, emails, and performs JavaScript endpoint/secret analysis.
    """

    def __init__(self, rate_limit: float = 0.2, user_agent: str = None,
                 verbose: bool = True):
        """Initialize the crawler.

        Args:
            rate_limit: Minimum seconds between requests (default 0.2 = 5 RPS)
            user_agent: Custom User-Agent string
            verbose: Log crawl progress
        """
        self.rate_limit = rate_limit
        self.user_agent = user_agent or (
            "Mozilla/5.0 (compatible; VIPER-Crawler/2.0; "
            "+https://github.com/viper-security)"
        )
        self.verbose = verbose
        self._robots_cache: Dict[str, Set[str]] = {}

    def log(self, msg: str, level: str = "INFO"):
        if self.verbose:
            from datetime import datetime
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] [CRAWLER] [{level}] {msg}")

    async def crawl(self, start_url: str, max_depth: int = 3,
                    max_pages: int = 100) -> CrawlResult:
        """Crawl a website starting from start_url.

        Args:
            start_url: URL to start crawling from
            max_depth: Maximum link depth to follow
            max_pages: Maximum number of pages to crawl

        Returns:
            CrawlResult with all extracted data
        """
        # Normalize start URL
        if not start_url.startswith(("http://", "https://")):
            start_url = f"https://{start_url}"

        parsed = urlparse(start_url)
        base_domain = parsed.netloc
        result = CrawlResult(target=start_url)
        start_time = time.time()

        visited: Set[str] = set()
        queue: List[Tuple[str, int]] = [(start_url, 0)]  # (url, depth)

        self.log(f"Starting crawl: {start_url} (depth={max_depth}, "
                 f"max_pages={max_pages})")

        # Parse robots.txt
        robots_disallowed = await self._parse_robots(
            f"{parsed.scheme}://{base_domain}"
        )

        headers = {"User-Agent": self.user_agent}

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False, limit=10),
            timeout=aiohttp.ClientTimeout(total=15),
            headers=headers,
        ) as session:
            while queue and result.pages_crawled < max_pages:
                url, depth = queue.pop(0)

                # Normalize and deduplicate
                url = self._normalize_url(url)
                if url in visited:
                    continue
                if not self._is_in_scope(url, base_domain):
                    continue
                if self._is_disallowed(url, robots_disallowed):
                    continue
                if self._is_static_resource(url):
                    # Track JS files but don't count as page
                    if url.endswith(".js") or ".js?" in url:
                        result.js_files.add(url)
                    continue

                visited.add(url)

                # Rate limit
                await asyncio.sleep(self.rate_limit)

                try:
                    async with session.get(url, allow_redirects=True) as resp:
                        if resp.status >= 400:
                            continue
                        content_type = resp.headers.get("Content-Type", "")
                        if "text/html" not in content_type and "application/xhtml" not in content_type:
                            continue

                        html = await resp.text(errors="replace")
                        result.pages_crawled += 1
                        result.urls.add(url)

                        if result.pages_crawled % 10 == 0:
                            self.log(f"  Crawled {result.pages_crawled} pages, "
                                     f"queue: {len(queue)}")

                        # Extract everything from this page
                        self._extract_from_page(url, html, result)

                        # Extract links for further crawling
                        if depth < max_depth:
                            links = self._extract_links(url, html)
                            for link in links:
                                if link not in visited:
                                    queue.append((link, depth + 1))

                except asyncio.TimeoutError:
                    logger.debug("Timeout crawling: %s", url)
                except Exception as e:
                    logger.debug("Error crawling %s: %s", url, e)

        # Analyze discovered JS files
        if result.js_files:
            self.log(f"Analyzing {len(result.js_files)} JavaScript files...")
            js_result = await self.analyze_javascript(
                list(result.js_files), headers=headers
            )
            result.js_endpoints = js_result.endpoints
            result.js_secrets = js_result.secrets
            result.source_maps = js_result.source_maps

        result.duration = time.time() - start_time
        self.log(f"Crawl complete: {result.pages_crawled} pages, "
                 f"{len(result.forms)} forms, {len(result.parameters)} params, "
                 f"{len(result.js_endpoints)} JS endpoints, "
                 f"{len(result.js_files)} JS files in {result.duration:.1f}s")
        return result

    async def analyze_javascript(self, js_urls: List[str],
                                 headers: Dict = None) -> JSAnalysisResult:
        """Fetch and analyze JavaScript files for endpoints and secrets.

        Args:
            js_urls: List of JS file URLs to analyze
            headers: Optional HTTP headers

        Returns:
            JSAnalysisResult with endpoints, secrets, and source maps
        """
        result = JSAnalysisResult()
        seen_endpoints: Set[str] = set()

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False, limit=5),
            timeout=aiohttp.ClientTimeout(total=15),
            headers=headers or {},
        ) as session:
            for js_url in js_urls[:50]:  # Cap at 50 JS files
                try:
                    async with session.get(js_url) as resp:
                        if resp.status != 200:
                            continue
                        js_content = await resp.text(errors="replace")

                        # Extract endpoints
                        for pattern in _ENDPOINT_PATTERNS:
                            for match in re.finditer(pattern, js_content):
                                endpoint = match.group(1)
                                if endpoint and endpoint not in seen_endpoints:
                                    # Filter out obviously non-endpoint matches
                                    if (len(endpoint) > 1 and
                                            not endpoint.startswith("//") and
                                            not endpoint.endswith(".png") and
                                            not endpoint.endswith(".jpg") and
                                            not endpoint.endswith(".css")):
                                        seen_endpoints.add(endpoint)
                                        result.endpoints.append(endpoint)

                        # Extract secrets
                        for secret_type, pattern in _SECRET_PATTERNS:
                            for match in re.finditer(pattern, js_content):
                                value = match.group(1) if match.lastindex else match.group(0)
                                result.secrets.append({
                                    "type": secret_type,
                                    "value": value[:20] + "..." if len(value) > 20 else value,
                                    "source": js_url,
                                })

                        # Extract source map URLs
                        for sm_match in re.finditer(
                            r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)',
                            js_content
                        ):
                            sm_url = sm_match.group(1)
                            if not sm_url.startswith("data:"):
                                full_url = urljoin(js_url, sm_url)
                                result.source_maps.append(full_url)

                    await asyncio.sleep(self.rate_limit)
                except Exception as e:
                    logger.debug("Error analyzing JS %s: %s", js_url, e)

        return result

    def extract_forms(self, html: str, page_url: str = "") -> List[FormInfo]:
        """Parse HTML and extract all forms with their inputs.

        Args:
            html: HTML content to parse
            page_url: URL of the page (for resolving relative actions)

        Returns:
            List of FormInfo objects
        """
        parser = _FormExtractor()
        try:
            parser.feed(html)
        except Exception:
            pass

        forms = []
        for raw_form in parser.forms:
            action = raw_form["action"]
            if page_url and action and not action.startswith(("http://", "https://")):
                action = urljoin(page_url, action)

            form_type = self._classify_form(raw_form)

            forms.append(FormInfo(
                url=page_url,
                action=action or page_url,
                method=raw_form["method"],
                inputs=raw_form["inputs"],
                form_type=form_type,
            ))

        return forms

    def extract_parameters(self, url: str, html: str) -> Set[str]:
        """Extract parameter names from URL query strings, forms, and JS.

        Args:
            url: URL to extract query params from
            html: HTML content to extract form fields and JS params from

        Returns:
            Set of parameter names
        """
        params: Set[str] = set()

        # URL query parameters
        parsed = urlparse(url)
        for key in parse_qs(parsed.query):
            params.add(key)

        # Form field names
        parser = _FormExtractor()
        try:
            parser.feed(html)
        except Exception:
            pass
        for form in parser.forms:
            for inp in form["inputs"]:
                name = inp.get("name", "")
                if name:
                    params.add(name)

        # Hidden inputs specifically
        for match in re.finditer(
            r'<input[^>]+type\s*=\s*["\']hidden["\'][^>]*name\s*=\s*["\']([^"\']+)',
            html, re.I
        ):
            params.add(match.group(1))

        # JS variable names used in fetch/XHR
        for match in re.finditer(
            r'(?:params|data|body)\s*[\[.]\s*["\'](\w+)["\']',
            html, re.I
        ):
            params.add(match.group(1))

        # URL params in JS strings
        for match in re.finditer(
            r'[?&](\w+)\s*=',
            html
        ):
            params.add(match.group(1))

        return params

    # -------------------------------------------------------------------
    # Internal methods
    # -------------------------------------------------------------------

    def _extract_from_page(self, url: str, html: str, result: CrawlResult):
        """Extract forms, params, comments, emails, JS files from a page."""
        # Forms
        forms = self.extract_forms(html, url)
        result.forms.extend(forms)

        # Parameters
        params = self.extract_parameters(url, html)
        result.parameters.update(params)

        # HTML comments
        for match in re.finditer(r'<!--(.*?)-->', html, re.DOTALL):
            comment = match.group(1).strip()
            if comment and len(comment) > 3:
                result.comments.append({"url": url, "comment": comment[:500]})

        # Emails
        for match in re.finditer(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            html
        ):
            email = match.group(0)
            if not email.endswith((".png", ".jpg", ".gif", ".css", ".js")):
                result.emails.add(email)

        # JS file references
        for match in re.finditer(
            r'<script[^>]+src\s*=\s*["\']([^"\']+\.js[^"\']*)["\']',
            html, re.I
        ):
            js_url = urljoin(url, match.group(1))
            result.js_files.add(js_url)

    def _extract_links(self, base_url: str, html: str) -> Set[str]:
        """Extract all links from HTML content."""
        links: Set[str] = set()

        # href attributes
        for match in re.finditer(
            r'<a[^>]+href\s*=\s*["\']([^"\'#]+)',
            html, re.I
        ):
            href = match.group(1).strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                full_url = urljoin(base_url, href)
                links.add(self._normalize_url(full_url))

        return links

    def _normalize_url(self, url: str) -> str:
        """Normalize a URL by removing fragments and trailing slashes."""
        parsed = urlparse(url)
        # Remove fragment
        normalized = parsed._replace(fragment="").geturl()
        # Remove trailing slash for consistency (except root)
        if normalized.endswith("/") and parsed.path != "/":
            normalized = normalized.rstrip("/")
        return normalized

    def _is_in_scope(self, url: str, base_domain: str) -> bool:
        """Check if a URL is within the same domain scope."""
        parsed = urlparse(url)
        return parsed.netloc == base_domain or parsed.netloc.endswith(f".{base_domain}")

    def _is_disallowed(self, url: str, disallowed: Set[str]) -> bool:
        """Check if a URL path is disallowed by robots.txt."""
        parsed = urlparse(url)
        path = parsed.path
        return any(path.startswith(d) for d in disallowed)

    def _is_static_resource(self, url: str) -> bool:
        """Check if a URL points to a static resource (image, CSS, font, etc.)."""
        static_exts = {
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
            ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip",
            ".tar", ".gz", ".rar", ".7z",
        }
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        return any(path_lower.endswith(ext) for ext in static_exts)

    def _classify_form(self, form: Dict) -> str:
        """Classify a form as login, upload, search, or generic."""
        input_types = {i.get("type", "").lower() for i in form["inputs"]}
        input_names = {i.get("name", "").lower() for i in form["inputs"]}

        if "password" in input_types:
            return "login"
        if "file" in input_types:
            return "upload"

        search_indicators = {"search", "query", "q", "keyword", "s", "term"}
        if input_names & search_indicators:
            return "search"

        login_indicators = {"username", "user", "email", "login", "passwd", "pass"}
        if input_names & login_indicators:
            return "login"

        return "generic"

    async def _parse_robots(self, base_url: str) -> Set[str]:
        """Parse robots.txt and return set of disallowed paths."""
        disallowed: Set[str] = set()
        robots_url = f"{base_url}/robots.txt"

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=5),
            ) as session:
                async with session.get(robots_url) as resp:
                    if resp.status != 200:
                        return disallowed
                    text = await resp.text()

            applicable = False
            for line in text.split("\n"):
                line = line.strip()
                if line.lower().startswith("user-agent:"):
                    agent = line.split(":", 1)[1].strip()
                    applicable = agent == "*" or "viper" in agent.lower()
                elif line.lower().startswith("disallow:") and applicable:
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.add(path)
        except Exception:
            pass

        self._robots_cache[base_url] = disallowed
        if disallowed:
            self.log(f"  robots.txt: {len(disallowed)} disallowed paths")
        return disallowed
