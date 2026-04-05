#!/usr/bin/env python3
"""
VIPER Playwright Browser Tool — WAF Bypass via Headless Chromium

Launches a real headless browser with realistic fingerprints to bypass
Akamai, Cloudflare, Imperva, and other WAFs that block Python HTTP clients.

Requires: pip install playwright && python -m playwright install chromium
"""

import asyncio
import logging
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("viper.tools.playwright")

# Check availability at import time
_playwright_available = False
try:
    from playwright.async_api import async_playwright
    _playwright_available = True
except ImportError:
    pass


@dataclass
class BrowserResult:
    """Result from a browser navigation."""
    success: bool
    url: str
    final_url: str = ""
    status: int = 0
    content: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[Dict] = field(default_factory=list)
    error: Optional[str] = None
    title: str = ""
    elapsed_ms: float = 0.0


# Realistic viewport/UA combos to avoid fingerprint detection
_FINGERPRINTS = [
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "viewport": {"width": 1920, "height": 1080},
        "locale": "en-US",
        "timezone": "America/New_York",
        "color_scheme": "light",
    },
    {
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "viewport": {"width": 1440, "height": 900},
        "locale": "en-US",
        "timezone": "America/Los_Angeles",
        "color_scheme": "light",
    },
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "viewport": {"width": 1536, "height": 864},
        "locale": "en-GB",
        "timezone": "Europe/London",
        "color_scheme": "light",
    },
    {
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "viewport": {"width": 1920, "height": 1080},
        "locale": "en-US",
        "timezone": "America/Chicago",
        "color_scheme": "dark",
    },
    {
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "viewport": {"width": 2560, "height": 1440},
        "locale": "en-US",
        "timezone": "America/Denver",
        "color_scheme": "light",
    },
]


class PlaywrightTool:
    """Headless browser automation for WAF bypass and authenticated scanning.

    Usage::

        pw = PlaywrightTool()
        result = await pw.navigate("https://target.com")
        if result.success:
            print(result.content)   # full rendered HTML
            print(result.headers)   # response headers
            print(result.cookies)   # session cookies
    """

    def __init__(self, headless: bool = True, proxy: Optional[str] = None,
                 timeout_ms: int = 30000):
        self.headless = headless
        self.proxy = proxy
        self.timeout_ms = timeout_ms
        self._playwright = None
        self._browser = None

    @staticmethod
    def is_available() -> bool:
        """Check if playwright is installed and usable."""
        return _playwright_available

    async def _ensure_browser(self):
        """Launch browser if not already running."""
        if self._browser and self._browser.is_connected():
            return

        self._playwright = await async_playwright().start()

        fingerprint = random.choice(_FINGERPRINTS)

        launch_args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
            "--disable-infobars",
            "--no-first-run",
            "--no-default-browser-check",
        ]

        launch_kwargs = {
            "headless": self.headless,
            "args": launch_args,
        }
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}

        self._browser = await self._playwright.chromium.launch(**launch_kwargs)
        self._fingerprint = fingerprint

    async def _create_context(self):
        """Create a browser context with realistic fingerprint."""
        fp = self._fingerprint
        ctx = await self._browser.new_context(
            user_agent=fp["user_agent"],
            viewport=fp["viewport"],
            locale=fp["locale"],
            timezone_id=fp["timezone"],
            color_scheme=fp.get("color_scheme", "light"),
            java_script_enabled=True,
            ignore_https_errors=True,
            extra_http_headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            },
        )
        # Patch navigator.webdriver to return undefined
        await ctx.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5]
            });
            window.chrome = { runtime: {} };
        """)
        return ctx

    async def navigate(self, url: str, wait_for: str = "domcontentloaded",
                       wait_extra_ms: int = 0) -> BrowserResult:
        """Navigate to URL and return rendered page content.

        Args:
            url: Target URL.
            wait_for: Playwright wait condition — 'domcontentloaded', 'load', or 'networkidle'.
            wait_extra_ms: Additional wait after page load (for JS rendering).

        Returns:
            BrowserResult with full HTML, headers, cookies.
        """
        import time
        start = time.monotonic()

        try:
            await self._ensure_browser()
            ctx = await self._create_context()
            page = await ctx.new_page()

            # Capture response headers
            response_headers: Dict[str, str] = {}
            response_status = 0

            response = await page.goto(
                url,
                wait_until=wait_for,
                timeout=self.timeout_ms,
            )

            if response:
                response_status = response.status
                response_headers = {k: v for k, v in response.headers.items()}

            # Wait extra time for JS rendering if requested
            if wait_extra_ms > 0:
                await asyncio.sleep(wait_extra_ms / 1000.0)

            # Get full rendered HTML
            content = await page.content()
            title = await page.title()
            final_url = page.url

            # Extract cookies
            cookies = await ctx.cookies()
            cookie_list = [
                {
                    "name": c["name"],
                    "value": c["value"],
                    "domain": c.get("domain", ""),
                    "path": c.get("path", "/"),
                    "secure": c.get("secure", False),
                    "httpOnly": c.get("httpOnly", False),
                }
                for c in cookies
            ]

            elapsed = (time.monotonic() - start) * 1000

            await page.close()
            await ctx.close()

            return BrowserResult(
                success=True,
                url=url,
                final_url=final_url,
                status=response_status,
                content=content,
                headers=response_headers,
                cookies=cookie_list,
                title=title,
                elapsed_ms=elapsed,
            )

        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            logger.warning("Playwright navigation failed for %s: %s", url, e)
            return BrowserResult(
                success=False,
                url=url,
                error=str(e),
                elapsed_ms=elapsed,
            )

    async def bypass_waf(self, url: str) -> BrowserResult:
        """Navigate to a WAF-protected URL using a real browser to bypass bot detection.

        - Launches headless Chromium with realistic fingerprint
        - Navigates to URL as a real browser
        - Returns full rendered HTML + response headers + cookies
        - Bypasses Akamai/Cloudflare/Imperva WAF that block Python requests

        Args:
            url: The WAF-protected target URL.

        Returns:
            BrowserResult with .content (rendered HTML), .headers, .cookies.
        """
        logger.info("[WAF Bypass] Attempting browser-based bypass for %s", url)

        # First try with domcontentloaded (fast)
        result = await self.navigate(url, wait_for="domcontentloaded", wait_extra_ms=1000)

        if result.success and result.status == 200:
            logger.info("[WAF Bypass] Success on first attempt (%d chars)", len(result.content))
            return result

        # If we got a challenge page (403/503), retry with networkidle + extra wait
        # Cloudflare often serves a JS challenge that needs time to solve
        if result.success and result.status in (403, 503):
            logger.info("[WAF Bypass] Got %d, retrying with networkidle wait...", result.status)
            result = await self.navigate(url, wait_for="networkidle", wait_extra_ms=5000)

            if result.success and result.status == 200:
                logger.info("[WAF Bypass] Success after challenge wait (%d chars)", len(result.content))
                return result

        # If still blocked, try with a different fingerprint
        if result.success and result.status in (403, 503):
            logger.info("[WAF Bypass] Still blocked, trying new fingerprint...")
            await self.close()
            self._browser = None
            result = await self.navigate(url, wait_for="networkidle", wait_extra_ms=5000)

        return result

    async def fill_and_submit(self, url: str, fields: Dict[str, str],
                              submit_selector: str = 'button[type="submit"], input[type="submit"]'
                              ) -> BrowserResult:
        """Fill form fields and submit. Useful for login forms.

        Args:
            url: URL of the form page.
            fields: Dict mapping CSS selector -> value to fill.
            submit_selector: CSS selector for the submit button.

        Returns:
            BrowserResult from the page after submission.
        """
        import time
        start = time.monotonic()

        try:
            await self._ensure_browser()
            ctx = await self._create_context()
            page = await ctx.new_page()

            await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)

            # Fill each field
            for selector, value in fields.items():
                await page.fill(selector, value)
                # Small random delay between fields (human-like)
                await asyncio.sleep(random.uniform(0.1, 0.3))

            # Click submit and wait for navigation
            async with page.expect_navigation(wait_until="domcontentloaded", timeout=self.timeout_ms):
                await page.click(submit_selector)

            content = await page.content()
            title = await page.title()
            final_url = page.url
            cookies = await ctx.cookies()
            cookie_list = [
                {"name": c["name"], "value": c["value"], "domain": c.get("domain", ""),
                 "path": c.get("path", "/"), "secure": c.get("secure", False),
                 "httpOnly": c.get("httpOnly", False)}
                for c in cookies
            ]

            elapsed = (time.monotonic() - start) * 1000
            await page.close()
            await ctx.close()

            return BrowserResult(
                success=True, url=url, final_url=final_url, status=200,
                content=content, headers={}, cookies=cookie_list,
                title=title, elapsed_ms=elapsed,
            )
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            logger.warning("Playwright fill_and_submit failed: %s", e)
            return BrowserResult(success=False, url=url, error=str(e), elapsed_ms=elapsed)

    async def close(self):
        """Shut down browser and playwright."""
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
