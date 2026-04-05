#!/usr/bin/env python3
"""
VIPER Authenticated Scanner — Login to targets and pass session to all requests.

Supports three authentication methods:
1. HTML form POST (username/password login pages)
2. Bearer token (API authentication)
3. Custom cookies (pre-existing session)

Once authenticated, all subsequent VIPER requests include the captured
session cookies and auth headers automatically.
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("viper.core.auth_scanner")

# Check for playwright (used for JS-rendered login forms)
_playwright_available = False
try:
    from tools.playwright_tool import PlaywrightTool
    _playwright_available = PlaywrightTool.is_available()
except ImportError:
    pass


class AuthScanner:
    """Authenticated vulnerability scanning.

    Logs into target application, captures session cookies/tokens,
    then passes them to all subsequent VIPER requests.

    Usage::

        auth = AuthScanner(http_client=viper.http_client)
        await auth.login_form("https://target.com/login", "admin", "password123")

        # Now inject into every request
        headers = auth.get_auth_headers()
        cookies = auth.get_auth_cookies()
        status, body, hdrs = await viper.request(url, headers=headers, cookies=cookies)
    """

    def __init__(self, http_client=None):
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.authenticated: bool = False
        self.auth_method: str = ""
        self.session_info: Dict = {}
        self.http_client = http_client

    async def login_form(self, login_url: str, username: str, password: str,
                         username_field: str = "username",
                         password_field: str = "password",
                         extra_fields: Optional[Dict[str, str]] = None,
                         use_browser: bool = False) -> bool:
        """Login via HTML form POST.

        Sends a POST request to the login URL with the provided credentials.
        Captures session cookies from the Set-Cookie response headers.

        Args:
            login_url: Full URL of the login endpoint.
            username: Username or email for authentication.
            password: Password string.
            username_field: Form field name for username (default: 'username').
            password_field: Form field name for password (default: 'password').
            extra_fields: Additional form fields (e.g., CSRF token).
            use_browser: Use Playwright for JS-rendered login forms.

        Returns:
            True if login succeeded (got session cookies or redirect).
        """
        logger.info("[Auth] Attempting form login at %s", login_url)

        if use_browser and _playwright_available:
            return await self._login_form_browser(
                login_url, username, password,
                username_field, password_field, extra_fields,
            )

        # Build form data
        form_data = {
            username_field: username,
            password_field: password,
        }
        if extra_fields:
            form_data.update(extra_fields)

        # First GET the login page to extract CSRF tokens
        csrf_token = None
        if self.http_client:
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    async with session.get(login_url, ssl=False, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        page_html = await resp.text()
                        # Extract CSRF token from common patterns
                        csrf_token = self._extract_csrf(page_html)
                        # Capture any initial cookies
                        for cookie in resp.cookies.values():
                            self.cookies[cookie.key] = cookie.value
            except Exception as e:
                logger.debug("[Auth] GET login page failed: %s", e)

        if csrf_token and not extra_fields:
            # Auto-inject CSRF token
            for field_name in ("_token", "csrf_token", "csrfmiddlewaretoken",
                               "_csrf", "authenticity_token", "csrf"):
                form_data[field_name] = csrf_token

        # POST login request
        try:
            import aiohttp
            async with aiohttp.ClientSession(cookies=self.cookies) as session:
                async with session.post(
                    login_url,
                    data=form_data,
                    ssl=False,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    # Capture session cookies
                    for cookie in resp.cookies.values():
                        self.cookies[cookie.key] = cookie.value

                    # Also capture from Set-Cookie header directly
                    for hdr_val in resp.headers.getall("Set-Cookie", []):
                        parts = hdr_val.split(";")[0].strip()
                        if "=" in parts:
                            k, v = parts.split("=", 1)
                            self.cookies[k.strip()] = v.strip()

                    body = await resp.text()
                    status = resp.status

            # Determine success: got cookies + not still on login page
            has_session = bool(self.cookies)
            not_login_page = "login" not in body.lower()[:500] or status in (301, 302)

            if has_session and (not_login_page or status < 400):
                self.authenticated = True
                self.auth_method = "form"
                self.session_info = {
                    "login_url": login_url,
                    "username": username,
                    "cookies_count": len(self.cookies),
                    "status": status,
                }
                logger.info("[Auth] Form login successful (%d cookies captured)", len(self.cookies))
                return True
            else:
                logger.warning("[Auth] Form login likely failed (status=%d, cookies=%d)",
                               status, len(self.cookies))
                return False

        except Exception as e:
            logger.error("[Auth] Form login error: %s", e)
            return False

    async def _login_form_browser(self, login_url: str, username: str, password: str,
                                   username_field: str, password_field: str,
                                   extra_fields: Optional[Dict[str, str]]) -> bool:
        """Login using Playwright browser (handles JS-rendered forms)."""
        pw = PlaywrightTool()
        try:
            # Build CSS selectors from field names
            fields = {
                f'input[name="{username_field}"], input[id="{username_field}"], '
                f'input[type="email"], input[type="text"]': username,
                f'input[name="{password_field}"], input[id="{password_field}"], '
                f'input[type="password"]': password,
            }
            if extra_fields:
                for name, val in extra_fields.items():
                    fields[f'input[name="{name}"], input[id="{name}"]'] = val

            result = await pw.fill_and_submit(login_url, fields)

            if result.success and result.cookies:
                for cookie in result.cookies:
                    self.cookies[cookie["name"]] = cookie["value"]
                self.authenticated = True
                self.auth_method = "form_browser"
                self.session_info = {
                    "login_url": login_url,
                    "username": username,
                    "cookies_count": len(self.cookies),
                    "final_url": result.final_url,
                }
                logger.info("[Auth] Browser login successful (%d cookies)", len(self.cookies))
                return True
            else:
                logger.warning("[Auth] Browser login failed: %s", result.error or "no cookies")
                return False
        finally:
            await pw.close()

    async def login_bearer(self, token: str) -> bool:
        """Set Bearer token for API authentication.

        Args:
            token: Bearer/JWT token string.

        Returns:
            True (always succeeds — token validity checked on first use).
        """
        self.headers["Authorization"] = f"Bearer {token}"
        self.authenticated = True
        self.auth_method = "bearer"
        self.session_info = {
            "token_prefix": token[:8] + "...",
            "token_length": len(token),
        }
        logger.info("[Auth] Bearer token set (length=%d)", len(token))
        return True

    async def login_cookie(self, cookies: Dict[str, str]) -> bool:
        """Set custom cookies for session-based authentication.

        Args:
            cookies: Dict of cookie name -> value pairs.

        Returns:
            True if at least one cookie was set.
        """
        self.cookies.update(cookies)
        self.authenticated = bool(self.cookies)
        self.auth_method = "cookie"
        self.session_info = {
            "cookies_count": len(self.cookies),
            "cookie_names": list(self.cookies.keys()),
        }
        logger.info("[Auth] Custom cookies set (%d cookies)", len(self.cookies))
        return self.authenticated

    async def login_api_key(self, key: str, header_name: str = "X-API-Key") -> bool:
        """Set API key header for authentication.

        Args:
            key: API key string.
            header_name: HTTP header name (default: 'X-API-Key').

        Returns:
            True (always succeeds).
        """
        self.headers[header_name] = key
        self.authenticated = True
        self.auth_method = "api_key"
        self.session_info = {
            "header": header_name,
            "key_prefix": key[:6] + "...",
        }
        logger.info("[Auth] API key set via header %s", header_name)
        return True

    def get_auth_headers(self) -> Dict[str, str]:
        """Return headers with auth tokens for authenticated requests."""
        return dict(self.headers)

    def get_auth_cookies(self) -> Dict[str, str]:
        """Return session cookies for authenticated requests."""
        return dict(self.cookies)

    def inject_into_request_kwargs(self, kwargs: dict) -> dict:
        """Merge auth cookies/headers into existing request kwargs.

        Usage::

            kwargs = {"headers": {"Accept": "text/html"}}
            kwargs = auth.inject_into_request_kwargs(kwargs)
        """
        if self.headers:
            existing = kwargs.get("headers", {}) or {}
            existing.update(self.headers)
            kwargs["headers"] = existing

        if self.cookies:
            existing = kwargs.get("cookies", {}) or {}
            existing.update(self.cookies)
            kwargs["cookies"] = existing

        return kwargs

    def is_authenticated(self) -> bool:
        """Check if authentication state is active."""
        return self.authenticated

    def get_status(self) -> Dict:
        """Return authentication status summary."""
        return {
            "authenticated": self.authenticated,
            "method": self.auth_method,
            "cookies_count": len(self.cookies),
            "headers_count": len(self.headers),
            "info": self.session_info,
        }

    def reset(self):
        """Clear all authentication state."""
        self.cookies.clear()
        self.headers.clear()
        self.authenticated = False
        self.auth_method = ""
        self.session_info = {}
        logger.info("[Auth] Authentication state reset")

    @staticmethod
    def _extract_csrf(html: str) -> Optional[str]:
        """Extract CSRF token from HTML page using common patterns."""
        patterns = [
            r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)',
            r'name=["\']_token["\'][^>]*value=["\']([^"\']+)',
            r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)',
            r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)',
            r'name=["\']_csrf["\'][^>]*value=["\']([^"\']+)',
            # Reversed order: value before name
            r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf[_-]?token["\']',
            r'value=["\']([^"\']+)["\'][^>]*name=["\']_token["\']',
            # Meta tag CSRF
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)',
            r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']csrf-token["\']',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
