#!/usr/bin/env python3
"""
Async HTTP Client for HackAgent

Features:
- Rate limiting with exponential backoff
- WAF detection
- User-agent rotation
- Proxy support
- Response analysis integration
"""

import asyncio
import aiohttp
import random
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse
import ssl


@dataclass
class RequestResult:
    """Result of an HTTP request."""
    url: str
    method: str
    status: int
    headers: Dict[str, str]
    body: str
    elapsed_ms: float
    error: Optional[str] = None
    waf_detected: Optional[str] = None
    rate_limited: bool = False


class RateLimiter:
    """Respect rate limits like a good hacker."""

    def __init__(self, requests_per_second: float = 2.0):
        self.rps = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request: Dict[str, float] = {}  # domain -> timestamp
        self.backoff: Dict[str, float] = {}  # domain -> backoff multiplier

    async def wait(self, domain: str):
        """Wait if needed before making request."""
        now = time.time()

        if domain in self.last_request:
            elapsed = now - self.last_request[domain]
            wait_time = self.min_interval * self.backoff.get(domain, 1.0)

            if elapsed < wait_time:
                await asyncio.sleep(wait_time - elapsed)

        self.last_request[domain] = time.time()

    def got_rate_limited(self, domain: str):
        """Increase backoff for domain."""
        current = self.backoff.get(domain, 1.0)
        self.backoff[domain] = min(current * 2, 60.0)  # Max 60s backoff

    def reset_backoff(self, domain: str):
        """Reset backoff after successful request."""
        if domain in self.backoff:
            del self.backoff[domain]


class AdaptiveRateLimiter(RateLimiter):
    """
    Enhanced rate limiter with per-domain tracking, 429 detection,
    exponential backoff, and auto-pause after repeated rate limits.
    """

    def __init__(self, default_rps: float = 2.0, per_domain_limits: Dict[str, float] = None):
        super().__init__(default_rps)
        self.per_domain_limits = per_domain_limits or {}
        self.consecutive_429s: Dict[str, int] = {}
        self.paused_until: Dict[str, float] = {}  # domain -> timestamp

    async def wait(self, domain: str):
        """Wait with adaptive timing and per-domain limits."""
        now = time.time()

        # Check if domain is paused
        if domain in self.paused_until:
            if now < self.paused_until[domain]:
                wait = self.paused_until[domain] - now
                await asyncio.sleep(wait)
            else:
                del self.paused_until[domain]

        # Use per-domain RPS if set, otherwise default
        rps = self.per_domain_limits.get(domain, self.rps)
        min_interval = 1.0 / rps

        if domain in self.last_request:
            elapsed = now - self.last_request[domain]
            wait_time = min_interval * self.backoff.get(domain, 1.0)
            if elapsed < wait_time:
                await asyncio.sleep(wait_time - elapsed)

        self.last_request[domain] = time.time()

    def got_rate_limited(self, domain: str, retry_after: Optional[int] = None):
        """Track 429s with exponential backoff and auto-pause."""
        self.consecutive_429s[domain] = self.consecutive_429s.get(domain, 0) + 1

        if retry_after:
            self.backoff[domain] = retry_after
        else:
            current = self.backoff.get(domain, 1.0)
            self.backoff[domain] = min(current * 2, 120.0)

        # Auto-pause after 5 consecutive 429s
        if self.consecutive_429s[domain] >= 5:
            self.paused_until[domain] = time.time() + 300.0  # 5 min pause

    def reset_backoff(self, domain: str):
        """Reset backoff and 429 counter after successful request."""
        if domain in self.backoff:
            del self.backoff[domain]
        if domain in self.consecutive_429s:
            del self.consecutive_429s[domain]

    def set_domain_limit(self, domain: str, rps: float):
        """Set per-domain rate limit."""
        self.per_domain_limits[domain] = rps

    def is_paused(self, domain: str) -> bool:
        """Check if a domain is currently paused."""
        return domain in self.paused_until and time.time() < self.paused_until[domain]


USER_AGENTS = [
    # Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]


WAF_SIGNATURES = {
    "cloudflare": [
        "cf-ray",
        "__cfduid",
        "cloudflare",
        "cf-request-id",
    ],
    "akamai": [
        "akamai",
        "x-akamai",
    ],
    "aws_waf": [
        "awswaf",
        "x-amzn-waf",
    ],
    "mod_security": [
        "mod_security",
        "modsec",
        "noyb",
    ],
    "incapsula": [
        "incap_ses",
        "visid_incap",
        "incapsula",
    ],
    "sucuri": [
        "sucuri",
        "x-sucuri",
    ],
    "f5_big_ip": [
        "bigip",
        "f5",
        "x-wa-info",
    ],
    "fortinet": [
        "fortigate",
        "fortiweb",
    ],
}


class HackerHTTPClient:
    """
    HTTP client that thinks like a hacker.
    
    - Rotates user agents
    - Respects (but remembers) rate limits
    - Detects WAFs
    - Supports proxies
    - Analyzes responses for vulnerabilities
    """
    
    def __init__(
        self,
        requests_per_second: float = 2.0,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        rotate_ua: bool = True,
    ):
        self.rate_limiter = AdaptiveRateLimiter(requests_per_second)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.rotate_ua = rotate_ua
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Statistics
        self.requests_made = 0
        self.rate_limits_hit = 0
        self.wafs_detected: Dict[str, str] = {}  # domain -> waf type
    
    async def __aenter__(self):
        await self.start()
        return self
    
    async def __aexit__(self, *args):
        await self.close()
    
    async def start(self):
        """Initialize session."""
        ssl_context = None if self.verify_ssl else ssl.create_default_context()
        if not self.verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        self.session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
        )
    
    async def close(self):
        """Close session."""
        if self.session:
            await self.session.close()
    
    def _get_headers(self, custom_headers: Optional[Dict] = None) -> Dict:
        """Get request headers with optional rotation."""
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        if self.rotate_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        else:
            headers["User-Agent"] = USER_AGENTS[0]
        
        if custom_headers:
            headers.update(custom_headers)
        
        return headers
    
    def _detect_waf(self, headers: Dict, body: str) -> Optional[str]:
        """Detect WAF from response."""
        # Combine headers and body for checking
        check_text = str(headers).lower() + body.lower()
        
        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in check_text:
                    return waf_name
        
        # Check for generic block pages
        block_indicators = [
            "access denied",
            "forbidden",
            "blocked",
            "security",
            "firewall",
            "protection",
        ]
        
        if any(ind in body.lower() for ind in block_indicators):
            # Could be a WAF block page
            return "unknown_waf"
        
        return None
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        data: Optional[str] = None,
        json: Optional[Dict] = None,
        params: Optional[Dict] = None,
        allow_redirects: bool = True,
    ) -> RequestResult:
        """Make an HTTP request with all the hacker goodness."""
        
        if not self.session:
            await self.start()
        
        domain = urlparse(url).netloc
        
        # Rate limiting
        await self.rate_limiter.wait(domain)
        
        self.requests_made += 1
        start_time = time.time()
        
        try:
            async with self.session.request(
                method=method.upper(),
                url=url,
                headers=self._get_headers(headers),
                data=data,
                json=json,
                params=params,
                proxy=self.proxy,
                allow_redirects=allow_redirects,
            ) as response:
                body = await response.text()
                elapsed = (time.time() - start_time) * 1000
                
                resp_headers = dict(response.headers)
                
                # Check for rate limiting
                rate_limited = response.status == 429
                if rate_limited:
                    self.rate_limits_hit += 1
                    retry_after = None
                    ra_header = response.headers.get("Retry-After")
                    if ra_header:
                        try:
                            retry_after = int(ra_header)
                        except ValueError:
                            pass
                    self.rate_limiter.got_rate_limited(domain, retry_after=retry_after)
                else:
                    self.rate_limiter.reset_backoff(domain)
                
                # Detect WAF
                waf = self._detect_waf(resp_headers, body)
                if waf:
                    self.wafs_detected[domain] = waf
                
                return RequestResult(
                    url=url,
                    method=method.upper(),
                    status=response.status,
                    headers=resp_headers,
                    body=body,
                    elapsed_ms=elapsed,
                    waf_detected=waf,
                    rate_limited=rate_limited,
                )
                
        except asyncio.TimeoutError:
            return RequestResult(
                url=url,
                method=method.upper(),
                status=0,
                headers={},
                body="",
                elapsed_ms=(time.time() - start_time) * 1000,
                error="Timeout",
            )
        except Exception as e:
            return RequestResult(
                url=url,
                method=method.upper(),
                status=0,
                headers={},
                body="",
                elapsed_ms=(time.time() - start_time) * 1000,
                error=str(e),
            )
    
    async def get(self, url: str, **kwargs) -> RequestResult:
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> RequestResult:
        return await self.request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> RequestResult:
        return await self.request("PUT", url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> RequestResult:
        return await self.request("DELETE", url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> RequestResult:
        return await self.request("HEAD", url, **kwargs)
    
    async def options(self, url: str, **kwargs) -> RequestResult:
        return await self.request("OPTIONS", url, **kwargs)
    
    async def parallel_requests(
        self,
        requests: List[Tuple[str, str, Optional[Dict]]],  # (method, url, headers)
        max_concurrent: int = 10,
    ) -> List[RequestResult]:
        """Make multiple requests in parallel with concurrency limit."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def bounded_request(method: str, url: str, headers: Optional[Dict]):
            async with semaphore:
                return await self.request(method, url, headers=headers)
        
        tasks = [
            bounded_request(method, url, headers)
            for method, url, headers in requests
        ]
        
        return await asyncio.gather(*tasks)
    
    def get_stats(self) -> Dict:
        """Get client statistics."""
        return {
            "requests_made": self.requests_made,
            "rate_limits_hit": self.rate_limits_hit,
            "wafs_detected": self.wafs_detected,
        }


# Convenience function for quick scans
async def quick_scan(urls: List[str], rps: float = 2.0) -> List[RequestResult]:
    """Quick scan multiple URLs."""
    async with HackerHTTPClient(requests_per_second=rps) as client:
        requests = [("GET", url, None) for url in urls]
        return await client.parallel_requests(requests)


if __name__ == "__main__":
    # Demo
    async def demo():
        print("HackerHTTPClient Demo")
        print("=" * 50)
        
        async with HackerHTTPClient(requests_per_second=1.0) as client:
            result = await client.get("https://httpbin.org/headers")
            print(f"Status: {result.status}")
            print(f"Elapsed: {result.elapsed_ms:.0f}ms")
            print(f"WAF detected: {result.waf_detected}")
            print(f"User-Agent sent: {result.body[:200]}...")
    
    asyncio.run(demo())
