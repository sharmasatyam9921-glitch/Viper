#!/usr/bin/env python3
"""
VIPER Stealth Mode — WAF evasion and fingerprint randomization.

4 stealth levels:
  0 = None (raw requests, maximum speed)
  1 = Basic (realistic headers, UA rotation)
  2 = Evasive (proxy rotation, timing jitter, payload encoding variation)
  3 = Paranoid (decoy requests, TLS fingerprint randomization, full anti-detection)
"""

import asyncio
import base64
import random
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Set, Tuple


class StealthLevel(IntEnum):
    NONE = 0
    BASIC = 1
    EVASIVE = 2
    PARANOID = 3


# 24 realistic User-Agent strings across browsers/OS/versions
USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Firefox macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Firefox Linux
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    # Mobile Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/122.0.6261.62 Mobile/15E148 Safari/604.1",
    # Mobile Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    # Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0",
    # Brave
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Brave/122",
    # Vivaldi
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Vivaldi/6.5",
]

# Accept headers that match the UA family
ACCEPT_PROFILES = {
    "chrome": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "sec-ch-ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    },
    "firefox": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
    },
    "safari": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    },
}

# Common referrers for decoy traffic
REFERRERS = [
    "https://www.google.com/",
    "https://www.google.com/search?q=site:",
    "https://www.bing.com/search?q=",
    "https://duckduckgo.com/?q=",
    "https://t.co/",
    "https://www.linkedin.com/",
    "https://www.reddit.com/",
    "https://news.ycombinator.com/",
]

# WAF detection signatures (expanded)
WAF_SIGNATURES: Dict[str, List[str]] = {
    "cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id", "cloudflare"],
    "akamai": ["x-akamai", "akamai-grn", "akamai"],
    "aws_waf": ["awswaf", "x-amzn-waf", "x-amzn-requestid"],
    "imperva": ["incap_ses", "visid_incap", "incapsula", "x-iinfo"],
    "sucuri": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "f5_bigip": ["bigip", "x-wa-info", "f5-"],
    "fortiweb": ["fortigate", "fortiweb", "fortiwafd"],
    "modsecurity": ["mod_security", "modsec", "noyb"],
    "barracuda": ["barra_counter_session", "barracuda"],
    "wordfence": ["wordfence", "wfwaf-"],
    "comodo": ["comodowaf", "x-cwaf"],
    "edgecast": ["ecdf", "x-ec-"],
    "fastly": ["x-fastly", "fastly-io"],
    "stackpath": ["x-sp-", "stackpath"],
}

# Benign decoy paths (safe, common resources)
DECOY_PATHS = [
    "/", "/robots.txt", "/favicon.ico", "/sitemap.xml",
    "/about", "/contact", "/privacy", "/terms",
    "/css/style.css", "/js/main.js", "/images/logo.png",
]


@dataclass
class StealthProfile:
    """Active stealth configuration for a session."""
    level: StealthLevel = StealthLevel.NONE
    proxies: List[str] = field(default_factory=list)
    min_delay: float = 0.0
    max_delay: float = 0.0
    detected_wafs: Dict[str, str] = field(default_factory=dict)  # domain -> waf
    blocked_domains: Set[str] = field(default_factory=set)
    requests_since_decoy: int = 0
    decoy_interval: int = 5  # send decoy every N requests at level 3
    _proxy_index: int = 0
    _ua_sticky: Optional[str] = None  # sticky UA per session at level 1

    def summary(self) -> Dict:
        return {
            "level": self.level.name,
            "proxies": len(self.proxies),
            "detected_wafs": dict(self.detected_wafs),
            "blocked_domains": list(self.blocked_domains),
        }


class StealthEngine:
    """
    Stealth mode engine for VIPER.

    Manages request fingerprint randomization, timing jitter,
    proxy rotation, WAF detection, payload encoding, and decoy generation.
    """

    def __init__(self, level: int = 0, proxies: Optional[List[str]] = None):
        self.profile = StealthProfile(
            level=StealthLevel(min(max(level, 0), 3)),
            proxies=proxies or [],
        )
        self._configure_timing()

    def _configure_timing(self):
        """Set timing parameters based on stealth level."""
        if self.profile.level == StealthLevel.NONE:
            self.profile.min_delay = 0.0
            self.profile.max_delay = 0.0
        elif self.profile.level == StealthLevel.BASIC:
            self.profile.min_delay = 0.3
            self.profile.max_delay = 1.5
            # Pick a sticky UA for the session (real browsers don't rotate mid-session)
            self.profile._ua_sticky = random.choice(USER_AGENTS)
        elif self.profile.level == StealthLevel.EVASIVE:
            self.profile.min_delay = 1.0
            self.profile.max_delay = 4.0
        elif self.profile.level == StealthLevel.PARANOID:
            self.profile.min_delay = 2.0
            self.profile.max_delay = 8.0
            self.profile.decoy_interval = random.randint(3, 7)

    @property
    def level(self) -> StealthLevel:
        return self.profile.level

    # ─── Header Generation ───

    def get_headers(self, url: str, custom_headers: Optional[Dict] = None) -> Dict[str, str]:
        """Generate realistic headers based on stealth level."""
        if self.profile.level == StealthLevel.NONE:
            headers = {"User-Agent": USER_AGENTS[0]}
            if custom_headers:
                headers.update(custom_headers)
            return headers

        # Pick UA
        if self.profile.level == StealthLevel.BASIC and self.profile._ua_sticky:
            ua = self.profile._ua_sticky
        else:
            ua = random.choice(USER_AGENTS)

        # Determine browser family for matching accept headers
        family = "chrome"
        if "Firefox" in ua:
            family = "firefox"
        elif "Safari" in ua and "Chrome" not in ua:
            family = "safari"

        headers = dict(ACCEPT_PROFILES.get(family, ACCEPT_PROFILES["chrome"]))
        headers["User-Agent"] = ua
        headers["Connection"] = "keep-alive"
        headers["Upgrade-Insecure-Requests"] = "1"

        # Level 2+: add referrer variation
        if self.profile.level >= StealthLevel.EVASIVE:
            if random.random() < 0.6:
                domain = urllib.parse.urlparse(url).netloc
                ref = random.choice(REFERRERS)
                if "search" in ref or "?q=" in ref:
                    ref += domain
                headers["Referer"] = ref

        # Level 3: randomize header order by using OrderedDict tricks
        # (aiohttp preserves insertion order)
        if self.profile.level >= StealthLevel.PARANOID:
            items = list(headers.items())
            random.shuffle(items)
            headers = dict(items)
            # Add DNT randomly
            if random.random() < 0.3:
                headers["DNT"] = "1"

        if custom_headers:
            headers.update(custom_headers)

        return headers

    # ─── Timing Jitter ───

    async def jitter(self):
        """Apply timing jitter between requests."""
        if self.profile.min_delay <= 0:
            return
        delay = random.uniform(self.profile.min_delay, self.profile.max_delay)
        # Add occasional longer pause at paranoid level
        if self.profile.level >= StealthLevel.PARANOID and random.random() < 0.1:
            delay += random.uniform(3.0, 10.0)
        await asyncio.sleep(delay)

    # ─── Proxy Rotation ───

    def get_proxy(self) -> Optional[str]:
        """Get next proxy from rotation list."""
        if not self.profile.proxies or self.profile.level < StealthLevel.EVASIVE:
            return None
        proxy = self.profile.proxies[self.profile._proxy_index % len(self.profile.proxies)]
        self.profile._proxy_index += 1
        return proxy

    # ─── Payload Encoding Variation ───

    def encode_payload(self, payload: str) -> str:
        """Apply random encoding variation to payloads for WAF evasion."""
        if self.profile.level < StealthLevel.EVASIVE:
            return payload

        encoders = [
            self._encode_url,
            self._encode_double_url,
            self._encode_mixed_case,
            self._encode_unicode,
            self._encode_html_entities,
            lambda p: p,  # sometimes send raw
        ]

        # At paranoid level, chain two encodings occasionally
        if self.profile.level >= StealthLevel.PARANOID and random.random() < 0.3:
            p = random.choice(encoders)(payload)
            return random.choice(encoders)(p)

        return random.choice(encoders)(payload)

    @staticmethod
    def _encode_url(payload: str) -> str:
        """Standard URL encoding of special chars."""
        return urllib.parse.quote(payload, safe='')

    @staticmethod
    def _encode_double_url(payload: str) -> str:
        """Double URL encoding."""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

    @staticmethod
    def _encode_mixed_case(payload: str) -> str:
        """Randomly change case of SQL/HTML keywords."""
        keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR",
                     "INSERT", "UPDATE", "DELETE", "DROP", "SCRIPT",
                     "ALERT", "ONERROR", "ONLOAD", "IMG", "SRC"]
        result = payload
        for kw in keywords:
            if kw.lower() in result.lower():
                mixed = ''.join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in kw
                )
                # Case-insensitive replace
                import re
                result = re.sub(re.escape(kw), mixed, result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def _encode_unicode(payload: str) -> str:
        """Replace some ASCII chars with unicode equivalents."""
        replacements = {
            "'": "\u2019",  # right single quote
            '"': "\u201c",  # left double quote
            "<": "\uff1c",  # fullwidth less-than
            ">": "\uff1e",  # fullwidth greater-than
            "/": "\u2215",  # division slash
        }
        result = list(payload)
        for i, c in enumerate(result):
            if c in replacements and random.random() < 0.4:
                result[i] = replacements[c]
        return ''.join(result)

    @staticmethod
    def _encode_html_entities(payload: str) -> str:
        """Replace chars with HTML entities."""
        entities = {
            "'": "&#39;",
            '"': "&quot;",
            "<": "&lt;",
            ">": "&gt;",
            "&": "&amp;",
        }
        result = list(payload)
        for i, c in enumerate(result):
            if c in entities and random.random() < 0.5:
                result[i] = entities[c]
        return ''.join(result)

    # ─── WAF Detection ───

    def detect_waf(self, domain: str, headers: Dict[str, str], body: str) -> Optional[str]:
        """Detect WAF from response headers and body."""
        check_text = (str(headers) + body).lower()

        for waf_name, signatures in WAF_SIGNATURES.items():
            if any(sig.lower() in check_text for sig in signatures):
                self.profile.detected_wafs[domain] = waf_name
                return waf_name

        # Generic block detection
        block_phrases = [
            "access denied", "request blocked", "web application firewall",
            "security violation", "your request has been blocked",
            "automated access", "bot detected", "captcha",
        ]
        if any(phrase in check_text for phrase in block_phrases):
            self.profile.detected_wafs[domain] = "unknown_waf"
            return "unknown_waf"

        return None

    def is_blocked(self, status: int, body: str) -> bool:
        """Determine if a response indicates blocking."""
        if status in (403, 406, 429, 503):
            block_indicators = [
                "blocked", "denied", "forbidden", "captcha",
                "challenge", "security", "firewall", "waf",
            ]
            if any(ind in body.lower() for ind in block_indicators):
                return True
        return False

    def on_blocked(self, domain: str):
        """Record that a domain blocked us."""
        self.profile.blocked_domains.add(domain)

    # ─── Decoy Requests ───

    def should_send_decoy(self) -> bool:
        """Check if it's time for a decoy request (level 3 only)."""
        if self.profile.level < StealthLevel.PARANOID:
            return False
        self.profile.requests_since_decoy += 1
        if self.profile.requests_since_decoy >= self.profile.decoy_interval:
            self.profile.requests_since_decoy = 0
            self.profile.decoy_interval = random.randint(3, 7)
            return True
        return False

    def get_decoy_url(self, base_url: str) -> str:
        """Generate a benign decoy URL."""
        parsed = urllib.parse.urlparse(base_url)
        path = random.choice(DECOY_PATHS)
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    # ─── Integration Helpers ───

    def escalate(self):
        """Increase stealth level by 1 (e.g. after WAF detection)."""
        if self.profile.level < StealthLevel.PARANOID:
            self.profile.level = StealthLevel(self.profile.level + 1)
            self._configure_timing()

    def get_stats(self) -> Dict:
        """Return stealth statistics."""
        return {
            "level": self.profile.level.name,
            "level_value": int(self.profile.level),
            "detected_wafs": dict(self.profile.detected_wafs),
            "blocked_domains": list(self.profile.blocked_domains),
            "proxies_available": len(self.profile.proxies),
            "timing": {
                "min_delay": self.profile.min_delay,
                "max_delay": self.profile.max_delay,
            },
        }
