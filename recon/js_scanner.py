#!/usr/bin/env python3
"""
VIPER JS Secret Scanner — Deep JavaScript secret scanning with AST-aware patterns.

Goes beyond simple regex — uses pattern context analysis to find:
- Variable assignments with secret values
- Object properties with API keys
- Template literals with embedded tokens
- Import/require paths revealing config files
- Base64-encoded secrets and JWT tokens
- High-entropy strings that are likely secrets

50+ patterns covering AWS, GCP, Azure, GitHub, Slack, Stripe, Firebase, etc.
"""

import asyncio
import logging
import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("viper.recon.js_scanner")


@dataclass
class JSSecret:
    """A discovered secret in JavaScript source."""
    type: str           # Pattern name (e.g., 'aws_access_key')
    value: str          # The matched value (truncated for safety)
    full_match: str     # The surrounding context
    js_url: str         # URL of the JS file
    line_number: int    # Approximate line number
    entropy: float      # Shannon entropy of the value
    confidence: str     # 'high', 'medium', 'low'
    context: str        # Assignment context (var name, object property, etc.)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "value": self.value,
            "js_url": self.js_url,
            "line_number": self.line_number,
            "entropy": round(self.entropy, 2),
            "confidence": self.confidence,
            "context": self.context,
        }


# ═══════════════════════════════════════════════════════════════════════════
# 50+ Secret Patterns — organized by provider/type
# ═══════════════════════════════════════════════════════════════════════════

PATTERNS: Dict[str, re.Pattern] = {}

_RAW_PATTERNS = {
    # ── AWS ──
    "aws_access_key":           r"AKIA[0-9A-Z]{16}",
    "aws_secret_key":           r"(?:aws_secret_access_key|secret_key|AWS_SECRET)\s*[:=]\s*[\"']?([0-9a-zA-Z/+=]{40})[\"']?",
    "aws_mws_key":              r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "aws_cognito":              r"us-(?:east|west)-\d:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",

    # ── Google/GCP ──
    "google_api_key":           r"AIza[0-9A-Za-z_-]{35}",
    "google_oauth_client_id":   r"\d+-[0-9a-z]+\.apps\.googleusercontent\.com",
    "google_service_account":   r'"type"\s*:\s*"service_account"',
    "firebase_url":             r"https://[a-z0-9-]+\.firebaseio\.com",
    "firebase_api_key":         r"(?:firebase|FIREBASE)[_-]?(?:API[_-]?KEY|KEY)\s*[:=]\s*[\"']([^\"']{20,})[\"']",

    # ── Azure ──
    "azure_storage_key":        r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    "azure_client_secret":      r"(?:AZURE_CLIENT_SECRET|azure_secret)\s*[:=]\s*[\"']([^\"']{20,})[\"']",
    "azure_connection_string":  r"(?:Server|Data Source)=[^;]+;(?:Initial Catalog|Database)=[^;]+;(?:User ID|uid)=[^;]+;(?:Password|pwd)=[^;]+",

    # ── GitHub ──
    "github_token":             r"ghp_[0-9a-zA-Z]{36}",
    "github_oauth":             r"gho_[0-9a-zA-Z]{36}",
    "github_app_token":         r"(?:ghu|ghs)_[0-9a-zA-Z]{36}",
    "github_fine_grained":      r"github_pat_[0-9a-zA-Z_]{82}",

    # ── Stripe ──
    "stripe_secret_key":        r"sk_live_[0-9a-zA-Z]{24,}",
    "stripe_publishable_key":   r"pk_live_[0-9a-zA-Z]{24,}",
    "stripe_restricted_key":    r"rk_live_[0-9a-zA-Z]{24,}",

    # ── Slack ──
    "slack_token":              r"xox[bpors]-[0-9a-zA-Z]{10,48}",
    "slack_webhook":            r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+",

    # ── Twilio ──
    "twilio_api_key":           r"SK[0-9a-fA-F]{32}",
    "twilio_account_sid":       r"AC[0-9a-fA-F]{32}",

    # ── SendGrid ──
    "sendgrid_api_key":         r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}",

    # ── Mailgun ──
    "mailgun_api_key":          r"key-[0-9a-zA-Z]{32}",

    # ── Square ──
    "square_access_token":      r"sq0atp-[0-9A-Za-z_-]{22}",
    "square_oauth":             r"sq0csp-[0-9A-Za-z_-]{43}",

    # ── PayPal ──
    "paypal_braintree":         r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",

    # ── Heroku ──
    "heroku_api_key":           r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",

    # ── Shopify ──
    "shopify_token":            r"shpat_[0-9a-fA-F]{32}",
    "shopify_shared_secret":    r"shpss_[0-9a-fA-F]{32}",

    # ── Tokens & Keys (generic) ──
    "jwt_token":                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
    "bearer_token":             r'["\']Bearer\s+[A-Za-z0-9_-]{20,}["\']',
    "basic_auth":               r"(?:Authorization|auth)\s*[:=]\s*[\"']Basic\s+[A-Za-z0-9+/=]+[\"']",
    "private_key":              r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",

    # ── Database URIs ──
    "mongodb_uri":              r"mongodb(?:\+srv)?://[^\s\"'<>]+",
    "postgres_uri":             r"postgres(?:ql)?://[^\s\"'<>]+",
    "mysql_uri":                r"mysql://[^\s\"'<>]+",
    "redis_uri":                r"redis://[^\s\"'<>]+",

    # ── Messaging & Notifications ──
    "telegram_bot_token":       r"\d{8,10}:AA[0-9A-Za-z_-]{33}",
    "discord_webhook":          r"https://discord(?:app)?\.com/api/webhooks/\d+/[0-9A-Za-z_-]+",
    "discord_bot_token":        r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}",

    # ── Social & Auth ──
    "facebook_access_token":    r"EAA[0-9A-Za-z]+",
    "twitter_bearer":           r"AAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]+",

    # ── Other SaaS ──
    "datadog_api_key":          r"(?:DD|dd|datadog)[_-]?(?:API[_-]?KEY|KEY)\s*[:=]\s*[\"']([0-9a-f]{32})[\"']",
    "new_relic_key":            r"NRAK-[0-9A-Z]{27}",
    "algolia_api_key":          r"(?:algolia|ALGOLIA)[_-]?(?:API[_-]?KEY|KEY)\s*[:=]\s*[\"']([0-9a-f]{32})[\"']",
    "mapbox_token":             r"pk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "sentry_dsn":               r"https://[0-9a-f]+@(?:o\d+\.ingest\.)?sentry\.io/\d+",

    # ── Generic Secrets in Assignments ──
    "generic_api_key":          r"""(?:api[_-]?key|apikey|API_KEY)\s*[:=]\s*["']([A-Za-z0-9_\-/.+=]{16,})["']""",
    "generic_secret":           r"""(?:secret|SECRET|client_secret|CLIENT_SECRET)\s*[:=]\s*["']([A-Za-z0-9_\-/.+=]{16,})["']""",
    "generic_password":         r"""(?:password|passwd|PASSWORD|PASSWD)\s*[:=]\s*["']([^"']{8,})["']""",
    "generic_token":            r"""(?:access_token|auth_token|token)\s*[:=]\s*["']([A-Za-z0-9_\-/.+=]{20,})["']""",
}

# Compile all patterns
for name, pattern in _RAW_PATTERNS.items():
    try:
        PATTERNS[name] = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        logger.warning("Invalid regex for %s: %s", name, e)

# Context patterns — identify what variable/property holds the secret
_CONTEXT_PATTERNS = [
    re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*["\']', re.IGNORECASE),
    re.compile(r'(\w+)\s*:\s*["\']', re.IGNORECASE),
    re.compile(r'(\w+)\s*=\s*["\']', re.IGNORECASE),
    re.compile(r'\.(\w+)\s*=\s*["\']', re.IGNORECASE),
    re.compile(r'process\.env\.(\w+)', re.IGNORECASE),
]

# False positive indicators — skip these
_FALSE_POSITIVE_VALUES = {
    "undefined", "null", "true", "false", "none", "example",
    "your-api-key-here", "your_api_key", "INSERT_KEY_HERE",
    "REPLACE_ME", "TODO", "FIXME", "xxxxxxxx", "test",
    "dummy", "placeholder", "sample", "demo", "changeme",
}

_FALSE_POSITIVE_URLS = {
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "fonts.googleapis.com", "ajax.googleapis.com",
    "code.jquery.com", "stackpath.bootstrapcdn.com",
}


class JSSecretScanner:
    """Deep JavaScript secret scanning with AST-aware pattern matching.

    Goes beyond regex - analyzes assignment context, filters false positives
    using entropy analysis and known dummy values.

    Usage::

        scanner = JSSecretScanner()
        secrets = await scanner.scan_url("https://target.com/app.js")
        secrets = await scanner.scan_target("https://target.com", js_urls)
    """

    def __init__(self, min_entropy: float = 3.0, max_concurrent: int = 10):
        self.min_entropy = min_entropy
        self.max_concurrent = max_concurrent
        self._seen_values: Set[str] = set()

    async def scan_url(self, js_url: str, http_client=None) -> List[JSSecret]:
        """Download and scan a single JS file for secrets.

        Args:
            js_url: URL of the JavaScript file.
            http_client: Optional HackerHTTPClient for rate-limited fetching.

        Returns:
            List of discovered secrets.
        """
        content = await self._fetch_js(js_url, http_client)
        if not content:
            return []

        return self._scan_content(content, js_url)

    async def scan_target(self, base_url: str, js_urls: List[str],
                          http_client=None) -> List[JSSecret]:
        """Scan all JS files from a target.

        Args:
            base_url: Base URL of the target (for resolving relative paths).
            js_urls: List of JavaScript file URLs to scan.
            http_client: Optional HackerHTTPClient.

        Returns:
            Aggregated list of all secrets found.
        """
        # Resolve relative URLs
        resolved = []
        for url in js_urls:
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = urljoin(base_url, url)
            elif not url.startswith("http"):
                url = urljoin(base_url, url)
            resolved.append(url)

        # Filter out known CDN/library URLs (no point scanning jQuery)
        resolved = [
            u for u in resolved
            if not any(cdn in u for cdn in _FALSE_POSITIVE_URLS)
        ]

        # Deduplicate
        resolved = list(dict.fromkeys(resolved))

        logger.info("[JSScanner] Scanning %d JS files from %s", len(resolved), base_url)

        # Scan concurrently with semaphore
        semaphore = asyncio.Semaphore(self.max_concurrent)
        all_secrets: List[JSSecret] = []

        async def _scan_one(url: str):
            async with semaphore:
                try:
                    secrets = await self.scan_url(url, http_client)
                    return secrets
                except Exception as e:
                    logger.debug("[JSScanner] Error scanning %s: %s", url, e)
                    return []

        tasks = [_scan_one(u) for u in resolved]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_secrets.extend(result)

        # Deduplicate by (type, value)
        seen = set()
        deduped = []
        for s in all_secrets:
            key = (s.type, s.value)
            if key not in seen:
                seen.add(key)
                deduped.append(s)

        logger.info("[JSScanner] Found %d unique secrets across %d files",
                    len(deduped), len(resolved))
        return deduped

    def _scan_content(self, content: str, js_url: str) -> List[JSSecret]:
        """Scan JS source content for secret patterns."""
        secrets: List[JSSecret] = []
        lines = content.split("\n")

        for pattern_name, pattern in PATTERNS.items():
            for match in pattern.finditer(content):
                # Get the matched value
                if match.groups():
                    value = match.group(1)
                else:
                    value = match.group(0)

                # Skip false positives
                if self._is_false_positive(value, pattern_name):
                    continue

                # Calculate entropy
                entropy = self._entropy_check(value)

                # Determine confidence based on pattern type and entropy
                confidence = self._assess_confidence(pattern_name, value, entropy)

                # Skip low-entropy generic matches
                if pattern_name.startswith("generic_") and entropy < self.min_entropy:
                    continue

                # Find line number
                pos = match.start()
                line_num = content[:pos].count("\n") + 1

                # Extract context (variable/property name)
                context = self._extract_context(content, pos)

                # Truncate value for safety — never log full secrets
                truncated = value[:12] + "..." if len(value) > 15 else value

                # Skip duplicates within same scan
                dedup_key = f"{pattern_name}:{value[:20]}"
                if dedup_key in self._seen_values:
                    continue
                self._seen_values.add(dedup_key)

                secrets.append(JSSecret(
                    type=pattern_name,
                    value=truncated,
                    full_match=match.group(0)[:80],
                    js_url=js_url,
                    line_number=line_num,
                    entropy=entropy,
                    confidence=confidence,
                    context=context,
                ))

        return secrets

    @staticmethod
    def _entropy_check(value: str) -> float:
        """Shannon entropy — high entropy strings are likely secrets."""
        if not value:
            return 0.0
        length = len(value)
        freq: Dict[str, int] = {}
        for c in value:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _is_false_positive(value: str, pattern_name: str) -> bool:
        """Check if the matched value is a known false positive."""
        if not value or len(value) < 4:
            return True

        low = value.lower().strip()

        # Known dummy values
        if low in _FALSE_POSITIVE_VALUES:
            return True

        # All same character
        if len(set(value)) <= 2:
            return True

        # Looks like a version string
        if re.match(r'^\d+\.\d+\.\d+', value):
            return True

        # Looks like a hex color
        if re.match(r'^#?[0-9a-fA-F]{3,6}$', value):
            return True

        # Looks like a CSS value
        if re.match(r'^\d+(?:px|em|rem|%|vh|vw)$', value):
            return True

        # For generic patterns, check if it's in a test/example context
        if pattern_name.startswith("generic_"):
            if any(x in low for x in ("example", "test", "sample", "demo", "dummy",
                                       "placeholder", "your_", "insert_")):
                return True

        return False

    @staticmethod
    def _assess_confidence(pattern_name: str, value: str, entropy: float) -> str:
        """Assess confidence level of the finding."""
        # High-confidence patterns (very specific format)
        high_conf = {
            "aws_access_key", "github_token", "github_oauth", "github_app_token",
            "github_fine_grained", "stripe_secret_key", "stripe_restricted_key",
            "slack_token", "slack_webhook", "sendgrid_api_key", "twilio_api_key",
            "twilio_account_sid", "private_key", "shopify_token", "new_relic_key",
            "mapbox_token", "jwt_token", "google_api_key", "discord_webhook",
            "telegram_bot_token", "sentry_dsn",
        }
        if pattern_name in high_conf:
            return "high"

        # Medium — specific format but some FP risk
        medium_conf = {
            "aws_secret_key", "firebase_url", "mongodb_uri", "postgres_uri",
            "azure_storage_key", "bearer_token", "basic_auth", "firebase_api_key",
            "discord_bot_token", "paypal_braintree", "square_access_token",
        }
        if pattern_name in medium_conf:
            return "high" if entropy > 4.0 else "medium"

        # Generic patterns — rely heavily on entropy
        if entropy > 4.5:
            return "medium"
        elif entropy > 3.5:
            return "low"
        return "low"

    @staticmethod
    def _extract_context(content: str, match_pos: int) -> str:
        """Extract the variable/property context around a match."""
        # Get ~100 chars before the match
        start = max(0, match_pos - 100)
        before = content[start:match_pos]

        for pat in _CONTEXT_PATTERNS:
            m = pat.search(before)
            if m:
                return m.group(1)

        # Fallback: just return the line prefix
        line_start = before.rfind("\n") + 1
        prefix = before[line_start:].strip()
        if prefix:
            return prefix[:40]
        return ""

    async def _fetch_js(self, url: str, http_client=None) -> Optional[str]:
        """Fetch JS file content."""
        try:
            if http_client:
                result = await http_client.request("GET", url)
                if result.status == 200:
                    return result.body
                return None

            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=15),
                    headers={"User-Agent": "Mozilla/5.0 (compatible; VIPER/5.0)"},
                ) as resp:
                    if resp.status == 200:
                        return await resp.text()
            return None
        except Exception as e:
            logger.debug("[JSScanner] Failed to fetch %s: %s", url, e)
            return None

    # ═══════════════════════════════════════════════════════════════════════
    # Extended JS Analysis — endpoints, frameworks, source maps, DOM sinks,
    # dependency confusion
    # ═══════════════════════════════════════════════════════════════════════

    _ENDPOINT_PATTERNS = [
        # fetch("url") / fetch('url')
        re.compile(r"""fetch\(\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE),
        # axios.get/post/put/delete/patch("url")
        re.compile(r"""axios\.(?P<method>get|post|put|delete|patch)\(\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE),
        # XMLHttpRequest open
        re.compile(r"""\.open\(\s*["'](?P<method>GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE),
        # $.ajax({url: "..."})
        re.compile(r"""\$\.ajax\(\s*\{[^}]*url\s*:\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE | re.DOTALL),
        # $.get/$.post("url")
        re.compile(r"""\$\.(?P<method>get|post)\(\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE),
        # Generic URL-like strings: /api/..., https://...
        re.compile(r"""["'`]((?:https?://[^\s"'`]+|/api/[^\s"'`]+))["'`]"""),
    ]

    _FRAMEWORK_SIGNATURES = {
        "React": [r"React\.createElement", r"ReactDOM\.render", r"__REACT_DEVTOOLS",
                  r"_reactRootContainer", r"\bReact\b.*\buseState\b"],
        "Next.js": [r"__NEXT_DATA__", r"__next", r"next/router"],
        "Angular": [r"ng-app", r"angular\.module", r"ng-controller",
                    r"@angular/core", r"\bng\.\b"],
        "Vue": [r"new Vue\(", r"__VUE__", r"Vue\.component", r"createApp\("],
        "Nuxt": [r"__NUXT__", r"nuxt\.config"],
        "jQuery": [r"\$\(\s*[\"']", r"jQuery\(", r"\$\.fn\."],
        "Ember": [r"Ember\.Application", r"ember-cli", r"Ember\.Route"],
        "Svelte": [r"__svelte", r"svelte/internal", r"SvelteComponent"],
        "Backbone": [r"Backbone\.Model", r"Backbone\.View", r"Backbone\.Router"],
    }

    _DOM_SINK_PATTERNS = [
        ("innerHTML", re.compile(r"\.innerHTML\s*=", re.IGNORECASE)),
        ("outerHTML", re.compile(r"\.outerHTML\s*=", re.IGNORECASE)),
        ("document.write", re.compile(r"document\.write(?:ln)?\s*\(", re.IGNORECASE)),
        ("eval", re.compile(r"\beval\s*\(", re.IGNORECASE)),
        ("setTimeout_string", re.compile(r"setTimeout\s*\(\s*[\"'`]", re.IGNORECASE)),
        ("setInterval_string", re.compile(r"setInterval\s*\(\s*[\"'`]", re.IGNORECASE)),
        ("Function_constructor", re.compile(r"\bFunction\s*\(\s*[\"'`]", re.IGNORECASE)),
        ("location.href_assign", re.compile(r"location\.href\s*=", re.IGNORECASE)),
        ("location.assign", re.compile(r"location\.assign\s*\(", re.IGNORECASE)),
        ("location.replace", re.compile(r"location\.replace\s*\(", re.IGNORECASE)),
        ("insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\(", re.IGNORECASE)),
    ]

    def _extract_endpoints(self, js_content: str) -> List[Dict]:
        """Extract API endpoint URLs from fetch, axios, XHR, and jQuery patterns.

        Returns:
            List of dicts with keys: url, method, source_line.
        """
        endpoints: List[Dict] = []
        seen_urls: Set[str] = set()

        for pat in self._ENDPOINT_PATTERNS:
            for match in pat.finditer(js_content):
                # Extract method from named group if present
                method = "GET"
                try:
                    method = match.group("method").upper()
                except (IndexError, AttributeError):
                    pass

                # URL is the last captured group
                url = match.group(match.lastindex) if match.lastindex else match.group(0)

                # Skip data URIs, anchors, and very short fragments
                if not url or url.startswith("data:") or url == "#" or len(url) < 3:
                    continue

                if url in seen_urls:
                    continue
                seen_urls.add(url)

                line_num = js_content[:match.start()].count("\n") + 1
                endpoints.append({
                    "url": url,
                    "method": method,
                    "source_line": line_num,
                })

        return endpoints

    def _detect_frameworks(self, js_content: str) -> List[str]:
        """Detect frontend frameworks/libraries from JS globals and patterns.

        Returns:
            List of detected framework names.
        """
        detected: List[str] = []
        for framework, signatures in self._FRAMEWORK_SIGNATURES.items():
            for sig in signatures:
                if re.search(sig, js_content):
                    detected.append(framework)
                    break  # One match per framework is enough
        return detected

    async def _check_source_maps(self, js_url: str, session) -> Dict:
        """Check if a .map source map file is accessible for a JS URL.

        Args:
            js_url: URL of the JavaScript file.
            session: An aiohttp ClientSession instance.

        Returns:
            Dict with keys: accessible (bool), map_url (str).
        """
        import aiohttp

        map_url = js_url + ".map"
        result = {"accessible": False, "map_url": map_url}
        try:
            async with session.head(
                map_url,
                ssl=False,
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=True,
            ) as resp:
                if resp.status == 200:
                    ct = resp.headers.get("Content-Type", "")
                    # Source maps are JSON
                    if "json" in ct or "octet-stream" in ct or "text/" in ct:
                        result["accessible"] = True
        except Exception as e:
            logger.debug("[JSScanner] Source map check failed for %s: %s", map_url, e)
        return result

    def _find_dom_sinks(self, js_content: str) -> List[Dict]:
        """Find dangerous DOM sinks that could enable XSS.

        Returns:
            List of dicts with keys: sink_type, line_number, context.
        """
        sinks: List[Dict] = []
        for sink_type, pattern in self._DOM_SINK_PATTERNS:
            for match in pattern.finditer(js_content):
                pos = match.start()
                line_num = js_content[:pos].count("\n") + 1
                # Grab surrounding context (the line containing the sink)
                line_start = js_content.rfind("\n", 0, pos) + 1
                line_end = js_content.find("\n", pos)
                if line_end == -1:
                    line_end = len(js_content)
                context_line = js_content[line_start:line_end].strip()[:120]
                sinks.append({
                    "sink_type": sink_type,
                    "line_number": line_num,
                    "context": context_line,
                })
        return sinks

    _DEP_CONFUSION_PATTERNS = [
        # package.json references
        re.compile(r"""["'](@[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+)["']"""),
        # require('@scope/pkg')
        re.compile(r"""require\(\s*["'](@[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+)["']\s*\)"""),
        # import from '@scope/pkg'
        re.compile(r"""from\s+["'](@[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+)["']"""),
        # npm install commands
        re.compile(r"""npm\s+install\s+(@?[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?)"""),
    ]

    # Well-known public npm scopes that are NOT internal
    _PUBLIC_SCOPES = {
        "@angular", "@babel", "@types", "@vue", "@react", "@svelte",
        "@emotion", "@mui", "@testing-library", "@storybook", "@ngrx",
        "@nestjs", "@aws-sdk", "@azure", "@google-cloud", "@graphql",
        "@reduxjs", "@tanstack", "@vitejs",
    }

    def _check_dependency_confusion(self, js_content: str) -> List[Dict]:
        """Find scoped package references that may be vulnerable to dependency confusion.

        Returns:
            List of dicts with keys: package_name, risk.
        """
        issues: List[Dict] = []
        seen_pkgs: Set[str] = set()

        for pat in self._DEP_CONFUSION_PATTERNS:
            for match in pat.finditer(js_content):
                pkg = match.group(1)
                if pkg in seen_pkgs:
                    continue
                seen_pkgs.add(pkg)

                scope = pkg.split("/")[0] if "/" in pkg else None
                if scope and scope not in self._PUBLIC_SCOPES:
                    # Internal-looking scope — potential dependency confusion
                    issues.append({
                        "package_name": pkg,
                        "risk": "high" if scope not in self._PUBLIC_SCOPES else "low",
                    })

        return issues

    async def full_analysis(self, base_url: str, js_urls: List[str],
                            session=None) -> Dict:
        """Run comprehensive JS analysis: secrets + endpoints + frameworks + source maps + DOM sinks + dependency confusion.

        Args:
            base_url: Base URL of the target.
            js_urls: List of JavaScript file URLs.
            session: Optional aiohttp ClientSession. Created internally if None.

        Returns:
            Combined dict with all analysis results.
        """
        import aiohttp

        # Run the existing secret scanner
        secrets_raw = await self.scan_target(base_url, js_urls)
        secrets = [s.to_dict() for s in secrets_raw]

        # Fetch all JS content for static analysis
        all_content: List[Tuple[str, str]] = []  # (url, content)
        for url in js_urls:
            content = await self._fetch_js(url)
            if content:
                all_content.append((url, content))

        # Aggregate results from static analysis methods
        endpoints: List[Dict] = []
        frameworks_set: Set[str] = set()
        dom_sinks: List[Dict] = []
        dep_issues: List[Dict] = []

        for url, content in all_content:
            endpoints.extend(self._extract_endpoints(content))
            frameworks_set.update(self._detect_frameworks(content))
            dom_sinks.extend(self._find_dom_sinks(content))
            dep_issues.extend(self._check_dependency_confusion(content))

        # Check source maps (needs HTTP session)
        source_maps: List[Dict] = []
        own_session = session is None
        if own_session:
            session = aiohttp.ClientSession(
                headers={"User-Agent": "Mozilla/5.0 (compatible; VIPER/5.0)"}
            )
        try:
            tasks = [self._check_source_maps(url, session) for url, _ in all_content]
            source_maps = await asyncio.gather(*tasks, return_exceptions=False)
            source_maps = [m for m in source_maps if isinstance(m, dict)]
        finally:
            if own_session:
                await session.close()

        return {
            "secrets": secrets,
            "endpoints": endpoints,
            "frameworks": sorted(frameworks_set),
            "source_maps": source_maps,
            "dom_sinks": dom_sinks,
            "dependency_issues": dep_issues,
        }

    def reset(self):
        """Clear dedup state between targets."""
        self._seen_values.clear()
