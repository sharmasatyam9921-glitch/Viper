#!/usr/bin/env python3
"""
VIPER Finding Validator - Confirm findings are real before reporting.

Each vuln type has a specific validation strategy that goes beyond
simple pattern matching to behavioral confirmation.
"""

import re
import time
import asyncio
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


class FindingValidator:
    """
    Validate findings before they become reportable.

    Returns (is_valid, confidence, reason) for each finding.
    Confidence: 0.0 = likely FP, 1.0 = confirmed exploit.
    """

    def __init__(self, http_client=None):
        """
        Args:
            http_client: HackerHTTPClient instance (or any object with async get/post/request methods).
                        If None, behavioral validation is skipped.
        """
        self.http = http_client

    async def validate(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """
        Validate a finding. Dispatches to vuln-type-specific validator.

        finding should have: attack/vuln_type, payload, marker, url
        """
        vuln_type = finding.get("attack", finding.get("vuln_type", "")).lower()

        validators = {
            "sqli": self._validate_sqli,
            "sqli_error": self._validate_sqli,
            "sqli_union": self._validate_sqli,
            "sqli_blind": self._validate_sqli,
            "sql_injection": self._validate_sqli,
            "xss": self._validate_xss,
            "xss_reflected": self._validate_xss,
            "cross_site_scripting": self._validate_xss,
            "reflected_xss": self._validate_xss,
            "lfi": self._validate_lfi,
            "lfi_basic": self._validate_lfi,
            "lfi_wrapper": self._validate_lfi,
            "local_file_inclusion": self._validate_lfi,
            "path_traversal": self._validate_lfi,
            "ssti": self._validate_ssti,
            "ssti_basic": self._validate_ssti,
            "template_injection": self._validate_ssti,
            "cmdi": self._validate_timing,
            "cmdi_basic": self._validate_timing,
            "command_injection": self._validate_timing,
            "rce": self._validate_timing,
            "ssrf": self._validate_ssrf,
            "ssrf_basic": self._validate_ssrf,
            "cors": self._validate_cors,
            "cors_check": self._validate_cors,
            "cors_misconfiguration": self._validate_cors,
            "open_redirect": self._validate_redirect,
            "open_redirect_basic": self._validate_redirect,
            "header_missing": self._validate_header,
            "info": self._validate_info,
            # v2.3 new validators
            "jwt_none_alg": self._validate_jwt,
            "jwt_weak_secret": self._validate_jwt,
            "idor_enum": self._validate_idor,
            "debug_endpoints": self._validate_debug_endpoint,
            "source_maps": self._validate_source_map,
            "graphql_introspection": self._validate_graphql_introspection,
            "graphql_injection": self._validate_graphql_injection,
            "xxe_basic": self._validate_xxe,
            "crlf_injection": self._validate_crlf,
            "host_header_injection": self._validate_host_header,
            "subdomain_takeover": self._validate_subdomain_takeover,
            "verb_tampering": self._validate_verb_tampering,
            "cache_poisoning": self._validate_cache_poisoning,
            "prototype_pollution": self._validate_generic,
            "insecure_deserialization": self._validate_generic,
            "request_smuggling": self._validate_generic,
        }

        validator = validators.get(vuln_type, self._validate_generic)
        try:
            return await asyncio.wait_for(
                validator(finding, target_url),
                timeout=30.0,
            )
        except asyncio.TimeoutError:
            return False, 0.0, "Validation timed out"
        except Exception as e:
            return False, 0.0, f"Validation error: {e}"

    async def _validate_sqli(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Boolean blind comparison: true condition vs false condition should differ."""
        url = finding.get("url", target_url)
        payload = finding.get("payload", "")

        # Parse the URL to find injection point
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return False, 0.1, "No query parameters to test"

        # Find which param has the payload
        inject_param = None
        for key, values in params.items():
            for v in values:
                if payload in v or "'" in v or "OR" in v.upper():
                    inject_param = key
                    break

        if not inject_param:
            inject_param = list(params.keys())[0]

        base_url = urlunparse(parsed._replace(query=""))

        # True condition
        true_params = dict(params)
        true_params[inject_param] = ["1' AND '1'='1"]
        r_true = await self.http.get(f"{base_url}?{urlencode(true_params, doseq=True)}")

        # False condition
        false_params = dict(params)
        false_params[inject_param] = ["1' AND '1'='2"]
        r_false = await self.http.get(f"{base_url}?{urlencode(false_params, doseq=True)}")

        # Compare: true and false should differ significantly
        if r_true.status == 0 or r_false.status == 0:
            return False, 0.1, "Request failed during validation"

        len_diff = abs(len(r_true.body) - len(r_false.body))
        status_diff = r_true.status != r_false.status

        if status_diff or len_diff > 15:
            # Also check original payload reproduces
            orig_params = dict(params)
            orig_params[inject_param] = [payload]
            r_orig = await self.http.get(f"{base_url}?{urlencode(orig_params, doseq=True)}")
            marker = finding.get("marker", "")
            if marker and marker.lower() in r_orig.body.lower():
                return True, 0.85, f"Boolean blind confirmed: len_diff={len_diff}, status_diff={status_diff}"
            return True, 0.6, f"Boolean blind likely: len_diff={len_diff}"
        elif len_diff > 0:
            return True, 0.6, f"Boolean blind: minor response diff len_diff={len_diff}"

        # Time-based SQLi fallback
        time_params = dict(params)
        time_params[inject_param] = ["1' AND SLEEP(5)-- -"]
        t0 = time.time()
        r_sleep = await self.http.get(f"{base_url}?{urlencode(time_params, doseq=True)}")
        delay_ms = (time.time() - t0) * 1000
        if delay_ms > 4000:
            return True, 0.85, f"Time-based SQLi confirmed: delay={delay_ms:.0f}ms"

        return False, 0.15, f"Boolean blind test inconclusive: len_diff={len_diff}"

    async def _validate_xss(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Verify payload appears unencoded in response."""
        url = finding.get("url", target_url)
        payload = finding.get("payload", "")

        if not payload:
            return False, 0.0, "No payload to validate"

        # Re-send the exact request
        result = await self.http.get(url)
        if result.status == 0:
            return False, 0.0, "Request failed"

        body = result.body
        # Also check headers for reflected content
        header_str = "\n".join(f"{k}: {v}" for k, v in result.headers.items())
        search_text = body + "\n" + header_str

        # Check for exact unencoded reflection in body or headers
        if payload in search_text:
            # Verify it's not HTML-encoded (only relevant for body)
            if payload in body:
                encoded_variants = [
                    payload.replace("<", "&lt;").replace(">", "&gt;"),
                    payload.replace('"', "&quot;"),
                    payload.replace("'", "&#39;"),
                ]
                for encoded in encoded_variants:
                    if encoded in body and payload not in body.replace(encoded, ""):
                        return False, 0.2, "Payload is HTML-encoded in response"

            # DOM XSS: check if payload appears inside <script> tags
            script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
            for block in script_blocks:
                if payload in block:
                    return True, 0.9, "Payload reflected inside <script> context (DOM XSS)"

            # Check if CSP would block execution
            csp = result.headers.get("Content-Security-Policy", "")
            if csp and "script-src" in csp and "'unsafe-inline'" not in csp:
                return True, 0.7, "XSS reflected but CSP may block execution"

            return True, 0.9, "Payload reflected unencoded in response"

        return False, 0.1, "Payload not found in response"

    async def _validate_lfi(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Verify full file content, not just keyword match."""
        url = finding.get("url", target_url)

        result = await self.http.get(url)
        if result.status == 0:
            return False, 0.0, "Request failed"

        body = result.body

        # Check for real /etc/passwd format (not just "root:")
        passwd_pattern = r"root:[x*]:0:0:"
        if re.search(passwd_pattern, body):
            # Negative test: request a non-existent file
            neg_url = url.replace("etc/passwd", "etc/nonexistent_file_viper_test")
            neg_result = await self.http.get(neg_url)
            if neg_result.body != body:
                return True, 0.95, "Full passwd format confirmed + negative test passed"
            return True, 0.7, "Full passwd format found (negative test inconclusive)"

        # Check for Windows file inclusion
        win_pattern = r"\[boot loader\]|\[operating systems\]|; for 16-bit app support"
        if re.search(win_pattern, body):
            return True, 0.9, "Windows system file content confirmed"

        return False, 0.1, "No recognizable file content in response"

    async def _validate_ssti(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Verify math evaluation in template."""
        url = finding.get("url", target_url)
        payload = finding.get("payload", "")

        # Test with a unique math expression
        test_expressions = [
            ("{{7*7}}", "49"),
            ("{{7*'7'}}", "7777777"),
            ("${7*7}", "49"),
            ("#{7*7}", "49"),
            ("<%= 7*7 %>", "49"),
        ]

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return False, 0.1, "No query parameters"

        inject_param = list(params.keys())[0]
        # Try to find the param that had the original payload
        for key, values in params.items():
            for v in values:
                if "{{" in v or "${" in v or "<%" in v:
                    inject_param = key
                    break

        base_url = urlunparse(parsed._replace(query=""))

        for expr, expected in test_expressions:
            test_params = dict(params)
            test_params[inject_param] = [expr]
            result = await self.http.get(f"{base_url}?{urlencode(test_params, doseq=True)}")
            if result.status != 0 and expected in result.body:
                # If expression is absent, it was fully evaluated — higher confidence
                if expr not in result.body:
                    return True, 0.95, f"SSTI confirmed: {expr} → {expected} (expression consumed)"
                # Expression still present but result also present — still SSTI
                return True, 0.9, f"SSTI confirmed: {expr} → {expected}"

        return False, 0.15, "No template evaluation detected"

    async def _validate_timing(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Time-based validation for command injection / time-based SQLi."""
        url = finding.get("url", target_url)

        # Baseline: normal request
        t0 = time.time()
        r_base = await self.http.get(url)
        baseline_ms = (time.time() - t0) * 1000

        if r_base.status == 0:
            return False, 0.0, "Request failed"

        # Inject sleep/delay payload
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return False, 0.1, "No params for timing test"

        inject_param = list(params.keys())[0]
        base_url = urlunparse(parsed._replace(query=""))

        delay_payloads = [
            ("sleep(5)", 5000),
            ("$(sleep 5)", 5000),
            ("; sleep 5 ;", 5000),
            ("' OR SLEEP(5)-- -", 5000),
            ("1' AND SLEEP(5)-- -", 5000),
        ]

        for payload, expected_delay_ms in delay_payloads:
            test_params = dict(params)
            test_params[inject_param] = [payload]
            t0 = time.time()
            r_delay = await self.http.get(f"{base_url}?{urlencode(test_params, doseq=True)}")
            delay_ms = (time.time() - t0) * 1000

            if delay_ms > baseline_ms + (expected_delay_ms * 0.7):
                return True, 0.8, f"Timing confirmed: baseline={baseline_ms:.0f}ms, delayed={delay_ms:.0f}ms"

        return False, 0.1, "No timing differential detected"

    async def _validate_ssrf(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Verify SSRF by checking if internal content was returned."""
        url = finding.get("url", target_url)
        result = await self.http.get(url)
        if result.status == 0:
            return False, 0.0, "Request failed"

        body = result.body.lower()
        # Check for cloud metadata indicators
        metadata_indicators = [
            "ami-id", "instance-id", "iam", "security-credentials",
            "computeMetadata", "access_token", "instance/service-accounts",
            "169.254.169.254", "metadata.google.internal",
        ]
        for indicator in metadata_indicators:
            if indicator.lower() in body:
                return True, 0.9, f"Cloud metadata indicator found: {indicator}"

        # Check for internal service response patterns
        if any(x in body for x in ["localhost", "127.0.0.1", "internal"]):
            return True, 0.5, "Internal host reference in response"

        return False, 0.2, "No SSRF indicators in response"

    async def _validate_cors(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Verify CORS misconfiguration is actually exploitable."""
        url = finding.get("url", target_url)

        # Test with evil origin
        evil_origin = "https://evil-viper-test.com"
        result = await self.http.get(url, headers={"Origin": evil_origin})
        if result.status == 0:
            return False, 0.0, "Request failed"

        acao = result.headers.get("Access-Control-Allow-Origin", "")
        acac = result.headers.get("Access-Control-Allow-Credentials", "").lower()

        # ACAO reflects evil origin
        if evil_origin in acao:
            if acac == "true":
                # This is exploitable — credentials can be stolen
                return True, 0.95, f"CORS: origin reflected ({acao}) + credentials=true"
            else:
                # Reflected but no credentials — limited impact
                return True, 0.4, f"CORS: origin reflected ({acao}) but no credentials"

        if acao == "*":
            if acac == "true":
                # Browsers actually block this combo, so it's NOT exploitable
                return False, 0.1, "CORS: ACAO=* + ACAC=true is blocked by browsers (not exploitable)"
            return True, 0.3, "CORS: wildcard origin (limited impact, no credential access)"

        return False, 0.05, f"CORS: origin not reflected (ACAO={acao})"

    async def _validate_redirect(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Verify open redirect actually redirects to external domain."""
        url = finding.get("url", target_url)

        result = await self.http.request("GET", url, allow_redirects=False)
        if result.status == 0:
            return False, 0.0, "Request failed"

        if result.status in (301, 302, 303, 307, 308):
            location = result.headers.get("Location", "")
            if location:
                loc_domain = urlparse(location).netloc
                orig_domain = urlparse(url).netloc
                if loc_domain and loc_domain != orig_domain:
                    return True, 0.9, f"Redirects to external: {location}"
                return False, 0.1, f"Redirect stays on same domain: {location}"

        return False, 0.1, f"No redirect (status={result.status})"

    async def _validate_header(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Missing security headers are informational, not real vulns."""
        return True, 0.2, "Informational: missing header (not exploitable alone)"

    async def _validate_info(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Info-level findings pass but with low confidence."""
        return True, 0.1, "Informational finding"

    async def _validate_generic(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Generic validator: re-send and check if marker still present."""
        url = finding.get("url", target_url)
        marker = finding.get("marker", "")

        if not marker:
            return False, 0.1, "No marker to validate"

        result = await self.http.get(url)
        if result.status == 0:
            return False, 0.0, "Request failed"

        if marker.lower() in result.body.lower():
            return True, 0.5, "Marker confirmed on re-request"

        return False, 0.15, "Marker not found on re-request"

    # ── v2.3 Validators ──

    async def _validate_jwt(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Validate JWT none-algorithm or weak-secret bypass."""
        url = finding.get("url", target_url)
        payload = finding.get("payload", "")

        # Send request with the forged JWT as Authorization header
        headers = {"Authorization": f"Bearer {payload}"}
        result = await self.http.get(url, headers=headers)
        if result.status == 0:
            return False, 0.0, "Request failed"

        # Also try without JWT for comparison
        result_noauth = await self.http.get(url)

        body = result.body.lower()
        body_noauth = result_noauth.body.lower()

        # If authenticated content differs from unauthenticated
        auth_indicators = ["admin", "dashboard", "welcome", "logout", "profile", "settings"]
        for indicator in auth_indicators:
            if indicator in body and indicator not in body_noauth:
                return True, 0.85, f"JWT bypass confirmed: '{indicator}' present only with forged token"

        # If status codes differ (e.g., 200 vs 401)
        if result.status == 200 and result_noauth.status in (401, 403):
            return True, 0.8, f"JWT bypass: forged token returns 200, without returns {result_noauth.status}"

        # If response lengths differ significantly
        len_diff = abs(len(result.body) - len(result_noauth.body))
        if len_diff > 100 and result.status == 200:
            return True, 0.5, f"JWT bypass possible: response diff={len_diff} bytes"

        return False, 0.15, "JWT bypass not confirmed"

    async def _validate_idor(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Validate IDOR by comparing responses for different IDs."""
        url = finding.get("url", target_url)
        payload = finding.get("payload", "")

        result = await self.http.get(url)
        if result.status == 0:
            return False, 0.0, "Request failed"

        body = result.body

        # Check if response contains user-specific data
        pii_patterns = [
            r'"email"\s*:\s*"[^"]+@[^"]+"',
            r'"phone"\s*:\s*"[\d\+\-\s]+"',
            r'"name"\s*:\s*"[^"]+"',
            r'"address"\s*:\s*"[^"]+"',
            r'"ssn"\s*:\s*"[^"]+"',
            r'"credit_card"\s*:\s*"[^"]+"',
        ]
        pii_found = []
        for pattern in pii_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                pii_found.append(pattern.split('"')[1])

        if not pii_found:
            return False, 0.15, "No PII-like data in response"

        # Negative test: try a clearly invalid ID
        parsed = urlparse(url)
        neg_url = url.replace(f"={payload}", "=99999999")
        if neg_url == url:
            neg_url = url.replace(f"/{payload}", "/99999999")
        neg_result = await self.http.get(neg_url)

        if neg_result.status == 200 and neg_result.body == body:
            return False, 0.1, "Same response for different IDs (likely not IDOR)"

        if neg_result.status in (403, 404) or len(neg_result.body) < len(body) * 0.5:
            return True, 0.7, f"IDOR likely: PII fields ({', '.join(pii_found)}) + different response for invalid ID"

        return True, 0.5, f"IDOR possible: PII fields ({', '.join(pii_found)}) found"

    async def _validate_debug_endpoint(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Validate exposed debug/admin endpoints."""
        url = finding.get("url", target_url)
        result = await self.http.get(url)
        if result.status == 0:
            return False, 0.0, "Request failed"
        if result.status == 404:
            return False, 0.0, "Endpoint returns 404"
        if result.status == 403:
            return True, 0.3, "Debug endpoint exists but is forbidden (information disclosure)"

        body = result.body
        # High-confidence indicators of real debug/admin endpoints
        high_confidence = [
            r"phpinfo\(\)", r"PHP Version", r"DOCUMENT_ROOT",
            r"\"status\"\s*:\s*\"UP\"", r"actuator",
            r"goroutine", r"pprof", r"heapdump",
            r"swagger", r"openapi", r"\"paths\"\s*:",
            r"server-status", r"Apache Server Status",
            r"graphiql", r"GraphQL Playground",
            r"Spring Boot", r"configprops",
        ]
        for pattern in high_confidence:
            if re.search(pattern, body, re.IGNORECASE):
                return True, 0.85, f"Debug endpoint confirmed: matched '{pattern}'"

        # Medium-confidence: generic health/info endpoints
        if result.status == 200 and len(body) > 50:
            return True, 0.5, f"Endpoint accessible (status={result.status}, size={len(body)})"

        return False, 0.1, "No debug content indicators found"

    async def _validate_source_map(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Validate exposed source map files."""
        url = finding.get("url", target_url)
        result = await self.http.get(url)
        if result.status == 0 or result.status == 404:
            return False, 0.0, "Source map not accessible"

        body = result.body
        # Source maps have a very specific JSON structure
        if '"version"' in body and '"sources"' in body and '"mappings"' in body:
            has_content = '"sourcesContent"' in body
            confidence = 0.9 if has_content else 0.75
            return True, confidence, f"Source map confirmed (sourcesContent={'yes' if has_content else 'no'})"

        if "webpack://" in body or "module.exports" in body:
            return True, 0.7, "Webpack configuration exposed"

        return False, 0.1, "Not a valid source map"

    async def _validate_graphql_introspection(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Validate GraphQL introspection is enabled."""
        url = finding.get("url", target_url)
        payload = finding.get("payload", "")

        # Re-send introspection query
        headers = {"Content-Type": "application/json"}
        try:
            result = await self.http.request(
                "POST", url, headers=headers, data=payload
            )
        except Exception:
            result = await self.http.get(url)

        if result.status == 0:
            return False, 0.0, "Request failed"

        body = result.body
        if "__schema" in body and "types" in body:
            # Count types to gauge exposure
            type_count = body.count('"name"')
            return True, 0.85, f"GraphQL introspection enabled: ~{type_count} types exposed"

        if "__type" in body or "queryType" in body:
            return True, 0.7, "GraphQL introspection partially enabled"

        return False, 0.1, "Introspection not confirmed"

    async def _validate_graphql_injection(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Validate GraphQL injection / data leakage."""
        url = finding.get("url", target_url)
        marker = finding.get("marker", "")
        payload = finding.get("payload", "")

        headers = {"Content-Type": "application/json"}
        try:
            result = await self.http.request(
                "POST", url, headers=headers, data=payload
            )
        except Exception:
            result = await self.http.get(url)

        if result.status == 0:
            return False, 0.0, "Request failed"

        body = result.body.lower()
        # Check for sensitive data in response
        sensitive = ["password", "secret", "apikey", "api_key", "token", "credit"]
        for s in sensitive:
            if s in body and "error" not in body[:50].lower():
                return True, 0.8, f"GraphQL data leakage: '{s}' in response"

        if "syntax error" in body or "cannot query field" in body:
            return True, 0.5, "GraphQL error disclosure (schema information leak)"

        return False, 0.15, "No GraphQL injection confirmed"

    async def _validate_xxe(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Validate XXE by checking for file content in response."""
        url = finding.get("url", target_url)
        result = await self.http.get(url)
        if result.status == 0:
            return False, 0.0, "Request failed"

        body = result.body
        # Check for /etc/passwd content
        if re.search(r"root:x?:\d+:\d+", body):
            return True, 0.9, "XXE confirmed: /etc/passwd content in response"

        # Check for Windows file content
        if re.search(r"\[extensions\]|\[fonts\]", body):
            return True, 0.9, "XXE confirmed: win.ini content in response"

        # Check for cloud metadata
        if any(x in body.lower() for x in ["ami-id", "instance-id", "computemetadata"]):
            return True, 0.9, "XXE confirmed: cloud metadata in response"

        # Check for XML parsing errors that reveal XXE processing
        if "ENTITY" in body or "DOCTYPE" in body:
            return True, 0.4, "XXE processing detected (entity/doctype in response)"

        return False, 0.1, "No XXE indicators in response"

    async def _validate_crlf(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Validate CRLF injection by checking response headers."""
        url = finding.get("url", target_url)
        result = await self.http.request("GET", url, allow_redirects=False)
        if result.status == 0:
            return False, 0.0, "Request failed"

        headers_str = "\n".join(f"{k}: {v}" for k, v in result.headers.items())

        # Check if injected headers appear in response
        if "viper=crlf" in headers_str or "viper-crlf-test" in headers_str:
            return True, 0.9, "CRLF injection confirmed: injected header in response"

        if "X-Injected" in headers_str and "viper" in headers_str:
            return True, 0.85, "CRLF injection confirmed: custom header injected"

        # Check for header injection in Set-Cookie
        for key, val in result.headers.items():
            if "viper" in str(val).lower() and key.lower() == "set-cookie":
                return True, 0.9, "CRLF injection: cookie injection confirmed"

        return False, 0.1, "No CRLF injection in response headers"

    async def _validate_host_header(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Validate host header injection."""
        url = finding.get("url", target_url)
        payload = finding.get("payload", "evil.com")

        result = await self.http.get(url, headers={"Host": payload})
        if result.status == 0:
            return False, 0.0, "Request failed"

        body = result.body.lower()
        payload_lower = payload.lower().split(":")[0]  # Strip port

        # Check if injected host appears in response body (password reset links, etc.)
        if payload_lower in body:
            # Check it's in a meaningful context (link, action, form)
            link_pattern = rf'(href|action|src|url)\s*=\s*["\'][^"\']*{re.escape(payload_lower)}'
            if re.search(link_pattern, body):
                return True, 0.85, f"Host header injection: '{payload_lower}' in link/action attribute"
            return True, 0.6, f"Host header injection: '{payload_lower}' reflected in response body"

        return False, 0.1, "Host header not reflected"

    async def _validate_subdomain_takeover(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Validate subdomain takeover indicators."""
        url = finding.get("url", target_url)
        result = await self.http.get(url)
        if result.status == 0:
            # Connection failure could indicate dangling CNAME
            return True, 0.4, "Connection failed (possible dangling DNS)"

        body = result.body
        takeover_signatures = {
            "NoSuchBucket": ("AWS S3", 0.9),
            "The specified bucket does not exist": ("AWS S3", 0.9),
            "There isn't a GitHub Pages site here": ("GitHub Pages", 0.9),
            "Repository not found": ("GitHub", 0.7),
            "No such app": ("Heroku", 0.85),
            "Fastly error: unknown domain": ("Fastly", 0.85),
            "Help Center Closed": ("Zendesk", 0.8),
            "PROJECT_NOT_FOUND": ("Google Cloud", 0.8),
            "The request could not be satisfied": ("AWS CloudFront", 0.6),
        }

        for signature, (service, confidence) in takeover_signatures.items():
            if signature in body:
                return True, confidence, f"Subdomain takeover ({service}): '{signature}'"

        return False, 0.05, "No takeover signatures found"

    async def _validate_verb_tampering(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Validate HTTP verb tampering bypasses access controls."""
        url = finding.get("url", target_url)
        payload = finding.get("payload", "PUT")  # The HTTP method

        # First check if the endpoint is normally restricted
        result_get = await self.http.get(url)

        # Then try with the tampered verb
        result_verb = await self.http.request(payload, url)
        if result_verb.status == 0:
            return False, 0.0, "Request failed"

        # If GET is forbidden but alternative verb works
        if result_get.status in (401, 403, 405) and result_verb.status == 200:
            return True, 0.8, f"Verb tampering bypass: GET={result_get.status}, {payload}=200"

        # TRACE echoing the request is a vulnerability
        if payload == "TRACE" and result_verb.status == 200:
            if "TRACE" in result_verb.body:
                return True, 0.7, "TRACE method enabled (XST risk)"

        # OPTIONS revealing allowed methods
        if payload == "OPTIONS" and result_verb.status == 200:
            allow = result_verb.headers.get("Allow", "")
            if any(m in allow for m in ["PUT", "DELETE", "PATCH"]):
                return True, 0.4, f"Dangerous methods allowed: {allow}"

        return False, 0.1, f"Verb tampering inconclusive (GET={result_get.status}, {payload}={result_verb.status})"

    async def _validate_cache_poisoning(self, finding: Dict, target_url: str) -> Tuple[bool, float, str]:
        """Validate web cache poisoning."""
        url = finding.get("url", target_url)
        payload = finding.get("payload", "")

        # Parse the header from payload
        if ": " in payload:
            header_name, header_value = payload.split(": ", 1)
        else:
            return False, 0.1, "Invalid cache poisoning payload format"

        result = await self.http.get(url, headers={header_name: header_value})
        if result.status == 0:
            return False, 0.0, "Request failed"

        body = result.body.lower()
        header_value_lower = header_value.lower()

        # Check if injected value appears in response
        if header_value_lower in body:
            # Check for caching headers
            cache_hit = result.headers.get("X-Cache", "")
            age = result.headers.get("Age", "")
            if "HIT" in cache_hit.upper() or age:
                return True, 0.85, f"Cache poisoning confirmed: injected value cached (X-Cache={cache_hit})"
            return True, 0.5, f"Cache poisoning possible: '{header_value}' reflected in response"

        return False, 0.1, "Injected header value not reflected"

    # ── Deduplication ──

    async def check_duplicate(self, finding: Dict, db) -> Tuple[bool, Optional[int]]:
        """
        Check if this finding is a duplicate of an existing one in the DB.

        Args:
            finding: dict with attack/vuln_type, url, payload keys
            db: ViperDB instance

        Returns: (is_duplicate, existing_finding_id)
        """
        url = finding.get("url", "")
        vuln_type = finding.get("attack", finding.get("vuln_type", ""))
        payload = finding.get("payload")

        parsed = urlparse(url)
        domain = parsed.netloc
        target_id = db.get_target_id(url)

        if not target_id:
            # Try domain-level match
            row = db.conn.execute(
                "SELECT id FROM targets WHERE domain = ?", (domain,)
            ).fetchone()
            if row:
                target_id = row["id"]

        if target_id:
            return db.is_duplicate(target_id, vuln_type, url, payload)

        return False, None
