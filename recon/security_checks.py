"""
VIPER 4.0 — Security Checks Module
====================================
Automated security header / TLS / WAF / cookie / redirect analysis.
Stdlib-only (urllib, ssl, socket, http.cookiejar). Async-compatible via asyncio.to_thread().
"""

import asyncio
import hashlib
import http.cookiejar
import json
import logging
import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("viper.recon.security_checks")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class SecurityCheckResult:
    url: str
    headers_score: float = 0.0          # 0-100
    missing_headers: List[str] = field(default_factory=list)
    weak_headers: List[dict] = field(default_factory=list)
    tls_info: dict = field(default_factory=dict)
    cookies: List[dict] = field(default_factory=list)
    waf_detected: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    info_disclosure: List[dict] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "headers_score": self.headers_score,
            "missing_headers": self.missing_headers,
            "weak_headers": self.weak_headers,
            "tls_info": self.tls_info,
            "cookies": self.cookies,
            "waf_detected": self.waf_detected,
            "redirect_chain": self.redirect_chain,
            "info_disclosure": self.info_disclosure,
            "findings": self.findings,
        }

    @property
    def severity_summary(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_opener(follow_redirects: bool = True, timeout: int = 10):
    """Build a urllib opener with cookie support."""
    cj = http.cookiejar.CookieJar()
    handlers = [urllib.request.HTTPCookieProcessor(cj)]
    if not follow_redirects:
        handlers.append(_NoRedirectHandler())
    # Allow self-signed certs for security testing
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    return opener, cj


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent urllib from following redirects so we can inspect each hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise _RedirectCaught(code, newurl, dict(headers))


class _RedirectCaught(urllib.error.HTTPError):
    """Raised to capture redirect without following it."""

    def __init__(self, code, url, headers):
        self.code = code
        self.redirect_url = url
        self.redirect_headers = headers
        super().__init__(url, code, f"Redirect {code}", headers, None)


def _fetch(url: str, timeout: int = 10, follow: bool = True) -> Tuple[Optional[Any], Optional[http.cookiejar.CookieJar]]:
    """Fetch URL with custom opener. Returns (response, cookiejar) or (None, None)."""
    opener, cj = _build_opener(follow_redirects=follow, timeout=timeout)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        resp = opener.open(req, timeout=timeout)
        return resp, cj
    except _RedirectCaught as e:
        return e, cj
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, OSError):
        return None, None


def _get_response_headers(url: str, timeout: int = 10) -> Optional[Dict[str, str]]:
    """Fetch headers (following redirects) and return lowercase-key dict."""
    resp, cj = _fetch(url, timeout=timeout, follow=True)
    if resp is None:
        return None
    hdrs = {}
    # http.client.HTTPResponse or HTTPError both have .headers / .getheaders()
    raw = getattr(resp, "headers", None) or getattr(resp, "redirect_headers", {})
    if hasattr(raw, "items"):
        for k, v in raw.items():
            hdrs[k.lower()] = v
    return hdrs


# ===================================================================
# 1. SECURITY HEADERS CHECK
# ===================================================================

# (header_name, weight, evaluator_func)
# evaluator returns ("strong"|"weak"|"missing", detail_str)

def _eval_hsts(value: Optional[str]) -> Tuple[str, str]:
    if not value:
        return "missing", "Header not present"
    val_lower = value.lower()
    max_age_m = re.search(r"max-age=(\d+)", val_lower)
    if not max_age_m:
        return "weak", "max-age not set"
    age = int(max_age_m.group(1))
    has_sub = "includesubdomains" in val_lower
    has_preload = "preload" in val_lower
    if age >= 31536000 and has_sub and has_preload:
        return "strong", f"max-age={age}, includeSubDomains, preload"
    if age >= 15768000 and has_sub:
        return "strong", f"max-age={age}, includeSubDomains"
    if age < 2592000:
        return "weak", f"max-age too low ({age}s < 30 days)"
    return "strong", value


def _eval_csp(value: Optional[str]) -> Tuple[str, str]:
    if not value:
        return "missing", "Header not present"
    val_lower = value.lower()
    issues = []
    if "unsafe-inline" in val_lower:
        issues.append("unsafe-inline allows inline scripts")
    if "unsafe-eval" in val_lower:
        issues.append("unsafe-eval allows eval()")
    if "'none'" not in val_lower and "default-src" not in val_lower:
        issues.append("No default-src directive")
    if "*" in val_lower:
        # wildcard source
        issues.append("Wildcard (*) source allows any origin")
    if issues:
        return "weak", "; ".join(issues)
    return "strong", "Policy defined"


def _eval_x_frame_options(value: Optional[str]) -> Tuple[str, str]:
    if not value:
        return "missing", "Header not present — clickjacking risk"
    val_upper = value.upper().strip()
    if val_upper in ("DENY", "SAMEORIGIN"):
        return "strong", val_upper
    if val_upper.startswith("ALLOW-FROM"):
        return "weak", f"ALLOW-FROM is deprecated: {value}"
    return "weak", f"Unrecognized value: {value}"


def _eval_x_content_type_options(value: Optional[str]) -> Tuple[str, str]:
    if not value:
        return "missing", "Header not present — MIME-sniffing risk"
    if value.strip().lower() == "nosniff":
        return "strong", "nosniff"
    return "weak", f"Unexpected value: {value}"


def _eval_x_xss_protection(value: Optional[str]) -> Tuple[str, str]:
    if not value:
        return "missing", "Header not present (deprecated but still useful for older browsers)"
    if "1" in value and "mode=block" in value.lower():
        return "strong", value.strip()
    if value.strip() == "0":
        return "weak", "Explicitly disabled"
    return "weak", f"Incomplete: {value}"


def _eval_referrer_policy(value: Optional[str]) -> Tuple[str, str]:
    if not value:
        return "missing", "Header not present — referrer leakage risk"
    safe = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
    if value.strip().lower() in safe:
        return "strong", value.strip()
    if value.strip().lower() in ("no-referrer-when-downgrade", "origin", "origin-when-cross-origin"):
        return "weak", f"{value.strip()} may leak URL paths"
    if value.strip().lower() == "unsafe-url":
        return "weak", "unsafe-url leaks full URL to all origins"
    return "weak", f"Unrecognized: {value}"


def _eval_permissions_policy(value: Optional[str]) -> Tuple[str, str]:
    if not value:
        return "missing", "Header not present — browser features unrestricted"
    # Check if it actually restricts anything
    if "=()" in value or "=self" in value.lower():
        return "strong", "Features restricted"
    return "weak", "Policy present but may not restrict effectively"


def _eval_coop(value: Optional[str]) -> Tuple[str, str]:
    if not value:
        return "missing", "Header not present"
    if value.strip().lower() == "same-origin":
        return "strong", "same-origin"
    return "weak", value.strip()


def _eval_corp(value: Optional[str]) -> Tuple[str, str]:
    if not value:
        return "missing", "Header not present"
    if value.strip().lower() in ("same-origin", "same-site"):
        return "strong", value.strip()
    return "weak", value.strip()


def _eval_coep(value: Optional[str]) -> Tuple[str, str]:
    if not value:
        return "missing", "Header not present"
    if value.strip().lower() in ("require-corp", "credentialless"):
        return "strong", value.strip()
    return "weak", value.strip()


_HEADER_CHECKS = [
    # (display_name, header_key_lowercase, weight, evaluator)
    ("Strict-Transport-Security", "strict-transport-security", 15, _eval_hsts),
    ("Content-Security-Policy", "content-security-policy", 15, _eval_csp),
    ("X-Frame-Options", "x-frame-options", 10, _eval_x_frame_options),
    ("X-Content-Type-Options", "x-content-type-options", 10, _eval_x_content_type_options),
    ("X-XSS-Protection", "x-xss-protection", 5, _eval_x_xss_protection),
    ("Referrer-Policy", "referrer-policy", 10, _eval_referrer_policy),
    ("Permissions-Policy", "permissions-policy", 10, _eval_permissions_policy),
    ("Cross-Origin-Opener-Policy", "cross-origin-opener-policy", 8, _eval_coop),
    ("Cross-Origin-Resource-Policy", "cross-origin-resource-policy", 8, _eval_corp),
    ("Cross-Origin-Embedder-Policy", "cross-origin-embedder-policy", 9, _eval_coep),
]


def check_security_headers(headers: Dict[str, str]) -> Tuple[float, List[str], List[dict], List[dict]]:
    """
    Evaluate security headers.

    Returns: (score 0-100, missing_headers, weak_headers, findings)
    """
    total_weight = sum(w for _, _, w, _ in _HEADER_CHECKS)
    earned = 0.0
    missing = []
    weak = []
    findings = []

    for display, key, weight, evaluator in _HEADER_CHECKS:
        val = headers.get(key)
        grade, detail = evaluator(val)

        if grade == "strong":
            earned += weight
        elif grade == "weak":
            earned += weight * 0.4
            weak.append({"header": display, "value": val, "issue": detail})
            findings.append({
                "type": "weak_header",
                "severity": "low",
                "name": f"Weak {display}",
                "detail": detail,
            })
        else:  # missing
            missing.append(display)
            sev = "medium" if weight >= 10 else "low"
            findings.append({
                "type": "missing_header",
                "severity": sev,
                "name": f"Missing {display}",
                "detail": detail,
            })

    score = round((earned / total_weight) * 100, 1) if total_weight else 0
    return score, missing, weak, findings


# ===================================================================
# 2. TLS / SSL ANALYSIS
# ===================================================================

def check_tls(hostname: str, port: int = 443, timeout: int = 10) -> Tuple[dict, List[dict]]:
    """
    Analyze TLS certificate and connection properties.

    Returns: (tls_info dict, findings list)
    """
    tls_info: Dict[str, Any] = {}
    findings: List[dict] = []

    # --- Certificate info ---
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                negotiated = ssock.version()  # e.g. "TLSv1.3"
                cipher_info = ssock.cipher()   # (name, version, bits)

        tls_info["protocol"] = negotiated
        if cipher_info:
            tls_info["cipher_name"] = cipher_info[0]
            tls_info["cipher_bits"] = cipher_info[2]

        # Parse cert via ssl helper
        decoded = ssl._ssl._test_decode_cert(None) if False else None  # type: ignore
    except Exception as e:
        tls_info["error"] = str(e)
        findings.append({
            "type": "tls_error",
            "severity": "high",
            "name": "TLS Connection Failed",
            "detail": str(e),
        })
        return tls_info, findings

    # --- Get cert details using a validating context ---
    try:
        ctx2 = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock2:
            with ctx2.wrap_socket(sock2, server_hostname=hostname) as ssock2:
                cert_dict = ssock2.getpeercert()
        tls_info["cert_valid"] = True
    except ssl.SSLCertVerificationError as e:
        cert_dict = None
        tls_info["cert_valid"] = False
        findings.append({
            "type": "tls_cert_invalid",
            "severity": "high",
            "name": "Invalid TLS Certificate",
            "detail": str(e),
        })
    except Exception:
        cert_dict = None
        tls_info["cert_valid"] = False

    if cert_dict:
        # Subject
        subj = dict(x[0] for x in cert_dict.get("subject", ()))
        tls_info["subject"] = subj.get("commonName", "")

        # Issuer
        issuer = dict(x[0] for x in cert_dict.get("issuer", ()))
        tls_info["issuer"] = issuer.get("organizationName", issuer.get("commonName", ""))

        # SAN
        san_list = [v for t, v in cert_dict.get("subjectAltName", ()) if t == "DNS"]
        tls_info["san"] = san_list

        # Expiry
        not_after = cert_dict.get("notAfter", "")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                tls_info["expires"] = not_after
                days_left = (exp - datetime.now(timezone.utc)).days
                tls_info["days_until_expiry"] = days_left
                if days_left < 0:
                    findings.append({
                        "type": "tls_expired",
                        "severity": "critical",
                        "name": "TLS Certificate Expired",
                        "detail": f"Expired {abs(days_left)} days ago",
                    })
                elif days_left < 14:
                    findings.append({
                        "type": "tls_expiring_soon",
                        "severity": "medium",
                        "name": "TLS Certificate Expiring Soon",
                        "detail": f"Expires in {days_left} days",
                    })
            except ValueError:
                pass

    # --- Protocol check ---
    proto = tls_info.get("protocol", "")
    if proto in ("TLSv1", "TLSv1.0", "TLSv1.1"):
        findings.append({
            "type": "tls_weak_protocol",
            "severity": "high",
            "name": "Deprecated TLS Protocol",
            "detail": f"{proto} is deprecated and insecure",
        })
    elif proto == "TLSv1.2":
        tls_info["protocol_rating"] = "acceptable"
    elif proto == "TLSv1.3":
        tls_info["protocol_rating"] = "strong"

    # --- Legacy protocol probing (TLS 1.0 / 1.1) ---
    for legacy_ver in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        label = "TLSv1.0" if legacy_ver == ssl.TLSVersion.TLSv1 else "TLSv1.1"
        try:
            ctx_leg = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_leg.check_hostname = False
            ctx_leg.verify_mode = ssl.CERT_NONE
            ctx_leg.minimum_version = legacy_ver
            ctx_leg.maximum_version = legacy_ver
            with socket.create_connection((hostname, port), timeout=5) as s:
                with ctx_leg.wrap_socket(s, server_hostname=hostname) as ss:
                    pass
            # If we get here, the server accepted the legacy version
            tls_info[f"supports_{label.replace('.', '_')}"] = True
            findings.append({
                "type": "tls_legacy_supported",
                "severity": "medium",
                "name": f"Server Supports {label}",
                "detail": f"{label} is deprecated — should be disabled",
            })
        except (ssl.SSLError, OSError, socket.timeout):
            tls_info[f"supports_{label.replace('.', '_')}"] = False

    # --- Weak cipher check ---
    cipher_name = tls_info.get("cipher_name", "")
    weak_ciphers = ("RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5")
    for wc in weak_ciphers:
        if wc.upper() in cipher_name.upper():
            findings.append({
                "type": "tls_weak_cipher",
                "severity": "high",
                "name": "Weak Cipher Detected",
                "detail": f"Cipher {cipher_name} contains weak algorithm {wc}",
            })
            break

    return tls_info, findings


# ===================================================================
# 3. COOKIE SECURITY
# ===================================================================

def check_cookies(url: str, timeout: int = 10) -> Tuple[List[dict], List[dict]]:
    """
    Analyze cookie security flags.

    Returns: (cookies list, findings list)
    """
    resp, cj = _fetch(url, timeout=timeout, follow=True)
    if resp is None or cj is None:
        return [], []

    cookies_out: List[dict] = []
    findings: List[dict] = []

    for cookie in cj:
        info: Dict[str, Any] = {
            "name": cookie.name,
            "domain": cookie.domain,
            "path": cookie.path,
            "secure": cookie.secure,
            "httponly": bool(getattr(cookie, "_rest", {}).get("HttpOnly", False)),
        }

        # SameSite — not directly exposed by http.cookiejar, check raw header
        info["samesite"] = None  # will be patched below

        cookies_out.append(info)

        is_https = url.startswith("https")

        if not cookie.secure and is_https:
            findings.append({
                "type": "cookie_no_secure",
                "severity": "medium",
                "name": f"Cookie '{cookie.name}' Missing Secure Flag",
                "detail": "Cookie sent over HTTPS but lacks Secure flag — may leak over HTTP",
            })

        if not info["httponly"]:
            # Session-like cookies without HttpOnly are higher risk
            is_session = any(k in cookie.name.lower() for k in ("sess", "token", "auth", "jwt", "sid"))
            sev = "medium" if is_session else "low"
            findings.append({
                "type": "cookie_no_httponly",
                "severity": sev,
                "name": f"Cookie '{cookie.name}' Missing HttpOnly Flag",
                "detail": "Cookie accessible to JavaScript — XSS exfiltration risk",
            })

    # Also parse raw Set-Cookie headers for SameSite
    raw_headers = getattr(resp, "headers", None)
    if raw_headers:
        set_cookies_raw = raw_headers.get_all("Set-Cookie") if hasattr(raw_headers, "get_all") else []
        if not set_cookies_raw and hasattr(raw_headers, "items"):
            set_cookies_raw = [v for k, v in raw_headers.items() if k.lower() == "set-cookie"]
        for sc in set_cookies_raw:
            # Extract name and SameSite
            name_m = re.match(r"^([^=]+)=", sc)
            ss_m = re.search(r"samesite\s*=\s*(\w+)", sc, re.I)
            if name_m:
                cname = name_m.group(1).strip()
                # Update the matching cookie entry
                for ci in cookies_out:
                    if ci["name"] == cname:
                        ci["samesite"] = ss_m.group(1) if ss_m else None
                        break
                if not ss_m:
                    findings.append({
                        "type": "cookie_no_samesite",
                        "severity": "low",
                        "name": f"Cookie '{cname}' Missing SameSite Attribute",
                        "detail": "No SameSite — browser defaults to Lax but explicit is better",
                    })

    return cookies_out, findings


# ===================================================================
# 4. WAF DETECTION
# ===================================================================

_WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {"server": "cloudflare", "cf-ray": ""},
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
    },
    "AWS WAF / CloudFront": {
        "headers": {"x-amz-cf-id": "", "x-amz-cf-pop": "", "server": "cloudfront"},
        "cookies": ["awsalb", "awsalbcors"],
    },
    "Akamai": {
        "headers": {"x-akamai-transformed": "", "server": "akamaighost"},
        "cookies": ["akamai_"],
    },
    "Imperva / Incapsula": {
        "headers": {"x-iinfo": "", "x-cdn": "incapsula"},
        "cookies": ["incap_ses", "visid_incap", "__utm"],
    },
    "Sucuri": {
        "headers": {"x-sucuri-id": "", "server": "sucuri"},
        "cookies": ["sucuri_"],
    },
    "ModSecurity": {
        "headers": {"server": "mod_security"},
        "cookies": [],
    },
    "F5 BIG-IP": {
        "headers": {"server": "big-ip", "x-wa-info": ""},
        "cookies": ["bigipserver", "ts"],
    },
    "Barracuda": {
        "headers": {"server": "barracuda"},
        "cookies": ["barra_counter_session"],
    },
}


def detect_waf(headers: Dict[str, str], cookies: List[dict], body: str = "") -> Tuple[Optional[str], List[dict]]:
    """
    Detect WAF based on headers, cookies, and response body patterns.

    Returns: (waf_name or None, findings)
    """
    findings: List[dict] = []

    for waf_name, sigs in _WAF_SIGNATURES.items():
        # Check header signatures
        for hdr_key, hdr_val in sigs["headers"].items():
            actual = headers.get(hdr_key, "")
            if hdr_val and hdr_val.lower() in actual.lower():
                findings.append({
                    "type": "waf_detected",
                    "severity": "info",
                    "name": f"WAF Detected: {waf_name}",
                    "detail": f"Header '{hdr_key}: {actual}' matches {waf_name} signature",
                })
                return waf_name, findings
            if not hdr_val and actual:
                # Header presence alone is enough
                findings.append({
                    "type": "waf_detected",
                    "severity": "info",
                    "name": f"WAF Detected: {waf_name}",
                    "detail": f"Header '{hdr_key}' present — indicates {waf_name}",
                })
                return waf_name, findings

        # Check cookie signatures
        cookie_names = [c.get("name", "").lower() for c in cookies]
        for sig_cookie in sigs["cookies"]:
            for cn in cookie_names:
                if sig_cookie.lower() in cn:
                    findings.append({
                        "type": "waf_detected",
                        "severity": "info",
                        "name": f"WAF Detected: {waf_name}",
                        "detail": f"Cookie '{cn}' matches {waf_name} pattern",
                    })
                    return waf_name, findings

    # Body-based detection (error pages)
    body_sigs = {
        "Cloudflare": ["attention required! | cloudflare", "cloudflare ray id"],
        "Imperva / Incapsula": ["incapsula incident id", "powered by incapsula"],
        "Sucuri": ["sucuri website firewall", "access denied - sucuri"],
        "ModSecurity": ["mod_security", "modsecurity", "not acceptable!"],
        "AWS WAF": ["request blocked", "aws waf"],
    }
    body_lower = body.lower()
    for waf_name, patterns in body_sigs.items():
        for pat in patterns:
            if pat in body_lower:
                findings.append({
                    "type": "waf_detected",
                    "severity": "info",
                    "name": f"WAF Detected: {waf_name}",
                    "detail": f"Response body contains '{pat}'",
                })
                return waf_name, findings

    return None, []


# ===================================================================
# 5. REDIRECT CHAIN ANALYSIS
# ===================================================================

def analyze_redirects(url: str, max_hops: int = 15, timeout: int = 10) -> Tuple[List[str], List[dict]]:
    """
    Follow redirects manually, recording each hop.

    Returns: (chain of URLs, findings)
    """
    chain: List[str] = [url]
    findings: List[dict] = []
    current = url
    visited = {url}

    for _ in range(max_hops):
        opener, _ = _build_opener(follow_redirects=False, timeout=timeout)
        req = urllib.request.Request(current, headers={"User-Agent": UA})
        try:
            resp = opener.open(req, timeout=timeout)
            # No redirect — final destination
            break
        except _RedirectCaught as e:
            next_url = e.redirect_url
            chain.append(next_url)

            # Detect HTTP -> HTTPS upgrade
            if current.startswith("http://") and next_url.startswith("https://"):
                findings.append({
                    "type": "redirect_http_upgrade",
                    "severity": "info",
                    "name": "HTTP to HTTPS Redirect",
                    "detail": f"{current} -> {next_url}",
                })

            # Detect HTTPS -> HTTP downgrade
            if current.startswith("https://") and next_url.startswith("http://"):
                findings.append({
                    "type": "redirect_https_downgrade",
                    "severity": "high",
                    "name": "HTTPS to HTTP Downgrade",
                    "detail": f"Redirect downgrades security: {current} -> {next_url}",
                })

            # Detect open redirect potential (redirect to different domain)
            orig_host = urlparse(current).hostname
            next_host = urlparse(next_url).hostname
            if orig_host and next_host and orig_host != next_host:
                # Only flag if the redirect target includes user-controllable params
                if "?" in current or "url=" in current.lower() or "redirect" in current.lower():
                    findings.append({
                        "type": "open_redirect_potential",
                        "severity": "medium",
                        "name": "Potential Open Redirect",
                        "detail": f"Cross-domain redirect: {orig_host} -> {next_host}",
                    })

            # Loop detection
            if next_url in visited:
                findings.append({
                    "type": "redirect_loop",
                    "severity": "medium",
                    "name": "Redirect Loop Detected",
                    "detail": f"Loop at {next_url}",
                })
                break
            visited.add(next_url)
            current = next_url

        except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, OSError):
            break

    if len(chain) > 5:
        findings.append({
            "type": "redirect_chain_long",
            "severity": "low",
            "name": "Long Redirect Chain",
            "detail": f"{len(chain)} hops — may indicate misconfiguration",
        })

    return chain, findings


# ===================================================================
# 6. INFORMATION DISCLOSURE
# ===================================================================

def check_info_disclosure(headers: Dict[str, str], body: str = "") -> List[dict]:
    """
    Check for information leakage in headers and response body.

    Returns: list of findings
    """
    findings: List[dict] = []

    # Server header version leak
    server = headers.get("server", "")
    if server:
        # Check if it contains a version number
        ver_match = re.search(r"[\d]+\.[\d]+", server)
        if ver_match:
            findings.append({
                "type": "info_server_version",
                "severity": "low",
                "name": "Server Version Disclosed",
                "detail": f"Server: {server}",
                "header": "Server",
                "value": server,
            })
        elif server.lower() not in ("cloudflare", "cloudfront"):
            findings.append({
                "type": "info_server_name",
                "severity": "info",
                "name": "Server Software Disclosed",
                "detail": f"Server: {server}",
                "header": "Server",
                "value": server,
            })

    # X-Powered-By
    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        findings.append({
            "type": "info_powered_by",
            "severity": "low",
            "name": "X-Powered-By Disclosed",
            "detail": f"X-Powered-By: {powered_by}",
            "header": "X-Powered-By",
            "value": powered_by,
        })

    # X-AspNet-Version / X-AspNetMvc-Version
    for hdr in ("x-aspnet-version", "x-aspnetmvc-version"):
        val = headers.get(hdr, "")
        if val:
            findings.append({
                "type": "info_framework_version",
                "severity": "low",
                "name": f"{hdr} Disclosed",
                "detail": f"{hdr}: {val}",
                "header": hdr,
                "value": val,
            })

    # X-Generator
    gen = headers.get("x-generator", "")
    if gen:
        findings.append({
            "type": "info_generator",
            "severity": "info",
            "name": "Generator Disclosed",
            "detail": f"X-Generator: {gen}",
            "header": "X-Generator",
            "value": gen,
        })

    # Body fingerprinting — technology disclosure in error pages / HTML
    if body:
        body_lower = body.lower()
        tech_sigs = [
            (r"<address>Apache/([\d.]+)", "Apache", "medium"),
            (r"<address>nginx/([\d.]+)", "nginx", "low"),
            (r"Microsoft-IIS/([\d.]+)", "IIS", "low"),
            (r"PHP/([\d.]+)", "PHP", "low"),
            (r"X-Powered-By:\s*Express", "Express.js", "info"),
            (r"Servlet/([\d.]+)", "Java Servlet", "info"),
            (r"<meta name=\"generator\" content=\"([^\"]+)\"", "CMS/Generator", "info"),
        ]
        for pattern, tech, sev in tech_sigs:
            m = re.search(pattern, body, re.I)
            if m:
                findings.append({
                    "type": "info_body_fingerprint",
                    "severity": sev,
                    "name": f"Technology Fingerprint: {tech}",
                    "detail": f"Found in response body: {m.group(0)[:120]}",
                })

    return findings


# ===================================================================
# 7. DIRECT IP — API EXPOSURE CHECK
# ===================================================================

API_PROBE_PATHS = [
    "/api", "/api/v1", "/api/v2", "/graphql", "/rest",
    "/swagger", "/openapi.json", "/.well-known",
    "/v1", "/v2",
]


def check_ip_api_exposed(ip: str, port: int = 443, timeout: int = 10) -> dict:
    """
    Probe a direct IP for unprotected API endpoints (HTTP and HTTPS).

    Tests common API paths with and without a Host header.  Any path that
    returns 200/401/403 with JSON-ish content is flagged as an exposed API.

    Returns:
        {exposed_apis: [{path, status, content_type, sample, with_host}], ip: str}
    """
    exposed: list = []

    for scheme in ("https", "http"):
        for path in API_PROBE_PATHS:
            for host_hdr in (None, ip):
                url = f"{scheme}://{ip}:{port}{path}" if port not in (80, 443) else f"{scheme}://{ip}{path}"
                hdrs = {"User-Agent": UA, "Accept": "application/json"}
                if host_hdr:
                    hdrs["Host"] = host_hdr
                req = urllib.request.Request(url, headers=hdrs)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
                    status = resp.getcode()
                    ct = resp.headers.get("Content-Type", "")
                    body_sample = resp.read(512).decode("utf-8", errors="replace")
                except urllib.error.HTTPError as e:
                    status = e.code
                    ct = e.headers.get("Content-Type", "") if e.headers else ""
                    try:
                        body_sample = e.read(512).decode("utf-8", errors="replace")
                    except Exception:
                        body_sample = ""
                except Exception:
                    continue

                is_api = ("json" in ct.lower()
                          or body_sample.lstrip().startswith("{")
                          or body_sample.lstrip().startswith("["))

                if status in (200, 401, 403) and (is_api or status in (401, 403)):
                    exposed.append({
                        "path": path,
                        "scheme": scheme,
                        "status": status,
                        "content_type": ct,
                        "sample": body_sample[:200],
                        "with_host": host_hdr is not None,
                    })
                    break  # one hit per path is enough
            # once a path is found exposed, skip Host variations
            if exposed and exposed[-1]["path"] == path:
                continue

    return {"ip": ip, "port": port, "exposed_apis": exposed}


# ===================================================================
# 8. WAF BYPASS via DIRECT IP
# ===================================================================

_WAF_INDICATORS = [
    "cloudflare", "akamai", "cloudfront", "fastly",
    "imperva", "incapsula", "sucuri", "barracuda",
    "f5 big-ip", "fortiweb", "wallarm", "stackpath",
]

_BYPASS_HEADERS_SETS = [
    {},  # plain — just Host header
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Forwarded-Host": "127.0.0.1"},
]


def check_waf_bypass(domain: str, ip: str, timeout: int = 10) -> dict:
    """
    Compare WAF-protected response (via domain) with direct-IP response.

    Checks:
    1. Fetch ``https://domain/`` → baseline (hash, size, server).
    2. Fetch ``https://ip/`` with ``Host: domain`` → compare.
    3. If content size within ±10 % and same status → bypass likely.
    4. Also try common bypass headers.

    Returns:
        {bypass_found: bool, method: str|None, evidence: str, details: dict}
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _quick_get(url: str, extra_headers: dict | None = None) -> dict | None:
        hdrs = {"User-Agent": UA}
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            body = resp.read(100_000).decode("utf-8", errors="replace")
            server = ""
            for k, v in resp.headers.items():
                if k.lower() == "server":
                    server = v.lower()
            return {
                "status": resp.getcode(),
                "size": len(body),
                "hash": hashlib.md5(body.encode()).hexdigest(),
                "server": server,
                "body_prefix": body[:300],
            }
        except urllib.error.HTTPError as e:
            server = ""
            if e.headers:
                for k, v in e.headers.items():
                    if k.lower() == "server":
                        server = v.lower()
            return {"status": e.code, "size": 0, "hash": "", "server": server, "body_prefix": ""}
        except Exception:
            return None

    # 1. Baseline via domain
    baseline = _quick_get(f"https://{domain}/")
    if baseline is None:
        return {"bypass_found": False, "method": None, "evidence": "Domain unreachable", "details": {}}

    domain_has_waf = any(w in baseline["server"] for w in _WAF_INDICATORS)

    # 2. Try each bypass header set against direct IP
    for idx, extra in enumerate(_BYPASS_HEADERS_SETS):
        hdr_set = {"Host": domain}
        hdr_set.update(extra)
        ip_resp = _quick_get(f"https://{ip}/", extra_headers=hdr_set)
        if ip_resp is None:
            continue

        ip_has_waf = any(w in ip_resp["server"] for w in _WAF_INDICATORS)

        # Case A: domain behind WAF, IP not — classic bypass
        if domain_has_waf and not ip_has_waf and ip_resp["status"] < 500:
            method_desc = "Direct IP (no bypass headers)" if not extra else f"Headers: {extra}"
            return {
                "bypass_found": True,
                "method": method_desc,
                "evidence": (
                    f"WAF detected on domain ({baseline['server']}) but not on IP. "
                    f"IP returned status {ip_resp['status']}."
                ),
                "details": {
                    "domain_server": baseline["server"],
                    "ip_server": ip_resp["server"],
                    "domain_status": baseline["status"],
                    "ip_status": ip_resp["status"],
                },
            }

        # Case B: similar content size (±10 %) without WAF on IP
        if (ip_resp["status"] == baseline["status"]
                and baseline["size"] > 0
                and abs(ip_resp["size"] - baseline["size"]) / max(baseline["size"], 1) < 0.10):
            method_desc = "Direct IP (no bypass headers)" if not extra else f"Headers: {extra}"
            return {
                "bypass_found": True,
                "method": method_desc,
                "evidence": (
                    f"Similar content served via direct IP "
                    f"(domain size={baseline['size']}, ip size={ip_resp['size']}, "
                    f"status={ip_resp['status']})."
                ),
                "details": {
                    "domain_hash": baseline["hash"],
                    "ip_hash": ip_resp["hash"],
                    "size_diff_pct": round(
                        abs(ip_resp["size"] - baseline["size"]) / max(baseline["size"], 1) * 100, 1
                    ),
                },
            }

    return {"bypass_found": False, "method": None, "evidence": "No bypass detected", "details": {}}


# ===================================================================
# 9. DNS SECURITY CHECKS
# ===================================================================

def _dns_resolve(qname: str, rdtype: str) -> list:
    """Resolve DNS using dns.resolver if available, else subprocess nslookup fallback."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(qname, rdtype)
        return [str(r) for r in answers]
    except ImportError:
        pass
    except Exception:
        return []
    # Fallback: subprocess nslookup (Windows-friendly)
    import subprocess
    try:
        out = subprocess.check_output(
            ["nslookup", "-type=" + rdtype, qname],
            timeout=10, stderr=subprocess.STDOUT
        ).decode("utf-8", errors="replace")
        lines = []
        for line in out.splitlines():
            line = line.strip()
            if "text =" in line.lower():
                # TXT record
                m = re.search(r'"([^"]+)"', line)
                if m:
                    lines.append(m.group(1))
            elif rdtype == "NS" and "nameserver" not in line.lower() and "." in line and "=" not in line:
                lines.append(line)
        return lines
    except Exception:
        return []


def check_spf_missing(domain: str) -> Optional[dict]:
    """Check if SPF record is missing — email spoofing risk."""
    try:
        records = _dns_resolve(domain, "TXT")
        for r in records:
            txt = r.strip('"').strip("'")
            if txt.startswith("v=spf1"):
                return None  # SPF exists
        return {
            "name": "SPF Record Missing",
            "severity": "medium",
            "passed": False,
            "details": f"No TXT record starting with 'v=spf1' found for {domain}",
            "finding": {
                "type": "spf_missing",
                "severity": "medium",
                "name": "SPF Record Missing",
                "detail": f"Domain {domain} has no SPF record — allows email spoofing",
            },
        }
    except Exception:
        return None


def check_dmarc_missing(domain: str) -> Optional[dict]:
    """Check if DMARC record is missing."""
    dmarc_domain = f"_dmarc.{domain}"
    try:
        records = _dns_resolve(dmarc_domain, "TXT")
        for r in records:
            txt = r.strip('"').strip("'")
            if txt.startswith("v=DMARC1"):
                return None
        return {
            "name": "DMARC Record Missing",
            "severity": "medium",
            "passed": False,
            "details": f"No TXT record at _dmarc.{domain} starting with 'v=DMARC1'",
            "finding": {
                "type": "dmarc_missing",
                "severity": "medium",
                "name": "DMARC Record Missing",
                "detail": f"Domain {domain} has no DMARC record — email authentication unverifiable",
            },
        }
    except Exception:
        return None


def check_dnssec_missing(domain: str) -> Optional[dict]:
    """Check if DNSSEC is not enabled (no DNSKEY records)."""
    try:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(domain, "DNSKEY")
            if answers:
                return None  # DNSSEC enabled
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            return None
        return {
            "name": "DNSSEC Not Enabled",
            "severity": "low",
            "passed": False,
            "details": f"No DNSKEY records found for {domain}",
            "finding": {
                "type": "dnssec_missing",
                "severity": "low",
                "name": "DNSSEC Not Enabled",
                "detail": f"Domain {domain} DNS responses are not cryptographically signed",
            },
        }
    except ImportError:
        # dns.resolver not available — skip
        return None
    except Exception:
        return None


def check_zone_transfer(domain: str, timeout: int = 10) -> Optional[dict]:
    """Check if DNS zone transfer (AXFR) is allowed on any nameserver."""
    try:
        import dns.resolver
        import dns.query
        import dns.zone
    except ImportError:
        return None

    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        for ns in ns_answers:
            ns_host = str(ns.target).rstrip(".")
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_host, domain, timeout=timeout, lifetime=timeout)
                )
                if zone:
                    record_count = len(list(zone.nodes.keys()))
                    return {
                        "name": "DNS Zone Transfer Enabled",
                        "severity": "high",
                        "passed": False,
                        "details": f"Nameserver {ns_host} allows AXFR for {domain} ({record_count} records)",
                        "finding": {
                            "type": "zone_transfer",
                            "severity": "high",
                            "name": "DNS Zone Transfer Enabled",
                            "detail": f"AXFR on {ns_host} exposes all DNS records for {domain}",
                        },
                    }
            except Exception:
                continue
    except Exception:
        pass
    return None


# ===================================================================
# 10. AUTHENTICATION SECURITY CHECKS
# ===================================================================

def check_login_no_https(url: str, timeout: int = 10) -> Optional[dict]:
    """Detect login forms served over plain HTTP."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    # Check HTTP version of the site for login forms
    http_url = f"http://{hostname}/"
    try:
        req = urllib.request.Request(http_url, headers={"User-Agent": UA})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read(50000).decode("utf-8", errors="replace")
        # Look for login forms
        login_patterns = [
            r'<form[^>]*>.*?type\s*=\s*["\']password["\']',
            r'<input[^>]*type\s*=\s*["\']password["\']',
            r'<form[^>]*action\s*=\s*["\'][^"\']*login[^"\']*["\']',
        ]
        for pat in login_patterns:
            if re.search(pat, body, re.I | re.S):
                return {
                    "name": "Login Form Over HTTP",
                    "severity": "high",
                    "passed": False,
                    "details": f"Login form detected on {http_url} without TLS encryption",
                    "finding": {
                        "type": "login_no_https",
                        "severity": "high",
                        "name": "Login Form Served Over HTTP",
                        "detail": f"Credentials submitted via {http_url} are sent in plaintext",
                    },
                }
    except Exception:
        pass
    return None


def check_basic_auth_no_tls(url: str, timeout: int = 10) -> Optional[dict]:
    """Detect HTTP Basic Authentication over plain HTTP."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    http_url = f"http://{hostname}/"
    try:
        req = urllib.request.Request(http_url, headers={"User-Agent": UA})
        resp = urllib.request.urlopen(req, timeout=timeout)
        www_auth = resp.headers.get("WWW-Authenticate", "")
    except urllib.error.HTTPError as e:
        www_auth = e.headers.get("WWW-Authenticate", "") if e.headers else ""
    except Exception:
        return None

    if www_auth and "basic" in www_auth.lower():
        return {
            "name": "Basic Auth Over HTTP",
            "severity": "high",
            "passed": False,
            "details": f"HTTP Basic Authentication on {http_url} — credentials sent base64-encoded (not encrypted)",
            "finding": {
                "type": "basic_auth_no_tls",
                "severity": "high",
                "name": "Basic Auth Without TLS",
                "detail": f"WWW-Authenticate: {www_auth} on plain HTTP — trivial credential interception",
            },
        }
    return None


def check_session_cookies(url: str, timeout: int = 10) -> Optional[dict]:
    """Check session cookie flags: Secure, HttpOnly, SameSite."""
    resp, cj = _fetch(url, timeout=timeout, follow=True)
    if not cj:
        return None

    issues = []
    for cookie in cj:
        is_session = any(k in cookie.name.lower() for k in ("sess", "token", "auth", "jwt", "sid", "csrftoken"))
        if not is_session:
            continue
        if not cookie.secure:
            issues.append(f"Cookie '{cookie.name}' missing Secure flag")
        httponly = bool(getattr(cookie, "_rest", {}).get("HttpOnly", False))
        if not httponly:
            issues.append(f"Cookie '{cookie.name}' missing HttpOnly flag")

    if issues:
        return {
            "name": "Session Cookie Flags Missing",
            "severity": "medium",
            "passed": False,
            "details": "; ".join(issues),
            "finding": {
                "type": "session_cookie_flags",
                "severity": "medium",
                "name": "Session Cookie Security Flags Missing",
                "detail": "; ".join(issues),
            },
        }
    return None


# ===================================================================
# 11. DIRECT IP SECURITY CHECKS
# ===================================================================

def check_direct_ip_http(ip: str, timeout: int = 10) -> Optional[dict]:
    """Check if IP responds on HTTP without a hostname — indicates exposed origin."""
    try:
        url = f"http://{ip}/"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        resp = urllib.request.urlopen(req, timeout=timeout)
        status = resp.getcode()
        if status < 500:
            return {
                "name": "Direct IP HTTP Access",
                "severity": "medium",
                "passed": False,
                "details": f"http://{ip}/ returned status {status} — origin server directly reachable",
                "finding": {
                    "type": "direct_ip_http",
                    "severity": "medium",
                    "name": "Direct IP HTTP Access",
                    "detail": f"IP {ip} serves content on HTTP (status {status}) — potential WAF bypass",
                },
            }
    except urllib.error.HTTPError as e:
        if e.code < 500:
            return {
                "name": "Direct IP HTTP Access",
                "severity": "low",
                "passed": False,
                "details": f"http://{ip}/ returned status {e.code}",
                "finding": {
                    "type": "direct_ip_http",
                    "severity": "low",
                    "name": "Direct IP HTTP Access",
                    "detail": f"IP {ip} responds on HTTP (status {e.code})",
                },
            }
    except Exception:
        pass
    return None


def check_direct_ip_https(ip: str, timeout: int = 10) -> Optional[dict]:
    """Check if IP responds on HTTPS without a hostname."""
    try:
        url = f"https://{ip}/"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        status = resp.getcode()
        if status < 500:
            return {
                "name": "Direct IP HTTPS Access",
                "severity": "medium",
                "passed": False,
                "details": f"https://{ip}/ returned status {status} — origin server directly reachable over HTTPS",
                "finding": {
                    "type": "direct_ip_https",
                    "severity": "medium",
                    "name": "Direct IP HTTPS Access",
                    "detail": f"IP {ip} serves content on HTTPS (status {status}) — potential WAF bypass",
                },
            }
    except urllib.error.HTTPError as e:
        if e.code < 500:
            return {
                "name": "Direct IP HTTPS Access",
                "severity": "low",
                "passed": False,
                "details": f"https://{ip}/ returned status {e.code}",
                "finding": {
                    "type": "direct_ip_https",
                    "severity": "low",
                    "name": "Direct IP HTTPS Access",
                    "detail": f"IP {ip} responds on HTTPS (status {e.code})",
                },
            }
    except Exception:
        pass
    return None


# ===================================================================
# 12. PORT / SERVICE SECURITY CHECKS
# ===================================================================

_ADMIN_PORTS = {
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Unencrypted remote access"),
    3389: ("RDP", "Remote Desktop Protocol"),
    5900: ("VNC", "Virtual Network Computing"),
}

_DATABASE_PORTS = {
    3306: ("MySQL", "MySQL Database"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    27017: ("MongoDB", "MongoDB NoSQL"),
    6379: ("Redis", "Redis Key-Value Store"),
    1433: ("MSSQL", "Microsoft SQL Server"),
}


def _port_open(ip: str, port: int, timeout: int = 3) -> bool:
    """Quick TCP connect check."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, OSError):
        return False


def check_admin_ports_exposed(ip: str, timeout: int = 5) -> list:
    """Check if admin ports (SSH, RDP, VNC, Telnet) are open on the IP."""
    findings = []
    for port, (svc, desc) in _ADMIN_PORTS.items():
        if _port_open(ip, port, timeout):
            findings.append({
                "name": f"{svc} Port Exposed",
                "severity": "medium",
                "passed": False,
                "details": f"{desc} port {port} is open on {ip}",
                "finding": {
                    "type": "admin_port_exposed",
                    "severity": "medium",
                    "name": f"{svc} Port {port} Exposed",
                    "detail": f"{desc} on {ip}:{port} is publicly accessible",
                },
            })
    return findings


def check_database_ports_exposed(ip: str, timeout: int = 5) -> list:
    """Check if database ports (MySQL, Postgres, Mongo, Redis, MSSQL) are open."""
    findings = []
    for port, (svc, desc) in _DATABASE_PORTS.items():
        if _port_open(ip, port, timeout):
            sev = "high" if port != 6379 else "medium"
            findings.append({
                "name": f"{svc} Port Exposed",
                "severity": sev,
                "passed": False,
                "details": f"{desc} port {port} is open on {ip}",
                "finding": {
                    "type": "database_exposed",
                    "severity": sev,
                    "name": f"{svc} Port {port} Exposed",
                    "detail": f"{desc} on {ip}:{port} is publicly reachable — should be firewalled",
                },
            })
    return findings


def check_redis_no_auth(ip: str, port: int = 6379, timeout: int = 5) -> Optional[dict]:
    """Connect to Redis and try PING without authentication."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.send(b"PING\r\n")
        response = sock.recv(1024).decode("utf-8", errors="ignore")
        sock.close()
        if "+PONG" in response:
            return {
                "name": "Redis Without Authentication",
                "severity": "critical",
                "passed": False,
                "details": f"Redis at {ip}:{port} responds to PING without auth",
                "finding": {
                    "type": "redis_no_auth",
                    "severity": "critical",
                    "name": "Redis Without Authentication",
                    "detail": f"Redis {ip}:{port} accepts commands without authentication — full data access",
                },
            }
    except Exception:
        pass
    return None


def check_kubernetes_api_exposed(ip: str, timeout: int = 10) -> Optional[dict]:
    """Try GET on common K8s API ports (6443, 8443) for Kubernetes API."""
    k8s_ports = [6443, 8443, 443]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for port in k8s_ports:
        url = f"https://{ip}:{port}/api"
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        try:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            status = resp.getcode()
            body = resp.read(2048).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            status = e.code
            try:
                body = e.read(2048).decode("utf-8", errors="replace")
            except Exception:
                body = ""
        except Exception:
            continue

        if status in (200, 401, 403):
            body_lower = body.lower()
            if "kind" in body_lower or "kubernetes" in body_lower or "apiversion" in body_lower:
                sev = "critical" if status == 200 else "high"
                return {
                    "name": "Kubernetes API Exposed",
                    "severity": sev,
                    "passed": False,
                    "details": f"K8s API at {ip}:{port} responded with status {status}",
                    "finding": {
                        "type": "kubernetes_api_exposed",
                        "severity": sev,
                        "name": "Kubernetes API Exposed",
                        "detail": f"Kubernetes API accessible at {ip}:{port} (status {status}) — cluster control risk",
                    },
                }
    return None


def check_smtp_open_relay(ip: str, port: int = 25, timeout: int = 10) -> Optional[dict]:
    """Connect to SMTP port and test for open relay (MAIL FROM/RCPT TO external)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        banner = sock.recv(1024).decode("utf-8", errors="ignore")
        if "220" not in banner:
            sock.close()
            return None

        sock.send(b"HELO test.example.com\r\n")
        sock.recv(1024)

        sock.send(b"MAIL FROM:<test@external-domain.com>\r\n")
        resp1 = sock.recv(1024).decode("utf-8", errors="ignore")

        if "250" in resp1:
            sock.send(b"RCPT TO:<test@another-external-domain.com>\r\n")
            resp2 = sock.recv(1024).decode("utf-8", errors="ignore")

            if "250" in resp2 or "251" in resp2:
                sock.send(b"QUIT\r\n")
                sock.close()
                return {
                    "name": "SMTP Open Relay",
                    "severity": "high",
                    "passed": False,
                    "details": f"SMTP at {ip}:{port} accepts relay from external domains",
                    "finding": {
                        "type": "smtp_open_relay",
                        "severity": "high",
                        "name": "SMTP Open Relay",
                        "detail": f"SMTP {ip}:{port} relays mail for external domains — spam/spoofing abuse risk",
                    },
                }

        sock.send(b"QUIT\r\n")
        sock.close()
    except Exception:
        pass
    return None


# ===================================================================
# 13. APPLICATION SECURITY CHECKS
# ===================================================================

def check_csp_unsafe_inline(url: str, timeout: int = 10) -> Optional[dict]:
    """Parse CSP header for unsafe-inline / unsafe-eval directives."""
    headers = _get_response_headers(url, timeout=timeout)
    if not headers:
        return None
    csp = headers.get("content-security-policy", "")
    if not csp:
        return None

    issues = []
    for directive in csp.split(";"):
        directive = directive.strip()
        d_lower = directive.lower()
        if "'unsafe-inline'" in d_lower:
            dname = directive.split()[0] if directive.split() else "unknown"
            issues.append(f"unsafe-inline in {dname}")
        if "'unsafe-eval'" in d_lower:
            dname = directive.split()[0] if directive.split() else "unknown"
            issues.append(f"unsafe-eval in {dname}")

    if issues:
        return {
            "name": "CSP Allows Unsafe Inline/Eval",
            "severity": "medium",
            "passed": False,
            "details": "; ".join(issues),
            "finding": {
                "type": "csp_unsafe_inline",
                "severity": "medium",
                "name": "CSP Allows Unsafe Inline/Eval",
                "detail": f"Content-Security-Policy weakened: {'; '.join(issues)}",
            },
        }
    return None


def check_insecure_form_action(url: str, timeout: int = 10) -> list:
    """Find forms on HTTPS pages posting to HTTP endpoints."""
    findings = []
    if not url.startswith("https"):
        return findings
    resp, _ = _fetch(url, timeout=timeout, follow=True)
    if resp is None:
        return findings
    try:
        body = resp.read(100000).decode("utf-8", errors="replace")
    except Exception:
        return findings

    form_pattern = r'<form[^>]*action\s*=\s*["\']?(http://[^"\'>\s]+)["\']?'
    matches = re.findall(form_pattern, body, re.I)
    for http_action in matches:
        findings.append({
            "name": "HTTPS Form Posts to HTTP",
            "severity": "high",
            "passed": False,
            "details": f"Form on {url} submits to {http_action}",
            "finding": {
                "type": "insecure_form_action",
                "severity": "high",
                "name": "HTTPS Form Posts to HTTP",
                "detail": f"Form data sent unencrypted to {http_action}",
            },
        })
    return findings


def check_cache_control_missing(url: str, timeout: int = 10) -> Optional[dict]:
    """Check for missing Cache-Control on potentially sensitive pages."""
    headers = _get_response_headers(url, timeout=timeout)
    if not headers:
        return None

    cc = headers.get("cache-control", "")
    pragma = headers.get("pragma", "")

    # Only flag if there's no caching directive at all
    if not cc and not pragma:
        return {
            "name": "Cache-Control Missing",
            "severity": "low",
            "passed": False,
            "details": "No Cache-Control or Pragma header — sensitive content may be cached by proxies/browsers",
            "finding": {
                "type": "cache_control_missing",
                "severity": "low",
                "name": "Cache-Control Header Missing",
                "detail": "Responses may be cached by intermediaries — risk of data leakage from shared caches",
            },
        }

    # Check for explicitly insecure caching
    if cc and "no-store" not in cc.lower() and "private" not in cc.lower():
        if "public" in cc.lower():
            return {
                "name": "Cache-Control Allows Public Caching",
                "severity": "low",
                "passed": False,
                "details": f"Cache-Control: {cc} — allows public caching of responses",
                "finding": {
                    "type": "cache_control_weak",
                    "severity": "low",
                    "name": "Cache-Control Allows Public Caching",
                    "detail": f"Cache-Control: {cc} — sensitive data may be stored in shared caches",
                },
            }
    return None


def check_cors_wildcard(url: str, timeout: int = 10) -> Optional[dict]:
    """Check if Access-Control-Allow-Origin: * is set with credentials."""
    headers = _get_response_headers(url, timeout=timeout)
    if not headers:
        return None

    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")

    if acao == "*":
        if acac.lower() == "true":
            sev = "high"
            detail = "CORS allows any origin WITH credentials — critical data theft risk"
        else:
            sev = "medium"
            detail = "CORS allows any origin (wildcard) — cross-origin data readable"
        return {
            "name": "CORS Wildcard Origin",
            "severity": sev,
            "passed": False,
            "details": f"Access-Control-Allow-Origin: * (credentials: {acac or 'not set'})",
            "finding": {
                "type": "cors_wildcard",
                "severity": sev,
                "name": "CORS Wildcard Origin",
                "detail": detail,
            },
        }
    return None


# ===================================================================
# 14. RATE LIMITING CHECKS
# ===================================================================

def check_no_rate_limiting(url: str, timeout: int = 5) -> Optional[dict]:
    """Send 20 rapid requests to detect missing rate limiting."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Find auth endpoints
    auth_endpoints = [
        "/login", "/signin", "/auth", "/api/login", "/api/auth",
        "/wp-login.php", "/admin/login", "/user/login",
    ]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for endpoint in auth_endpoints:
        test_url = f"{parsed.scheme}://{hostname}{endpoint}"
        # Check if endpoint exists
        req = urllib.request.Request(test_url, headers={"User-Agent": UA})
        try:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            status = resp.getcode()
        except urllib.error.HTTPError as e:
            status = e.code
        except Exception:
            continue

        if status == 404:
            continue

        # Send 20 rapid requests
        success_count = 0
        rate_limited = False
        for i in range(20):
            data = f"username=test{i}&password=test".encode()
            req2 = urllib.request.Request(
                test_url, data=data, headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"}
            )
            try:
                resp2 = urllib.request.urlopen(req2, timeout=timeout, context=ctx)
                hdrs2 = {k.lower(): v for k, v in resp2.headers.items()}
                if resp2.getcode() == 429:
                    rate_limited = True
                    break
                if hdrs2.get("retry-after"):
                    rate_limited = True
                    break
                success_count += 1
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    rate_limited = True
                    break
                success_count += 1
            except Exception:
                break

        if success_count >= 20 and not rate_limited:
            return {
                "name": "No Rate Limiting on Login",
                "severity": "medium",
                "passed": False,
                "details": f"Sent 20 requests to {endpoint} without triggering rate limit",
                "finding": {
                    "type": "no_rate_limiting",
                    "severity": "medium",
                    "name": "No Rate Limiting on Login",
                    "detail": f"Endpoint {test_url} accepts unlimited login attempts — brute force risk",
                },
            }

    return None


def check_no_account_lockout(url: str, timeout: int = 5) -> Optional[dict]:
    """Send 10 bad login attempts and check for lockout response."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    auth_endpoints = ["/login", "/signin", "/api/login", "/wp-login.php"]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for endpoint in auth_endpoints:
        test_url = f"{parsed.scheme}://{hostname}{endpoint}"
        req = urllib.request.Request(test_url, headers={"User-Agent": UA})
        try:
            urllib.request.urlopen(req, timeout=timeout, context=ctx)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
        except Exception:
            continue

        lockout_detected = False
        for i in range(10):
            data = f"username=admin&password=wrongpassword{i}".encode()
            req2 = urllib.request.Request(
                test_url, data=data, headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"}
            )
            try:
                resp2 = urllib.request.urlopen(req2, timeout=timeout, context=ctx)
                body = resp2.read(5000).decode("utf-8", errors="replace").lower()
                if "locked" in body or "too many" in body or "temporarily" in body:
                    lockout_detected = True
                    break
            except urllib.error.HTTPError as e:
                if e.code == 429 or e.code == 423:
                    lockout_detected = True
                    break
                try:
                    body = e.read(5000).decode("utf-8", errors="replace").lower()
                    if "locked" in body or "too many" in body:
                        lockout_detected = True
                        break
                except Exception:
                    pass
            except Exception:
                break

        if not lockout_detected:
            return {
                "name": "No Account Lockout",
                "severity": "medium",
                "passed": False,
                "details": f"10 failed logins to {endpoint} without lockout",
                "finding": {
                    "type": "no_account_lockout",
                    "severity": "medium",
                    "name": "No Account Lockout",
                    "detail": f"Endpoint {test_url} does not lock accounts after failed attempts",
                },
            }

    return None


# ===================================================================
# 15. ADDITIONAL HEADER CHECKS
# ===================================================================

def check_x_frame_options_missing(url: str, timeout: int = 10) -> Optional[dict]:
    """Verify X-Frame-Options header is present."""
    headers = _get_response_headers(url, timeout=timeout)
    if not headers:
        return None
    if not headers.get("x-frame-options"):
        return {
            "name": "X-Frame-Options Missing",
            "severity": "medium",
            "passed": False,
            "details": "No X-Frame-Options header — clickjacking risk",
            "finding": {
                "type": "x_frame_options_missing",
                "severity": "medium",
                "name": "X-Frame-Options Missing",
                "detail": "Page can be embedded in iframes — clickjacking attacks possible",
            },
        }
    return None


def check_hsts_missing(url: str, timeout: int = 10) -> Optional[dict]:
    """Verify Strict-Transport-Security header is present."""
    if not url.startswith("https"):
        return None
    headers = _get_response_headers(url, timeout=timeout)
    if not headers:
        return None
    if not headers.get("strict-transport-security"):
        return {
            "name": "HSTS Missing",
            "severity": "medium",
            "passed": False,
            "details": "No Strict-Transport-Security header — SSL stripping risk",
            "finding": {
                "type": "hsts_missing",
                "severity": "medium",
                "name": "HSTS Missing",
                "detail": "HTTPS site without HSTS — vulnerable to protocol downgrade attacks",
            },
        }
    return None


def check_server_version_leak(url: str, timeout: int = 10) -> Optional[dict]:
    """Check Server and X-Powered-By headers for version information."""
    headers = _get_response_headers(url, timeout=timeout)
    if not headers:
        return None

    leaks = []
    server = headers.get("server", "")
    if server and re.search(r"[\d]+\.[\d]+", server):
        leaks.append(f"Server: {server}")
    powered = headers.get("x-powered-by", "")
    if powered:
        leaks.append(f"X-Powered-By: {powered}")
    aspnet = headers.get("x-aspnet-version", "")
    if aspnet:
        leaks.append(f"X-AspNet-Version: {aspnet}")

    if leaks:
        return {
            "name": "Server Version Leak",
            "severity": "low",
            "passed": False,
            "details": "; ".join(leaks),
            "finding": {
                "type": "server_version_leak",
                "severity": "low",
                "name": "Server Version Information Disclosed",
                "detail": f"Version info leaked: {'; '.join(leaks)} — aids attacker fingerprinting",
            },
        }
    return None


# ===================================================================
# 16. CATEGORY ORCHESTRATORS
# ===================================================================

def run_dns_checks(domain: str, timeout: int = 10) -> List[dict]:
    """Run all DNS security checks and return findings list."""
    findings = []
    for check_fn in (check_spf_missing, check_dmarc_missing, check_dnssec_missing):
        try:
            result = check_fn(domain)
            if result and not result.get("passed", True):
                findings.append(result["finding"])
        except Exception as exc:
            logger.debug("DNS check %s failed: %s", check_fn.__name__, exc)

    try:
        result = check_zone_transfer(domain, timeout=timeout)
        if result and not result.get("passed", True):
            findings.append(result["finding"])
    except Exception as exc:
        logger.debug("Zone transfer check failed: %s", exc)

    return findings


def run_auth_checks(url: str, timeout: int = 10) -> List[dict]:
    """Run all authentication security checks and return findings list."""
    findings = []
    for check_fn in (check_login_no_https, check_basic_auth_no_tls, check_session_cookies):
        try:
            result = check_fn(url, timeout=timeout)
            if result and not result.get("passed", True):
                findings.append(result["finding"])
        except Exception as exc:
            logger.debug("Auth check %s failed: %s", check_fn.__name__, exc)
    return findings


def run_port_service_checks(ip: str, timeout: int = 5) -> List[dict]:
    """Run all port/service security checks and return findings list."""
    findings = []

    # Admin ports
    try:
        for r in check_admin_ports_exposed(ip, timeout=timeout):
            if not r.get("passed", True):
                findings.append(r["finding"])
    except Exception as exc:
        logger.debug("Admin port check failed: %s", exc)

    # Database ports
    try:
        for r in check_database_ports_exposed(ip, timeout=timeout):
            if not r.get("passed", True):
                findings.append(r["finding"])
    except Exception as exc:
        logger.debug("Database port check failed: %s", exc)

    # Redis no-auth (only if port open)
    if _port_open(ip, 6379, timeout=timeout):
        try:
            result = check_redis_no_auth(ip, timeout=timeout)
            if result and not result.get("passed", True):
                findings.append(result["finding"])
        except Exception as exc:
            logger.debug("Redis check failed: %s", exc)

    # Kubernetes API
    try:
        result = check_kubernetes_api_exposed(ip, timeout=timeout)
        if result and not result.get("passed", True):
            findings.append(result["finding"])
    except Exception as exc:
        logger.debug("K8s API check failed: %s", exc)

    # SMTP open relay
    if _port_open(ip, 25, timeout=timeout):
        try:
            result = check_smtp_open_relay(ip, timeout=timeout)
            if result and not result.get("passed", True):
                findings.append(result["finding"])
        except Exception as exc:
            logger.debug("SMTP relay check failed: %s", exc)

    return findings


def run_app_security_checks(url: str, timeout: int = 10) -> List[dict]:
    """Run all application security checks and return findings list."""
    findings = []
    for check_fn in (check_csp_unsafe_inline, check_cache_control_missing, check_cors_wildcard,
                     check_x_frame_options_missing, check_hsts_missing, check_server_version_leak):
        try:
            result = check_fn(url, timeout=timeout)
            if result and not result.get("passed", True):
                findings.append(result["finding"])
        except Exception as exc:
            logger.debug("App check %s failed: %s", check_fn.__name__, exc)

    # Insecure form action returns a list
    try:
        for r in check_insecure_form_action(url, timeout=timeout):
            if not r.get("passed", True):
                findings.append(r["finding"])
    except Exception as exc:
        logger.debug("Insecure form action check failed: %s", exc)

    return findings


# ===================================================================
# MAIN ORCHESTRATOR
# ===================================================================

def run_security_checks(url: str, timeout: int = 12) -> SecurityCheckResult:
    """
    Run all security checks against a URL (synchronous).

    Args:
        url: Target URL (should start with http:// or https://)
        timeout: Request timeout in seconds

    Returns:
        SecurityCheckResult with all findings
    """
    result = SecurityCheckResult(url=url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    is_https = parsed.scheme == "https"

    # --- Fetch response for analysis ---
    resp, cj = _fetch(url, timeout=timeout, follow=True)
    headers: Dict[str, str] = {}
    body = ""
    if resp and not isinstance(resp, _RedirectCaught):
        raw = getattr(resp, "headers", {})
        if hasattr(raw, "items"):
            headers = {k.lower(): v for k, v in raw.items()}
        try:
            body = resp.read().decode("utf-8", errors="replace")[:50000]
        except Exception:
            pass

    # 1. Security headers
    if headers:
        score, missing, weak, h_findings = check_security_headers(headers)
        result.headers_score = score
        result.missing_headers = missing
        result.weak_headers = weak
        result.findings.extend(h_findings)

    # 2. TLS
    if is_https and hostname:
        port = parsed.port or 443
        tls_info, tls_findings = check_tls(hostname, port=port, timeout=timeout)
        result.tls_info = tls_info
        result.findings.extend(tls_findings)
    elif not is_https:
        result.findings.append({
            "type": "no_tls",
            "severity": "high",
            "name": "No TLS Encryption",
            "detail": f"URL uses plain HTTP — all traffic is unencrypted",
        })

    # 3. Cookies
    cookie_list, cookie_findings = check_cookies(url, timeout=timeout)
    result.cookies = cookie_list
    result.findings.extend(cookie_findings)

    # 4. WAF
    waf_name, waf_findings = detect_waf(headers, cookie_list, body)
    result.waf_detected = waf_name
    result.findings.extend(waf_findings)

    # 5. Redirects
    redirect_chain, redir_findings = analyze_redirects(url, timeout=timeout)
    result.redirect_chain = redirect_chain
    result.findings.extend(redir_findings)

    # 6. Info disclosure
    disclosure_findings = check_info_disclosure(headers, body)
    result.info_disclosure = disclosure_findings
    result.findings.extend(disclosure_findings)

    # 7 & 8. Direct-IP API exposure + WAF bypass (when IP resolvable)
    try:
        resolved_ip = socket.gethostbyname(hostname) if hostname else None
    except (socket.gaierror, OSError):
        resolved_ip = None

    if resolved_ip and resolved_ip != hostname:
        # 7. IP API exposure
        try:
            api_result = check_ip_api_exposed(resolved_ip, port=parsed.port or 443, timeout=timeout)
            for api_hit in api_result.get("exposed_apis", []):
                result.findings.append({
                    "type": "ip_api_exposed",
                    "severity": "high",
                    "name": f"API Endpoint Exposed on IP ({api_hit['path']})",
                    "detail": (
                        f"Direct IP {resolved_ip} exposes {api_hit['path']} "
                        f"via {api_hit['scheme'].upper()} (status {api_hit['status']}, "
                        f"content-type: {api_hit['content_type']})"
                    ),
                })
        except Exception as exc:
            logger.debug("IP API check failed: %s", exc)

        # 8. WAF bypass
        try:
            waf_result = check_waf_bypass(hostname, resolved_ip, timeout=timeout)
            if waf_result.get("bypass_found"):
                result.findings.append({
                    "type": "waf_bypass",
                    "severity": "high",
                    "name": "WAF Bypass via Direct IP Access",
                    "detail": (
                        f"WAF bypass confirmed for {hostname} → {resolved_ip}. "
                        f"Method: {waf_result['method']}. {waf_result['evidence']}"
                    ),
                })
        except Exception as exc:
            logger.debug("WAF bypass check failed: %s", exc)

        # 9. Direct IP HTTP/HTTPS access checks
        try:
            ip_http = check_direct_ip_http(resolved_ip, timeout=timeout)
            if ip_http and not ip_http.get("passed", True):
                result.findings.append(ip_http["finding"])
        except Exception as exc:
            logger.debug("Direct IP HTTP check failed: %s", exc)

        try:
            ip_https = check_direct_ip_https(resolved_ip, timeout=timeout)
            if ip_https and not ip_https.get("passed", True):
                result.findings.append(ip_https["finding"])
        except Exception as exc:
            logger.debug("Direct IP HTTPS check failed: %s", exc)

        # 10. Port/service security checks
        try:
            port_findings = run_port_service_checks(resolved_ip, timeout=timeout)
            result.findings.extend(port_findings)
        except Exception as exc:
            logger.debug("Port/service checks failed: %s", exc)

    # 11. DNS security checks
    if hostname:
        # Extract base domain for DNS checks
        domain_parts = hostname.split(".")
        base_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname
        try:
            dns_findings = run_dns_checks(base_domain, timeout=timeout)
            result.findings.extend(dns_findings)
        except Exception as exc:
            logger.debug("DNS checks failed: %s", exc)

    # 12. Authentication security checks
    try:
        auth_findings = run_auth_checks(url, timeout=timeout)
        result.findings.extend(auth_findings)
    except Exception as exc:
        logger.debug("Auth checks failed: %s", exc)

    # 13. Application security checks
    try:
        app_findings = run_app_security_checks(url, timeout=timeout)
        result.findings.extend(app_findings)
    except Exception as exc:
        logger.debug("App security checks failed: %s", exc)

    # 14. Rate limiting checks
    try:
        rate_result = check_no_rate_limiting(url, timeout=timeout)
        if rate_result and not rate_result.get("passed", True):
            result.findings.append(rate_result["finding"])
    except Exception as exc:
        logger.debug("Rate limiting check failed: %s", exc)

    try:
        lockout_result = check_no_account_lockout(url, timeout=timeout)
        if lockout_result and not lockout_result.get("passed", True):
            result.findings.append(lockout_result["finding"])
    except Exception as exc:
        logger.debug("Account lockout check failed: %s", exc)

    return result


async def run_security_checks_async(url: str, timeout: int = 12) -> SecurityCheckResult:
    """Async wrapper — runs blocking checks in a thread."""
    return await asyncio.to_thread(run_security_checks, url, timeout)


# ===================================================================
# CLI entry point (standalone testing)
# ===================================================================

if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(f"[*] Running security checks on {target}\n")

    res = run_security_checks(target)

    print(f"  Headers Score : {res.headers_score}/100")
    print(f"  Missing Headers: {', '.join(res.missing_headers) or 'None'}")
    print(f"  WAF Detected  : {res.waf_detected or 'None'}")
    print(f"  Redirect Chain: {' -> '.join(res.redirect_chain)}")
    print(f"  TLS Protocol  : {res.tls_info.get('protocol', 'N/A')}")
    print(f"  Cert Valid    : {res.tls_info.get('cert_valid', 'N/A')}")
    print(f"  Cert Expires  : {res.tls_info.get('expires', 'N/A')} ({res.tls_info.get('days_until_expiry', '?')} days)")
    print(f"  Cookies       : {len(res.cookies)}")
    print(f"\n  Findings ({len(res.findings)}):")
    for f in res.findings:
        print(f"    [{f['severity'].upper():8s}] {f['name']}: {f['detail'][:100]}")

    sev = res.severity_summary
    print(f"\n  Summary: {sev}")
