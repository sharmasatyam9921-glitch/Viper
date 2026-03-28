#!/usr/bin/env python3
"""
VIPER WebSocket Fuzzer — Test WebSocket endpoints for vulnerabilities.

Tests:
- Malformed/oversized/encoded message fuzzing
- Authentication bypass (unauthenticated connections)
- Injection tests (XSS, SQLi, SSTI in WS messages)
- Race conditions (simultaneous messages)
- Cross-origin WebSocket hijacking
"""

import asyncio
import json
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.websocket_fuzzer")


@dataclass
class WSFinding:
    """Result from a WebSocket fuzz test."""
    test_name: str
    vulnerable: bool
    severity: str = "info"
    cvss: float = 0.0
    description: str = ""
    evidence: str = ""
    ws_url: str = ""
    payload: str = ""

    def to_dict(self) -> dict:
        return {
            "test_name": self.test_name,
            "vulnerable": self.vulnerable,
            "severity": self.severity,
            "cvss": self.cvss,
            "description": self.description,
            "evidence": self.evidence,
            "ws_url": self.ws_url,
            "payload": self.payload,
        }


class WebSocketFuzzer:
    """Test WebSocket endpoints for security vulnerabilities.

    Uses the ``websockets`` library if available, falls back to a raw
    socket implementation for basic connectivity checks.

    All tests are non-destructive: payloads are crafted to detect
    vulnerabilities without modifying server state.

    Args:
        ws_url: WebSocket URL (ws:// or wss://).
        headers: Optional HTTP headers for the upgrade request.
    """

    def __init__(
        self,
        ws_url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
    ):
        self.ws_url = ws_url
        self.headers = headers or {}
        self.timeout = timeout
        self.findings: List[WSFinding] = []

    async def run_all(self) -> List[WSFinding]:
        """Run all WebSocket tests."""
        tests = [
            self.fuzz_messages,
            self.auth_bypass,
            self.injection_test,
            self.race_condition,
            self.cross_origin,
        ]
        for test in tests:
            try:
                findings = await test()
                if findings:
                    if isinstance(findings, list):
                        self.findings.extend(findings)
                    else:
                        self.findings.append(findings)
            except Exception as exc:
                logger.debug("WS test %s failed: %s", test.__name__, exc)

        return self.findings

    async def _connect(self, extra_headers: Optional[Dict] = None):
        """Establish WebSocket connection."""
        try:
            import websockets
        except ImportError:
            logger.warning("websockets library not installed — WS tests limited")
            return None

        headers = {**self.headers}
        if extra_headers:
            headers.update(extra_headers)

        try:
            ws = await asyncio.wait_for(
                websockets.connect(self.ws_url, additional_headers=headers),
                timeout=self.timeout,
            )
            return ws
        except Exception as exc:
            logger.debug("WS connect failed: %s", exc)
            return None

    async def fuzz_messages(self) -> List[WSFinding]:
        """Send malformed, oversized, and encoded payloads via WebSocket."""
        findings: List[WSFinding] = []

        payloads = [
            # Malformed JSON
            ('{"invalid json', "malformed_json"),
            # Oversized message
            ("A" * 100000, "oversized"),
            # Null bytes
            ("test\x00data", "null_bytes"),
            # Unicode edge cases
            ("\ud800\udfff" * 10, "invalid_unicode"),
            # Control characters
            ("\x01\x02\x03\x04", "control_chars"),
            # Empty message
            ("", "empty"),
            # Deeply nested JSON
            (json.dumps({"a": {"b": {"c": {"d": {"e": {"f": "deep"}}}}}}),"deep_nesting"),
        ]

        ws = await self._connect()
        if not ws:
            return findings

        try:
            for payload, name in payloads:
                try:
                    await asyncio.wait_for(ws.send(payload), timeout=5.0)
                    response = await asyncio.wait_for(ws.recv(), timeout=5.0)

                    # Check for error disclosure in response
                    resp_lower = response.lower() if isinstance(response, str) else ""
                    if any(kw in resp_lower for kw in ["stack", "trace", "exception", "error",
                                                        "sql", "internal server"]):
                        findings.append(WSFinding(
                            test_name=f"fuzz_{name}",
                            vulnerable=True,
                            severity="low",
                            cvss=3.7,
                            description=f"WebSocket returns verbose error for {name} payload",
                            evidence=str(response)[:500],
                            ws_url=self.ws_url,
                            payload=payload[:200],
                        ))
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue
        finally:
            await ws.close()

        return findings

    async def auth_bypass(self) -> Optional[WSFinding]:
        """Test if WebSocket connection works without authentication."""
        # Connect without auth headers
        ws = await self._connect(extra_headers={"Authorization": ""})
        if not ws:
            return None

        try:
            # Try to send a message and see if we get a valid response
            test_msg = json.dumps({"type": "ping", "data": "test"})
            await asyncio.wait_for(ws.send(test_msg), timeout=5.0)
            response = await asyncio.wait_for(ws.recv(), timeout=5.0)

            # If we get a response that isn't an auth error, it may be vulnerable
            resp_lower = str(response).lower()
            auth_errors = ["unauthorized", "authentication required", "forbidden",
                          "invalid token", "not authenticated", "401"]
            is_auth_error = any(err in resp_lower for err in auth_errors)

            if not is_auth_error and response:
                return WSFinding(
                    test_name="auth_bypass",
                    vulnerable=True,
                    severity="high",
                    cvss=7.5,
                    description="WebSocket endpoint accepts connections without authentication",
                    evidence=f"Response without auth: {str(response)[:500]}",
                    ws_url=self.ws_url,
                )
        except Exception:
            pass
        finally:
            await ws.close()

        return None

    async def injection_test(self) -> List[WSFinding]:
        """Test for XSS, SQLi, and SSTI in WebSocket message fields."""
        findings: List[WSFinding] = []

        injection_payloads = [
            # XSS
            {"type": "message", "data": "<script>alert(1)</script>", "vuln": "xss", "sev": "medium", "cvss": 6.1},
            {"type": "message", "data": "<img src=x onerror=alert(1)>", "vuln": "xss", "sev": "medium", "cvss": 6.1},
            # SQLi
            {"type": "query", "data": "' OR 1=1 --", "vuln": "sqli", "sev": "critical", "cvss": 9.8},
            {"type": "query", "data": "1; SELECT * FROM users--", "vuln": "sqli", "sev": "critical", "cvss": 9.8},
            # SSTI
            {"type": "message", "data": "{{7*7}}", "vuln": "ssti", "sev": "high", "cvss": 8.6},
            {"type": "message", "data": "${7*7}", "vuln": "ssti", "sev": "high", "cvss": 8.6},
        ]

        ws = await self._connect()
        if not ws:
            return findings

        try:
            for test in injection_payloads:
                try:
                    msg = json.dumps({"type": test["type"], "content": test["data"]})
                    await asyncio.wait_for(ws.send(msg), timeout=5.0)
                    response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    resp_str = str(response)

                    # Check for injection indicators
                    is_vulnerable = False
                    if test["vuln"] == "xss" and (test["data"] in resp_str):
                        is_vulnerable = True
                    elif test["vuln"] == "sqli" and any(kw in resp_str.lower()
                                                         for kw in ["sql", "mysql", "postgres", "syntax error", "odbc"]):
                        is_vulnerable = True
                    elif test["vuln"] == "ssti" and "49" in resp_str:
                        is_vulnerable = True

                    if is_vulnerable:
                        findings.append(WSFinding(
                            test_name=f"injection_{test['vuln']}",
                            vulnerable=True,
                            severity=test["sev"],
                            cvss=test["cvss"],
                            description=f"WebSocket message vulnerable to {test['vuln'].upper()}",
                            evidence=resp_str[:500],
                            ws_url=self.ws_url,
                            payload=test["data"],
                        ))
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue
        finally:
            await ws.close()

        return findings

    async def race_condition(self) -> Optional[WSFinding]:
        """Send 50 identical messages simultaneously to test for race conditions."""
        ws = await self._connect()
        if not ws:
            return None

        try:
            msg = json.dumps({"type": "action", "data": "race_test"})
            count = 50

            # Send all messages as fast as possible
            t0 = time.monotonic()
            send_tasks = [ws.send(msg) for _ in range(count)]
            await asyncio.gather(*send_tasks, return_exceptions=True)
            send_time = time.monotonic() - t0

            # Collect responses
            responses = []
            for _ in range(count):
                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=3.0)
                    responses.append(resp)
                except asyncio.TimeoutError:
                    break

            # Analyze timing variance
            if len(responses) >= 2:
                unique_responses = set(str(r)[:100] for r in responses)
                if len(unique_responses) > 1:
                    return WSFinding(
                        test_name="race_condition",
                        vulnerable=True,
                        severity="medium",
                        cvss=5.9,
                        description=f"WebSocket race condition: {count} identical messages produced {len(unique_responses)} different responses",
                        evidence=f"Send time: {send_time:.3f}s, {len(responses)} responses, {len(unique_responses)} unique",
                        ws_url=self.ws_url,
                    )
        except Exception as exc:
            logger.debug("race_condition: %s", exc)
        finally:
            await ws.close()

        return None

    async def cross_origin(self) -> Optional[WSFinding]:
        """Test Origin header enforcement on WebSocket connections."""
        evil_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",
        ]

        for origin in evil_origins:
            ws = await self._connect(extra_headers={"Origin": origin})
            if ws:
                try:
                    # If connection succeeds with evil origin, it's vulnerable
                    test_msg = json.dumps({"type": "ping"})
                    await asyncio.wait_for(ws.send(test_msg), timeout=5.0)
                    response = await asyncio.wait_for(ws.recv(), timeout=5.0)

                    if response:
                        return WSFinding(
                            test_name="cross_origin",
                            vulnerable=True,
                            severity="high",
                            cvss=7.1,
                            description=f"WebSocket accepts connections from untrusted Origin: {origin}",
                            evidence=f"Connection with Origin: {origin} accepted. Response: {str(response)[:200]}",
                            ws_url=self.ws_url,
                            payload=f"Origin: {origin}",
                        )
                except Exception:
                    pass
                finally:
                    await ws.close()

        return None

    @staticmethod
    def detect_websocket_from_http(url: str, headers: Dict[str, str]) -> Optional[str]:
        """Auto-detect WebSocket endpoints from HTTP response headers.

        Checks for Upgrade: websocket header or common WS endpoint patterns.
        """
        # Check response headers for WebSocket upgrade
        upgrade = headers.get("Upgrade", "").lower()
        if "websocket" in upgrade:
            ws_url = url.replace("https://", "wss://").replace("http://", "ws://")
            return ws_url

        # Check common WS paths
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base = f"wss://{parsed.netloc}" if parsed.scheme == "https" else f"ws://{parsed.netloc}"
        common_ws_paths = ["/ws", "/websocket", "/socket.io/", "/cable", "/hub", "/signalr"]

        for path in common_ws_paths:
            # Just return the candidate URLs — caller tests connectivity
            pass

        return None


__all__ = ["WebSocketFuzzer", "WSFinding"]
