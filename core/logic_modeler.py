#!/usr/bin/env python3
"""
VIPER Logic Modeler — Business logic flaw detection.

Maps application flows, identifies state transitions, and tests
for step-skipping, price manipulation, and privilege escalation.
"""

import asyncio
import json
import logging
import re
import ssl
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("viper.logic_modeler")


@dataclass
class AppFlow:
    """A mapped application flow (e.g., checkout, registration)."""
    name: str
    steps: List[dict] = field(default_factory=list)
    entry_url: str = ""
    final_url: str = ""
    requires_auth: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "steps": self.steps,
            "entry_url": self.entry_url,
            "final_url": self.final_url,
            "requires_auth": self.requires_auth,
        }


@dataclass
class LogicFinding:
    """Result from a business logic test."""
    test_name: str
    vulnerable: bool
    severity: str = "info"
    cvss: float = 0.0
    description: str = ""
    evidence: str = ""
    endpoint: str = ""
    payload: str = ""
    flow_name: str = ""

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
            "flow_name": self.flow_name,
        }


class LogicModeler:
    """Model and test application business logic for flaws.

    Crawls user journeys, identifies multi-step flows, and tests for
    common logic bugs: step skipping, parameter manipulation,
    price tampering, and privilege escalation.

    All tests are non-destructive: they observe server behavior
    without completing malicious transactions.

    Args:
        base_url: Base URL of the target application.
        session: Optional authenticated session cookies/headers.
    """

    def __init__(
        self,
        base_url: str,
        session: Optional[Dict[str, str]] = None,
        timeout: float = 15.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = session or {}
        self.timeout = timeout
        self._ssl_ctx = ssl.create_default_context()
        self.flows: List[AppFlow] = []
        self.findings: List[LogicFinding] = []

    async def run_all(self) -> List[LogicFinding]:
        """Run all logic modeling tests."""
        # First, map application flows
        await self.map_app_flows()

        # Then run tests
        tests = [
            self.test_step_skip,
            self.test_price_manipulation,
            self.test_privilege_escalation,
        ]
        for test in tests:
            try:
                result = await test()
                if isinstance(result, list):
                    self.findings.extend(result)
                elif result:
                    self.findings.append(result)
            except Exception as exc:
                logger.debug("Logic test %s failed: %s", test.__name__, exc)

        # Generate hypotheses
        hypotheses = await self.generate_logic_hypotheses()
        self.findings.extend(hypotheses)

        return self.findings

    async def _request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, Dict[str, str]]:
        """Make HTTP request with session context."""
        hdrs = {"User-Agent": "VIPER-LogicModeler/1.0"}
        hdrs.update(self.session)
        if headers:
            hdrs.update(headers)
        if data and "Content-Type" not in hdrs:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"

        req = urllib.request.Request(
            url,
            data=data.encode() if data else None,
            method=method,
            headers=hdrs,
        )

        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx),
            )
            body = resp.read().decode("utf-8", errors="replace")[:10000]
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, body, resp_headers
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:5000] if e.fp else ""
            return e.code, body, {}
        except Exception as exc:
            return 0, str(exc), {}

    async def map_app_flows(self) -> List[AppFlow]:
        """Crawl and map common user journeys.

        Identifies multi-step flows by looking for form actions,
        redirect chains, and common flow patterns.
        """
        # Common application flows to probe
        flow_patterns = [
            {
                "name": "registration",
                "paths": ["/register", "/signup", "/api/register", "/api/v1/register"],
                "methods": ["GET", "POST"],
            },
            {
                "name": "login",
                "paths": ["/login", "/signin", "/api/login", "/api/auth/login"],
                "methods": ["GET", "POST"],
            },
            {
                "name": "checkout",
                "paths": ["/checkout", "/cart/checkout", "/api/checkout", "/payment"],
                "methods": ["GET", "POST"],
            },
            {
                "name": "password_reset",
                "paths": ["/forgot-password", "/reset-password", "/api/password/reset"],
                "methods": ["GET", "POST"],
            },
            {
                "name": "profile",
                "paths": ["/profile", "/account", "/settings", "/api/user/profile"],
                "methods": ["GET"],
            },
        ]

        for pattern in flow_patterns:
            flow = AppFlow(name=pattern["name"])
            for path in pattern["paths"]:
                url = f"{self.base_url}{path}"
                status, body, headers = await self._request(url)

                if status in (200, 302, 301):
                    step = {
                        "url": url,
                        "status": status,
                        "method": "GET",
                        "has_form": "<form" in body.lower(),
                        "has_csrf": "csrf" in body.lower() or "_token" in body.lower(),
                    }
                    flow.steps.append(step)
                    if not flow.entry_url:
                        flow.entry_url = url

                    # Extract form actions as next steps
                    form_actions = re.findall(r'action=["\']([^"\']+)["\']', body)
                    for action in form_actions[:3]:
                        if action.startswith("/"):
                            action = f"{self.base_url}{action}"
                        flow.steps.append({
                            "url": action,
                            "status": None,
                            "method": "POST",
                            "has_form": False,
                            "has_csrf": False,
                        })

            if flow.steps:
                self.flows.append(flow)

        logger.info("Mapped %d application flows", len(self.flows))
        return self.flows

    async def identify_state_transitions(self) -> List[dict]:
        """Identify state transition points in mapped flows.

        Looks for: form submissions, AJAX endpoints, redirect chains,
        and parameter-based state changes.
        """
        transitions = []
        for flow in self.flows:
            for i, step in enumerate(flow.steps):
                if step.get("method") == "POST" or step.get("has_form"):
                    transitions.append({
                        "flow": flow.name,
                        "step_index": i,
                        "url": step["url"],
                        "type": "form_submit" if step.get("has_form") else "api_call",
                        "has_csrf": step.get("has_csrf", False),
                    })
        return transitions

    async def test_step_skip(self) -> List[LogicFinding]:
        """Test step-skipping in multi-step flows.

        For each flow with 2+ steps, try accessing the final step
        directly without completing intermediate steps.
        """
        findings: List[LogicFinding] = []

        for flow in self.flows:
            if len(flow.steps) < 2:
                continue

            # Try to access later steps directly
            for i in range(1, len(flow.steps)):
                step = flow.steps[i]
                url = step["url"]
                method = step.get("method", "GET")

                status, body, _ = await self._request(url, method=method)

                # If we can access a later step without completing prior steps
                if status == 200 and not any(kw in body.lower()
                                              for kw in ["login", "redirect", "unauthorized", "forbidden",
                                                        "please complete", "previous step"]):
                    findings.append(LogicFinding(
                        test_name="step_skip",
                        vulnerable=True,
                        severity="medium",
                        cvss=5.4,
                        description=f"Step {i+1} of '{flow.name}' flow accessible without completing prior steps",
                        evidence=f"Direct access to step {i+1} ({url}) returned status {status}",
                        endpoint=url,
                        flow_name=flow.name,
                    ))

        return findings

    async def test_price_manipulation(self) -> List[LogicFinding]:
        """Test for price/quantity manipulation in checkout flows."""
        findings: List[LogicFinding] = []

        # Look for checkout-related flows
        checkout_flows = [f for f in self.flows if f.name in ("checkout", "payment")]

        for flow in checkout_flows:
            for step in flow.steps:
                if step.get("method") != "POST":
                    continue

                url = step["url"]

                # Test negative quantities
                test_payloads = [
                    {"name": "negative_quantity", "data": "quantity=-1&price=100", "sev": "high", "cvss": 8.1},
                    {"name": "zero_price", "data": "quantity=1&price=0", "sev": "high", "cvss": 8.1},
                    {"name": "integer_overflow", "data": "quantity=999999999&price=1", "sev": "medium", "cvss": 5.4},
                    {"name": "float_precision", "data": "quantity=1&price=0.001", "sev": "medium", "cvss": 5.4},
                ]

                for test in test_payloads:
                    status, body, _ = await self._request(url, method="POST", data=test["data"])

                    if status == 200 and not any(kw in body.lower()
                                                  for kw in ["invalid", "error", "negative", "not allowed"]):
                        findings.append(LogicFinding(
                            test_name=f"price_manipulation_{test['name']}",
                            vulnerable=True,
                            severity=test["sev"],
                            cvss=test["cvss"],
                            description=f"Price manipulation via {test['name']} accepted",
                            evidence=f"POST to {url} with {test['data']} returned status {status}",
                            endpoint=url,
                            payload=test["data"],
                            flow_name=flow.name,
                        ))

        return findings

    async def test_privilege_escalation(self) -> List[LogicFinding]:
        """Test for horizontal/vertical privilege escalation via parameters.

        Checks if adding role/admin/tier parameters to requests
        is accepted by the server.
        """
        findings: List[LogicFinding] = []

        # Common escalation parameters
        escalation_params = [
            ("role", "admin"),
            ("is_admin", "true"),
            ("admin", "1"),
            ("tier", "premium"),
            ("access_level", "9"),
            ("group", "administrators"),
        ]

        # Test against profile and settings endpoints
        target_flows = [f for f in self.flows if f.name in ("profile", "registration")]

        for flow in target_flows:
            for step in flow.steps:
                url = step["url"]

                for param, value in escalation_params:
                    # Add param to URL query string
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param}={value}"

                    status, body, _ = await self._request(test_url)

                    # Check if the parameter was reflected or accepted
                    if status == 200 and (value in body or param in body):
                        findings.append(LogicFinding(
                            test_name="privilege_escalation",
                            vulnerable=True,
                            severity="high",
                            cvss=8.8,
                            description=f"Privilege escalation parameter '{param}={value}' reflected/accepted",
                            evidence=f"GET {test_url} returned status {status}, parameter reflected in response",
                            endpoint=url,
                            payload=f"{param}={value}",
                            flow_name=flow.name,
                        ))
                        break  # One finding per endpoint is enough

        return findings

    async def generate_logic_hypotheses(self) -> List[LogicFinding]:
        """Generate hypotheses about potential business logic flaws.

        Analyzes mapped flows and generates informational findings about
        areas that warrant manual investigation.
        """
        hypotheses: List[LogicFinding] = []

        for flow in self.flows:
            # Check for missing CSRF protection
            unprotected = [s for s in flow.steps if s.get("method") == "POST" and not s.get("has_csrf")]
            if unprotected:
                hypotheses.append(LogicFinding(
                    test_name="logic_hypothesis_csrf",
                    vulnerable=False,
                    severity="info",
                    description=f"Flow '{flow.name}' has {len(unprotected)} POST endpoints without visible CSRF protection",
                    evidence=f"Endpoints: {', '.join(s['url'] for s in unprotected[:3])}",
                    flow_name=flow.name,
                ))

            # Single-step sensitive flows
            if flow.name in ("checkout", "password_reset") and len(flow.steps) == 1:
                hypotheses.append(LogicFinding(
                    test_name="logic_hypothesis_single_step",
                    vulnerable=False,
                    severity="info",
                    description=f"Sensitive flow '{flow.name}' appears to be single-step — investigate for missing validation",
                    evidence=f"Only 1 step detected for {flow.name}",
                    flow_name=flow.name,
                ))

        return hypotheses


__all__ = ["LogicModeler", "LogicFinding", "AppFlow"]
