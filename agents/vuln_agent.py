#!/usr/bin/env python3
"""
VIPER Vuln Agent — Subscribes to 'vuln' topic on the agent bus.

Responsibilities:
- Hypothesis generation using Tree-of-Thought
- Pattern matching against attack database
- Initial probing and signal detection
- Publishes confirmed candidates to 'exploit' topic
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.agents.vuln")


@dataclass
class Hypothesis:
    """A vulnerability hypothesis to test."""
    vuln_type: str
    confidence: float  # 0.0 - 1.0
    reasoning: str
    target_url: str
    parameters: List[str] = field(default_factory=list)
    attack_pattern: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "target_url": self.target_url,
            "parameters": self.parameters,
            "attack_pattern": self.attack_pattern,
            "evidence": self.evidence,
        }


class VulnAgent:
    """Vulnerability analysis agent using Tree-of-Thought reasoning.

    Subscribes to ``vuln`` topic. For each asset, generates top-5 hypothesis
    branches, tests lightweight signals, and publishes confirmed candidates
    to the ``exploit`` topic.

    Args:
        agent_bus: The shared :class:`AgentBus` instance.
        registry: The shared :class:`AgentRegistry` instance.
        agent_id: Unique identifier for this agent instance.
        attack_patterns: Optional dict of known attack patterns.
        think_engine: Optional think engine for LLM-powered reasoning.
        hacker_mind: Optional hacker_mind engine for cognitive reasoning.
    """

    CAPABILITIES = ["vuln"]
    MAX_HYPOTHESES = 5

    def __init__(
        self,
        agent_bus: Any,
        registry: Any,
        agent_id: str = "vuln-agent-1",
        attack_patterns: Optional[Dict] = None,
        think_engine: Any = None,
        hacker_mind: Any = None,
    ):
        self.bus = agent_bus
        self.registry = registry
        self.agent_id = agent_id
        self.attack_patterns = attack_patterns or {}
        self.think_engine = think_engine
        self.hacker_mind = hacker_mind
        self._processed: set = set()

    async def start(self) -> None:
        """Register and subscribe."""
        self.registry.register(
            agent_id=self.agent_id,
            name="VulnAgent",
            capabilities=self.CAPABILITIES,
            factory=self._restart,
        )
        self.bus.subscribe("vuln", self.handle_message)
        logger.info("VulnAgent '%s' started", self.agent_id)

    async def stop(self) -> None:
        self.bus.unsubscribe("vuln", self.handle_message)
        self.registry.deregister(self.agent_id)
        logger.info("VulnAgent '%s' stopped", self.agent_id)

    async def _restart(self) -> None:
        self._processed.clear()
        self.bus.subscribe("vuln", self.handle_message)
        self.registry.heartbeat(self.agent_id)

    async def handle_message(self, message: Any) -> None:
        """Process an asset from the vuln topic."""
        self.registry.mark_busy(self.agent_id)
        self.registry.heartbeat(self.agent_id)

        try:
            payload = message.payload or {}
            url = payload.get("url", "")
            if not url:
                return

            asset_key = f"{url}:{payload.get('asset_type', '')}"
            if asset_key in self._processed:
                return

            logger.info("VulnAgent analyzing asset: %s", url)

            # Generate hypotheses
            hypotheses = await self._generate_hypotheses(payload)

            # Test each hypothesis with lightweight probes
            confirmed = []
            for hyp in hypotheses[:self.MAX_HYPOTHESES]:
                result = await self._test_hypothesis(hyp)
                if result:
                    confirmed.append(result)

            # Publish confirmed candidates to exploit topic
            for candidate in confirmed:
                from core.agent_bus import Priority
                priority = Priority.HIGH if candidate.confidence > 0.7 else Priority.MEDIUM
                await self.bus.publish(
                    topic="exploit",
                    payload=candidate.to_dict(),
                    priority=priority,
                    agent_id=self.agent_id,
                )

            self._processed.add(asset_key)
            logger.info(
                "VulnAgent completed analysis of '%s': %d/%d hypotheses confirmed",
                url, len(confirmed), len(hypotheses),
            )

        except Exception as exc:
            logger.error("VulnAgent error: %s", exc)
        finally:
            self.registry.mark_idle(self.agent_id)

    async def _generate_hypotheses(self, asset: dict) -> List[Hypothesis]:
        """Generate vulnerability hypotheses using Tree-of-Thought.

        Considers asset type, technologies, and known attack patterns
        to produce ranked hypotheses.
        """
        url = asset.get("url", "")
        techs = asset.get("technologies", [])
        asset_type = asset.get("asset_type", "")
        hypotheses: List[Hypothesis] = []

        # Branch 1: Technology-based hypotheses
        tech_vulns = self._match_tech_patterns(techs)
        for vuln_type, conf, reason in tech_vulns:
            hypotheses.append(Hypothesis(
                vuln_type=vuln_type,
                confidence=conf,
                reasoning=reason,
                target_url=url,
            ))

        # Branch 2: Asset-type hypotheses
        type_vulns = self._match_asset_type(asset_type, url)
        for vuln_type, conf, reason in type_vulns:
            hypotheses.append(Hypothesis(
                vuln_type=vuln_type,
                confidence=conf,
                reasoning=reason,
                target_url=url,
            ))

        # Branch 3: Universal checks (CORS, headers, info disclosure)
        universal = [
            Hypothesis(
                vuln_type="cors_misconfiguration",
                confidence=0.4,
                reasoning="CORS misconfigurations are common across all web targets",
                target_url=url,
            ),
            Hypothesis(
                vuln_type="security_headers_missing",
                confidence=0.5,
                reasoning="Missing security headers are prevalent",
                target_url=url,
            ),
            Hypothesis(
                vuln_type="information_disclosure",
                confidence=0.3,
                reasoning="Server banners and error pages may leak info",
                target_url=url,
            ),
        ]
        hypotheses.extend(universal)

        # Branch 4: LLM-powered reasoning (if available)
        if self.hacker_mind:
            try:
                llm_hypotheses = await self._llm_hypotheses(asset)
                hypotheses.extend(llm_hypotheses)
            except Exception as exc:
                logger.debug("LLM hypothesis generation failed: %s", exc)

        # Sort by confidence (descending) and return top N
        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return hypotheses[:self.MAX_HYPOTHESES]

    def _match_tech_patterns(self, techs: List[str]) -> List[tuple]:
        """Match technologies to known vulnerability patterns."""
        matches = []
        tech_lower = [t.lower() for t in techs]

        tech_vuln_map = {
            "php": [("lfi", 0.5, "PHP apps commonly vulnerable to LFI"), ("sqli", 0.4, "PHP + SQL often hand-written")],
            "wordpress": [("sqli", 0.4, "WordPress plugins often SQLi-prone"), ("xss", 0.5, "WP themes often reflect user input")],
            "express": [("prototype_pollution", 0.4, "Node.js prototype pollution"), ("ssrf", 0.3, "Express proxy misconfigs")],
            "nginx": [("path_traversal", 0.3, "Nginx alias traversal"), ("cors_misconfiguration", 0.4, "Nginx CORS wildcards")],
            "apache": [("path_traversal", 0.3, "Apache mod_rewrite bypasses")],
            "asp.net": [("viewstate_deserialization", 0.4, "ASP.NET ViewState attacks")],
            "cloudflare": [("waf_bypass", 0.3, "Cloudflare WAF bypass techniques")],
        }

        for tech in tech_lower:
            for key, vulns in tech_vuln_map.items():
                if key in tech:
                    matches.extend(vulns)

        return matches

    def _match_asset_type(self, asset_type: str, url: str) -> List[tuple]:
        """Match asset type to vulnerability classes."""
        matches = []

        type_map = {
            "api": [("idor", 0.5, "APIs commonly have IDOR"), ("auth_bypass", 0.4, "API auth often misconfigured")],
            "graphql": [("graphql_introspection", 0.7, "GraphQL introspection often enabled"), ("graphql_injection", 0.4, "GraphQL batching/injection")],
            "admin_panel": [("auth_bypass", 0.5, "Admin panels may have weak auth"), ("default_credentials", 0.4, "Default creds common")],
            "api_docs": [("information_disclosure", 0.6, "API docs expose endpoints")],
            "sensitive_file": [("information_disclosure", 0.8, "Sensitive file exposed")],
        }

        if asset_type in type_map:
            matches.extend(type_map[asset_type])

        # URL-based pattern matching
        url_lower = url.lower()
        if "/graphql" in url_lower:
            matches.append(("graphql_introspection", 0.7, "GraphQL endpoint detected"))
        if "/api/" in url_lower or "/v1/" in url_lower or "/v2/" in url_lower:
            matches.append(("idor", 0.4, "API versioned endpoint"))

        return matches

    async def _test_hypothesis(self, hyp: Hypothesis) -> Optional[Hypothesis]:
        """Lightweight probe to validate a hypothesis.

        Does NOT exploit — just checks for indicators of vulnerability.
        Returns the hypothesis with updated confidence if confirmed, else None.
        """
        url = hyp.target_url

        try:
            if hyp.vuln_type == "cors_misconfiguration":
                return await self._test_cors(hyp)
            elif hyp.vuln_type == "security_headers_missing":
                return await self._test_headers(hyp)
            elif hyp.vuln_type == "information_disclosure":
                return await self._test_info_disclosure(hyp)
            elif hyp.vuln_type == "graphql_introspection":
                return await self._test_graphql_introspection(hyp)
            else:
                # For other types, pass through with reduced confidence
                # (exploit agent will do the real testing)
                hyp.confidence *= 0.8
                return hyp if hyp.confidence > 0.2 else None
        except Exception as exc:
            logger.debug("Hypothesis test failed for %s on %s: %s", hyp.vuln_type, url, exc)
            return None

    async def _test_cors(self, hyp: Hypothesis) -> Optional[Hypothesis]:
        """Quick CORS check."""
        try:
            import urllib.request
            import ssl

            ctx = ssl.create_default_context()
            req = urllib.request.Request(hyp.target_url, headers={
                "User-Agent": "VIPER-VulnAgent/1.0",
                "Origin": "https://evil.com",
            })
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=10, context=ctx),
            )
            acao = resp.getheader("Access-Control-Allow-Origin", "")
            acac = resp.getheader("Access-Control-Allow-Credentials", "")

            if acao == "*" or "evil.com" in acao:
                hyp.confidence = 0.9 if "evil.com" in acao else 0.6
                hyp.evidence = [f"ACAO: {acao}", f"ACAC: {acac}"]
                return hyp
        except Exception:
            pass
        return None

    async def _test_headers(self, hyp: Hypothesis) -> Optional[Hypothesis]:
        """Check for missing security headers."""
        try:
            import urllib.request
            import ssl

            ctx = ssl.create_default_context()
            req = urllib.request.Request(hyp.target_url, method="HEAD", headers={
                "User-Agent": "VIPER-VulnAgent/1.0",
            })
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=10, context=ctx),
            )
            headers = {k.lower(): v for k, v in resp.getheaders()}

            missing = []
            for hdr in ["x-frame-options", "x-content-type-options", "strict-transport-security",
                        "content-security-policy", "x-xss-protection"]:
                if hdr not in headers:
                    missing.append(hdr)

            if len(missing) >= 3:
                hyp.confidence = 0.6
                hyp.evidence = [f"Missing headers: {', '.join(missing)}"]
                return hyp
        except Exception:
            pass
        return None

    async def _test_info_disclosure(self, hyp: Hypothesis) -> Optional[Hypothesis]:
        """Check for information disclosure indicators."""
        try:
            import urllib.request
            import ssl

            ctx = ssl.create_default_context()
            req = urllib.request.Request(hyp.target_url, method="HEAD", headers={
                "User-Agent": "VIPER-VulnAgent/1.0",
            })
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=10, context=ctx),
            )
            server = resp.getheader("Server", "")
            powered = resp.getheader("X-Powered-By", "")

            evidence = []
            if server:
                evidence.append(f"Server: {server}")
            if powered:
                evidence.append(f"X-Powered-By: {powered}")

            if evidence:
                hyp.confidence = 0.5
                hyp.evidence = evidence
                return hyp
        except Exception:
            pass
        return None

    async def _test_graphql_introspection(self, hyp: Hypothesis) -> Optional[Hypothesis]:
        """Test if GraphQL introspection is enabled."""
        try:
            import urllib.request
            import json
            import ssl

            ctx = ssl.create_default_context()
            query = json.dumps({"query": "{__schema{types{name}}}"}).encode()
            req = urllib.request.Request(
                hyp.target_url,
                data=query,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "VIPER-VulnAgent/1.0",
                },
            )
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=10, context=ctx),
            )
            body = json.loads(resp.read().decode())
            if "data" in body and "__schema" in body.get("data", {}):
                hyp.confidence = 0.9
                hyp.evidence = ["GraphQL introspection enabled"]
                return hyp
        except Exception:
            pass
        return None

    async def _llm_hypotheses(self, asset: dict) -> List[Hypothesis]:
        """Use LLM to generate creative vulnerability hypotheses."""
        # Placeholder for LLM integration — returns empty if hacker_mind unavailable
        return []


__all__ = ["VulnAgent", "Hypothesis"]
