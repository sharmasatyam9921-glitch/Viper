#!/usr/bin/env python3
"""
VIPER Chain Agent — Subscribes to 'chain' topic on the agent bus.

Responsibilities:
- Combine low-severity findings into critical attack chains
- Cross-target correlation (same pattern across targets)
- Publishes chained findings to 'report' topic
"""

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("viper.agents.chain")


@dataclass
class AttackChainResult:
    """A chain of low-severity findings that combine into a higher-severity exploit."""
    chain_id: str
    title: str
    severity: str
    cvss: float
    findings: List[dict]  # list of ValidatedFinding dicts
    chain_description: str
    impact: str
    target_url: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "severity": self.severity,
            "cvss": self.cvss,
            "findings": self.findings,
            "chain_description": self.chain_description,
            "impact": self.impact,
            "target_url": self.target_url,
            "timestamp": self.timestamp,
        }


# Known attack chain patterns
CHAIN_PATTERNS = [
    {
        "name": "CORS + Information Disclosure → Session Hijack",
        "requires": ["cors_misconfiguration", "information_disclosure"],
        "severity": "high",
        "cvss": 8.1,
        "impact": "Attacker chains CORS misconfiguration with information disclosure to steal user sessions cross-origin.",
    },
    {
        "name": "GraphQL Introspection + IDOR → Data Exfiltration",
        "requires": ["graphql_introspection", "idor"],
        "severity": "critical",
        "cvss": 9.1,
        "impact": "Full API schema enumeration combined with IDOR enables mass data exfiltration.",
    },
    {
        "name": "Open Redirect + CORS → OAuth Token Theft",
        "requires": ["open_redirect", "cors_misconfiguration"],
        "severity": "high",
        "cvss": 8.5,
        "impact": "Open redirect chains with CORS to steal OAuth tokens via crafted redirect URIs.",
    },
    {
        "name": "Info Disclosure + Auth Bypass → Full Account Takeover",
        "requires": ["information_disclosure", "auth_bypass"],
        "severity": "critical",
        "cvss": 9.8,
        "impact": "Server information leakage enables targeted auth bypass leading to account takeover.",
    },
    {
        "name": "SSRF + Info Disclosure → Cloud Metadata Access",
        "requires": ["ssrf", "information_disclosure"],
        "severity": "critical",
        "cvss": 9.6,
        "impact": "SSRF combined with cloud infrastructure info enables access to metadata endpoints and credentials.",
    },
    {
        "name": "Missing Headers + XSS → Persistent XSS",
        "requires": ["security_headers_missing", "xss"],
        "severity": "high",
        "cvss": 7.5,
        "impact": "Missing CSP and X-Frame-Options enable XSS escalation and clickjacking attacks.",
    },
]


class ChainAgent:
    """Attack chain agent that combines findings into high-impact chains.

    Subscribes to ``chain`` topic. Maintains a buffer of findings per target
    and checks for chainable patterns. Cross-target correlation checks if
    the same vulnerability class appears across multiple targets.

    Publishes chained findings to the ``report`` topic.
    """

    CAPABILITIES = ["chain"]

    def __init__(
        self,
        agent_bus: Any,
        registry: Any,
        agent_id: str = "chain-agent-1",
    ):
        self.bus = agent_bus
        self.registry = registry
        self.agent_id = agent_id
        # Buffer findings per target for chain analysis
        self._findings_buffer: Dict[str, List[dict]] = {}
        # Track all findings across targets for cross-target correlation
        self._all_findings: List[dict] = []
        self._emitted_chains: Set[str] = set()

    async def start(self) -> None:
        self.registry.register(
            agent_id=self.agent_id,
            name="ChainAgent",
            capabilities=self.CAPABILITIES,
            factory=self._restart,
        )
        self.bus.subscribe("chain", self.handle_message)
        logger.info("ChainAgent '%s' started", self.agent_id)

    async def stop(self) -> None:
        self.bus.unsubscribe("chain", self.handle_message)
        self.registry.deregister(self.agent_id)
        logger.info("ChainAgent '%s' stopped", self.agent_id)

    async def _restart(self) -> None:
        self.bus.subscribe("chain", self.handle_message)
        self.registry.heartbeat(self.agent_id)

    async def handle_message(self, message: Any) -> None:
        """Process a validated finding and check for chains."""
        self.registry.mark_busy(self.agent_id)
        self.registry.heartbeat(self.agent_id)

        try:
            finding = message.payload or {}
            target_url = finding.get("target_url", "")
            vuln_type = finding.get("vuln_type", "")

            if not target_url or not vuln_type:
                return

            # Buffer the finding
            self._findings_buffer.setdefault(target_url, []).append(finding)
            self._all_findings.append(finding)

            logger.info(
                "ChainAgent received finding: %s on %s (buffer: %d)",
                vuln_type, target_url, len(self._findings_buffer[target_url]),
            )

            # Check for attack chains on this target
            chains = self._find_chains(target_url)
            for chain in chains:
                chain_key = f"{chain.chain_id}"
                if chain_key not in self._emitted_chains:
                    self._emitted_chains.add(chain_key)
                    from core.agent_bus import Priority
                    await self.bus.publish(
                        topic="report",
                        payload=chain.to_dict(),
                        priority=Priority.HIGH,
                        agent_id=self.agent_id,
                    )
                    logger.info("Chain discovered: %s (severity: %s)", chain.title, chain.severity)

            # Cross-target correlation
            correlations = self._cross_target_correlate(finding)
            for corr in correlations:
                from core.agent_bus import Priority
                await self.bus.publish(
                    topic="exploit",
                    payload=corr,
                    priority=Priority.MEDIUM,
                    agent_id=self.agent_id,
                )

            # Always forward individual findings to report topic too
            from core.agent_bus import Priority
            await self.bus.publish(
                topic="report",
                payload=finding,
                priority=Priority.MEDIUM,
                agent_id=self.agent_id,
            )

        except Exception as exc:
            logger.error("ChainAgent error: %s", exc)
        finally:
            self.registry.mark_idle(self.agent_id)

    def _find_chains(self, target_url: str) -> List[AttackChainResult]:
        """Check if buffered findings for a target form known attack chains."""
        findings = self._findings_buffer.get(target_url, [])
        vuln_types = {f.get("vuln_type", "") for f in findings}
        chains: List[AttackChainResult] = []

        for pattern in CHAIN_PATTERNS:
            required = set(pattern["requires"])
            if required.issubset(vuln_types):
                # Build chain ID from components
                chain_hash = hashlib.sha256(
                    f"{target_url}:{'|'.join(sorted(required))}".encode()
                ).hexdigest()[:12]
                chain_id = f"chain_{chain_hash}"

                if chain_id in self._emitted_chains:
                    continue

                # Gather component findings
                component_findings = [
                    f for f in findings if f.get("vuln_type", "") in required
                ]

                chains.append(AttackChainResult(
                    chain_id=chain_id,
                    title=pattern["name"],
                    severity=pattern["severity"],
                    cvss=pattern["cvss"],
                    findings=component_findings,
                    chain_description=f"Attack chain combining {' + '.join(required)} on {target_url}",
                    impact=pattern["impact"],
                    target_url=target_url,
                ))

        return chains

    def _cross_target_correlate(self, finding: dict) -> List[dict]:
        """Check if the same vuln type exists on other targets.

        If so, publish probing requests for those targets.
        """
        vuln_type = finding.get("vuln_type", "")
        target_url = finding.get("target_url", "")
        correlations: List[dict] = []

        # Group findings by target
        targets_with_type: Dict[str, bool] = {}
        for f in self._all_findings:
            ft = f.get("target_url", "")
            fv = f.get("vuln_type", "")
            if fv == vuln_type and ft != target_url:
                targets_with_type[ft] = True

        # For targets that already have this vuln confirmed, skip.
        # For targets we've never checked, suggest probing.
        # (In practice, this would feed back into exploit agent.)
        # We don't auto-probe here — just log for awareness.
        for other_target in targets_with_type:
            logger.info(
                "Cross-target correlation: %s also found on %s",
                vuln_type, other_target,
            )

        return correlations

    def get_stats(self) -> dict:
        """Return chain agent statistics."""
        return {
            "buffered_targets": len(self._findings_buffer),
            "total_findings": sum(len(v) for v in self._findings_buffer.values()),
            "chains_discovered": len(self._emitted_chains),
            "cross_target_findings": len(self._all_findings),
        }


__all__ = ["ChainAgent", "AttackChainResult", "CHAIN_PATTERNS"]
