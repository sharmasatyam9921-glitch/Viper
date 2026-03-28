#!/usr/bin/env python3
"""
VIPER Recon Agent — Subscribes to 'recon' topic on the agent bus.

Responsibilities:
- Subdomain enumeration
- Technology fingerprinting
- Asset discovery (APIs, admin panels, staging)
- Publishes discovered assets to 'vuln' topic
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("viper.agents.recon")


@dataclass
class DiscoveredAsset:
    """An asset discovered during recon."""
    url: str
    asset_type: str  # "subdomain", "api", "admin_panel", "staging", "endpoint"
    technologies: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "asset_type": self.asset_type,
            "technologies": self.technologies,
            "ports": self.ports,
            "metadata": self.metadata,
        }


class ReconAgent:
    """Autonomous recon agent that discovers and publishes assets.

    Subscribes to the ``recon`` topic on the agent bus.
    Publishes discovered assets to the ``vuln`` topic for analysis.

    Args:
        agent_bus: The shared :class:`AgentBus` instance.
        registry: The shared :class:`AgentRegistry` instance.
        agent_id: Unique identifier for this agent instance.
    """

    AGENT_ID_PREFIX = "recon"
    CAPABILITIES = ["recon"]

    def __init__(
        self,
        agent_bus: Any,
        registry: Any,
        agent_id: str = "recon-agent-1",
    ):
        self.bus = agent_bus
        self.registry = registry
        self.agent_id = agent_id
        self._processed: Set[str] = set()  # track processed targets
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Register with the registry and subscribe to the bus."""
        self.registry.register(
            agent_id=self.agent_id,
            name="ReconAgent",
            capabilities=self.CAPABILITIES,
            factory=self._restart,
        )
        self.bus.subscribe("recon", self.handle_message)
        logger.info("ReconAgent '%s' started", self.agent_id)

    async def stop(self) -> None:
        """Clean up."""
        self.bus.unsubscribe("recon", self.handle_message)
        self.registry.deregister(self.agent_id)
        logger.info("ReconAgent '%s' stopped", self.agent_id)

    async def _restart(self) -> None:
        """Factory callable for auto-restart."""
        self._processed.clear()
        self.bus.subscribe("recon", self.handle_message)
        self.registry.heartbeat(self.agent_id)
        logger.info("ReconAgent '%s' restarted", self.agent_id)

    async def handle_message(self, message: Any) -> None:
        """Process a recon request from the bus."""
        self.registry.mark_busy(self.agent_id)
        self.registry.heartbeat(self.agent_id)

        try:
            payload = message.payload or {}
            target = payload.get("target", "")
            if not target:
                logger.warning("ReconAgent received message with no target")
                return

            if target in self._processed:
                logger.debug("Target '%s' already processed, skipping", target)
                return

            logger.info("ReconAgent starting recon on '%s'", target)
            assets = await self._run_recon(target, payload)

            # Publish each discovered asset to vuln topic
            for asset in assets:
                from core.agent_bus import Priority
                await self.bus.publish(
                    topic="vuln",
                    payload=asset.to_dict(),
                    priority=Priority.MEDIUM,
                    agent_id=self.agent_id,
                )

            self._processed.add(target)
            logger.info(
                "ReconAgent completed recon on '%s': %d assets discovered",
                target, len(assets),
            )
        except Exception as exc:
            logger.error("ReconAgent error processing '%s': %s", message.topic, exc)
        finally:
            self.registry.mark_idle(self.agent_id)

    async def _run_recon(self, target: str, options: dict) -> List[DiscoveredAsset]:
        """Execute recon pipeline on *target*.

        Tries the full ReconPipeline (subfinder, naabu, httpx, etc.) first.
        Falls back to lightweight Python-only recon if external tools unavailable.
        """
        assets: List[DiscoveredAsset] = []

        # Phase 1: Target itself as a base asset
        base_asset = DiscoveredAsset(
            url=target if target.startswith("http") else f"https://{target}",
            asset_type="primary",
            metadata={"source": "initial_target"},
        )
        assets.append(base_asset)

        # Phase 2: Try full recon pipeline (external tools: subfinder, naabu, etc.)
        subdomains = await self._enumerate_subdomains_heavy(target)
        if not subdomains:
            # Fallback: lightweight crt.sh-only enumeration
            subdomains = await self._enumerate_subdomains(target)
        for sub in subdomains:
            assets.append(DiscoveredAsset(
                url=f"https://{sub}",
                asset_type="subdomain",
                metadata={"parent": target},
            ))

        # Phase 3: Technology fingerprinting
        for asset in list(assets):
            techs = await self._fingerprint_tech(asset.url)
            asset.technologies = techs

        # Phase 4: Common endpoint discovery
        endpoints = await self._discover_endpoints(target)
        for ep in endpoints:
            assets.append(DiscoveredAsset(
                url=ep["url"],
                asset_type=ep.get("type", "endpoint"),
                metadata=ep.get("metadata", {}),
            ))

        return assets

    async def _enumerate_subdomains_heavy(self, domain: str) -> List[str]:
        """Subdomain enumeration via external tools (subfinder, amass).

        Delegates to the real recon pipeline's subprocess calls.
        Returns empty list if tools not available (graceful degradation).
        """
        if "://" in domain:
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc

        subdomains: List[str] = []
        import shutil

        # Try subfinder (fast, passive)
        subfinder = shutil.which("subfinder")
        if subfinder:
            try:
                proc = await asyncio.create_subprocess_exec(
                    subfinder, "-d", domain, "-silent", "-all", "-t", "10",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                for line in stdout.decode(errors="ignore").splitlines():
                    line = line.strip()
                    if line and line.endswith(domain):
                        subdomains.append(line)
                logger.info("subfinder found %d subdomains for %s", len(subdomains), domain)
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug("subfinder failed for %s: %s", domain, e)

        return list(set(subdomains))[:500]

    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Passive subdomain enumeration.

        In production, delegates to subfinder/amass. Here we provide the
        framework; tool integration is handled by the tool registry.
        """
        # Strip protocol if present
        if "://" in domain:
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc

        subdomains: List[str] = []

        # Try certificate transparency logs via crt.sh
        try:
            import urllib.request
            import json
            import ssl

            ctx = ssl.create_default_context()
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "VIPER-Recon/1.0"})
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=15, context=ctx),
            )
            data = json.loads(resp.read().decode())
            seen = set()
            for entry in data[:200]:  # cap to avoid memory issues
                name = entry.get("name_value", "").strip().lower()
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(domain) and n not in seen:
                        seen.add(n)
                        subdomains.append(n)
        except Exception as exc:
            logger.debug("crt.sh lookup failed for %s: %s", domain, exc)

        return subdomains[:100]  # cap results

    async def _fingerprint_tech(self, url: str) -> List[str]:
        """Lightweight technology fingerprinting from HTTP headers."""
        techs: List[str] = []
        try:
            import urllib.request
            import ssl

            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, method="HEAD", headers={
                "User-Agent": "VIPER-Recon/1.0"
            })
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=10, context=ctx),
            )
            headers = {k.lower(): v for k, v in resp.getheaders()}

            server = headers.get("server", "").lower()
            powered = headers.get("x-powered-by", "").lower()

            if "nginx" in server:
                techs.append("nginx")
            if "apache" in server:
                techs.append("apache")
            if "cloudflare" in server:
                techs.append("cloudflare")
            if "php" in powered:
                techs.append("php")
            if "express" in powered:
                techs.append("express")
            if "asp.net" in powered:
                techs.append("asp.net")

        except Exception as exc:
            logger.debug("Tech fingerprint failed for %s: %s", url, exc)

        return techs

    async def _discover_endpoints(self, target: str) -> List[Dict[str, Any]]:
        """Discover common API and admin endpoints."""
        base = target if target.startswith("http") else f"https://{target}"
        base = base.rstrip("/")

        common_paths = [
            ("/api", "api"),
            ("/graphql", "graphql"),
            ("/api/v1", "api"),
            ("/api/v2", "api"),
            ("/admin", "admin_panel"),
            ("/wp-admin", "admin_panel"),
            ("/.env", "sensitive_file"),
            ("/robots.txt", "info"),
            ("/sitemap.xml", "info"),
            ("/.git/HEAD", "sensitive_file"),
            ("/swagger-ui.html", "api_docs"),
            ("/api-docs", "api_docs"),
        ]

        endpoints: List[Dict[str, Any]] = []

        async def _check(path: str, ep_type: str) -> Optional[Dict]:
            try:
                import urllib.request
                import ssl

                ctx = ssl.create_default_context()
                url = f"{base}{path}"
                req = urllib.request.Request(url, method="HEAD", headers={
                    "User-Agent": "VIPER-Recon/1.0"
                })
                resp = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: urllib.request.urlopen(req, timeout=8, context=ctx),
                )
                if resp.status < 400:
                    return {"url": url, "type": ep_type, "metadata": {"status": resp.status}}
            except Exception:
                pass
            return None

        # Run checks concurrently but with some rate limiting
        sem = asyncio.Semaphore(5)

        async def _throttled(path: str, ep_type: str) -> Optional[Dict]:
            async with sem:
                return await _check(path, ep_type)

        results = await asyncio.gather(
            *[_throttled(p, t) for p, t in common_paths],
            return_exceptions=True,
        )

        for r in results:
            if isinstance(r, dict):
                endpoints.append(r)

        return endpoints


__all__ = ["ReconAgent", "DiscoveredAsset"]
