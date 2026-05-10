#!/usr/bin/env python3
"""
VIPER 5.0 — Nmap Integration

Service detection, version fingerprinting, and NSE script scanning.
Used after masscan/naabu to identify services on open ports.
"""

import asyncio
import logging
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from xml.etree import ElementTree

logger = logging.getLogger("viper.tools.nmap")


@dataclass
class NmapService:
    """A discovered service from nmap."""
    ip: str
    port: int
    proto: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    cpe: str = ""
    scripts: Dict[str, str] = field(default_factory=dict)


NSE_CATEGORIES = {
    "vuln": "vulners,vulscan/vulscan.nse,http-vuln-*,ssl-*",
    "auth": "http-auth,http-auth-finder,ssh-auth-methods,ftp-anon",
    "discovery": "http-headers,http-title,ssl-cert,dns-brute",
    "default": "default",
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d+")


class NmapScanner:
    """Nmap subprocess wrapper for service detection.

    Args:
        binary: Path to nmap binary.
        timing: Nmap timing template (0-5, default 4).
        scripts: NSE scripts to run (comma-separated).
    """

    def __init__(
        self,
        binary: Optional[str] = None,
        timing: int = 4,
        scripts: Optional[str] = None,
    ):
        self.binary = binary or shutil.which("nmap")
        self.available = self.binary is not None
        self.timing = min(max(timing, 0), 5)
        self.scripts = scripts  # e.g., "vulners,http-title,ssl-cert"

    async def service_scan(self, targets: List[str], ports: Optional[str] = None) -> List[NmapService]:
        """Service version detection scan (-sV).

        Args:
            targets: List of IPs or hostnames.
            ports: Specific ports (e.g., "80,443,8080"). Auto-detected if None.
        """
        if not self.available:
            logger.warning("nmap not installed, skipping")
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(targets))
            target_file = tf.name

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as of:
            output_file = of.name

        try:
            cmd = [
                self.binary, "-sV",
                f"-T{self.timing}",
                "-iL", target_file,
                "-oX", output_file,
                "--open",
                "--host-timeout", "120s",
            ]

            if ports:
                cmd.extend(["-p", ports])

            if self.scripts:
                cmd.extend(["--script", self.scripts])

            logger.info("Running nmap service scan: targets=%d, timing=T%d", len(targets), self.timing)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=600)

            return self._parse_xml(output_file)

        finally:
            Path(target_file).unlink(missing_ok=True)
            Path(output_file).unlink(missing_ok=True)

    async def vuln_scan(self, targets: List[str], ports: Optional[str] = None) -> List[NmapService]:
        """Vulnerability scan using NSE scripts."""
        if not self.available:
            return []

        old_scripts = self.scripts
        self.scripts = "vulners,vulscan/vulscan.nse,http-vuln-*,ssl-*"
        results = await self.service_scan(targets, ports)
        self.scripts = old_scripts
        return results

    async def nse_scan(self, targets: List[str], scripts: str = "vuln",
                       ports: str = None, timeout: int = 600) -> List[Dict]:
        """Run NSE script scan and parse results with CVE extraction.

        Args:
            targets: List of IPs or hostnames.
            scripts: Script category key from NSE_CATEGORIES or a raw nmap
                     script string (e.g. "http-vuln-cve2017-5638,ssl-heartbleed").
            ports: Specific ports (e.g. "80,443"). Scans all open if None.
            timeout: Max seconds to wait for nmap (default 600).

        Returns:
            List of dicts: [{host, port, script_id, output, cves, status}]
        """
        if not self.available:
            logger.warning("nmap not installed, skipping NSE scan")
            return []

        # Resolve category name to actual script list
        resolved_scripts = NSE_CATEGORIES.get(scripts, scripts)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(targets))
            target_file = tf.name

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as of:
            output_file = of.name

        try:
            cmd = [
                self.binary, "-sV",
                f"-T{self.timing}",
                "--script", resolved_scripts,
                "-iL", target_file,
                "-oX", output_file,
                "--open",
                "--host-timeout", "120s",
            ]
            if ports:
                cmd.extend(["-p", ports])

            logger.info("Running NSE scan: scripts=%s targets=%d", resolved_scripts, len(targets))

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=timeout)

            return self._parse_nse_xml(output_file)

        finally:
            Path(target_file).unlink(missing_ok=True)
            Path(output_file).unlink(missing_ok=True)

    def _parse_nse_xml(self, xml_path: str) -> List[Dict]:
        """Parse nmap XML output for NSE script results with CVE extraction."""
        results: List[Dict] = []
        try:
            tree = ElementTree.parse(xml_path)
            root = tree.getroot()

            for host in root.findall(".//host"):
                addr_elem = host.find("address")
                if addr_elem is None:
                    continue
                ip = addr_elem.get("addr", "")

                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue

                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue

                    port_id = int(port_elem.get("portid", 0))

                    for script in port_elem.findall("script"):
                        script_id = script.get("id", "")
                        output = script.get("output", "")
                        cves = sorted(set(_CVE_RE.findall(output)))

                        # Determine status from output keywords
                        output_lower = output.lower()
                        if any(kw in output_lower for kw in ("vulnerable", "exploitable", "state: vulnerable")):
                            status = "VULNERABLE"
                        elif any(kw in output_lower for kw in ("not vulnerable", "safe", "patched")):
                            status = "NOT_VULNERABLE"
                        else:
                            status = "VULNERABLE" if cves else "NOT_VULNERABLE"

                        results.append({
                            "host": ip,
                            "port": port_id,
                            "script_id": script_id,
                            "output": output[:1000],
                            "cves": cves,
                            "status": status,
                        })

        except (ElementTree.ParseError, FileNotFoundError) as e:
            logger.warning("Failed to parse NSE XML: %s", e)

        logger.info("NSE scan: %d script results, %d vulnerable",
                    len(results), sum(1 for r in results if r["status"] == "VULNERABLE"))
        return results

    async def quick_scan(self, targets: List[str]) -> List[NmapService]:
        """Fast top-100 port scan with service detection."""
        if not self.available:
            return []

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as of:
            output_file = of.name

        try:
            cmd = [
                self.binary, "-sV", "-F",  # Fast (top 100)
                f"-T{self.timing}",
                "--open",
                "--host-timeout", "60s",
                "-oX", output_file,
            ] + targets[:20]  # Cap targets

            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)
            return self._parse_xml(output_file)
        finally:
            Path(output_file).unlink(missing_ok=True)

    def _parse_xml(self, xml_path: str) -> List[NmapService]:
        """Parse nmap XML output."""
        results: List[NmapService] = []
        try:
            tree = ElementTree.parse(xml_path)
            root = tree.getroot()

            for host in root.findall(".//host"):
                addr_elem = host.find("address")
                if addr_elem is None:
                    continue
                ip = addr_elem.get("addr", "")

                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue

                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue

                    service_elem = port_elem.find("service")
                    svc = NmapService(
                        ip=ip,
                        port=int(port_elem.get("portid", 0)),
                        proto=port_elem.get("protocol", "tcp"),
                        state="open",
                    )

                    if service_elem is not None:
                        svc.service = service_elem.get("name", "")
                        svc.version = service_elem.get("version", "")
                        svc.product = service_elem.get("product", "")
                        svc.extra_info = service_elem.get("extrainfo", "")
                        cpe_elem = service_elem.find("cpe")
                        if cpe_elem is not None and cpe_elem.text:
                            svc.cpe = cpe_elem.text

                    # Parse NSE scripts
                    for script in port_elem.findall("script"):
                        svc.scripts[script.get("id", "")] = script.get("output", "")[:500]

                    results.append(svc)

        except (ElementTree.ParseError, FileNotFoundError) as e:
            logger.warning("Failed to parse nmap XML: %s", e)

        logger.info("nmap found %d services", len(results))
        return results


__all__ = ["NmapScanner", "NmapService", "NSE_CATEGORIES"]
