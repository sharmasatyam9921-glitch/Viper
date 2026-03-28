#!/usr/bin/env python3
"""
VIPER 5.0 — Masscan Integration

Masscan is the fastest port scanner (10M packets/sec).
Used in parallel with naabu for comprehensive port discovery.
"""

import asyncio
import json
import logging
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("viper.tools.masscan")


@dataclass
class MasscanResult:
    """Result from a masscan scan."""
    ip: str
    port: int
    proto: str = "tcp"
    state: str = "open"
    ttl: int = 0


class MasscanScanner:
    """Masscan subprocess wrapper for high-speed port scanning.

    Args:
        rate: Packets per second (default 1000, max 10000000).
        ports: Port range to scan (default top 1000).
        binary: Path to masscan binary.
    """

    def __init__(
        self,
        rate: int = 1000,
        ports: str = "1-65535",
        binary: Optional[str] = None,
    ):
        self.rate = min(rate, 100000)  # Cap for safety
        self.ports = ports
        self.binary = binary or shutil.which("masscan")
        self.available = self.binary is not None

    async def scan(self, targets: List[str], ports: Optional[str] = None) -> List[MasscanResult]:
        """Run masscan on targets.

        Args:
            targets: List of IPs or CIDR ranges.
            ports: Override port range.

        Returns:
            List of MasscanResult with open ports.
        """
        if not self.available:
            logger.warning("masscan not installed, skipping")
            return []

        results: List[MasscanResult] = []
        scan_ports = ports or self.ports

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(targets))
            target_file = tf.name

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as of:
            output_file = of.name

        try:
            cmd = [
                self.binary,
                "-iL", target_file,
                "-p", scan_ports,
                "--rate", str(self.rate),
                "-oJ", output_file,
                "--wait", "3",
            ]

            logger.info("Running masscan: rate=%d ports=%s targets=%d", self.rate, scan_ports, len(targets))

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

            if proc.returncode != 0:
                logger.warning("masscan exited %d: %s", proc.returncode, stderr.decode()[:200])

            # Parse JSON output
            try:
                content = Path(output_file).read_text()
                # masscan JSON can be malformed (trailing comma)
                content = content.rstrip().rstrip(",")
                if not content.endswith("]"):
                    content += "]"
                if not content.startswith("["):
                    content = "[" + content

                data = json.loads(content)
                for entry in data:
                    ip = entry.get("ip", "")
                    for port_info in entry.get("ports", []):
                        results.append(MasscanResult(
                            ip=ip,
                            port=port_info.get("port", 0),
                            proto=port_info.get("proto", "tcp"),
                            state=port_info.get("status", "open"),
                            ttl=port_info.get("ttl", 0),
                        ))
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("Failed to parse masscan output: %s", e)

        finally:
            Path(target_file).unlink(missing_ok=True)
            Path(output_file).unlink(missing_ok=True)

        logger.info("masscan found %d open ports", len(results))
        return results

    async def scan_top_ports(self, targets: List[str], top: int = 1000) -> List[MasscanResult]:
        """Scan common ports only."""
        port_ranges = {
            100: "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
            1000: "1-1024,1433,1521,2049,2082,2083,2086,2087,3000,3306,3389,4443,5000,5432,5900,5985,6379,8000,8080,8443,8888,9090,9200,9300,27017",
            65535: "1-65535",
        }
        ports = port_ranges.get(top, port_ranges[1000])
        return await self.scan(targets, ports=ports)


__all__ = ["MasscanScanner", "MasscanResult"]
