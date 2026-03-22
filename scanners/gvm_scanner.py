#!/usr/bin/env python3
"""
GVM/OpenVAS Integration for VIPER — Network-Layer Vulnerability Scanning.

Supports:
- GMP (Greenbone Management Protocol) over Unix socket or SSH
- GVM REST API (gsad)
- Docker-based GVM deployment
- Graceful skip when GVM is not available

Scans for network-layer vulnerabilities: SSH, FTP, SMTP, DNS, SNMP,
SSL/TLS misconfigs, default credentials, etc.
"""

import asyncio
import json
import os
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


class GVMConnectionType(Enum):
    UNIX_SOCKET = "unix"
    SSH = "ssh"
    REST_API = "rest"


@dataclass
class GVMFinding:
    """A vulnerability finding from GVM/OpenVAS."""
    oid: str
    name: str
    severity: float  # CVSS score 0-10
    severity_label: str  # critical/high/medium/low/info
    host: str
    port: str
    protocol: str
    description: str
    solution: str
    family: str
    cve_list: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    qod: int = 0  # Quality of Detection (0-100)

    def to_dict(self) -> Dict:
        return {
            "source": "gvm_openvas",
            "oid": self.oid,
            "name": self.name,
            "severity": self.severity,
            "severity_label": self.severity_label,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "description": self.description,
            "solution": self.solution,
            "family": self.family,
            "cves": self.cve_list,
            "references": self.references,
            "qod": self.qod,
        }

    def to_viper_finding(self) -> Dict:
        """Convert to VIPER's standard finding format."""
        return {
            "type": self._map_vuln_type(),
            "attack": f"gvm_{self.family.lower().replace(' ', '_')}",
            "vuln_type": self._map_vuln_type(),
            "severity": self.severity_label,
            "url": f"{self.host}:{self.port}",
            "payload": self.oid,
            "details": f"OpenVAS: {self.name}",
            "source": "gvm_openvas",
            "validated": True,
            "confidence": min(self.qod / 100.0, 0.95),
            "cves": self.cve_list,
            "solution": self.solution,
        }

    def _map_vuln_type(self) -> str:
        family_lower = self.family.lower()
        mappings = {
            "ssh": "network_ssh",
            "ftp": "network_ftp",
            "smtp": "network_smtp",
            "ssl": "ssl_tls",
            "tls": "ssl_tls",
            "dns": "network_dns",
            "snmp": "network_snmp",
            "http": "web_server",
            "default": "default_credentials",
            "brute": "brute_force",
            "dos": "denial_of_service",
            "rce": "remote_code_execution",
            "priv": "privilege_escalation",
        }
        for key, vtype in mappings.items():
            if key in family_lower:
                return vtype
        return "network_vuln"


@dataclass
class GVMScanResult:
    """Complete result from a GVM scan."""
    target: str
    scan_id: str
    started: str
    finished: str
    findings: List[GVMFinding] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "started": self.started,
            "finished": self.finished,
            "total_findings": len(self.findings),
            "by_severity": self._count_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
            "duration_seconds": self.scan_duration_seconds,
            "error": self.error,
        }

    def _count_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity_label] = counts.get(f.severity_label, 0) + 1
        return counts


# Pre-built scan configs matching GVM defaults
SCAN_CONFIGS = {
    "discovery": "8715c877-47a0-438d-98a3-27c7a6ab2196",
    "full_and_fast": "daba56c8-73ec-11df-a475-002264764cea",
    "full_and_deep": "708f25c4-7489-11df-8094-002264764cea",
    "network_discovery": "2d3f051c-55ba-11e3-bf43-406186ea4fc5",
}


class GVMScanner:
    """
    GVM/OpenVAS scanner integration.

    Connects via GMP protocol (Unix socket or SSH) or REST API.
    Falls back gracefully if GVM is not available.
    """

    def __init__(
        self,
        connection_type: str = "unix",
        socket_path: str = "/run/gvmd/gvmd.sock",
        host: str = "localhost",
        port: int = 9390,
        username: str = "admin",
        password: str = "admin",
        rest_url: Optional[str] = None,
        rest_api_key: Optional[str] = None,
        verbose: bool = True,
        tool_manager: Optional[Any] = None,
    ):
        self.connection_type = GVMConnectionType(connection_type)
        self.socket_path = socket_path
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.rest_url = rest_url or f"https://{host}:9392"
        self.rest_api_key = rest_api_key
        self.verbose = verbose
        self.tool_manager = tool_manager
        self._available: Optional[bool] = None
        self._gmp_connection = None

    def log(self, msg: str, level: str = "INFO"):
        if self.verbose:
            ts = datetime.now().strftime('%H:%M:%S')
            print(f"[{ts}] [GVM] [{level}] {msg}")

    # ─── Availability Check ───

    async def is_available(self) -> bool:
        """Check if GVM is reachable."""
        if self._available is not None:
            return self._available

        # Try GMP library
        if await self._check_gmp():
            self._available = True
            self.log("GVM available via GMP")
            return True

        # Try REST API
        if await self._check_rest():
            self._available = True
            self.connection_type = GVMConnectionType.REST_API
            self.log("GVM available via REST API")
            return True

        # Try docker
        if await self._check_docker():
            self._available = True
            self.log("GVM available via Docker")
            return True

        self._available = False
        self.log("GVM not available — skipping network scan", "WARN")
        return False

    async def _check_gmp(self) -> bool:
        """Check if python-gvm is installed and socket is accessible."""
        try:
            import gvm  # noqa: F401
            if self.connection_type == GVMConnectionType.UNIX_SOCKET:
                return os.path.exists(self.socket_path)
            return True  # SSH mode, assume reachable
        except ImportError:
            return False

    async def _check_rest(self) -> bool:
        """Check if GVM REST API is reachable."""
        try:
            import aiohttp
            import ssl
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    f"{self.rest_url}/api/version",
                    ssl=ssl_ctx,
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def _check_docker(self) -> bool:
        """Check if GVM is running in Docker."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "ps", "--filter", "name=gvm", "--format", "{{.Names}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return b"gvm" in stdout.lower()
        except Exception:
            return False

    # ─── Scan Execution ───

    async def scan(
        self,
        target: str,
        scan_config: str = "full_and_fast",
        max_wait_minutes: int = 60,
        port_list: Optional[str] = None,
    ) -> GVMScanResult:
        """
        Run a GVM scan against a target.

        Args:
            target: IP, hostname, or CIDR to scan
            scan_config: Scan config name or UUID
            max_wait_minutes: Maximum time to wait for scan completion
            port_list: Optional port list UUID

        Returns:
            GVMScanResult with findings
        """
        if not await self.is_available():
            return GVMScanResult(
                target=target,
                scan_id="",
                started=datetime.now().isoformat(),
                finished=datetime.now().isoformat(),
                error="GVM not available",
            )

        start = datetime.now()
        config_id = SCAN_CONFIGS.get(scan_config, scan_config)

        if self.connection_type == GVMConnectionType.REST_API:
            return await self._scan_rest(target, config_id, max_wait_minutes)

        return await self._scan_gmp(target, config_id, max_wait_minutes, port_list)

    async def _scan_gmp(
        self,
        target: str,
        config_id: str,
        max_wait_minutes: int,
        port_list: Optional[str],
    ) -> GVMScanResult:
        """Run scan via GMP protocol."""
        start = datetime.now()
        try:
            from gvm.connections import UnixSocketConnection, SSHConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform

            if self.connection_type == GVMConnectionType.UNIX_SOCKET:
                conn = UnixSocketConnection(path=self.socket_path)
            else:
                conn = SSHConnection(hostname=self.host, port=self.port)

            transform = EtreeTransform()

            with Gmp(connection=conn, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                self.log("Authenticated to GVM")

                # Create target
                target_resp = gmp.create_target(
                    name=f"VIPER-{target}-{int(time.time())}",
                    hosts=[target],
                    port_list_id=port_list,
                )
                target_id = target_resp.get("id")
                if not target_id:
                    target_id = self._extract_id(target_resp)
                self.log(f"Created target: {target_id}")

                # Create and start task
                task_resp = gmp.create_task(
                    name=f"VIPER-scan-{target}-{int(time.time())}",
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id="08b69003-5fc2-4037-a479-93b440211c73",  # OpenVAS default
                )
                task_id = task_resp.get("id")
                if not task_id:
                    task_id = self._extract_id(task_resp)
                self.log(f"Created task: {task_id}")

                start_resp = gmp.start_task(task_id)
                report_id = self._extract_report_id(start_resp)
                self.log(f"Scan started, report: {report_id}")

                # Poll for completion
                findings = await self._poll_gmp(gmp, task_id, report_id, max_wait_minutes)

                elapsed = (datetime.now() - start).total_seconds()
                return GVMScanResult(
                    target=target,
                    scan_id=task_id,
                    started=start.isoformat(),
                    finished=datetime.now().isoformat(),
                    findings=findings,
                    scan_duration_seconds=elapsed,
                )

        except ImportError:
            return GVMScanResult(
                target=target, scan_id="", started=start.isoformat(),
                finished=datetime.now().isoformat(),
                error="python-gvm not installed (pip install python-gvm)",
            )
        except Exception as e:
            self.log(f"GMP scan error: {e}", "ERROR")
            return GVMScanResult(
                target=target, scan_id="", started=start.isoformat(),
                finished=datetime.now().isoformat(), error=str(e),
            )

    async def _poll_gmp(self, gmp, task_id: str, report_id: str, max_wait: int) -> List[GVMFinding]:
        """Poll GMP for scan completion and parse results."""
        deadline = time.time() + max_wait * 60
        while time.time() < deadline:
            task_status = gmp.get_task(task_id)
            status = self._get_task_status(task_status)
            progress = self._get_task_progress(task_status)
            self.log(f"Scan progress: {progress}% (status: {status})")

            if status in ("Done", "Stopped", "Error"):
                break
            await asyncio.sleep(15)

        # Get report
        if not report_id:
            return []
        report = gmp.get_report(report_id, details=True)
        return self._parse_gmp_report(report)

    async def _scan_rest(
        self,
        target: str,
        config_id: str,
        max_wait_minutes: int,
    ) -> GVMScanResult:
        """Run scan via REST API (gsad)."""
        import aiohttp
        import ssl

        start = datetime.now()
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        headers = {}
        if self.rest_api_key:
            headers["X-API-Key"] = self.rest_api_key

        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Authenticate
                if not self.rest_api_key:
                    auth_data = {
                        "username": self.username,
                        "password": self.password,
                    }
                    async with session.post(
                        f"{self.rest_url}/api/login",
                        json=auth_data, ssl=ssl_ctx,
                    ) as resp:
                        if resp.status != 200:
                            return GVMScanResult(
                                target=target, scan_id="", started=start.isoformat(),
                                finished=datetime.now().isoformat(),
                                error=f"REST auth failed: {resp.status}",
                            )
                        data = await resp.json()
                        token = data.get("token", "")
                        headers["Authorization"] = f"Bearer {token}"

                self.log("REST API authenticated")

                # Create target
                target_data = {
                    "name": f"VIPER-{target}-{int(time.time())}",
                    "hosts": target,
                    "port_list_id": "33d0cd82-57c6-11e1-8ed1-406186ea4fc5",  # All TCP+UDP
                }
                async with session.post(
                    f"{self.rest_url}/api/targets",
                    json=target_data, headers=headers, ssl=ssl_ctx,
                ) as resp:
                    tdata = await resp.json()
                    target_id = tdata.get("id", "")

                # Create task
                task_data = {
                    "name": f"VIPER-scan-{int(time.time())}",
                    "config_id": config_id,
                    "target_id": target_id,
                    "scanner_id": "08b69003-5fc2-4037-a479-93b440211c73",
                }
                async with session.post(
                    f"{self.rest_url}/api/tasks",
                    json=task_data, headers=headers, ssl=ssl_ctx,
                ) as resp:
                    tdata = await resp.json()
                    task_id = tdata.get("id", "")

                # Start task
                async with session.post(
                    f"{self.rest_url}/api/tasks/{task_id}/start",
                    headers=headers, ssl=ssl_ctx,
                ) as resp:
                    sdata = await resp.json()
                    report_id = sdata.get("report_id", "")

                self.log(f"REST scan started: task={task_id}, report={report_id}")

                # Poll for completion
                deadline = time.time() + max_wait_minutes * 60
                while time.time() < deadline:
                    async with session.get(
                        f"{self.rest_url}/api/tasks/{task_id}",
                        headers=headers, ssl=ssl_ctx,
                    ) as resp:
                        tdata = await resp.json()
                        status = tdata.get("status", "")
                        progress = tdata.get("progress", 0)
                        self.log(f"Scan progress: {progress}% (status: {status})")
                        if status in ("Done", "Stopped", "Error"):
                            break
                    await asyncio.sleep(15)

                # Get results
                findings = []
                if report_id:
                    async with session.get(
                        f"{self.rest_url}/api/reports/{report_id}",
                        headers=headers, ssl=ssl_ctx,
                    ) as resp:
                        report_data = await resp.json()
                        findings = self._parse_rest_report(report_data)

                elapsed = (datetime.now() - start).total_seconds()
                return GVMScanResult(
                    target=target,
                    scan_id=task_id,
                    started=start.isoformat(),
                    finished=datetime.now().isoformat(),
                    findings=findings,
                    scan_duration_seconds=elapsed,
                )

        except Exception as e:
            self.log(f"REST scan error: {e}", "ERROR")
            return GVMScanResult(
                target=target, scan_id="", started=start.isoformat(),
                finished=datetime.now().isoformat(), error=str(e),
            )

    # ─── Result Parsing ───

    def _parse_gmp_report(self, report_xml) -> List[GVMFinding]:
        """Parse GMP XML report into findings."""
        findings = []
        try:
            # report_xml is an etree Element from python-gvm
            results = report_xml.findall('.//result') or []
            for result in results:
                severity = 0.0
                sev_elem = result.find('severity')
                if sev_elem is not None and sev_elem.text:
                    try:
                        severity = float(sev_elem.text)
                    except ValueError:
                        pass

                # Skip informational (severity 0) unless it's actually useful
                host_elem = result.find('host')
                port_elem = result.find('port')
                nvt = result.find('nvt')

                host = host_elem.text if host_elem is not None and host_elem.text else ""
                port_text = port_elem.text if port_elem is not None and port_elem.text else ""
                port, protocol = self._parse_port(port_text)

                name = ""
                oid = ""
                family = ""
                solution = ""
                cves = []
                refs = []

                if nvt is not None:
                    oid = nvt.get("oid", "")
                    name_elem = nvt.find("name")
                    name = name_elem.text if name_elem is not None and name_elem.text else ""
                    fam_elem = nvt.find("family")
                    family = fam_elem.text if fam_elem is not None and fam_elem.text else ""
                    sol_elem = nvt.find("solution")
                    solution = sol_elem.text if sol_elem is not None and sol_elem.text else ""
                    # CVEs
                    for ref in nvt.findall(".//ref"):
                        ref_type = ref.get("type", "")
                        ref_id = ref.get("id", "")
                        if ref_type == "cve":
                            cves.append(ref_id)
                        if ref_id:
                            refs.append(ref_id)

                desc_elem = result.find('description')
                description = desc_elem.text if desc_elem is not None and desc_elem.text else ""

                qod_elem = result.find('.//qod/value')
                qod = 0
                if qod_elem is not None and qod_elem.text:
                    try:
                        qod = int(qod_elem.text)
                    except ValueError:
                        pass

                findings.append(GVMFinding(
                    oid=oid,
                    name=name,
                    severity=severity,
                    severity_label=self._cvss_to_label(severity),
                    host=host,
                    port=port,
                    protocol=protocol,
                    description=description[:2000],
                    solution=solution[:1000],
                    family=family,
                    cve_list=cves,
                    references=refs,
                    qod=qod,
                ))
        except Exception as e:
            self.log(f"Report parse error: {e}", "ERROR")

        # Sort by severity descending
        findings.sort(key=lambda f: f.severity, reverse=True)
        return findings

    def _parse_rest_report(self, report_data: Dict) -> List[GVMFinding]:
        """Parse REST API report JSON into findings."""
        findings = []
        try:
            results = report_data.get("results", report_data.get("report", {}).get("results", []))
            if isinstance(results, dict):
                results = results.get("result", [])
            if not isinstance(results, list):
                return findings

            for r in results:
                severity = float(r.get("severity", 0))
                nvt = r.get("nvt", {})
                cves = [ref.get("id", "") for ref in nvt.get("refs", {}).get("ref", [])
                        if ref.get("type") == "cve"]
                refs = [ref.get("id", "") for ref in nvt.get("refs", {}).get("ref", [])
                        if ref.get("id")]

                port_text = r.get("port", "")
                port, protocol = self._parse_port(port_text)

                findings.append(GVMFinding(
                    oid=nvt.get("oid", r.get("id", "")),
                    name=nvt.get("name", r.get("name", "")),
                    severity=severity,
                    severity_label=self._cvss_to_label(severity),
                    host=r.get("host", {}).get("hostname", r.get("host", "")),
                    port=port,
                    protocol=protocol,
                    description=r.get("description", "")[:2000],
                    solution=nvt.get("solution", r.get("solution", ""))[:1000],
                    family=nvt.get("family", ""),
                    cve_list=cves,
                    references=refs,
                    qod=int(r.get("qod", {}).get("value", 0)),
                ))
        except Exception as e:
            self.log(f"REST report parse error: {e}", "ERROR")

        findings.sort(key=lambda f: f.severity, reverse=True)
        return findings

    # ─── Helpers ───

    @staticmethod
    def _cvss_to_label(cvss: float) -> str:
        if cvss >= 9.0:
            return "critical"
        elif cvss >= 7.0:
            return "high"
        elif cvss >= 4.0:
            return "medium"
        elif cvss > 0:
            return "low"
        return "info"

    @staticmethod
    def _parse_port(port_text: str) -> Tuple[str, str]:
        """Parse port string like '443/tcp' into (port, protocol)."""
        if "/" in port_text:
            parts = port_text.split("/")
            return parts[0].strip(), parts[1].strip()
        return port_text.strip(), "tcp"

    @staticmethod
    def _extract_id(resp) -> str:
        """Extract ID from GMP XML response."""
        if hasattr(resp, 'get'):
            return resp.get('id', '')
        if hasattr(resp, 'attrib'):
            return resp.attrib.get('id', '')
        return ''

    @staticmethod
    def _extract_report_id(resp) -> str:
        """Extract report ID from start_task response."""
        if hasattr(resp, 'find'):
            report = resp.find('.//report_id')
            if report is not None and report.text:
                return report.text
        if hasattr(resp, 'get'):
            return resp.get('report_id', '')
        return ''

    @staticmethod
    def _get_task_status(resp) -> str:
        if hasattr(resp, 'find'):
            status = resp.find('.//status')
            if status is not None and status.text:
                return status.text
        return ''

    @staticmethod
    def _get_task_progress(resp) -> int:
        if hasattr(resp, 'find'):
            progress = resp.find('.//progress')
            if progress is not None and progress.text:
                try:
                    return int(progress.text)
                except ValueError:
                    pass
        return 0

    # ─── Quick Scan Helper ───

    async def quick_network_scan(self, target: str) -> GVMScanResult:
        """Run a fast network discovery scan."""
        return await self.scan(target, scan_config="network_discovery", max_wait_minutes=30)

    async def full_scan(self, target: str) -> GVMScanResult:
        """Run a comprehensive vulnerability scan."""
        return await self.scan(target, scan_config="full_and_fast", max_wait_minutes=60)
