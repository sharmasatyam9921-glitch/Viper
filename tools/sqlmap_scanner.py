#!/usr/bin/env python3
"""
VIPER 5.0 — SQLMap Integration

Automated SQL injection detection and exploitation via sqlmap subprocess.
Non-destructive by default (--risk=1 --level=1, read-only techniques).
"""

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("viper.tools.sqlmap")


@dataclass
class SQLiResult:
    """SQL injection finding from sqlmap."""
    url: str
    parameter: str
    technique: str  # B=boolean, T=time, U=union, E=error, S=stacked
    dbms: str = ""
    payload: str = ""
    title: str = ""
    severity: str = "high"
    details: Dict = field(default_factory=dict)


class SQLMapScanner:
    """SQLMap subprocess wrapper for SQL injection testing.

    Non-destructive by default. Uses --risk=1 --level=1 and read-only techniques.

    Args:
        binary: Path to sqlmap binary or "python -m sqlmap".
        risk: Risk level 1-3 (default 1 = safe).
        level: Test level 1-5 (default 1 = basic).
        threads: Concurrent threads (default 4).
        timeout: Per-request timeout in seconds.
        tamper: Tamper scripts for WAF bypass (comma-separated).
    """

    def __init__(
        self,
        binary: Optional[str] = None,
        risk: int = 1,
        level: int = 1,
        threads: int = 4,
        timeout: int = 10,
        tamper: Optional[str] = None,
    ):
        self.binary = binary or shutil.which("sqlmap")
        if not self.binary:
            # Try python -m sqlmap
            try:
                import sqlmap  # noqa: F401
                self.binary = "sqlmap_module"
            except ImportError:
                pass
        self.available = self.binary is not None
        self.risk = min(max(risk, 1), 3)
        self.level = min(max(level, 1), 5)
        self.threads = threads
        self.timeout = timeout
        self.tamper = tamper

    async def scan_url(self, url: str, method: str = "GET",
                       data: Optional[str] = None,
                       cookies: Optional[str] = None,
                       headers: Optional[Dict[str, str]] = None) -> List[SQLiResult]:
        """Test a single URL for SQL injection.

        Args:
            url: Target URL with parameters (e.g., "https://target.com/page?id=1").
            method: HTTP method (GET or POST).
            data: POST data string.
            cookies: Cookie string.
            headers: Extra headers dict.
        """
        if not self.available:
            logger.warning("sqlmap not installed, skipping")
            return []

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = os.path.join(tmpdir, "output")

            cmd = self._build_cmd(url, method, data, cookies, headers, output_dir)

            logger.info("Running sqlmap: %s (risk=%d level=%d)", url[:80], self.risk, self.level)

            try:
                if self.binary == "sqlmap_module":
                    cmd_str = ["python", "-m", "sqlmap"] + cmd[1:]
                else:
                    cmd_str = cmd

                proc = await asyncio.create_subprocess_exec(
                    *cmd_str,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
                output = stdout.decode(errors="ignore")

                return self._parse_output(url, output, output_dir)

            except asyncio.TimeoutError:
                logger.warning("sqlmap timed out for %s", url[:80])
                return []
            except Exception as e:
                logger.error("sqlmap failed: %s", e)
                return []

    async def scan_batch(self, urls: List[str], max_concurrent: int = 3) -> List[SQLiResult]:
        """Test multiple URLs for SQL injection.

        Args:
            urls: List of URLs with parameters.
            max_concurrent: Max parallel sqlmap instances.
        """
        sem = asyncio.Semaphore(max_concurrent)
        all_results: List[SQLiResult] = []

        async def _scan(url: str):
            async with sem:
                results = await self.scan_url(url)
                all_results.extend(results)

        await asyncio.gather(*[_scan(u) for u in urls], return_exceptions=True)
        return all_results

    async def scan_request_file(self, request_file: str) -> List[SQLiResult]:
        """Test using a saved Burp/ZAP request file (-r flag)."""
        if not self.available or not os.path.exists(request_file):
            return []

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = os.path.join(tmpdir, "output")
            cmd = [
                self.binary, "-r", request_file,
                "--batch", "--output-dir", output_dir,
                f"--risk={self.risk}", f"--level={self.level}",
                f"--threads={self.threads}",
                "--random-agent",
            ]
            if self.tamper:
                cmd.extend(["--tamper", self.tamper])

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
                return self._parse_output("request_file", stdout.decode(errors="ignore"), output_dir)
            except Exception as e:
                logger.error("sqlmap request file scan failed: %s", e)
                return []

    def _build_cmd(self, url, method, data, cookies, headers, output_dir):
        """Build sqlmap command line."""
        cmd = [
            self.binary,
            "-u", url,
            "--batch",  # Non-interactive
            "--output-dir", output_dir,
            f"--risk={self.risk}",
            f"--level={self.level}",
            f"--threads={self.threads}",
            f"--timeout={self.timeout}",
            "--random-agent",
            "--smart",  # Only test params that seem injectable
            "--flush-session",
        ]

        if method.upper() == "POST" and data:
            cmd.extend(["--method", "POST", "--data", data])

        if cookies:
            cmd.extend(["--cookie", cookies])

        if headers:
            for k, v in headers.items():
                cmd.extend(["--header", f"{k}: {v}"])

        if self.tamper:
            cmd.extend(["--tamper", self.tamper])

        return cmd

    def _parse_output(self, url: str, output: str, output_dir: str) -> List[SQLiResult]:
        """Parse sqlmap stdout for findings."""
        results: List[SQLiResult] = []

        # Look for injection confirmations
        # Pattern: "Parameter: X (GET)" or "Parameter: X (POST)"
        param_matches = re.findall(
            r"Parameter:\s+(\S+)\s+\((\w+)\)", output
        )

        # Pattern: "Type: time-based blind" etc.
        technique_matches = re.findall(
            r"Type:\s+(.+?)(?:\n|Title:)", output
        )

        # Pattern: "Title: ..."
        title_matches = re.findall(r"Title:\s+(.+)", output)

        # Pattern: "Payload: ..."
        payload_matches = re.findall(r"Payload:\s+(.+)", output)

        # DBMS detection
        dbms_match = re.search(r"back-end DBMS:\s+(.+)", output)
        dbms = dbms_match.group(1).strip() if dbms_match else ""

        # Build results from matches
        if param_matches:
            for i, (param, method) in enumerate(param_matches):
                technique = technique_matches[i] if i < len(technique_matches) else "unknown"
                title = title_matches[i] if i < len(title_matches) else ""
                payload = payload_matches[i] if i < len(payload_matches) else ""

                results.append(SQLiResult(
                    url=url,
                    parameter=param,
                    technique=technique,
                    dbms=dbms,
                    payload=payload,
                    title=title,
                    severity="critical" if "stacked" in technique.lower() else "high",
                ))

        # Also check for "is vulnerable" in output
        if not results and "is vulnerable" in output.lower():
            results.append(SQLiResult(
                url=url,
                parameter="unknown",
                technique="detected",
                dbms=dbms,
                severity="high",
            ))

        if results:
            logger.info("sqlmap found %d SQLi in %s", len(results), url[:60])

        return results


__all__ = ["SQLMapScanner", "SQLiResult"]
