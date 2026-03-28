"""TruffleHog integration for git secret scanning."""

import json
import logging
import shutil
import subprocess
from typing import Dict, List

logger = logging.getLogger("viper.trufflehog")


class TruffleHogScanner:
    """Scans git repos for secrets using TruffleHog (if installed)."""

    def __init__(self):
        self.binary = shutil.which("trufflehog")
        self.available = self.binary is not None

    def is_available(self) -> bool:
        return self.available

    def scan_repo(self, repo_url: str, max_depth: int = 50) -> List[Dict]:
        """Scan a git repository for leaked secrets."""
        if not self.available:
            logger.info("TruffleHog not installed — skipping repo scan")
            return []
        try:
            result = subprocess.run(
                [self.binary, "git", repo_url, "--json", "--max-depth", str(max_depth)],
                capture_output=True, text=True, timeout=300,
            )
            return self._parse_output(result.stdout)
        except subprocess.TimeoutExpired:
            logger.warning("TruffleHog scan timed out for %s", repo_url)
            return []
        except Exception as e:
            logger.error("TruffleHog error: %s", e)
            return []

    def scan_directory(self, path: str) -> List[Dict]:
        """Scan a local directory for secrets."""
        if not self.available:
            logger.info("TruffleHog not installed — skipping dir scan")
            return []
        try:
            result = subprocess.run(
                [self.binary, "filesystem", path, "--json"],
                capture_output=True, text=True, timeout=300,
            )
            return self._parse_output(result.stdout)
        except subprocess.TimeoutExpired:
            logger.warning("TruffleHog scan timed out for %s", path)
            return []
        except Exception as e:
            logger.error("TruffleHog error: %s", e)
            return []

    def _parse_output(self, stdout: str) -> List[Dict]:
        findings = []
        for line in stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                meta = data.get("SourceMetadata", {}).get("Data", {})
                file_info = meta.get("Filesystem", meta.get("Git", {}))
                findings.append({
                    "type": "secret_exposure",
                    "source": "trufflehog",
                    "detector": data.get("DetectorType", "unknown"),
                    "file": file_info.get("file", ""),
                    "verified": data.get("Verified", False),
                    "raw": (data.get("Raw", "") or "")[:50] + "...",
                    "severity": "critical" if data.get("Verified") else "high",
                })
            except json.JSONDecodeError:
                continue
        return findings
