#!/usr/bin/env python3
"""
VIPER Parallel Hunter — Hunt multiple targets simultaneously.

Uses asyncio semaphore-bounded concurrency with shared EvoGraph
for cross-target learning. Each target runs its own ViperCore
instance but shares the evolutionary memory.
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.parallel_hunter")

HACKAGENT_DIR = Path(__file__).parent.parent


class HuntResult:
    """Result container for a single target hunt."""

    def __init__(self, target: str):
        self.target = target
        self.findings: List[dict] = []
        self.error: Optional[str] = None
        self.elapsed_seconds: float = 0.0
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None
        self.status: str = "pending"  # pending, running, completed, failed

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "findings": self.findings,
            "findings_count": len(self.findings),
            "error": self.error,
            "elapsed_seconds": self.elapsed_seconds,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
        }


class ParallelHunter:
    """Hunt multiple targets simultaneously using asyncio.

    Manages concurrent ViperCore instances with shared EvoGraph
    for cross-target learning.

    Args:
        max_concurrent: Maximum number of simultaneous hunts.
        shared_evograph: Optional shared EvoGraph for cross-target learning.
                         If None, each hunt uses its own.
    """

    def __init__(self, max_concurrent: int = 3,
                 shared_evograph=None):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.shared_evograph = shared_evograph
        self.results: Dict[str, HuntResult] = {}
        self._active_count = 0
        self._total_findings = 0
        self._start_time: Optional[float] = None

    async def hunt_all(self, targets: List[str],
                       minutes_per_target: int = 15,
                       scope_file: Optional[str] = None,
                       full: bool = True,
                       stealth: int = 0,
                       on_finding=None,
                       on_target_complete=None) -> Dict[str, dict]:
        """Hunt all targets with bounded concurrency.

        Args:
            targets: List of target URLs to hunt.
            minutes_per_target: Time budget per target.
            scope_file: Optional path to scope JSON.
            full: Whether to run full hunt (vs quick).
            stealth: Stealth level 0-3.
            on_finding: Optional async callback(finding, target).
            on_target_complete: Optional async callback(target, result).

        Returns:
            Dict mapping target URL -> result dict.
        """
        self._start_time = time.monotonic()
        logger.info("Starting parallel hunt: %d targets, max %d concurrent, %d min/target",
                     len(targets), self.max_concurrent, minutes_per_target)

        # Load scope if provided
        scope = None
        if scope_file:
            try:
                scope_data = json.loads(Path(scope_file).read_text())
                from scope.scope_manager import BugBountyScope
                scope = BugBountyScope.from_dict(scope_data)
            except Exception as e:
                logger.warning("Failed to load scope file: %s", e)

        # Initialize shared evograph if not provided
        evograph = self.shared_evograph
        if evograph is None:
            try:
                from core.evograph import EvoGraph
                evograph = EvoGraph()
            except Exception:
                evograph = None

        tasks = []
        for target in targets:
            self.results[target] = HuntResult(target)
            task = asyncio.create_task(
                self._hunt_one(target, minutes_per_target, scope, full, stealth,
                               evograph, on_finding, on_target_complete)
            )
            tasks.append(task)

        # Wait for all to complete, catching exceptions
        await asyncio.gather(*tasks, return_exceptions=True)

        elapsed = time.monotonic() - self._start_time
        logger.info("Parallel hunt complete: %d targets, %d total findings, %.1f min",
                     len(targets), self._total_findings, elapsed / 60)

        return {t: r.to_dict() for t, r in self.results.items()}

    async def _hunt_one(self, target: str, minutes: int,
                        scope, full: bool, stealth: int,
                        evograph, on_finding, on_target_complete):
        """Hunt a single target within the semaphore-bounded pool."""
        result = self.results[target]
        result.status = "waiting"

        async with self.semaphore:
            self._active_count += 1
            result.status = "running"
            result.started_at = datetime.now().isoformat()
            start = time.monotonic()

            logger.info("[%d/%d active] Starting hunt: %s",
                        self._active_count, self.max_concurrent, target)

            try:
                from viper_core import ViperCore

                viper = ViperCore()

                # Share evograph for cross-target learning
                if evograph is not None and hasattr(viper, '_evograph'):
                    viper._evograph = evograph

                # Set stealth level
                if stealth > 0 and hasattr(viper, 'set_stealth_level'):
                    viper.set_stealth_level(stealth)

                if full:
                    hunt_result = await viper.full_hunt(
                        target_url=target,
                        scope=scope,
                        max_minutes=minutes,
                    )
                else:
                    import aiohttp
                    async with aiohttp.ClientSession() as viper.session:
                        hunt_result = await viper.hunt(
                            target,
                            max_minutes=minutes,
                        )

                if hunt_result:
                    result.findings = hunt_result.get("findings", [])
                    self._total_findings += len(result.findings)

                    # Fire per-finding callbacks
                    if on_finding and result.findings:
                        for finding in result.findings:
                            try:
                                await on_finding(finding, target)
                            except Exception as e:
                                logger.debug("Finding callback error: %s", e)

                result.status = "completed"

            except asyncio.CancelledError:
                result.status = "cancelled"
                result.error = "Hunt cancelled"
            except Exception as e:
                result.status = "failed"
                result.error = str(e)
                logger.error("Hunt failed for %s: %s", target, e)
            finally:
                result.elapsed_seconds = time.monotonic() - start
                result.completed_at = datetime.now().isoformat()
                self._active_count -= 1

                logger.info("[%s] %s: %d findings in %.1f min",
                            result.status, target,
                            len(result.findings), result.elapsed_seconds / 60)

                if on_target_complete:
                    try:
                        await on_target_complete(target, result)
                    except Exception as e:
                        logger.debug("Target complete callback error: %s", e)

    def get_summary(self) -> dict:
        """Get summary of all hunt results."""
        completed = [r for r in self.results.values() if r.status == "completed"]
        failed = [r for r in self.results.values() if r.status == "failed"]
        total_findings = sum(len(r.findings) for r in self.results.values())
        elapsed = time.monotonic() - self._start_time if self._start_time else 0

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in self.results.values():
            for f in r.findings:
                sev = f.get("severity", "info").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1

        return {
            "total_targets": len(self.results),
            "completed": len(completed),
            "failed": len(failed),
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "elapsed_minutes": elapsed / 60,
            "targets": {t: r.to_dict() for t, r in self.results.items()},
        }

    @staticmethod
    def load_targets_file(path: str) -> List[str]:
        """Load targets from a text file (one URL per line).

        Skips blank lines and lines starting with #.
        """
        targets = []
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                # Ensure scheme
                if not line.startswith(("http://", "https://")):
                    line = "https://" + line
                targets.append(line)
        return targets
