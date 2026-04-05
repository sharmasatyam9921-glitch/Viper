#!/usr/bin/env python3
"""
VIPER 5.0 — Training Mode (CTF Auto-Tune)

Runs VIPER against known-vulnerable targets (local vuln_server or external
CTF labs), measures detection rate per iteration, and adjusts Q-learning
parameters to maximize future performance.

Usage:
    python viper.py --train                           # Default: 3 iterations
    python viper.py --train --train-iterations 5      # Custom iterations
    python viper.py --train --train-minutes 10        # Time per run

Each iteration:
  1. Starts the local vuln_server (if needed)
  2. Runs a full VIPER hunt against it
  3. Scores found vs expected vulnerabilities
  4. Logs detection rate, false positives, missed vulns
  5. Q-table from successful runs is persisted for future hunts

After all iterations, prints a summary showing improvement trends.
"""

import asyncio
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from http.server import HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("viper.training_mode")

HACKAGENT_DIR = Path(__file__).parent.parent
MODELS_DIR = HACKAGENT_DIR / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

TRAINING_LOG = MODELS_DIR / "training_log.json"


@dataclass
class IterationResult:
    """Result of a single training iteration."""

    iteration: int
    detection_rate: float
    found: List[str]
    missed: List[str]
    false_positives: List[str]
    total_findings: int
    elapsed_seconds: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "iteration": self.iteration,
            "detection_rate": self.detection_rate,
            "found": self.found,
            "missed": self.missed,
            "false_positives": self.false_positives,
            "total_findings": self.total_findings,
            "elapsed_seconds": self.elapsed_seconds,
            "timestamp": self.timestamp,
        }


@dataclass
class TrainingReport:
    """Summary of a training session."""

    target_name: str
    iterations: List[IterationResult]
    improvement: float
    final_rate: float
    best_rate: float
    avg_rate: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_name": self.target_name,
            "iterations": [i.to_dict() for i in self.iterations],
            "improvement": self.improvement,
            "final_rate": self.final_rate,
            "best_rate": self.best_rate,
            "avg_rate": self.avg_rate,
            "timestamp": self.timestamp,
        }

    def print_summary(self):
        """Print a human-readable training summary."""
        print("\n" + "=" * 60)
        print(f"  VIPER Training Report — {self.target_name}")
        print("=" * 60)
        for r in self.iterations:
            bar = "#" * int(r.detection_rate / 5) + "." * (20 - int(r.detection_rate / 5))
            print(
                f"  Iteration {r.iteration}: {r.detection_rate:5.1f}% [{bar}] "
                f"({len(r.found)} found, {len(r.missed)} missed, "
                f"{len(r.false_positives)} FP)"
            )
        print("-" * 60)
        print(f"  Improvement: {self.improvement:+.1f}%")
        print(f"  Best rate:   {self.best_rate:.1f}%")
        print(f"  Final rate:  {self.final_rate:.1f}%")
        print(f"  Average:     {self.avg_rate:.1f}%")
        if self.iterations:
            last = self.iterations[-1]
            if last.missed:
                print(f"  Still missed: {', '.join(last.missed[:10])}")
            if last.false_positives:
                print(f"  False positives: {', '.join(last.false_positives[:10])}")
        print("=" * 60)


# ═══════════════════════════════════════════════════════════════
# Training Target Definitions
# ═══════════════════════════════════════════════════════════════

TRAINING_TARGETS: Dict[str, Dict[str, Any]] = {
    "local_vuln_server": {
        "url": "http://localhost:{port}",
        "server_module": "tests.vuln_server",
        "default_port": 9999,
        "description": "Built-in vulnerable test server (14 vulns)",
        "expected_vulns": [
            "xss_reflected",
            "sqli_error",
            "cors_misconfig",
            "security_headers_missing",
            "dir_listing",
            "csrf_token_leak",
            "open_redirect",
            "ssti_basic",
            "debug_endpoints",
            "env_file",
            "git_exposure",
            "lfi_basic",
            "header_injection",
            "info_disclosure",
        ],
        # Mapping from expected vuln names to patterns that match VIPER's
        # finding types (vuln_type, attack, or details fields).
        "vuln_patterns": {
            "xss_reflected": ["xss", "cross_site_scripting", "reflected"],
            "sqli_error": ["sqli", "sql_injection", "sql", "database_error"],
            "cors_misconfig": ["cors", "cross_origin"],
            "security_headers_missing": [
                "security_header",
                "missing_header",
                "clickjacking",
                "x-frame",
                "csp",
                "content_security",
            ],
            "dir_listing": ["directory_listing", "dir_listing", "index_of"],
            "csrf_token_leak": ["csrf", "cross_site_request"],
            "open_redirect": ["open_redirect", "redirect", "unvalidated"],
            "ssti_basic": ["ssti", "template_injection", "server_side_template"],
            "debug_endpoints": ["debug", "server_status", "actuator"],
            "env_file": ["env_file", "env_exposure", "dotenv", "environment"],
            "git_exposure": ["git_exposure", "git_config", "source_code"],
            "lfi_basic": ["lfi", "local_file", "path_traversal", "file_inclusion"],
            "header_injection": ["header_injection", "host_injection", "host_header"],
            "info_disclosure": [
                "info_disclosure",
                "information_disclosure",
                "error_message",
                "stack_trace",
                "traceback",
                "version_disclosure",
            ],
        },
    },
}


class TrainingMode:
    """Train VIPER against known-vulnerable targets to auto-tune Q-tables.

    Runs iterative hunts, measures detection rate, and persists Q-learning
    data from the best-performing iteration for future hunts.
    """

    def __init__(self):
        self.training_history: List[Dict] = []
        self._load_history()

    def _load_history(self):
        """Load previous training runs from disk."""
        if TRAINING_LOG.exists():
            try:
                self.training_history = json.loads(
                    TRAINING_LOG.read_text(encoding="utf-8")
                )
            except (json.JSONDecodeError, OSError):
                self.training_history = []

    def _save_history(self, report: TrainingReport):
        """Append a training report to the log."""
        self.training_history.append(report.to_dict())
        try:
            TRAINING_LOG.write_text(
                json.dumps(self.training_history, indent=2, default=str),
                encoding="utf-8",
            )
        except OSError as e:
            logger.warning("Failed to save training log: %s", e)

    async def train(
        self,
        target_name: str = "local_vuln_server",
        iterations: int = 3,
        minutes_per_run: int = 8,
        port: Optional[int] = None,
    ) -> TrainingReport:
        """Run training iterations and measure improvement.

        Args:
            target_name: Key in TRAINING_TARGETS.
            iterations: Number of hunt iterations to run.
            minutes_per_run: Time budget per iteration.
            port: Override port for local server.

        Returns:
            TrainingReport with per-iteration results and improvement metrics.
        """
        if target_name not in TRAINING_TARGETS:
            raise ValueError(
                f"Unknown training target: {target_name}. "
                f"Available: {', '.join(TRAINING_TARGETS.keys())}"
            )

        target_def = TRAINING_TARGETS[target_name]
        actual_port = port or target_def.get("default_port", 9999)
        target_url = target_def["url"].format(port=actual_port)
        expected = set(target_def["expected_vulns"])
        patterns = target_def.get("vuln_patterns", {})

        print(f"\n[TRAIN] Starting training against '{target_name}'")
        print(f"[TRAIN] Target: {target_url}")
        print(f"[TRAIN] Expected vulns: {len(expected)}")
        print(f"[TRAIN] Iterations: {iterations}, {minutes_per_run} min each")
        print("-" * 50)

        results: List[IterationResult] = []

        for i in range(iterations):
            print(f"\n[TRAIN] === Iteration {i + 1}/{iterations} ===")

            # Start local server if needed
            server = None
            if "server_module" in target_def:
                server = self._start_local_server(target_def, actual_port)
                if server is None:
                    print("[TRAIN] Failed to start local server, aborting")
                    break

            try:
                # Run VIPER hunt
                start_ts = time.time()
                hunt_result = await self._run_hunt(target_url, minutes_per_run)
                elapsed = time.time() - start_ts

                # Score the results
                findings = hunt_result.get("findings", [])
                found, missed, false_positives = self._score_findings(
                    findings, expected, patterns
                )

                rate = len(found) / len(expected) * 100 if expected else 0.0

                result = IterationResult(
                    iteration=i + 1,
                    detection_rate=rate,
                    found=sorted(found),
                    missed=sorted(missed),
                    false_positives=sorted(false_positives),
                    total_findings=len(findings),
                    elapsed_seconds=elapsed,
                )
                results.append(result)

                print(
                    f"[TRAIN] Detection: {rate:.1f}% "
                    f"({len(found)}/{len(expected)} expected, "
                    f"{len(false_positives)} FP, {elapsed:.0f}s)"
                )
                if missed:
                    print(f"[TRAIN] Missed: {', '.join(sorted(missed)[:8])}")

                # Save Q-table from best iteration
                if rate > 0:
                    self._save_iteration_qtable(hunt_result, i + 1, rate)

            finally:
                if server:
                    self._stop_server(server)

        # Build report
        if not results:
            return TrainingReport(
                target_name=target_name,
                iterations=[],
                improvement=0.0,
                final_rate=0.0,
                best_rate=0.0,
                avg_rate=0.0,
            )

        rates = [r.detection_rate for r in results]
        report = TrainingReport(
            target_name=target_name,
            iterations=results,
            improvement=rates[-1] - rates[0] if len(rates) > 1 else 0.0,
            final_rate=rates[-1],
            best_rate=max(rates),
            avg_rate=sum(rates) / len(rates),
        )

        report.print_summary()
        self._save_history(report)

        return report

    async def _run_hunt(self, target_url: str, max_minutes: int) -> Dict:
        """Run a single VIPER hunt iteration."""
        try:
            # Import here to avoid circular imports
            from viper_core import ViperCore

            viper = ViperCore()
            # Disable optional modules for faster training runs
            viper.secret_scanner = None
            viper.gvm_scanner = None

            result = await viper.full_hunt(
                target_url=target_url, max_minutes=max_minutes
            )
            return result or {}
        except Exception as e:
            logger.error("Hunt iteration failed: %s", e)
            print(f"[TRAIN] Hunt error: {e}")
            return {"findings": []}

    def _score_findings(
        self,
        findings: List[Dict],
        expected: Set[str],
        patterns: Dict[str, List[str]],
    ) -> Tuple[Set[str], Set[str], Set[str]]:
        """Score findings against expected vulnerabilities.

        Uses fuzzy matching: a finding matches an expected vuln if any of the
        vuln's patterns appear in the finding's type/attack/details fields.

        Returns:
            (found, missed, false_positives)
        """
        found: Set[str] = set()
        matched_findings: Set[int] = set()

        # Build a text blob per finding for pattern matching
        finding_texts: List[str] = []
        for f in findings:
            text = " ".join(
                str(f.get(k, "")).lower()
                for k in ("vuln_type", "attack", "type", "details", "payload")
            )
            finding_texts.append(text)

        # Check each expected vuln
        for vuln_name in expected:
            vuln_patterns = patterns.get(vuln_name, [vuln_name])
            matched = False
            for idx, text in enumerate(finding_texts):
                for pattern in vuln_patterns:
                    if pattern.lower() in text:
                        found.add(vuln_name)
                        matched_findings.add(idx)
                        matched = True
                        break
                if matched:
                    break

        missed = expected - found

        # False positives: findings that didn't match any expected vuln
        # (Only count significant findings, not info-level noise)
        false_positives: Set[str] = set()
        for idx, f in enumerate(findings):
            if idx not in matched_findings:
                severity = f.get("severity", "info").lower()
                if severity in ("critical", "high", "medium"):
                    fp_name = f.get("vuln_type", f.get("attack", f"finding_{idx}"))
                    false_positives.add(str(fp_name))

        return found, missed, false_positives

    def _start_local_server(
        self, target_def: Dict, port: int
    ) -> Optional[HTTPServer]:
        """Start the local vulnerable test server in a background thread."""
        # Check if port is already in use
        if self._port_in_use(port):
            print(f"[TRAIN] Port {port} already in use — assuming server is running")
            return None  # Return None but don't fail — server may be external

        try:
            # Import the vuln server module
            sys.path.insert(0, str(HACKAGENT_DIR))
            from tests.vuln_server import VulnHandler

            server = HTTPServer(("127.0.0.1", port), VulnHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            # Wait for server to be ready
            for _ in range(20):
                if self._port_in_use(port):
                    print(f"[TRAIN] Local vuln server started on port {port}")
                    return server
                time.sleep(0.1)

            print(f"[TRAIN] Server started but port {port} not responding")
            return server
        except Exception as e:
            logger.error("Failed to start local server: %s", e)
            print(f"[TRAIN] Server start failed: {e}")
            return None

    def _stop_server(self, server: HTTPServer):
        """Stop the local test server."""
        try:
            server.shutdown()
            print("[TRAIN] Local server stopped")
        except Exception as e:
            logger.debug("Server stop error: %s", e)

    def _port_in_use(self, port: int) -> bool:
        """Check if a port is currently in use."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.settimeout(0.5)
                s.connect(("127.0.0.1", port))
                return True
            except (ConnectionRefusedError, OSError):
                return False

    def _save_iteration_qtable(
        self, hunt_result: Dict, iteration: int, detection_rate: float
    ):
        """Save Q-table data from a hunt iteration for future use."""
        try:
            from core.evograph import EvoGraph

            evo = EvoGraph()
            session_id = evo.start_session(
                target="training_local",
                strategy=f"train_iter_{iteration}",
            )
            # Record the detection rate as the session reward
            evo.end_session(session_id, total_reward=detection_rate)
            logger.info(
                "Saved Q-table for iteration %d (rate=%.1f%%)",
                iteration,
                detection_rate,
            )
        except Exception as e:
            logger.debug("Q-table save skipped: %s", e)

    def list_targets(self) -> List[Dict[str, str]]:
        """List available training targets."""
        return [
            {
                "name": name,
                "description": t.get("description", ""),
                "expected_vulns": len(t.get("expected_vulns", [])),
            }
            for name, t in TRAINING_TARGETS.items()
        ]

    def get_history(self) -> List[Dict]:
        """Get previous training run history."""
        return self.training_history
