#!/usr/bin/env python3
"""
VIPER Cross-Target Correlator — Find the same vulnerability class across targets.

When a new finding is confirmed, checks viper_db for the same vulnerability
class across all historical targets and suggests probing similar targets.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.cross_target_correlator")


@dataclass
class SimilarTarget:
    """A target that may have the same vulnerability."""
    target: str
    vuln_type: str
    similarity_score: float
    shared_tech: List[str] = field(default_factory=list)
    original_finding_target: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "vuln_type": self.vuln_type,
            "similarity_score": self.similarity_score,
            "shared_tech": self.shared_tech,
            "original_finding_target": self.original_finding_target,
            "note": self.note,
        }


class CrossTargetCorrelator:
    """Correlate findings across multiple targets.

    On each new finding, queries viper_db for the same vulnerability
    class and tech stack across all historical targets, returning
    similar targets that might be vulnerable to the same attack.

    Args:
        viper_db: Instance of ViperDB for querying historical data.
        evograph: Optional EvoGraph for tech-stack correlation.
    """

    def __init__(self, viper_db: Any = None, evograph: Any = None):
        self.viper_db = viper_db
        self.evograph = evograph

    def correlate_finding(self, finding: dict) -> List[SimilarTarget]:
        """Find targets that may share the same vulnerability.

        Args:
            finding: Dict with keys: vuln_type, target_url, technologies (optional).

        Returns:
            List of SimilarTarget objects for targets worth probing.
        """
        vuln_type = finding.get("vuln_type", "")
        target_url = finding.get("target_url", "")
        technologies = finding.get("technologies", [])

        similar: List[SimilarTarget] = []

        if not self.viper_db or not vuln_type:
            return similar

        try:
            # Query viper_db for targets with same tech stack
            if hasattr(self.viper_db, "conn"):
                conn = self.viper_db.conn

                # Find targets with same tech stack
                if technologies:
                    for tech in technologies:
                        rows = conn.execute(
                            "SELECT DISTINCT target FROM targets WHERE tech_stack LIKE ? "
                            "AND target != ?",
                            (f"%{tech}%", target_url),
                        ).fetchall()

                        for row in rows:
                            other_target = row[0] if isinstance(row, tuple) else row["target"]
                            similar.append(SimilarTarget(
                                target=other_target,
                                vuln_type=vuln_type,
                                similarity_score=0.6,
                                shared_tech=[tech],
                                original_finding_target=target_url,
                                note=f"Correlated from {target_url} — shared technology: {tech}",
                            ))

                # Find targets where the same attack type succeeded before
                rows = conn.execute(
                    "SELECT DISTINCT target FROM findings WHERE type = ? AND target != ?",
                    (vuln_type, target_url),
                ).fetchall()

                for row in rows:
                    other_target = row[0] if isinstance(row, tuple) else row.get("target", "")
                    if other_target and not any(s.target == other_target for s in similar):
                        similar.append(SimilarTarget(
                            target=other_target,
                            vuln_type=vuln_type,
                            similarity_score=0.8,
                            original_finding_target=target_url,
                            note=f"Same vuln type previously found on this target",
                        ))

        except Exception as exc:
            logger.debug("Correlation query failed: %s", exc)

        # Also check evograph for tech-attack correlation
        if self.evograph and technologies:
            try:
                best_attacks = self.evograph.get_best_attacks_for_tech(technologies, top_n=5)
                for attack in best_attacks:
                    if attack["attack_type"] == vuln_type and attack["success_rate"] > 0.3:
                        # This attack type works well on this tech stack
                        for s in similar:
                            s.similarity_score = min(1.0, s.similarity_score + 0.1)
            except Exception as exc:
                logger.debug("EvoGraph correlation failed: %s", exc)

        # Deduplicate and sort by similarity
        seen = set()
        unique: List[SimilarTarget] = []
        for s in similar:
            if s.target not in seen:
                seen.add(s.target)
                unique.append(s)

        unique.sort(key=lambda s: s.similarity_score, reverse=True)
        return unique[:20]  # cap results

    async def auto_probe_similar(
        self,
        finding: dict,
        targets: List[SimilarTarget],
        agent_bus: Any = None,
    ) -> List[dict]:
        """Automatically probe similar targets for the same vulnerability.

        Publishes probing requests to the agent bus exploit topic.

        Args:
            finding: The original finding dict.
            targets: List of SimilarTarget to probe.
            agent_bus: AgentBus instance for publishing.

        Returns:
            List of probing payloads that were published.
        """
        probed: List[dict] = []

        if not agent_bus:
            return probed

        for target in targets:
            if target.similarity_score < 0.5:
                continue  # Skip low-confidence correlations

            probe_payload = {
                "target_url": target.target,
                "vuln_type": target.vuln_type,
                "confidence": target.similarity_score,
                "evidence": [],
                "correlated_from": target.original_finding_target,
                "note": target.note,
            }

            try:
                from core.agent_bus import Priority
                await agent_bus.publish(
                    topic="exploit",
                    payload=probe_payload,
                    priority=Priority.LOW,
                    agent_id="correlator",
                )
                probed.append(probe_payload)
                logger.info(
                    "Published correlation probe: %s on %s (score=%.2f)",
                    target.vuln_type, target.target, target.similarity_score,
                )
            except Exception as exc:
                logger.debug("Failed to publish probe: %s", exc)

        return probed


__all__ = ["CrossTargetCorrelator", "SimilarTarget"]
