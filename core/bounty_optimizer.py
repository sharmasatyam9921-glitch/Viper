#!/usr/bin/env python3
"""
VIPER Bounty ROI Optimizer — Prioritize targets by expected return.

Scores bug bounty programs based on multiple weighted factors:
- Bounty range (higher max bounty = better)
- Response efficiency (faster triage = less wasted time)
- Historical success rate (from EvoGraph cross-session memory)
- Program age (newer programs = less competition)
- Asset count (more assets = more attack surface)
- Technology stack (familiar tech = higher hit rate)
- Scope breadth (wildcards = more targets)
"""

import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("viper.bounty_optimizer")

HACKAGENT_DIR = Path(__file__).parent.parent

# Average bounties by severity tier (USD) for normalization
AVG_BOUNTIES = {
    "critical": 3000,
    "high": 1000,
    "medium": 400,
    "low": 100,
}

# Technology familiarity bonus — stack we know well gets a boost
TECH_FAMILIARITY = {
    "php": 0.8, "laravel": 0.85, "wordpress": 0.9,
    "python": 0.7, "django": 0.75, "flask": 0.75,
    "node": 0.7, "express": 0.7, "nextjs": 0.65,
    "java": 0.6, "spring": 0.65,
    "ruby": 0.6, "rails": 0.65,
    "graphql": 0.85, "rest": 0.7,
    "nginx": 0.5, "apache": 0.6,
    "react": 0.4, "angular": 0.4, "vue": 0.4,
    "aws": 0.6, "azure": 0.5, "gcp": 0.5,
}


class BountyOptimizer:
    """Prioritize bug bounty targets by expected ROI.

    Scores targets based on: bounty range, response efficiency,
    historical success rate, program age, competition level,
    technology familiarity, and scope breadth.

    Args:
        evograph: Optional EvoGraph instance for historical data.
        programs_dir: Directory containing program JSON files.
    """

    def __init__(self, evograph=None,
                 programs_dir: Optional[str] = None):
        self.evograph = evograph
        self.programs_dir = Path(programs_dir) if programs_dir else HACKAGENT_DIR / "programs"

    def score_program(self, program: dict) -> float:
        """Score a program 0-100 for expected ROI.

        Weights:
        - Bounty range:       30 points max
        - Response efficiency: 20 points max
        - Historical success:  20 points max
        - Program freshness:   15 points max
        - Asset surface:       15 points max

        Args:
            program: Dict with program metadata. Expected keys:
                - bounty_range: [min, max] in USD
                - response_efficiency: 0-100 percentage
                - domain: target domain
                - launched_at: ISO date string
                - in_scope: list of scope assets
                - tech_stack: list of technology strings
                - reports_resolved: number of resolved reports
                - average_bounty: average payout (optional)

        Returns:
            Score from 0 to 100.
        """
        score = 0.0

        score += self._bounty_score(program)
        score += self._efficiency_score(program)
        score += self._historical_score(program)
        score += self._freshness_score(program)
        score += self._surface_score(program)

        return min(round(score, 2), 100.0)

    def _bounty_score(self, program: dict) -> float:
        """Score based on bounty range (max 30 points)."""
        bounty_range = program.get("bounty_range", [0, 0])
        if isinstance(bounty_range, (list, tuple)) and len(bounty_range) >= 2:
            max_bounty = bounty_range[1]
        elif isinstance(bounty_range, (int, float)):
            max_bounty = bounty_range
        else:
            max_bounty = 0

        avg_bounty = program.get("average_bounty", 0)

        # Use average if available and meaningful, otherwise max
        effective = avg_bounty if avg_bounty > 0 else max_bounty

        if effective <= 0:
            return 0.0

        # Logarithmic scale: $100=10, $1000=20, $10000=30
        import math
        raw = math.log10(max(effective, 1)) * 10
        return min(raw, 30.0)

    def _efficiency_score(self, program: dict) -> float:
        """Score based on response efficiency (max 20 points).

        Higher efficiency = faster triage = less wasted time.
        """
        efficiency = program.get("response_efficiency", 0)
        if isinstance(efficiency, str):
            try:
                efficiency = float(efficiency.strip("%"))
            except ValueError:
                efficiency = 0

        # Also factor in average triage time if available
        avg_triage_days = program.get("average_triage_days", None)
        if avg_triage_days is not None:
            # Faster triage = better. 1 day = 20pts, 7 days = 10pts, 30 days = 5pts
            if avg_triage_days <= 1:
                triage_score = 20.0
            elif avg_triage_days <= 7:
                triage_score = 20.0 - (avg_triage_days - 1) * (10.0 / 6.0)
            elif avg_triage_days <= 30:
                triage_score = 10.0 - (avg_triage_days - 7) * (5.0 / 23.0)
            else:
                triage_score = max(5.0 - (avg_triage_days - 30) * 0.1, 0)
            return min(triage_score, 20.0)

        # Fallback to efficiency percentage
        return min(efficiency * 0.2, 20.0)

    def _historical_score(self, program: dict) -> float:
        """Score based on historical success from EvoGraph (max 20 points)."""
        domain = program.get("domain", "")
        if not domain:
            # Try to extract from URL
            url = program.get("url", program.get("target", ""))
            if url:
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(url).hostname or ""
                except Exception:
                    domain = ""

        if not domain:
            return 5.0  # Unknown = neutral score

        if self.evograph is None:
            return 5.0

        try:
            success_rate = self._get_historical_success(domain)
            return min(success_rate * 20.0, 20.0)
        except Exception:
            return 5.0

    def _get_historical_success(self, domain: str) -> float:
        """Query EvoGraph for historical success rate against a domain.

        Returns float 0.0-1.0 representing success ratio.
        """
        if self.evograph is None:
            return 0.25  # Default: assume moderate success

        try:
            # Query attack history for this domain
            cursor = self.evograph.conn.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes
                FROM attack_history ah
                JOIN sessions s ON ah.session_id = s.id
                WHERE s.target LIKE ?
            """, (f"%{domain}%",))
            row = cursor.fetchone()
            if row and row["total"] > 0:
                return row["successes"] / row["total"]
        except Exception as e:
            logger.debug("EvoGraph query failed: %s", e)

        # Check for similar tech stacks
        tech_stack = self._get_program_tech(domain)
        if tech_stack:
            return self._tech_success_rate(tech_stack)

        return 0.25

    def _tech_success_rate(self, tech_stack: List[str]) -> float:
        """Get success rate for a given tech stack from EvoGraph."""
        if self.evograph is None:
            return 0.25

        try:
            placeholders = ",".join("?" * len(tech_stack))
            cursor = self.evograph.conn.execute(f"""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes
                FROM attack_history
                WHERE target_tech IN ({placeholders})
            """, tech_stack)
            row = cursor.fetchone()
            if row and row["total"] > 2:  # Need at least 3 data points
                return row["successes"] / row["total"]
        except Exception:
            pass
        return 0.25

    def _get_program_tech(self, domain: str) -> List[str]:
        """Get known tech stack for a domain from EvoGraph."""
        if self.evograph is None:
            return []
        try:
            cursor = self.evograph.conn.execute("""
                SELECT DISTINCT tech_stack FROM sessions
                WHERE target LIKE ? AND tech_stack != ''
                ORDER BY start_time DESC LIMIT 5
            """, (f"%{domain}%",))
            techs = set()
            for row in cursor:
                for t in row["tech_stack"].split(","):
                    t = t.strip().lower()
                    if t:
                        techs.add(t)
            return list(techs)
        except Exception:
            return []

    def _freshness_score(self, program: dict) -> float:
        """Score based on program age / freshness (max 15 points).

        Newer programs have less competition and more low-hanging fruit.
        """
        launched_at = program.get("launched_at", program.get("created_at", ""))
        if not launched_at:
            return 7.5  # Unknown age = neutral

        try:
            if isinstance(launched_at, str):
                # Parse ISO date
                launched = datetime.fromisoformat(launched_at.replace("Z", "+00:00"))
            else:
                launched = launched_at

            now = datetime.now(launched.tzinfo) if launched.tzinfo else datetime.now()
            age_days = (now - launched).days

            if age_days < 0:
                return 15.0  # Future launch? Max score
            elif age_days <= 30:
                return 15.0  # Brand new
            elif age_days <= 90:
                return 13.0  # Very fresh
            elif age_days <= 180:
                return 10.0
            elif age_days <= 365:
                return 7.0
            elif age_days <= 730:
                return 4.0
            else:
                return 2.0  # Old program, heavily picked over

        except (ValueError, TypeError):
            return 7.5

    def _surface_score(self, program: dict) -> float:
        """Score based on attack surface size (max 15 points).

        More assets + wildcards = more opportunities.
        """
        in_scope = program.get("in_scope", [])
        if not in_scope:
            return 3.0

        asset_count = 0
        wildcard_count = 0
        web_count = 0

        for asset in in_scope:
            if isinstance(asset, dict):
                identifier = asset.get("asset_identifier", "")
                asset_type = asset.get("asset_type", "").lower()
            else:
                identifier = str(asset)
                asset_type = "url"

            asset_count += 1
            if "*" in identifier:
                wildcard_count += 1
            if asset_type in ("url", "domain", "wildcard", ""):
                web_count += 1

        # Base score from asset count
        base = min(asset_count * 1.5, 8.0)
        # Wildcard bonus (each wildcard is effectively many domains)
        wildcard_bonus = min(wildcard_count * 3, 5.0)
        # Web asset ratio bonus
        web_ratio = web_count / max(asset_count, 1)
        web_bonus = web_ratio * 2.0  # Max 2 points

        return min(base + wildcard_bonus + web_bonus, 15.0)

    def rank_targets(self, programs: List[dict]) -> List[dict]:
        """Rank programs by ROI score, highest first.

        Enriches each program dict with roi_score and roi_breakdown.

        Args:
            programs: List of program dicts.

        Returns:
            Sorted list with roi_score and roi_breakdown added.
        """
        for p in programs:
            p["roi_score"] = self.score_program(p)
            p["roi_breakdown"] = {
                "bounty": round(self._bounty_score(p), 1),
                "efficiency": round(self._efficiency_score(p), 1),
                "historical": round(self._historical_score(p), 1),
                "freshness": round(self._freshness_score(p), 1),
                "surface": round(self._surface_score(p), 1),
            }

        return sorted(programs, key=lambda p: p["roi_score"], reverse=True)

    def tech_affinity_bonus(self, program: dict) -> float:
        """Calculate bonus score based on tech stack familiarity.

        Not included in main score but useful for secondary ranking.
        Returns 0.0-1.0.
        """
        tech_stack = program.get("tech_stack", [])
        if isinstance(tech_stack, str):
            tech_stack = [t.strip().lower() for t in tech_stack.split(",")]
        elif isinstance(tech_stack, list):
            tech_stack = [str(t).lower() for t in tech_stack]
        else:
            return 0.0

        if not tech_stack:
            return 0.0

        scores = []
        for tech in tech_stack:
            for key, score in TECH_FAMILIARITY.items():
                if key in tech:
                    scores.append(score)
                    break

        return sum(scores) / len(scores) if scores else 0.0

    def recommend_targets(self, programs: List[dict], top_n: int = 5) -> List[dict]:
        """Get top N recommended programs with reasoning.

        Args:
            programs: List of program dicts.
            top_n: Number of recommendations to return.

        Returns:
            List of top N programs with added recommendation reasoning.
        """
        ranked = self.rank_targets(programs)

        for p in ranked[:top_n]:
            reasons = []
            breakdown = p.get("roi_breakdown", {})

            if breakdown.get("bounty", 0) >= 20:
                bounty_range = p.get("bounty_range", [0, 0])
                max_b = bounty_range[1] if isinstance(bounty_range, (list, tuple)) and len(bounty_range) >= 2 else 0
                reasons.append(f"High bounties (up to ${max_b:,})")
            if breakdown.get("efficiency", 0) >= 15:
                reasons.append("Fast triage response")
            if breakdown.get("freshness", 0) >= 12:
                reasons.append("Recently launched (less competition)")
            if breakdown.get("surface", 0) >= 10:
                reasons.append("Large attack surface")
            if breakdown.get("historical", 0) >= 12:
                reasons.append("Strong historical success rate")

            affinity = self.tech_affinity_bonus(p)
            if affinity >= 0.6:
                reasons.append("Familiar technology stack")

            if not reasons:
                reasons.append("Balanced opportunity")

            p["recommendation_reasons"] = reasons

        return ranked[:top_n]

    def load_programs(self) -> List[dict]:
        """Load program definitions from the programs directory.

        Reads all JSON files from programs_dir.
        """
        programs = []
        if not self.programs_dir.exists():
            logger.warning("Programs directory not found: %s", self.programs_dir)
            return programs

        for f in sorted(self.programs_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                if isinstance(data, list):
                    programs.extend(data)
                elif isinstance(data, dict):
                    if "programs" in data:
                        programs.extend(data["programs"])
                    else:
                        data.setdefault("_source_file", str(f))
                        programs.append(data)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to load program file %s: %s", f, e)

        return programs

    def print_rankings(self, programs: List[dict], top_n: int = 10):
        """Print a formatted ranking table to stdout."""
        ranked = self.recommend_targets(programs, top_n=top_n)
        print(f"\n{'='*80}")
        print(f"  VIPER Bounty ROI Rankings — Top {min(top_n, len(ranked))} Programs")
        print(f"{'='*80}\n")
        print(f"  {'#':>3}  {'Score':>5}  {'Program':<30}  {'Reasons'}")
        print(f"  {'─'*3}  {'─'*5}  {'─'*30}  {'─'*40}")

        for i, p in enumerate(ranked, 1):
            name = p.get("name", p.get("handle", p.get("domain", "unknown")))[:28]
            score = p.get("roi_score", 0)
            reasons = ", ".join(p.get("recommendation_reasons", []))
            print(f"  {i:>3}  {score:>5.1f}  {name:<30}  {reasons}")

        print()
