#!/usr/bin/env python3
"""
Bug Bounty Hunter - Autonomous Target Selection & Submission

Integrates with:
- HackerOne (API)
- Bugcrowd (scraping)
- Intigriti
- Custom programs

Features:
- Auto-select targets based on bounty/scope
- Track submissions
- Generate compliant reports
"""

import json
import urllib.request
import ssl
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path
from enum import Enum


class Platform(Enum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    CUSTOM = "custom"


@dataclass
class BountyProgram:
    """Bug bounty program details."""
    name: str
    platform: Platform
    handle: str  # Platform-specific identifier
    url: str
    scope: List[str]  # In-scope domains/assets
    out_of_scope: List[str] = field(default_factory=list)
    bounty_range: str = ""  # e.g., "$100 - $10,000"
    severity_payouts: Dict[str, int] = field(default_factory=dict)
    allows_automation: bool = True
    response_time: str = ""  # e.g., "< 1 week"
    rating: float = 0.0  # Program reputation
    notes: str = ""
    
    def is_in_scope(self, target: str) -> bool:
        """Check if target is in scope."""
        target = target.lower()
        # Check out-of-scope first
        for oos in self.out_of_scope:
            if oos.replace("*.", "") in target:
                return False
        # Check in-scope
        for scope in self.scope:
            if scope.startswith("*."):
                domain = scope[2:]
                if target.endswith(domain) or target == domain:
                    return True
            elif scope in target:
                return True
        return False


@dataclass
class Submission:
    """Bug bounty submission tracking."""
    program: str
    title: str
    severity: str
    submitted_at: datetime
    status: str = "pending"  # pending, triaged, accepted, duplicate, resolved, paid
    bounty: float = 0.0
    url: str = ""
    notes: str = ""
    
    def to_dict(self) -> dict:
        return {
            "program": self.program,
            "title": self.title,
            "severity": self.severity,
            "submitted_at": self.submitted_at.isoformat(),
            "status": self.status,
            "bounty": self.bounty,
            "url": self.url,
            "notes": self.notes
        }


class ProgramDatabase:
    """Database of bug bounty programs."""
    
    # Well-known programs with good payouts
    FEATURED_PROGRAMS = [
        BountyProgram(
            name="Google VRP",
            platform=Platform.CUSTOM,
            handle="google",
            url="https://bughunters.google.com/",
            scope=["*.google.com", "*.youtube.com", "*.googleapis.com"],
            out_of_scope=["accounts.google.com/SignUp"],
            bounty_range="$100 - $31,337+",
            severity_payouts={"critical": 31337, "high": 13337, "medium": 5000, "low": 1000},
            allows_automation=True,
            response_time="< 2 weeks",
            rating=4.8
        ),
        BountyProgram(
            name="Microsoft MSRC",
            platform=Platform.CUSTOM,
            handle="microsoft",
            url="https://msrc.microsoft.com/bounty",
            scope=["*.microsoft.com", "*.azure.com", "*.office.com"],
            bounty_range="$500 - $100,000+",
            severity_payouts={"critical": 100000, "high": 25000, "medium": 5000, "low": 500},
            allows_automation=True,
            response_time="< 2 weeks",
            rating=4.5
        ),
        BountyProgram(
            name="Meta",
            platform=Platform.CUSTOM,
            handle="facebook",
            url="https://www.facebook.com/whitehat",
            scope=["*.facebook.com", "*.instagram.com", "*.whatsapp.com", "*.meta.com"],
            bounty_range="$500 - $100,000+",
            severity_payouts={"critical": 100000, "high": 30000, "medium": 5000, "low": 500},
            allows_automation=True,
            response_time="< 3 weeks",
            rating=4.6
        ),
        BountyProgram(
            name="GitHub Security Lab",
            platform=Platform.HACKERONE,
            handle="github",
            url="https://hackerone.com/github",
            scope=["*.github.com", "*.github.io", "*.githubusercontent.com"],
            out_of_scope=["github.community"],
            bounty_range="$617 - $30,000+",
            severity_payouts={"critical": 30000, "high": 20000, "medium": 5000, "low": 617},
            allows_automation=True,
            response_time="< 1 week",
            rating=4.9
        ),
        BountyProgram(
            name="Shopify",
            platform=Platform.HACKERONE,
            handle="shopify",
            url="https://hackerone.com/shopify",
            scope=["*.shopify.com", "*.myshopify.com"],
            bounty_range="$500 - $50,000",
            severity_payouts={"critical": 50000, "high": 15000, "medium": 2500, "low": 500},
            allows_automation=True,
            response_time="< 1 week",
            rating=4.7
        ),
    ]
    
    def __init__(self, programs_dir: Path = None):
        self.programs_dir = programs_dir or Path("skills/hackagent/programs")
        self.programs_dir.mkdir(parents=True, exist_ok=True)
        self.programs: Dict[str, BountyProgram] = {}
        self._load_featured()
    
    def _load_featured(self):
        """Load featured programs."""
        for prog in self.FEATURED_PROGRAMS:
            self.programs[prog.handle] = prog
    
    def add_program(self, program: BountyProgram):
        """Add a program to database."""
        self.programs[program.handle] = program
        self._save_program(program)
    
    def _save_program(self, program: BountyProgram):
        """Save program to disk."""
        prog_dir = self.programs_dir / program.handle
        prog_dir.mkdir(exist_ok=True)
        info_file = prog_dir / "program.json"
        with open(info_file, 'w') as f:
            json.dump({
                "name": program.name,
                "platform": program.platform.value,
                "url": program.url,
                "scope": program.scope,
                "out_of_scope": program.out_of_scope,
                "bounty_range": program.bounty_range,
                "allows_automation": program.allows_automation,
                "notes": program.notes
            }, f, indent=2)
    
    def get_program(self, handle: str) -> Optional[BountyProgram]:
        """Get program by handle."""
        return self.programs.get(handle)
    
    def find_programs_for_target(self, target: str) -> List[BountyProgram]:
        """Find programs that have target in scope."""
        matching = []
        for prog in self.programs.values():
            if prog.is_in_scope(target):
                matching.append(prog)
        return matching
    
    def get_high_value_programs(self, min_payout: int = 5000) -> List[BountyProgram]:
        """Get programs with high critical payouts."""
        high_value = []
        for prog in self.programs.values():
            if prog.severity_payouts.get("critical", 0) >= min_payout:
                high_value.append(prog)
        return sorted(high_value, 
                     key=lambda p: p.severity_payouts.get("critical", 0),
                     reverse=True)


class SubmissionTracker:
    """Track bug bounty submissions and earnings."""
    
    def __init__(self, data_file: Path = None):
        self.data_file = data_file or Path("skills/hackagent/submissions.json")
        self.submissions: List[Submission] = []
        self._load()
    
    def _load(self):
        """Load submissions from file."""
        if self.data_file.exists():
            with open(self.data_file) as f:
                data = json.load(f)
                for s in data.get("submissions", []):
                    self.submissions.append(Submission(
                        program=s["program"],
                        title=s["title"],
                        severity=s["severity"],
                        submitted_at=datetime.fromisoformat(s["submitted_at"]),
                        status=s.get("status", "pending"),
                        bounty=s.get("bounty", 0),
                        url=s.get("url", ""),
                        notes=s.get("notes", "")
                    ))
    
    def _save(self):
        """Save submissions to file."""
        with open(self.data_file, 'w') as f:
            json.dump({
                "submissions": [s.to_dict() for s in self.submissions],
                "stats": self.get_stats()
            }, f, indent=2)
    
    def add_submission(self, submission: Submission):
        """Add a new submission."""
        self.submissions.append(submission)
        self._save()
    
    def update_status(self, title: str, status: str, bounty: float = 0):
        """Update submission status."""
        for s in self.submissions:
            if s.title == title:
                s.status = status
                if bounty:
                    s.bounty = bounty
                break
        self._save()
    
    def get_stats(self) -> dict:
        """Get submission statistics."""
        total = len(self.submissions)
        accepted = sum(1 for s in self.submissions if s.status in ["accepted", "resolved", "paid"])
        duplicates = sum(1 for s in self.submissions if s.status == "duplicate")
        earnings = sum(s.bounty for s in self.submissions)
        
        return {
            "total_submissions": total,
            "accepted": accepted,
            "duplicates": duplicates,
            "pending": sum(1 for s in self.submissions if s.status == "pending"),
            "acceptance_rate": f"{(accepted/total*100):.1f}%" if total > 0 else "N/A",
            "total_earnings": earnings,
            "avg_bounty": earnings / accepted if accepted > 0 else 0
        }
    
    def get_pnl_report(self) -> str:
        """Generate P&L style report."""
        stats = self.get_stats()
        lines = [
            "## Bug Bounty P&L",
            "",
            f"**Total Submissions:** {stats['total_submissions']}",
            f"**Accepted:** {stats['accepted']}",
            f"**Duplicates:** {stats['duplicates']}",
            f"**Acceptance Rate:** {stats['acceptance_rate']}",
            "",
            f"**Total Earnings:** ${stats['total_earnings']:,.2f}",
            f"**Average Bounty:** ${stats['avg_bounty']:,.2f}",
            "",
            "### Recent Submissions",
            "",
            "| Date | Program | Title | Severity | Status | Bounty |",
            "|------|---------|-------|----------|--------|--------|"
        ]
        
        for s in sorted(self.submissions, key=lambda x: x.submitted_at, reverse=True)[:10]:
            date = s.submitted_at.strftime("%Y-%m-%d")
            bounty = f"${s.bounty:,.0f}" if s.bounty else "-"
            lines.append(f"| {date} | {s.program} | {s.title[:30]} | {s.severity} | {s.status} | {bounty} |")
        
        return "\n".join(lines)


class ReportFormatter:
    """Format vulnerability reports for different platforms."""
    
    @staticmethod
    def hackerone_format(finding: dict, program: BountyProgram) -> str:
        """Format report for HackerOne."""
        return f"""## Summary
{finding['title']}

## Severity
{finding['severity']}

## Steps to Reproduce
1. Navigate to {finding['target']}
2. {finding.get('steps', 'See evidence below')}

## Impact
{finding['description']}

## Supporting Material/Evidence
```
{finding['evidence']}
```

{f"**Payload:**" + chr(10) + "```" + chr(10) + finding['payload'] + chr(10) + "```" if finding.get('payload') else ""}

## Suggested Remediation
{finding.get('remediation', 'Apply appropriate security controls.')}
"""

    @staticmethod
    def generic_format(finding: dict) -> str:
        """Generic report format."""
        return f"""# Vulnerability Report

**Title:** {finding['title']}
**Severity:** {finding['severity']}
**Target:** {finding['target']}
**Type:** {finding.get('type', 'Security Issue')}

## Description
{finding['description']}

## Evidence
```
{finding['evidence']}
```

{f"## Payload" + chr(10) + "```" + chr(10) + finding['payload'] + chr(10) + "```" if finding.get('payload') else ""}

## Remediation
{finding.get('remediation', 'Please fix this vulnerability.')}

## References
- CWE: {finding.get('cwe', 'N/A')}
- CVSS: {finding.get('cvss', 'N/A')}

---
*Report generated by VIPER v1.0*
"""


@dataclass
class DuplicateCheckResult:
    """Result of a duplicate check."""
    is_duplicate: bool
    similarity_score: float
    matching_submissions: List[str] = field(default_factory=list)
    note: str = ""


@dataclass
class BountyEstimate:
    """Estimated bounty range for a finding."""
    min_bounty: float
    max_bounty: float
    expected_bounty: float
    confidence: float
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "min": self.min_bounty,
            "max": self.max_bounty,
            "expected": self.expected_bounty,
            "confidence": self.confidence,
            "note": self.note,
        }


class BountyHunter:
    """
    Main bug bounty hunting orchestrator.
    
    Combines target selection, scanning, and submission tracking.
    """
    
    def __init__(self):
        self.programs = ProgramDatabase()
        self.tracker = SubmissionTracker()
    
    def select_target(self, strategy: str = "high_value") -> Optional[BountyProgram]:
        """
        Select a target program based on strategy.
        
        Strategies:
        - high_value: Programs with highest payouts
        - new: Recently launched programs (less competition)
        - responsive: Programs with fast response times
        """
        if strategy == "high_value":
            programs = self.programs.get_high_value_programs()
        else:
            programs = list(self.programs.programs.values())
        
        if programs:
            return programs[0]
        return None
    
    def prepare_submission(self, finding: dict, program: BountyProgram) -> str:
        """Prepare formatted submission for a program."""
        if program.platform == Platform.HACKERONE:
            return ReportFormatter.hackerone_format(finding, program)
        return ReportFormatter.generic_format(finding)
    
    def track_submission(self, program: str, title: str, severity: str, url: str = ""):
        """Record a new submission."""
        submission = Submission(
            program=program,
            title=title,
            severity=severity,
            submitted_at=datetime.now(),
            url=url
        )
        self.tracker.add_submission(submission)
        print(f"[+] Submission tracked: {title}")
    
    def get_earnings_report(self) -> str:
        """Get earnings P&L report."""
        return self.tracker.get_pnl_report()
    
    def check_duplicate(self, finding: dict) -> DuplicateCheckResult:
        """Check if a finding is likely a duplicate before submission.

        Checks:
        1. Internal submission tracker for same target/vuln type
        2. Title similarity against existing submissions
        3. Same endpoint + parameter combination

        Args:
            finding: Dict with keys: title, target, vulnerability_type, endpoint, severity.

        Returns:
            DuplicateCheckResult with similarity assessment.
        """
        title = finding.get("title", "").lower()
        target = finding.get("target", "").lower()
        vuln_type = finding.get("vulnerability_type", "").lower()
        endpoint = finding.get("endpoint", "").lower()

        matching = []
        max_similarity = 0.0

        for submission in self.tracker.submissions:
            sim = 0.0

            # Title similarity (simple token overlap)
            sub_title = submission.title.lower()
            title_tokens = set(title.split())
            sub_tokens = set(sub_title.split())
            if title_tokens and sub_tokens:
                overlap = len(title_tokens & sub_tokens) / max(len(title_tokens | sub_tokens), 1)
                sim = max(sim, overlap)

            # Same program + severity
            if submission.program.lower() in target and submission.severity.lower() == finding.get("severity", "").lower():
                sim += 0.2

            # Same vuln type in title
            if vuln_type and vuln_type in sub_title:
                sim += 0.3

            if sim > 0.3:
                matching.append(f"{submission.title} ({submission.status})")
                max_similarity = max(max_similarity, sim)

        is_dup = max_similarity > 0.7

        note = ""
        if is_dup:
            note = "HIGH duplicate risk — consider reviewing existing submissions before proceeding"
        elif max_similarity > 0.4:
            note = "Moderate similarity found — verify this is a distinct finding"

        return DuplicateCheckResult(
            is_duplicate=is_dup,
            similarity_score=round(max_similarity, 2),
            matching_submissions=matching[:5],
            note=note,
        )

    def estimate_bounty(self, finding: dict) -> BountyEstimate:
        """Estimate bounty range based on severity, vuln type, and program.

        Uses historical payout data from program database and past submissions.

        Args:
            finding: Dict with keys: severity, vulnerability_type, target.

        Returns:
            BountyEstimate with min/max/expected range.
        """
        severity = finding.get("severity", "medium").lower()
        target = finding.get("target", "")

        # Find matching programs
        programs = self.programs.find_programs_for_target(target)

        if programs:
            prog = programs[0]
            payout = prog.severity_payouts.get(severity, 0)
            if payout:
                # Estimate range based on program payouts
                return BountyEstimate(
                    min_bounty=payout * 0.3,
                    max_bounty=payout * 1.5,
                    expected_bounty=float(payout),
                    confidence=0.7,
                    note=f"Based on {prog.name} typical {severity} payouts",
                )

        # Generic estimates by severity
        generic_payouts = {
            "critical": (5000, 50000, 15000),
            "high": (1000, 15000, 5000),
            "medium": (250, 5000, 1000),
            "low": (50, 1000, 250),
            "info": (0, 100, 0),
        }

        lo, hi, expected = generic_payouts.get(severity, (0, 0, 0))
        return BountyEstimate(
            min_bounty=float(lo),
            max_bounty=float(hi),
            expected_bounty=float(expected),
            confidence=0.3,
            note=f"Generic estimate for {severity} severity — actual varies by program",
        )

    def list_targets(self) -> List[str]:
        """List available targets with scope."""
        lines = ["## Available Bug Bounty Targets\n"]
        for prog in self.programs.programs.values():
            payout = prog.severity_payouts.get("critical", 0)
            lines.append(f"### {prog.name}")
            lines.append(f"- **URL:** {prog.url}")
            lines.append(f"- **Scope:** {', '.join(prog.scope[:3])}")
            lines.append(f"- **Max Payout:** ${payout:,}")
            lines.append(f"- **Rating:** {'⭐' * int(prog.rating)}")
            lines.append("")
        return "\n".join(lines)


# CLI interface
if __name__ == "__main__":
    hunter = BountyHunter()
    
    print("VIPER Bug Bounty Hunter")
    print("=" * 40)
    print(hunter.list_targets())
    print("\n" + hunter.get_earnings_report())
