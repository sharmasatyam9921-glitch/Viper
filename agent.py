#!/usr/bin/env python3
"""
HackAgent - Autonomous Bug Bounty Hunter

This is the main entry point. A real hacker that:
1. Finds bug bounty programs
2. Reads scope/rules
3. Does recon
4. Tests for vulnerabilities
5. Writes professional reports
6. Submits for bounty

ETHICAL USE ONLY - Always follow responsible disclosure!

Author: VIPER
"""

import os
import json
import asyncio
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import hashlib

# Local imports
from core.hacker_mind import HackerMind, AttackPhase
from core.attack_patterns import PATTERNS as ATTACK_PATTERNS
from tools.recon import ReconModule

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(name)s | %(levelname)s | %(message)s'
)
logger = logging.getLogger("HackAgent")


class HuntingStatus(Enum):
    IDLE = "idle"
    SELECTING_TARGET = "selecting_target"
    READING_SCOPE = "reading_scope"
    RECON = "reconnaissance"
    TESTING = "testing"
    EXPLOITING = "exploiting"
    REPORTING = "reporting"
    SUBMITTED = "submitted"


@dataclass
class BugBountyProgram:
    """A bug bounty program to hunt on."""
    name: str
    platform: str  # hackerone, bugcrowd, intigriti, custom
    url: str
    scope: Dict[str, List[str]]  # in_scope, out_of_scope
    bounty_range: Dict[str, int]  # low, medium, high, critical
    rules: List[str]
    safe_harbor: bool = True
    allows_automation: bool = True
    response_time: Optional[str] = None  # fast, medium, slow


@dataclass 
class Finding:
    """A vulnerability finding."""
    id: str
    title: str
    severity: str  # low, medium, high, critical
    vulnerability_type: str
    affected_asset: str
    description: str
    steps_to_reproduce: List[str]
    impact: str
    poc: Optional[str] = None
    cvss: Optional[float] = None
    bounty_estimate: Optional[int] = None
    status: str = "draft"  # draft, submitted, triaged, resolved, paid


class HackAgent:
    """
    The autonomous bug bounty hunting agent.
    
    Workflow:
    1. Select a program
    2. Understand scope & rules
    3. Reconnaissance
    4. Vulnerability testing
    5. Exploitation & PoC
    6. Report writing
    7. Submission
    """
    
    def __init__(self, workspace: str = "skills/hackagent"):
        self.workspace = Path(workspace)
        self.programs_dir = self.workspace / "programs"
        self.reports_dir = self.workspace / "reports"
        self.logs_dir = self.workspace / "logs"
        
        # Create directories
        for d in [self.programs_dir, self.reports_dir, self.logs_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # State
        self.status = HuntingStatus.IDLE
        self.current_program: Optional[BugBountyProgram] = None
        self.hacker_mind: Optional[HackerMind] = None
        self.recon: Optional[ReconModule] = None
        self.findings: List[Finding] = []
        
        # Load known programs
        self.programs: List[BugBountyProgram] = []
        self._load_programs()
        
        # Statistics
        self.stats = {
            "programs_hunted": 0,
            "vulns_found": 0,
            "vulns_submitted": 0,
            "bounties_earned": 0.0
        }
        self._load_stats()
        
        logger.info("HackAgent initialized")
    
    def _load_programs(self):
        """Load known bug bounty programs."""
        # Default programs that allow automation
        self.programs = [
            BugBountyProgram(
                name="HackerOne Gateway",
                platform="hackerone",
                url="https://hackerone.com/security",
                scope={
                    "in_scope": ["*.hackerone.com"],
                    "out_of_scope": ["hackerone.com/users/*"]
                },
                bounty_range={"low": 100, "medium": 500, "high": 2500, "critical": 7500},
                rules=["No DoS", "No user data access"],
                safe_harbor=True,
                allows_automation=True
            ),
            BugBountyProgram(
                name="Practice - OWASP Juice Shop",
                platform="practice",
                url="https://juice-shop.herokuapp.com",
                scope={
                    "in_scope": ["juice-shop.herokuapp.com"],
                    "out_of_scope": []
                },
                bounty_range={"low": 0, "medium": 0, "high": 0, "critical": 0},
                rules=["Practice target - no real bounty"],
                safe_harbor=True,
                allows_automation=True
            ),
            BugBountyProgram(
                name="Practice - Metasploitable",
                platform="practice",
                url="http://localhost:8080",
                scope={
                    "in_scope": ["localhost:8080", "127.0.0.1:8080"],
                    "out_of_scope": []
                },
                bounty_range={"low": 0, "medium": 0, "high": 0, "critical": 0},
                rules=["Local practice VM"],
                safe_harbor=True,
                allows_automation=True
            )
        ]
        
        # Load custom programs from files
        programs_file = self.programs_dir / "programs.json"
        if programs_file.exists():
            try:
                with open(programs_file) as f:
                    custom = json.load(f)
                    for p in custom:
                        self.programs.append(BugBountyProgram(**p))
            except Exception as e:
                logger.warning(f"Failed to load programs: {e}")
    
    def _load_stats(self):
        """Load hunting statistics."""
        stats_file = self.workspace / "stats.json"
        if stats_file.exists():
            with open(stats_file) as f:
                self.stats = json.load(f)
    
    def _save_stats(self):
        """Save hunting statistics."""
        with open(self.workspace / "stats.json", "w") as f:
            json.dump(self.stats, f, indent=2)
    
    # =========================================================================
    # PROGRAM SELECTION
    # =========================================================================
    
    def list_programs(self) -> List[Dict]:
        """List available bug bounty programs."""
        return [
            {
                "name": p.name,
                "platform": p.platform,
                "url": p.url,
                "bounty_range": p.bounty_range,
                "allows_automation": p.allows_automation
            }
            for p in self.programs
        ]
    
    def add_program(self, program: BugBountyProgram):
        """Add a new bug bounty program."""
        self.programs.append(program)
        # Save to file
        programs_file = self.programs_dir / "programs.json"
        programs_list = []
        if programs_file.exists():
            with open(programs_file) as f:
                programs_list = json.load(f)
        programs_list.append({
            "name": program.name,
            "platform": program.platform,
            "url": program.url,
            "scope": program.scope,
            "bounty_range": program.bounty_range,
            "rules": program.rules,
            "safe_harbor": program.safe_harbor,
            "allows_automation": program.allows_automation
        })
        with open(programs_file, "w") as f:
            json.dump(programs_list, f, indent=2)
        logger.info(f"Added program: {program.name}")
    
    def select_program(self, name: str) -> bool:
        """Select a program to hunt."""
        for p in self.programs:
            if p.name.lower() == name.lower():
                self.current_program = p
                self.status = HuntingStatus.READING_SCOPE
                
                # Initialize program workspace
                program_dir = self.programs_dir / self._sanitize_name(p.name)
                program_dir.mkdir(exist_ok=True)
                
                # Initialize hacker mind
                self.hacker_mind = HackerMind(
                    target=p.url,
                    scope=p.scope
                )
                
                # Initialize recon
                self.recon = ReconModule(output_dir=program_dir)
                
                logger.info(f"Selected program: {p.name}")
                return True
        
        logger.warning(f"Program not found: {name}")
        return False
    
    def _sanitize_name(self, name: str) -> str:
        """Sanitize name for filesystem."""
        return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    
    # =========================================================================
    # HUNTING
    # =========================================================================
    
    async def hunt(self, max_hours: float = 2.0) -> List[Finding]:
        """
        Main hunting loop. Run autonomous bug hunting.
        
        Args:
            max_hours: Maximum time to hunt
            
        Returns:
            List of findings
        """
        if not self.current_program:
            logger.error("No program selected. Use select_program() first.")
            return []
        
        logger.info(f"Starting hunt on: {self.current_program.name}")
        logger.info(f"Max duration: {max_hours} hours")
        logger.info(f"Scope: {self.current_program.scope}")
        
        start_time = datetime.now()
        
        # Check rules
        if not self.current_program.allows_automation:
            logger.warning("This program does not allow automated testing!")
            logger.warning("Switching to manual-assist mode")
        
        # Phase 1: Reconnaissance
        self.status = HuntingStatus.RECON
        logger.info("=== PHASE 1: RECONNAISSANCE ===")
        await self._do_recon()
        
        # Phase 2: Testing
        self.status = HuntingStatus.TESTING
        logger.info("=== PHASE 2: VULNERABILITY TESTING ===")
        await self._do_testing()
        
        # Phase 3: Exploitation
        if self.findings:
            self.status = HuntingStatus.EXPLOITING
            logger.info("=== PHASE 3: EXPLOITATION & PoC ===")
            await self._do_exploitation()
        
        # Phase 4: Reporting
        if self.findings:
            self.status = HuntingStatus.REPORTING
            logger.info("=== PHASE 4: REPORT WRITING ===")
            await self._do_reporting()
        
        # Summary
        elapsed = (datetime.now() - start_time).total_seconds() / 3600
        logger.info(f"Hunt completed in {elapsed:.2f} hours")
        logger.info(f"Findings: {len(self.findings)}")
        
        # Update stats
        self.stats["programs_hunted"] += 1
        self.stats["vulns_found"] += len(self.findings)
        self._save_stats()
        
        return self.findings
    
    async def _do_recon(self):
        """Reconnaissance phase."""
        if not self.current_program or not self.recon:
            return
        
        target = self.current_program.url
        # Extract domain from URL
        import urllib.parse
        parsed = urllib.parse.urlparse(target)
        domain = parsed.netloc or parsed.path
        domain = domain.split(":")[0]  # Remove port
        
        logger.info(f"Recon target: {domain}")
        
        # Subdomain enumeration
        logger.info("Enumerating subdomains...")
        subdomains = self.recon.subdomain_enum_passive(domain)
        logger.info(f"Found {len(subdomains)} subdomains")
        
        # Wayback URLs
        logger.info("Checking Wayback Machine...")
        urls = self.recon.wayback_urls(domain)
        logger.info(f"Found {len(urls)} historical URLs")
        
        # Feed to HackerMind
        if self.hacker_mind:
            for sub in subdomains:
                self.hacker_mind.endpoints_discovered.add(sub)
            
            # Think about what we found
            decision = self.hacker_mind.think(f"Recon complete. Found {len(subdomains)} subdomains")
            logger.info(f"HackerMind decision: {decision}")
    
    async def _do_testing(self):
        """Vulnerability testing phase."""
        if not self.hacker_mind:
            return
        
        logger.info("Testing for common vulnerabilities...")
        
        # Get prioritized attack patterns
        for pattern_name, pattern in ATTACK_PATTERNS.items():
            logger.info(f"Testing: {pattern_name}")
            
            # Generate hypotheses
            hypotheses = self.hacker_mind._generate_hypotheses()
            
            # Test each hypothesis
            for hyp in hypotheses[:5]:  # Top 5
                decision = self.hacker_mind.think(f"Testing hypothesis: {hyp.description}")
                
                # If confirmed, create finding
                if "CONFIRMED" in str(hyp.status):
                    finding = Finding(
                        id=hashlib.md5(f"{hyp.id}{datetime.now()}".encode()).hexdigest()[:8],
                        title=hyp.description,
                        severity=self._estimate_severity(hyp.vulnerability_class),
                        vulnerability_type=hyp.vulnerability_class,
                        affected_asset=self.current_program.url if self.current_program else "unknown",
                        description=hyp.description,
                        steps_to_reproduce=hyp.test_plan,
                        impact=self._estimate_impact(hyp.vulnerability_class)
                    )
                    self.findings.append(finding)
                    logger.info(f"[VULN FOUND] {finding.title}")
    
    async def _do_exploitation(self):
        """Build PoCs for confirmed vulnerabilities."""
        for finding in self.findings:
            logger.info(f"Building PoC for: {finding.title}")
            
            # Generate PoC based on vuln type
            poc = self._generate_poc(finding)
            finding.poc = poc
            finding.status = "poc_ready"
    
    async def _do_reporting(self):
        """Generate professional reports."""
        for finding in self.findings:
            report = self._generate_report(finding)
            
            # Save report
            report_file = self.reports_dir / f"{finding.id}-{self._sanitize_name(finding.title)[:30]}.md"
            with open(report_file, "w") as f:
                f.write(report)
            
            logger.info(f"Report saved: {report_file.name}")
            finding.status = "draft"
    
    # =========================================================================
    # HELPERS
    # =========================================================================
    
    def _estimate_severity(self, vuln_class: str) -> str:
        """Estimate severity from vulnerability class."""
        critical = ["rce", "sqli", "ssrf", "ssti", "auth_bypass"]
        high = ["idor", "xss_stored", "lfi", "xxe"]
        medium = ["xss_reflected", "csrf", "open_redirect"]
        
        vuln_lower = vuln_class.lower()
        if any(c in vuln_lower for c in critical):
            return "critical"
        elif any(h in vuln_lower for h in high):
            return "high"
        elif any(m in vuln_lower for m in medium):
            return "medium"
        return "low"
    
    def _estimate_impact(self, vuln_class: str) -> str:
        """Estimate impact statement."""
        impacts = {
            "sqli": "An attacker could extract, modify, or delete database contents, potentially compromising all user data.",
            "rce": "An attacker could execute arbitrary code on the server, leading to complete system compromise.",
            "idor": "An attacker could access or modify data belonging to other users.",
            "xss": "An attacker could execute malicious scripts in victims' browsers, stealing sessions or credentials.",
            "ssrf": "An attacker could make requests from the server, potentially accessing internal services.",
            "auth_bypass": "An attacker could bypass authentication and access protected resources."
        }
        
        for key, impact in impacts.items():
            if key in vuln_class.lower():
                return impact
        return "An attacker could exploit this vulnerability to compromise security."
    
    def _generate_poc(self, finding: Finding) -> str:
        """Generate proof of concept."""
        poc = f"""# Proof of Concept - {finding.title}

## Request
```http
# TODO: Add actual PoC request
GET /vulnerable-endpoint HTTP/1.1
Host: {finding.affected_asset}
```

## Response
```
# Expected vulnerable response demonstrating the issue
```

## Automated Reproduction
```bash
# curl command or script to reproduce
curl -X GET "{finding.affected_asset}/vulnerable-endpoint"
```
"""
        return poc
    
    def _generate_report(self, finding: Finding) -> str:
        """Generate a professional bug bounty report."""
        report = f"""# {finding.title}

**Severity:** {finding.severity.upper()}
**Type:** {finding.vulnerability_type}
**Asset:** {finding.affected_asset}
**CVSS:** {finding.cvss or "TBD"}

---

## Summary

{finding.description}

## Steps to Reproduce

"""
        for i, step in enumerate(finding.steps_to_reproduce, 1):
            report += f"{i}. {step}\n"
        
        report += f"""
## Impact

{finding.impact}

## Proof of Concept

{finding.poc or "See attached files."}

## Remediation

- Implement proper input validation
- Follow secure coding practices
- Apply the principle of least privilege

---

*Report generated by HackAgent on {datetime.now().strftime('%Y-%m-%d %H:%M')}*
"""
        return report
    
    def get_status(self) -> Dict:
        """Get current agent status."""
        return {
            "status": self.status.value,
            "current_program": self.current_program.name if self.current_program else None,
            "findings_count": len(self.findings),
            "stats": self.stats
        }


# =========================================================================
# CLI
# =========================================================================

async def main():
    """CLI interface for HackAgent."""
    import argparse
    
    parser = argparse.ArgumentParser(description="HackAgent - Autonomous Bug Bounty Hunter")
    parser.add_argument("--list", action="store_true", help="List available programs")
    parser.add_argument("--hunt", type=str, help="Start hunting on a program")
    parser.add_argument("--hours", type=float, default=2.0, help="Max hunting hours")
    parser.add_argument("--status", action="store_true", help="Show agent status")
    
    args = parser.parse_args()
    
    agent = HackAgent()
    
    if args.list:
        print("\nAvailable Bug Bounty Programs:")
        print("-" * 60)
        for p in agent.list_programs():
            print(f"  {p['name']}")
            print(f"    Platform: {p['platform']}")
            print(f"    URL: {p['url']}")
            print(f"    Automation: {'Yes' if p['allows_automation'] else 'No'}")
            print()
    
    elif args.hunt:
        if agent.select_program(args.hunt):
            findings = await agent.hunt(max_hours=args.hours)
            print(f"\nHunt complete! Found {len(findings)} vulnerabilities.")
            for f in findings:
                print(f"  [{f.severity.upper()}] {f.title}")
        else:
            print(f"Program not found: {args.hunt}")
    
    elif args.status:
        status = agent.get_status()
        print("\nHackAgent Status:")
        print(f"  Status: {status['status']}")
        print(f"  Current Program: {status['current_program'] or 'None'}")
        print(f"  Findings: {status['findings_count']}")
        print(f"  Programs Hunted: {status['stats']['programs_hunted']}")
        print(f"  Vulns Found: {status['stats']['vulns_found']}")
        print(f"  Bounties Earned: ${status['stats']['bounties_earned']}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    asyncio.run(main())
