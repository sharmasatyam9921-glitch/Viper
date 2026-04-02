#!/usr/bin/env python3
"""
VIPER Scope Manager - Bug Bounty Program Scope Handling

Features:
- Parse HackerOne/Bugcrowd program scopes
- Validate targets against scope
- Track out-of-scope domains
- Import scopes from various formats
"""

import json
import logging

logger = logging.getLogger("viper.scope_manager")
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse
import fnmatch

HACKAGENT_DIR = Path(__file__).parent.parent
SCOPE_DIR = HACKAGENT_DIR / "data" / "scopes"
SCOPE_DIR.mkdir(parents=True, exist_ok=True)


class ScopeViolationError(Exception):
    """Raised when a request targets an out-of-scope URL."""
    pass


@dataclass
class ProgramRules:
    """Machine-enforceable rules parsed from bug bounty program policies."""
    max_severity: str = "critical"
    excluded_vuln_types: List[str] = field(default_factory=lambda: ["dos", "social_engineering", "spam"])
    max_rps: float = 10.0
    testing_hours: Optional[Tuple[int, int]] = None  # (start_hour, end_hour) UTC, None = anytime
    no_automated_tools: bool = False
    require_manual_verification: bool = False

    def is_vuln_type_allowed(self, vuln_type: str) -> bool:
        return vuln_type.lower() not in [v.lower() for v in self.excluded_vuln_types]

    def is_testing_time(self) -> bool:
        if self.testing_hours is None:
            return True
        from datetime import datetime, timezone
        hour = datetime.now(timezone.utc).hour
        start, end = self.testing_hours
        if start <= end:
            return start <= hour < end
        return hour >= start or hour < end  # Wraps midnight


@dataclass
class ScopeEntry:
    """A single scope entry"""
    target: str  # Domain, IP, URL, or wildcard
    asset_type: str  # 'domain', 'ip', 'url', 'wildcard', 'cidr', 'mobile', 'api'
    in_scope: bool = True
    eligible_for_bounty: bool = True
    max_severity: str = "critical"  # Max severity accepted
    notes: str = ""
    
    def matches(self, target: str) -> bool:
        """Check if target matches this scope entry"""
        target_lower = target.lower()
        entry_lower = self.target.lower()
        
        # Extract domain from URL if needed
        if '://' in target_lower:
            parsed = urlparse(target_lower)
            target_domain = parsed.netloc
        else:
            target_domain = target_lower
        
        # Remove port if present
        if ':' in target_domain:
            target_domain = target_domain.split(':')[0]
        
        if self.asset_type == 'wildcard' or '*' in entry_lower:
            # Wildcard matching
            pattern = entry_lower.replace('.', r'\.').replace('*', '.*')
            return bool(re.match(f'^{pattern}$', target_domain))
        
        elif self.asset_type == 'domain':
            # Exact domain or subdomain match
            return target_domain == entry_lower or target_domain.endswith('.' + entry_lower)
        
        elif self.asset_type == 'url':
            # URL prefix match
            return target_lower.startswith(entry_lower)
        
        elif self.asset_type == 'ip':
            # IP match
            return target_domain == entry_lower
        
        elif self.asset_type == 'cidr':
            # CIDR range - simplified check
            try:
                import ipaddress
                network = ipaddress.ip_network(self.target, strict=False)
                ip = ipaddress.ip_address(target_domain)
                return ip in network
            except Exception as e:  # noqa: BLE001
                return False
        
        return False


@dataclass
class BugBountyScope:
    """Bug bounty program scope"""
    program_name: str
    platform: str = "hackerone"  # hackerone, bugcrowd, intigriti, yeswehack
    program_url: str = ""
    
    in_scope: List[ScopeEntry] = field(default_factory=list)
    out_of_scope: List[ScopeEntry] = field(default_factory=list)
    
    # Program details
    bounty_range: Tuple[int, int] = (0, 0)
    response_efficiency: int = 0  # HackerOne's response metric
    
    # Restrictions
    no_public_disclosure: bool = False
    safe_harbor: bool = True
    
    # Timestamps
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> dict:
        return {
            "program_name": self.program_name,
            "platform": self.platform,
            "program_url": self.program_url,
            "in_scope": [
                {
                    "target": e.target,
                    "asset_type": e.asset_type,
                    "eligible_for_bounty": e.eligible_for_bounty,
                    "max_severity": e.max_severity,
                    "notes": e.notes
                }
                for e in self.in_scope
            ],
            "out_of_scope": [
                {
                    "target": e.target,
                    "asset_type": e.asset_type,
                    "notes": e.notes
                }
                for e in self.out_of_scope
            ],
            "bounty_range": self.bounty_range,
            "response_efficiency": self.response_efficiency,
            "no_public_disclosure": self.no_public_disclosure,
            "safe_harbor": self.safe_harbor,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'BugBountyScope':
        scope = cls(
            program_name=data.get('program_name', 'Unknown'),
            platform=data.get('platform', 'hackerone'),
            program_url=data.get('program_url', ''),
            bounty_range=tuple(data.get('bounty_range', [0, 0])),
            response_efficiency=data.get('response_efficiency', 0),
            no_public_disclosure=data.get('no_public_disclosure', False),
            safe_harbor=data.get('safe_harbor', True),
            created_at=data.get('created_at', datetime.now().isoformat()),
            updated_at=data.get('updated_at', datetime.now().isoformat())
        )
        
        for entry in data.get('in_scope', []):
            scope.in_scope.append(ScopeEntry(
                target=entry.get('target', ''),
                asset_type=entry.get('asset_type', 'domain'),
                in_scope=True,
                eligible_for_bounty=entry.get('eligible_for_bounty', True),
                max_severity=entry.get('max_severity', 'critical'),
                notes=entry.get('notes', '')
            ))
        
        for entry in data.get('out_of_scope', []):
            scope.out_of_scope.append(ScopeEntry(
                target=entry.get('target', ''),
                asset_type=entry.get('asset_type', 'domain'),
                in_scope=False,
                notes=entry.get('notes', '')
            ))
        
        return scope
    
    def save(self, filename: str = None) -> Path:
        if not filename:
            safe_name = re.sub(r'[^\w\-_]', '_', self.program_name)
            filename = f"scope_{safe_name}.json"
        
        filepath = SCOPE_DIR / filename
        filepath.write_text(json.dumps(self.to_dict(), indent=2))
        return filepath


class ScopeManager:
    """
    Manages bug bounty program scopes.
    
    Validates targets against scopes and tracks scope violations.
    """
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.active_scope: Optional[BugBountyScope] = None
        self.violation_log: List[Dict] = []
        self.rules: ProgramRules = ProgramRules()
    
    def log(self, msg: str, level: str = "INFO"):
        if self.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"[{timestamp}] [SCOPE] [{level}] {msg}")
    
    def load_scope(self, filename: str) -> bool:
        """Load scope from file"""
        filepath = SCOPE_DIR / filename
        if not filepath.exists():
            self.log(f"Scope file not found: {filepath}", "ERROR")
            return False
        
        try:
            data = json.loads(filepath.read_text())
            self.active_scope = BugBountyScope.from_dict(data)
            self.log(f"Loaded scope: {self.active_scope.program_name}")
            self.log(f"  In-scope targets: {len(self.active_scope.in_scope)}")
            self.log(f"  Out-of-scope targets: {len(self.active_scope.out_of_scope)}")
            return True
        except Exception as e:
            self.log(f"Error loading scope: {e}", "ERROR")
            return False
    
    def create_scope(self, program_name: str, 
                      platform: str = "hackerone") -> BugBountyScope:
        """Create new scope"""
        scope = BugBountyScope(program_name=program_name, platform=platform)
        self.active_scope = scope
        self.log(f"Created new scope: {program_name}")
        return scope
    
    def add_in_scope(self, target: str, 
                      asset_type: str = "domain",
                      eligible_for_bounty: bool = True,
                      notes: str = ""):
        """Add target to in-scope list"""
        if not self.active_scope:
            self.log("No active scope", "ERROR")
            return
        
        entry = ScopeEntry(
            target=target,
            asset_type=asset_type,
            in_scope=True,
            eligible_for_bounty=eligible_for_bounty,
            notes=notes
        )
        self.active_scope.in_scope.append(entry)
        self.log(f"Added in-scope: {target}")
    
    def add_out_of_scope(self, target: str, 
                          asset_type: str = "domain",
                          notes: str = ""):
        """Add target to out-of-scope list"""
        if not self.active_scope:
            self.log("No active scope", "ERROR")
            return
        
        entry = ScopeEntry(
            target=target,
            asset_type=asset_type,
            in_scope=False,
            notes=notes
        )
        self.active_scope.out_of_scope.append(entry)
        self.log(f"Added out-of-scope: {target}")
    
    def is_in_scope(self, target: str) -> Tuple[bool, Optional[str]]:
        """
        Check if target is in scope.
        
        Returns:
            (is_in_scope, reason)
        """
        if not self.active_scope:
            return True, "No active scope - allowing all"
        
        # First check out-of-scope (takes priority)
        for entry in self.active_scope.out_of_scope:
            if entry.matches(target):
                reason = f"Matches out-of-scope: {entry.target}"
                if entry.notes:
                    reason += f" ({entry.notes})"
                self._log_violation(target, reason)
                return False, reason
        
        # Then check in-scope
        for entry in self.active_scope.in_scope:
            if entry.matches(target):
                return True, f"Matches in-scope: {entry.target}"
        
        # Not explicitly in scope
        reason = "Target not in explicit scope"
        self._log_violation(target, reason)
        return False, reason
    
    def _log_violation(self, target: str, reason: str):
        """Log scope violation"""
        self.violation_log.append({
            "target": target,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        })
        self.log(f"[!] Scope violation: {target} - {reason}", "WARN")
    
    def enforce_before_request(self, url: str) -> bool:
        """
        Call before EVERY outbound request.
        Raises ScopeViolationError if target is out of scope.
        Returns True if in scope.
        """
        in_scope, reason = self.is_in_scope(url)
        if not in_scope:
            raise ScopeViolationError(f"BLOCKED: {url} — {reason}")
        if self.rules.no_automated_tools:
            raise ScopeViolationError(f"BLOCKED: {url} — program disallows automated tools")
        if not self.rules.is_testing_time():
            raise ScopeViolationError(f"BLOCKED: {url} — outside allowed testing hours")
        return True

    def set_rules(self, rules: ProgramRules):
        """Set program rules for enforcement."""
        self.rules = rules

    def parse_program_rules(self, rules_text: str) -> ProgramRules:
        """
        Parse human-readable program rules into machine-enforceable ProgramRules.
        Uses keyword matching to extract constraints.
        """
        text_lower = rules_text.lower()
        rules = ProgramRules()

        # Rate limiting
        import re
        rps_match = re.search(r'(\d+)\s*(?:requests?\s*(?:per|/)\s*second|rps)', text_lower)
        if rps_match:
            rules.max_rps = float(rps_match.group(1))

        rpm_match = re.search(r'(\d+)\s*(?:requests?\s*(?:per|/)\s*minute|rpm)', text_lower)
        if rpm_match:
            rules.max_rps = float(rpm_match.group(1)) / 60.0

        # Excluded vuln types
        excludes = ["dos", "social_engineering", "spam", "phishing"]
        if "no dos" in text_lower or "denial of service" in text_lower:
            excludes.append("dos")
        if "no social engineering" in text_lower:
            excludes.append("social_engineering")
        if "no physical" in text_lower:
            excludes.append("physical")
        rules.excluded_vuln_types = list(set(excludes))

        # Automated tools
        if "no automated" in text_lower or "manual only" in text_lower:
            rules.no_automated_tools = True

        # Verification
        if "manual verification" in text_lower or "manually verify" in text_lower:
            rules.require_manual_verification = True

        # Max severity
        if "low severity only" in text_lower:
            rules.max_severity = "low"
        elif "medium" in text_lower and "maximum" in text_lower:
            rules.max_severity = "medium"

        self.rules = rules
        return rules

    def filter_targets(self, targets: List[str]) -> List[str]:
        """Filter list of targets to only in-scope ones"""
        return [t for t in targets if self.is_in_scope(t)[0]]
    
    def get_all_in_scope_domains(self) -> List[str]:
        """Get all explicit in-scope domains"""
        if not self.active_scope:
            return []
        return [e.target for e in self.active_scope.in_scope]
    
    # =====================
    # Import from platforms
    # =====================
    
    def import_hackerone(self, data: Dict) -> BugBountyScope:
        """
        Import scope from HackerOne JSON.
        
        Expected format from HackerOne API or policy page.
        """
        scope = BugBountyScope(
            program_name=data.get('name', data.get('handle', 'Unknown')),
            platform="hackerone",
            program_url=f"https://hackerone.com/{data.get('handle', '')}"
        )
        
        # Parse targets
        targets = data.get('targets', {})
        
        # In-scope
        for target in targets.get('in_scope', []):
            asset_type = self._normalize_asset_type(target.get('asset_type', ''))
            entry = ScopeEntry(
                target=target.get('asset_identifier', ''),
                asset_type=asset_type,
                in_scope=True,
                eligible_for_bounty=target.get('eligible_for_bounty', True),
                max_severity=target.get('max_severity', 'critical'),
                notes=target.get('instruction', '')
            )
            scope.in_scope.append(entry)
        
        # Out-of-scope
        for target in targets.get('out_of_scope', []):
            asset_type = self._normalize_asset_type(target.get('asset_type', ''))
            entry = ScopeEntry(
                target=target.get('asset_identifier', ''),
                asset_type=asset_type,
                in_scope=False,
                notes=target.get('instruction', '')
            )
            scope.out_of_scope.append(entry)
        
        self.active_scope = scope
        scope.save()
        
        self.log(f"Imported HackerOne scope: {scope.program_name}")
        return scope
    
    def import_bugcrowd(self, data: Dict) -> BugBountyScope:
        """
        Import scope from Bugcrowd JSON.
        """
        scope = BugBountyScope(
            program_name=data.get('name', 'Unknown'),
            platform="bugcrowd",
            program_url=data.get('url', '')
        )
        
        # Bugcrowd uses different structure
        for target in data.get('target_groups', []):
            for item in target.get('targets', []):
                uri = item.get('uri', item.get('name', ''))
                if not uri:
                    continue
                
                in_scope = target.get('in_scope', True)
                
                entry = ScopeEntry(
                    target=uri,
                    asset_type=self._normalize_asset_type(item.get('category', '')),
                    in_scope=in_scope,
                    eligible_for_bounty=True,
                    notes=item.get('description', '')
                )
                
                if in_scope:
                    scope.in_scope.append(entry)
                else:
                    scope.out_of_scope.append(entry)
        
        self.active_scope = scope
        scope.save()
        
        self.log(f"Imported Bugcrowd scope: {scope.program_name}")
        return scope
    
    def import_simple(self, program_name: str,
                       in_scope_domains: List[str],
                       out_of_scope_domains: List[str] = None) -> BugBountyScope:
        """
        Simple import with domain lists.
        
        Useful for quick setup or testing.
        """
        scope = BugBountyScope(program_name=program_name)
        
        for domain in in_scope_domains:
            asset_type = 'wildcard' if '*' in domain else 'domain'
            scope.in_scope.append(ScopeEntry(
                target=domain,
                asset_type=asset_type,
                in_scope=True
            ))
        
        for domain in (out_of_scope_domains or []):
            asset_type = 'wildcard' if '*' in domain else 'domain'
            scope.out_of_scope.append(ScopeEntry(
                target=domain,
                asset_type=asset_type,
                in_scope=False
            ))
        
        self.active_scope = scope
        scope.save()
        
        self.log(f"Created simple scope: {program_name}")
        return scope
    
    def _normalize_asset_type(self, asset_type: str) -> str:
        """Normalize asset type string"""
        mapping = {
            'url': 'url',
            'domain': 'domain',
            'wildcard': 'wildcard',
            'cidr': 'cidr',
            'ip_address': 'ip',
            'ip': 'ip',
            'api': 'api',
            'mobile_application': 'mobile',
            'android': 'mobile',
            'ios': 'mobile',
            'hardware': 'hardware',
            'other': 'other'
        }
        return mapping.get(asset_type.lower(), 'domain')
    
    # =====================
    # Utilities
    # =====================
    
    def list_saved_scopes(self) -> List[str]:
        """List saved scope files"""
        return [f.name for f in SCOPE_DIR.glob("scope_*.json")]
    
    def get_violation_summary(self) -> Dict:
        """Get summary of scope violations"""
        summary = {
            "total_violations": len(self.violation_log),
            "unique_targets": len(set(v['target'] for v in self.violation_log)),
            "recent": self.violation_log[-10:] if self.violation_log else []
        }
        return summary


async def main():
    """Demo/test"""
    manager = ScopeManager()
    
    # Create a test scope
    scope = manager.import_simple(
        "Test Program",
        in_scope_domains=["*.example.com", "api.example.com"],
        out_of_scope_domains=["staging.example.com", "admin.example.com"]
    )
    
    # Test validation
    test_targets = [
        "https://www.example.com",
        "https://api.example.com/v1/users",
        "https://staging.example.com",  # Out of scope
        "https://admin.example.com",    # Out of scope
        "https://test.example.com",
        "https://other-domain.com",     # Not in scope
    ]
    
    print("\n=== Scope Validation Test ===")
    for target in test_targets:
        in_scope, reason = manager.is_in_scope(target)
        status = "✓" if in_scope else "✗"
        print(f"{status} {target}")
        print(f"   → {reason}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
