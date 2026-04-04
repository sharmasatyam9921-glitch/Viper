"""Canonical data models for VIPER.

All shared types (Finding, Severity, Phase, Target) live here.
Other modules should import from core.models, not define their own.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class Severity(str, Enum):
    """Vulnerability severity levels.

    Uses string values for JSON serialization and display.
    Numeric .score property for sorting/comparison.
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        return {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }[self.value]

    def __ge__(self, other):
        if isinstance(other, Severity):
            return self.score >= other.score
        return NotImplemented

    def __gt__(self, other):
        if isinstance(other, Severity):
            return self.score > other.score
        return NotImplemented

    def __le__(self, other):
        if isinstance(other, Severity):
            return self.score <= other.score
        return NotImplemented

    def __lt__(self, other):
        if isinstance(other, Severity):
            return self.score < other.score
        return NotImplemented


class Phase(str, Enum):
    """Attack workflow phases in execution order."""
    RECON = "RECON"
    SURFACE = "SURFACE"
    SCAN = "SCAN"
    EXPLOIT = "EXPLOIT"
    POST_EXPLOIT = "POST_EXPLOIT"


@dataclass
class Finding:
    """A single vulnerability finding — superset of all fields used across VIPER."""
    id: str = ""
    title: str = ""
    severity: str = "info"  # str for JSON compat; use Severity enum for typed code
    cvss: float = 0.0
    vulnerability_type: str = ""
    endpoint: str = ""
    target: str = ""
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cwe: str = ""
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Target:
    """A target being hunted."""
    url: str
    discovered: datetime = field(default_factory=datetime.now)

    # What we know
    technologies: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)
    parameters: Set[str] = field(default_factory=set)
    vulns_found: List[Dict] = field(default_factory=list)
    # URL → parameter mapping from surface mapping (preserves which param belongs to which URL)
    # e.g., {"http://host/search": ["q"], "http://host/users": ["id"]}
    url_parameters: Dict[str, List[str]] = field(default_factory=dict)

    # Recon data
    subdomains: Set[str] = field(default_factory=set)
    open_ports: Dict[str, List[int]] = field(default_factory=dict)
    js_endpoints: Set[str] = field(default_factory=set)
    api_endpoints: Set[str] = field(default_factory=set)

    # Hunt state
    attacks_tried: Dict[str, int] = field(default_factory=dict)
    last_progress: datetime = field(default_factory=datetime.now)
    access_level: int = 0  # 0=none, 1=info, 2=read, 3=write, 4=shell, 5=root

    # Scan results
    nuclei_findings: List[Dict] = field(default_factory=list)

    # Metrics
    total_requests: int = 0
    successful_requests: int = 0

    def should_try_attack(self, attack_name: str, max_attempts: int = 3) -> bool:
        return self.attacks_tried.get(attack_name, 0) < max_attempts

    def record_attack(self, attack_name: str, success: bool):
        self.attacks_tried[attack_name] = self.attacks_tried.get(attack_name, 0) + 1
        if success:
            self.last_progress = datetime.now()

    def is_stale(self, minutes: int = 10) -> bool:
        return datetime.now() - self.last_progress > timedelta(minutes=minutes)

    def get_untried_attacks(self, all_attacks: List[str]) -> List[str]:
        return [a for a in all_attacks if a not in self.attacks_tried]
