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
import logging

logger = logging.getLogger("viper.viper_core")
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

# ══════════════════════════════════════════════════════════════════════
# Module imports — all optional with graceful degradation
# ══════════════════════════════════════════════════════════════════════

import sys as _sys
if str(HACKAGENT_DIR) not in _sys.path:
    _sys.path.insert(0, str(HACKAGENT_DIR))

from core.module_loader import ModuleLoader

_ml = ModuleLoader()

# Core modules
_ml.register("recon.recon_engine", "ReconEngine", group="modules")
_ml.register("recon.surface_mapper", "SurfaceMapper", group="modules")
_ml.register("scanners.nuclei_scanner", "NucleiScanner", group="modules")
_ml.register("ai.llm_analyzer", "LLMAnalyzer", group="modules")
_ml.register("scope.scope_manager", "ScopeManager", "BugBountyScope", "ScopeViolationError", group="modules")

# Tools & upgrade modules
_ml.register("tools.tool_manager", "ToolManager", group="upgrade")
_ml.register("tools.http_client", "HackerHTTPClient", "RequestResult", group="upgrade")
_ml.register("core.viper_db", "ViperDB", group="upgrade")
_ml.register("core.finding_validator", "FindingValidator", group="upgrade")
_ml.register("core.poc_generator", "PoCGenerator", group="upgrade")
_ml.register("core.fuzzer", "SmartFuzzer", "GrammarFuzzer", "PayloadMutator", group="upgrade")

# Compliance & learning
_ml.register("core.compliance_mapper", "enrich_finding", "format_compliance_section")
_ml.register("core.evograph", "EvoGraph")
_ml.register("core.secret_scanner", "SecretScanner")

# Reporting
_ml.register("core.html_reporter", "generate_report", "save_report")
_ml.register("core.reporter", "CvssV4Score", "calculate_cvss4")
_ml.register("core.report_narrative", "ReportNarrative")
_ml.register("core.report_exporter", "ReportExporter")

# Observability + tool registry
_ml.register("ai.observability", "LLMObserver", "get_observer")
_ml.register("core.tool_registry", "ToolRegistry", "ToolType")
_ml.register("core.finding_stream", "FindingStream", "NotificationConfig")

# Engines
_ml.register("core.stealth", "StealthEngine", "FingerprintRandomizer")
_ml.register("core.phase_engine", "PhaseEngine", "Phase")
_ml.register("core.attack_graph", "AttackGraph")
_ml.register("core.mitre_mapper", "enrich_finding_mitre", "get_attack_narrative")
_ml.register("core.guardrails", "TargetGuardrail", "InputSanitizer")
_ml.register("core.rate_limiter", "HumanTimingProfile")

# Scanners & tools
_ml.register("scanners.gvm_scanner", "GVMScanner")
_ml.register("recon.web_crawler", "WebCrawler")
_ml.register("tools.brute_forcer", "BruteForcer")
_ml.register("tools.metasploit", "MetasploitClient")

# Agents
_ml.register("agents.codefix_agent", "CodeFixAgent")
_ml.register("agents.post_exploit", "PostExploitAgent")

# Knowledge graph & orchestrator
_ml.register("core.graph_engine", "GraphEngine")
_ml.register("core.chain_writer", "ChainWriter")
_ml.register("core.graph_query", "GraphQueryEngine")
_ml.register("core.orchestrator", "ViperOrchestrator")
_ml.register("core.agent_state", "Phase")  # OrcPhase
_ml.register("core.think_engine", "ThinkEngine")

# Advanced guardrails & classification
_ml.register("core.guardrail_hard", "is_blocked")
_ml.register("core.guardrail_llm", "check_target_allowed")
_ml.register("core.skill_classifier", "classify_attack")
_ml.register("core.skill_prompts", "get_skill_prompt")

# Enhanced recon
_ml.register("recon.wappalyzer", "Wappalyzer")
_ml.register("recon.mitre_enricher", "MitreEnricher")
_ml.register("recon.shodan_enricher", "enrich_ip_sync")
# Note: recon.github_secrets also exports SecretScanner but with different API.
# Import separately to avoid name collision with core.secret_scanner.
try:
    from recon.github_secrets import SecretScanner as GithubSecretScanner
except ImportError:
    GithubSecretScanner = None

# Triage & settings
_ml.register("core.triage_engine", "TriageEngine")
_ml.register("core.triage_queries", "run_triage_queries")
_ml.register("core.settings_manager", "SettingsManager")
_ml.register("recon.pipeline", "ReconPipeline")

# MCP & tools
_ml.register("tools.mcp_tools", "MCPToolInterface")
_ml.register("tools.msf_persistent", "PersistentMsfConsole")

# Attack modules (v5.0)
_ml.register("core.agent_bus", "AgentBus", "Priority")
_ml.register("core.agent_registry", "AgentRegistry")
_ml.register("core.oauth_fuzzer", "OAuthFuzzer")
_ml.register("core.websocket_fuzzer", "WebSocketFuzzer")
_ml.register("core.race_engine", "RaceEngine")
_ml.register("core.logic_modeler", "LogicModeler")
_ml.register("core.failure_analyzer", "FailureAnalyzer")
_ml.register("core.cross_target_correlator", "CrossTargetCorrelator")
_ml.register("core.fuzzer", "GeneticFuzzer")
_ml.register("core.chain_of_custody", "ChainOfCustody")

# Dashboard events
_ml.register("dashboard.server", "publish_event")

_ml.load_all()

# ── Backward-compatible availability flags ──
# These preserve the existing API so ViperCore.__init__ doesn't need rewriting yet.
MODULES_AVAILABLE = _ml.available("ReconEngine") and _ml.available("SurfaceMapper")
UPGRADE_AVAILABLE = _ml.available("ViperDB") and _ml.available("FindingValidator")
COMPLIANCE_AVAILABLE = _ml.available("enrich_finding")
EVOGRAPH_AVAILABLE = _ml.available("EvoGraph")
NOTIFIER_AVAILABLE = False  # Consolidated into FindingStream
SECRET_SCANNER_AVAILABLE = _ml.available("SecretScanner")
HTML_REPORTER_AVAILABLE = _ml.available("generate_report")
STEALTH_AVAILABLE = _ml.available("StealthEngine")
GVM_AVAILABLE = _ml.available("GVMScanner")
PHASE_ENGINE_AVAILABLE = _ml.available("PhaseEngine")
ATTACK_GRAPH_AVAILABLE = _ml.available("AttackGraph")
WEB_CRAWLER_AVAILABLE = _ml.available("WebCrawler")
MITRE_AVAILABLE = _ml.available("enrich_finding_mitre")
GUARDRAILS_AVAILABLE = _ml.available("TargetGuardrail")
BRUTE_FORCER_AVAILABLE = _ml.available("BruteForcer")
METASPLOIT_AVAILABLE = _ml.available("MetasploitClient")
CODEFIX_AVAILABLE = _ml.available("CodeFixAgent")
POST_EXPLOIT_AVAILABLE = _ml.available("PostExploitAgent")
GRAPH_ENGINE_AVAILABLE = _ml.available("GraphEngine")
ORCHESTRATOR_AVAILABLE = _ml.available("ViperOrchestrator")
ADVANCED_GUARDRAILS_AVAILABLE = _ml.available("is_blocked")
SKILL_CLASSIFIER_AVAILABLE = _ml.available("classify_attack")
ENHANCED_RECON_AVAILABLE = _ml.available("Wappalyzer")
TRIAGE_AVAILABLE = _ml.available("TriageEngine")
NARRATIVE_REPORT_AVAILABLE = _ml.available("ReportNarrative")
MCP_TOOLS_AVAILABLE = _ml.available("MCPToolInterface")
SETTINGS_AVAILABLE = _ml.available("SettingsManager")
PIPELINE_AVAILABLE = _ml.available("ReconPipeline")
DASHBOARD_EVENTS = _ml.available("publish_event")
AGENT_BUS_AVAILABLE = _ml.available("AgentBus")
OAUTH_FUZZER_AVAILABLE = _ml.available("OAuthFuzzer")
WS_FUZZER_AVAILABLE = _ml.available("WebSocketFuzzer")
RACE_ENGINE_AVAILABLE = _ml.available("RaceEngine")
LOGIC_MODELER_AVAILABLE = _ml.available("LogicModeler")
FAILURE_ANALYZER_AVAILABLE = _ml.available("FailureAnalyzer")
CROSS_CORRELATOR_AVAILABLE = _ml.available("CrossTargetCorrelator")
GENETIC_FUZZER_AVAILABLE = _ml.available("GeneticFuzzer")
FINGERPRINT_RANDOMIZER_AVAILABLE = _ml.available("FingerprintRandomizer")
HUMAN_TIMING_AVAILABLE = _ml.available("HumanTimingProfile")
CHAIN_OF_CUSTODY_AVAILABLE = _ml.available("ChainOfCustody")
CVSS4_AVAILABLE = _ml.available("CvssV4Score")
FINDING_STREAM_AVAILABLE = _ml.available("FindingStream")
LLM_OBSERVER_AVAILABLE = _ml.available("LLMObserver")
TOOL_REGISTRY_AVAILABLE = _ml.available("ToolRegistry")

# ── Convenience accessors for loaded modules ──
# These replace the direct imports (e.g., `ReconEngine` → `_ml.get("ReconEngine")`)
# Used by ViperCore.__init__ which checks *_AVAILABLE flags first.

def _get(name):
    """Get a loaded module object by name."""
    return _ml.get(name)

def _publish_event(event_type, data):
    """Safely emit a dashboard event."""
    fn = _ml.get("publish_event")
    if fn:
        try:
            fn(event_type, data)
        except Exception:
            pass

def _emit(event_type, **data):
    """Safely emit a dashboard event (no-op if dashboard unavailable)."""
    _publish_event(event_type, data)


from core.viper_knowledge import Attack, ViperKnowledge
from core.models import Target

# ── Backward-compatible name bindings ──
# ViperCore.__init__ uses bare class names; bind them from the loader.
ReconEngine = _ml.get("ReconEngine")
SurfaceMapper = _ml.get("SurfaceMapper")
NucleiScanner = _ml.get("NucleiScanner")
LLMAnalyzer = _ml.get("LLMAnalyzer")
ScopeManager = _ml.get("ScopeManager")
BugBountyScope = _ml.get("BugBountyScope")
ScopeViolationError = _ml.get("ScopeViolationError")
ToolManager = _ml.get("ToolManager")
HackerHTTPClient = _ml.get("HackerHTTPClient")
RequestResult = _ml.get("RequestResult")
ViperDB = _ml.get("ViperDB")
FindingValidator = _ml.get("FindingValidator")
PoCGenerator = _ml.get("PoCGenerator")
SmartFuzzer = _ml.get("SmartFuzzer")
GrammarFuzzer = _ml.get("GrammarFuzzer")
PayloadMutator = _ml.get("PayloadMutator")
EvoGraph = _ml.get("EvoGraph")
SecretScanner = _ml.get("SecretScanner")
StealthEngine = _ml.get("StealthEngine")
PhaseEngine = _ml.get("PhaseEngine")
Phase = _ml.get("Phase")
AttackGraph = _ml.get("AttackGraph")
WebCrawler = _ml.get("WebCrawler")
TargetGuardrail = _ml.get("TargetGuardrail")
InputSanitizer = _ml.get("InputSanitizer")
BruteForcer = _ml.get("BruteForcer")
MetasploitClient = _ml.get("MetasploitClient")
CodeFixAgent = _ml.get("CodeFixAgent")
PostExploitAgent = _ml.get("PostExploitAgent")
GraphEngine = _ml.get("GraphEngine")
ChainWriter = _ml.get("ChainWriter")
GraphQueryEngine = _ml.get("GraphQueryEngine")
ViperOrchestrator = _ml.get("ViperOrchestrator")
ThinkEngine = _ml.get("ThinkEngine")
Wappalyzer = _ml.get("Wappalyzer")
MitreEnricher = _ml.get("MitreEnricher")
SettingsManager = _ml.get("SettingsManager")
MCPToolInterface = _ml.get("MCPToolInterface")
GVMScanner = _ml.get("GVMScanner")
ReconPipeline = _ml.get("ReconPipeline")
OAuthFuzzer = _ml.get("OAuthFuzzer")
WebSocketFuzzer = _ml.get("WebSocketFuzzer")
RaceEngine = _ml.get("RaceEngine")
LogicModeler = _ml.get("LogicModeler")
FailureAnalyzer = _ml.get("FailureAnalyzer")
CrossTargetCorrelator = _ml.get("CrossTargetCorrelator")
GeneticFuzzer = _ml.get("GeneticFuzzer")
FingerprintRandomizer = _ml.get("FingerprintRandomizer")
HumanTimingProfile = _ml.get("HumanTimingProfile")
ChainOfCustody = _ml.get("ChainOfCustody")
FindingStream = _ml.get("FindingStream")
NotificationConfig = _ml.get("NotificationConfig")
ReportNarrative = _ml.get("ReportNarrative")
ReportExporter = _ml.get("ReportExporter")
_generate_html_report = _ml.get("generate_report")
_save_html_report = _ml.get("save_report")
_enrich_compliance = _ml.get("enrich_finding")
format_compliance_section = _ml.get("format_compliance_section")
enrich_finding_mitre = _ml.get("enrich_finding_mitre")
get_attack_narrative = _ml.get("get_attack_narrative")
classify_attack = _ml.get("classify_attack")
get_skill_prompt = _ml.get("get_skill_prompt")
hard_guardrail_check = _ml.get("is_blocked")
llm_guardrail_check = _ml.get("check_target_allowed")
TriageEngine = _ml.get("TriageEngine")
run_triage_queries = _ml.get("run_triage_queries")
shodan_enrich = _ml.get("enrich_ip_sync")
CvssV4Score = _ml.get("CvssV4Score")
calculate_cvss4 = _ml.get("calculate_cvss4")
LLMObserver = _ml.get("LLMObserver")
get_observer = _ml.get("get_observer")
ToolRegistry = _ml.get("ToolRegistry")
ToolType = _ml.get("ToolType")


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

        # Notifier — consolidated into FindingStream
        self.notifier = None

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
                except ImportError:
                    try:
                        import sys as _sys
                        from pathlib import Path as _Path
                        _archive = _Path(__file__).parent / "archive" / "old_entry_points"
                        if _archive.exists() and str(_archive) not in _sys.path:
                            _sys.path.insert(0, str(_archive))
                        from viper_brain import ViperBrain
                        self._brain = ViperBrain()
                    except Exception as _e:
                        self.log(f"[ViperBrain] Could not load: {_e}", "DEBUG")
                except Exception as _e:
                    self.log(f"[ViperBrain] Init failed: {_e}", "DEBUG")
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

        Heavy logic is delegated to standalone functions in core.hunt_phases.
        """
        from core.hunt_phases import (
            phase_pipeline, phase_recon, phase_secrets, phase_surface,
            phase_nuclei, phase_gvm, phase_manual_attacks, phase_llm_analysis,
            phase_finalize,
        )

        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=max_minutes)

        # Per-phase time budgets (minutes): recon 20%, surface 20%, nuclei 10%, manual 50%
        manual_min = max(3.0, max_minutes * 0.5)
        remaining_budget = max_minutes - manual_min
        recon_budget = remaining_budget * 0.4
        surface_budget = remaining_budget * 0.4
        nuclei_budget = remaining_budget * 0.2

        target = Target(url=target_url)
        self.current_target = target
        domain = self._extract_domain(target_url)
        _full_hunt_session_start = datetime.now().isoformat()

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

        if self.http_client:
            await self.http_client.start()

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False)
        ) as self.session:

            # Phase 1: Scope Check (stays inline — trivial)
            if scope and self.scope_manager:
                self.scope_manager.active_scope = scope
                in_scope, reason = self.scope_manager.is_in_scope(target_url)
                if not in_scope:
                    self.log(f"Target out of scope: {reason}", "WARN")
                    results["error"] = f"Out of scope: {reason}"
                    return results

            # Phase 1.5: Recon Pipeline
            if PIPELINE_AVAILABLE and self.settings.get("use_recon_pipeline", True):
                pipe_res = await phase_pipeline(
                    target=target, recon_budget_seconds=recon_budget * 60,
                    graph_engine=self.graph_engine, session=self.session,
                    settings=self.settings, log_fn=self.log,
                    pipeline_cls=ReconPipeline,
                )
                results["phases"].update(pipe_res)

            # Phase 2: Reconnaissance
            if self.recon_engine and datetime.now() < end_time:
                recon_res = await phase_recon(
                    target_url=target_url, domain=domain, target=target,
                    recon_engine=self.recon_engine, graph_engine=self.graph_engine,
                    wappalyzer=getattr(self, 'wappalyzer', None),
                    recon_budget_minutes=recon_budget, log_fn=self.log,
                )
                results["phases"].update(recon_res)

            # Phase 2.5: Secret Scanning
            if self.secret_scanner and datetime.now() < end_time:
                sec_res = await phase_secrets(
                    target_url=target_url, domain=domain,
                    secret_scanner=self.secret_scanner, session=self.session,
                    log_fn=self.log,
                )
                results["findings"].extend(sec_res.get("findings", []))
                if sec_res.get("phase"):
                    results["phases"]["secrets"] = sec_res["phase"]

            # Phase 3: Surface Mapping
            if self.surface_mapper and datetime.now() < end_time:
                surf_res = await phase_surface(
                    target_url=target_url, domain=domain, target=target,
                    surface_mapper=self.surface_mapper, db=self.db,
                    surface_budget_minutes=surface_budget,
                    session_start_iso=_full_hunt_session_start, log_fn=self.log,
                )
                results["findings"].extend(surf_res.get("findings", []))
                if surf_res.get("phase"):
                    results["phases"]["surface"] = surf_res["phase"]

            # Phase 4: Nuclei Scanning
            if self.nuclei_scanner and getattr(self.nuclei_scanner, 'nuclei_path', None) and datetime.now() < end_time:
                nuc_res = await phase_nuclei(
                    target_url=target_url, domain=domain, target=target,
                    nuclei_scanner=self.nuclei_scanner, db=self.db,
                    mitre_enricher=self.mitre_enricher, metrics=self.metrics,
                    nuclei_budget_minutes=nuclei_budget, log_fn=self.log,
                )
                results["findings"].extend(nuc_res.get("findings", []))
                results["nuclei_findings"] = nuc_res.get("nuclei_findings", [])
                if nuc_res.get("phase"):
                    results["phases"]["nuclei"] = nuc_res["phase"]

            # Phase 4b: GVM/OpenVAS Network Scan
            if self.gvm_scanner and datetime.now() < end_time:
                gvm_res = await phase_gvm(
                    target_url=target_url, domain=domain, target=target,
                    gvm_scanner=self.gvm_scanner, db=self.db,
                    metrics=self.metrics, end_time=end_time, log_fn=self.log,
                )
                results["findings"].extend(gvm_res.get("findings", []))
                if gvm_res.get("phase"):
                    results["phases"]["gvm"] = gvm_res["phase"]

            # Phase 5: Manual Attacks
            remaining_seconds = (end_time - datetime.now()).total_seconds()
            manual_minutes = max(manual_min, remaining_seconds / 60.0)
            manual_res = await phase_manual_attacks(
                target_url=target_url, target=target,
                orchestrator=self.orchestrator, phase_engine=self.phase_engine,
                hunt_fn=self.hunt, react_engine=self._react_engine,
                manual_minutes=manual_minutes, log_fn=self.log,
            )
            results["phases"]["manual"] = manual_res.get("manual", {})
            results["findings"].extend(manual_res.get("manual", {}).get("findings", []))
            target.access_level = manual_res.get("manual", {}).get("access_level", 0)
            if "react_trace" in manual_res:
                results["react_trace"] = manual_res["react_trace"]

            # Phase 6: LLM Analysis
            llm_res = await phase_llm_analysis(
                target_url=target_url, target=target,
                findings=results["findings"], llm_analyzer=self.llm_analyzer,
                log_fn=self.log,
            )
            if "llm_recommended_attacks" in llm_res:
                results["llm_recommended_attacks"] = llm_res["llm_recommended_attacks"]

        # Post-hunt: compliance, graph, reports, cleanup
        await phase_finalize(
            target_url=target_url, domain=domain, target=target,
            results=results, start_time=start_time,
            graph_engine=self.graph_engine, db=self.db,
            stealth=self.stealth, metrics=self.metrics,
            http_client=self.http_client, log_fn=self.log,
            generate_full_report_fn=self._generate_full_report,
            save_state_fn=self.save_state,
            enrich_compliance_fn=_enrich_compliance if COMPLIANCE_AVAILABLE else None,
            compliance_available=COMPLIANCE_AVAILABLE,
            html_reporter_available=HTML_REPORTER_AVAILABLE,
            generate_html_report_fn=_generate_html_report if HTML_REPORTER_AVAILABLE else None,
            save_html_report_fn=_save_html_report if HTML_REPORTER_AVAILABLE else None,
        )

        return results
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        from core.utils import extract_domain
        return extract_domain(url)
    
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

    async def execute_attack(self, target: Target, attack_name: str, session_start: str = None) -> Tuple[bool, Dict]:
        """Execute an attack against target."""
        attack = self.knowledge.attacks.get(attack_name)
        if not attack:
            return False, {}

        # session_start used for duplicate detection scoping
        _session_start = session_start or (datetime.utcnow() - timedelta(hours=2)).isoformat()

        base_url = target.url.rstrip('/')
        _attack_start = time.time()
        _max_attack_secs = 30  # Per-attack time limit to avoid one attack hogging the budget

        # Build attack surface: discovered endpoints with their parameters
        # This ensures we test /search?q=, /users?id=, etc. — not just the root URL
        _attack_urls = [base_url]
        if target.endpoints:
            for ep in list(target.endpoints)[:5]:
                ep_clean = ep.rstrip('/').split('?')[0]
                if ep_clean != base_url and ep_clean not in _attack_urls:
                    _attack_urls.append(ep_clean)

        for payload in attack.payloads:
            if time.time() - _attack_start > _max_attack_secs:
                self.log(f"  [{attack_name}] Time limit ({_max_attack_secs}s), moving on", "WARN")
                break
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
                    # Use URL→parameter mapping for targeted injection fuzzing
                    # This ensures /search gets tested with ?q=, /users with ?id=, etc.
                    found_hit = False

                    # Priority 1: test known URL→param pairs from surface mapping
                    if target.url_parameters:
                        for ep_url, ep_params in target.url_parameters.items():
                            if found_hit:
                                break
                            parsed = urllib.parse.urlparse(ep_url)
                            for param in ep_params:
                                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={urllib.parse.quote(payload)}"
                                status, body, headers = await self.request(test_url)
                                if status != 0:
                                    match_result = self._check_markers(attack.success_markers, body, headers)
                                    if match_result:
                                        found_hit = True
                                        break

                    # Priority 2: fallback to root URL + all params
                    if not found_hit:
                        params_to_test = list(target.parameters)[:3] if target.parameters else ["id", "q", "search"]
                        parsed = urllib.parse.urlparse(base_url)
                        for param in params_to_test:
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={urllib.parse.quote(payload)}"
                            status, body, headers = await self.request(test_url)
                            if status != 0:
                                match_result = self._check_markers(attack.success_markers, body, headers)
                                if match_result:
                                    found_hit = True
                                    break
            
            elif attack.category == "auth":
                if "jwt" in attack_name:
                    # Send JWT as Bearer token
                    hdrs = {"Authorization": f"Bearer {payload}"}
                    status, body, headers = await self.request(base_url, headers=hdrs)
                elif "idor" in attack_name:
                    # Use URL→param mapping for IDOR, prioritize ID-like params
                    idor_targets = []
                    if target.url_parameters:
                        for ep, params in target.url_parameters.items():
                            for p in params:
                                if any(k in p.lower() for k in ("id", "user", "account", "uid", "pid")):
                                    idor_targets.append((ep, p))
                    if not idor_targets:
                        fallback_params = list(target.parameters)[:3] if target.parameters else ["id"]
                        idor_targets = [(base_url, p) for p in fallback_params]
                    for ep, param in idor_targets[:5]:
                        parsed = urllib.parse.urlparse(ep)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={urllib.parse.quote(payload)}"
                        status, body, headers = await self.request(test_url)
                        if status != 0:
                            match_result = self._check_markers(attack.success_markers, body, headers)
                            if match_result:
                                break
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
                    hdr_val = hdr_val.replace("{target}", self._extract_domain(target.url))
                    # Test CORS on all discovered endpoints (API endpoints are most likely)
                    status, body, headers = 0, "", {}
                    for cors_url in _attack_urls:
                        status, body, headers = await self.request(
                            cors_url, headers={hdr_name: hdr_val}
                        )
                        if status != 0:
                            break
                    # CORS: check response headers for misconfiguration
                    if status != 0:
                        resp_headers_str = str(headers).lower()
                        if "access-control-allow-origin" in resp_headers_str:
                            acao = ""
                            for k, v in (headers.items() if hasattr(headers, 'items') else []):
                                if k.lower() == "access-control-allow-origin":
                                    acao = v
                            if acao and (acao == "*" or "evil" in acao or acao == "null"):
                                # Force a finding — CORS is misconfigured
                                body = f"CORS MISCONFIGURED: Access-Control-Allow-Origin: {acao}"
                elif "clickjacking" in attack_name or "x_frame" in attack_name:
                    status, body, headers = await self.request(base_url)
                    if status != 0:
                        resp_headers_lower = {k.lower(): v for k, v in (headers.items() if hasattr(headers, 'items') else [])}
                        has_xfo = "x-frame-options" in resp_headers_lower
                        has_csp_fa = any("frame-ancestors" in str(v) for v in resp_headers_lower.values())
                        if not has_xfo and not has_csp_fa:
                            body = "CLICKJACKING: No X-Frame-Options or CSP frame-ancestors header"
                elif "security_headers" in attack_name:
                    status, body, headers = await self.request(base_url)
                    if status != 0:
                        resp_headers_lower = {k.lower() for k, _ in (headers.items() if hasattr(headers, 'items') else [])}
                        missing = []
                        for hdr in ["strict-transport-security", "content-security-policy", "x-content-type-options"]:
                            if hdr not in resp_headers_lower:
                                missing.append(hdr)
                        if missing:
                            body = f"MISSING SECURITY HEADERS: {', '.join(missing)}"
                else:
                    status, body, headers = await self.request(base_url)

            else:
                status, body, headers = await self.request(base_url)

            if status == 0:
                continue

            # SSRF FP guard: if marker appears in the payload URL itself (URL reflection),
            # strip the payload from the body before checking success markers
            _body_for_check = body
            if "ssrf" in attack_name and isinstance(payload, str):
                # Remove the payload URL from the body to avoid reflection false positives
                try:
                    _body_for_check = body.replace(payload, "").replace(
                        urllib.parse.quote(payload), ""
                    )
                except Exception:
                    pass

            # Smart marker detection with regex and context awareness
            match_result = self._check_markers(attack.success_markers, _body_for_check, headers)
            if match_result:
                marker, marker_confidence = match_result
                candidate = {
                    "attack": attack_name,
                    "vuln_type": attack_name,  # for compliance_mapper lookup
                    "type": attack_name,
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
                        # Adaptive FP threshold — lower for vuln types with inherent ambiguity
                        _fp_thresholds = {
                            "cors": 0.2, "cors_misconfig": 0.2, "cors_misconfiguration": 0.2,
                            "xxe": 0.3, "debug_endpoints": 0.25, "clickjacking": 0.2,
                            "x_frame_options": 0.2, "cache_poisoning": 0.3,
                            "open_redirect": 0.3, "crlf_injection": 0.3,
                        }
                        min_conf = _fp_thresholds.get(attack_name, 0.35)
                        if confidence < min_conf:
                            self.log(f"  [FP] {attack_name} rejected: confidence={confidence:.2f} < {min_conf} — {reason}")
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
                        is_dup, dup_id = self.db.is_duplicate(tid, attack_name, test_url, payload, session_start=_session_start)
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
                    except (OSError, ValueError, TypeError) as e:
                        self.log(f"  [DB] Error persisting finding: {e}", "WARN")

                # VIPER 2.0: Generate PoC for high+ findings
                if self.poc_gen and candidate.get("severity") in ("high", "critical"):
                    try:
                        poc_path = self.poc_gen.save_poc(candidate)
                        candidate["poc_path"] = str(poc_path)
                        self.log(f"  [POC] Saved: {poc_path.name}")
                    except (OSError, AttributeError) as e:
                        self.log(f"  [POC] Save failed: {e}", "WARN")

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
        # Reuse existing target if already populated by full_hunt (preserves surface mapping data)
        if self.current_target and self.current_target.url.rstrip('/') == target_url.rstrip('/'):
            target = self.current_target
        else:
            target = Target(url=target_url)
            self.current_target = target
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=max_minutes)
        # Session start ISO timestamp — used to scope duplicate detection to this session only
        _session_start = start_time.isoformat()

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

        # VIPER 3.0: Phase engine — already starts at RECON by default (no-op reset)
        # Note: PhaseEngine has no .transition() — advance_phase() is the correct API

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

            # Build context for ReACT — include current phase so exploit tools are allowed
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
                # Pass current phase so ReACT engine allows exploit-phase tools
                "phase": (self.phase_engine.current_phase if self.phase_engine else "EXPLOIT"),
            }

            async def react_execute(url, action, ctx):
                """Bridge between ReACT engine and VIPER's attack execution."""
                nonlocal findings
                success, finding = await self.execute_attack(target, action, session_start=_session_start)
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
        # Always run fallback if time remains — even if ReACT found something,
        # there may be more vulnerabilities to discover
        if not self._react_engine or datetime.now() < end_time:
            if self._react_engine:
                self.log("  [Fallback] Running standard attacks for remaining time")
                # Prioritize: quick wins first, then injection attacks on discovered endpoints
                _priority_attacks = [
                    # Quick wins (header/config checks — fast, high confidence)
                    "clickjacking", "security_headers_missing", "cors_misconfiguration",
                    "csrf_token_leak",
                    # Recon file exposure (fast, high confidence)
                    "git_exposure", "env_file", "dir_listing", "debug_endpoints",
                    # Injection attacks (test discovered endpoints with payloads)
                    "sqli_error", "xss_reflected", "dom_xss", "lfi_basic",
                    "ssti_basic", "cmdi_basic", "open_redirect_basic",
                ]
                for atk in reversed(_priority_attacks):
                    if atk not in tried_attacks and atk in self.knowledge.attacks:
                        attack_queue.insert(0, atk)

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

                success, finding = await self.execute_attack(target, attack_name, session_start=_session_start)
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
                        if self.phase_engine.current_phase != "POST_EXPLOIT":
                            self.phase_engine.advance_phase("entering post-exploit phase")
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
            # Expose detected technologies so full_hunt can merge them into its Target
            "technologies": sorted(target.technologies) if target.technologies else [],
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
| Technologies | {', '.join(sorted({t.title() for t in target.technologies if t})) or 'Unknown'} |
| Parameters | {len(target.parameters)} |
| API Endpoints | {len(target.api_endpoints)} |

---

## Critical Findings

"""
        
        def _finding_name(f):
            """Resolve the best human-readable name for a finding dict."""
            return (f.get('attack') or f.get('vuln_type') or f.get('type')
                    or f.get('template_name') or 'Unknown')

        def _finding_evidence(f):
            details = f.get('details', {})
            if isinstance(details, dict):
                return (details.get('pattern') or details.get('value', '')[:80]
                        or f.get('marker') or f.get('matcher_name') or 'N/A')
            return f.get('marker') or f.get('matcher_name') or 'N/A'

        # Critical findings first
        critical = [f for f in findings + nuclei if f.get('severity', '').lower() in ['critical', 'high']]
        if critical:
            for i, f in enumerate(critical, 1):
                report += f"""
### {i}. {_finding_name(f)} [{f.get('severity', 'N/A').upper()}]

- **URL:** {f.get('url', f.get('matched_at', 'N/A'))}
- **Payload:** `{f.get('payload', 'N/A')}`
- **Evidence:** {_finding_evidence(f)}

"""
        else:
            report += "*No critical vulnerabilities found*\n"

        # All findings
        report += """
---

## All Findings

"""

        for i, f in enumerate(findings, 1):
            report += f"- [{f.get('severity', 'N/A').upper()}] {_finding_name(f)} @ {f.get('url', 'N/A')}\n"

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
            # Filter empty, None, and tool error messages (valid hostnames have no spaces)
            subs = [s for s in recon.get('subdomains', [])
                    if s and str(s).strip() and ' ' not in str(s) and len(str(s)) < 253]
            for sub in subs[:20]:
                report += f"- {sub}\n"
            if len(subs) > 20:
                report += f"- ... and {len(subs) - 20} more\n"
        
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
            
            # Read JS secrets from deduplicated findings, not raw surface dict
            js_secret_findings = [f for f in findings if f.get('vuln_type') == 'js_secret']
            if js_secret_findings:
                report += "\n### Potential Secrets in JS\n"
                for sf in js_secret_findings[:10]:
                    src = sf.get('url') or sf.get('details', {}).get('source', 'unknown')
                    pat = sf.get('details', {}).get('pattern', '')
                    report += f"- `{pat}` in {src}\n"
        
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
