# VIPER Core Modules

from .models import Finding, Severity, Phase, Target

from .ai_techniques import (
    EncodingEngine,
    PromptInjectionEngineV2 as PromptInjectionEngine,
    RAGPoisoningEngine,
    MultiAgentExploitEngine,
    AdversarialDualAgentV2 as AdversarialDualAgent,
    CollectiveMemoryV2 as CollectiveMemory,
    MCPSecurityScannerV2 as MCPSecurityScanner,
    MLInfrastructureExploitsV2 as MLInfrastructureExploits,
)

from .hacker_mind import HackerMind, AttackPhase

from .scanner import (
    HTTPScanner,
    VulnerabilityScanner,
    ReconScanner,
    ScanResult,
)

from .reporter import (
    ReportGenerator,
    create_finding_from_template,
    FINDING_TEMPLATES,
)

from .fuzzer import (
    PayloadMutator,
    GrammarFuzzer,
    SmartFuzzer,
    WordlistGenerator,
)

__all__ = [
    # Models
    'Finding',
    'Severity',
    'Phase',
    'Target',

    # AI Techniques
    'EncodingEngine',
    'PromptInjectionEngine',
    'RAGPoisoningEngine',
    'MultiAgentExploitEngine',
    'AdversarialDualAgent',
    'CollectiveMemory',
    'MCPSecurityScanner',
    'MLInfrastructureExploits',
    
    # Hacker Mind
    'HackerMind',
    'AttackPhase',
    
    # Scanner
    'HTTPScanner',
    'VulnerabilityScanner',
    'ReconScanner',
    'ScanResult',
    
    # Reporter
    'ReportGenerator',
    'Finding',
    'create_finding_from_template',
    'FINDING_TEMPLATES',
    
    # Fuzzer
    'PayloadMutator',
    'GrammarFuzzer',
    'SmartFuzzer',
    'WordlistGenerator',
]
