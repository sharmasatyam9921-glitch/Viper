# VIPER 🐍 - Ethical Bug Bounty Hunting Agent

**Codename: VIPER | Not a scanner. A hacker's brain.**

*Strike fast. Strike silent. Earn bounties.*

## Overview

VIPER (HackAgent) is an AI-powered ethical bug bounty hunting agent that thinks like a real hacker. It doesn't just run tools - it observes, hypothesizes, tests, adapts, and chains vulnerabilities.

## Features

### Core Capabilities
- **HackerMind** - Cognitive engine with phase-based reasoning
- **Attack Patterns DB** - OTP bypass, IDOR, SQLi, SSTI, SSRF, Race Conditions
- **WAF Detection & Bypass** - Cloudflare, ModSecurity, AWS WAF
- **Smart Payloads** - Context-aware based on discovered tech stack
- **Attack Chaining** - Combines low-severity findings into critical exploits

### AI/LLM Attack Module (NEW - 2026)
- **PromptInjectionEngine** - 147+ attack vectors (direct, indirect, jailbreaks)
- **AdversarialDualAgent** - CHAOS vs ORDER exploitation strategy
- **CollectiveMemory** - Cross-scan learning that improves over time
- **MCPSecurityScanner** - OWASP MCP Top 10 security checks
- **MLInfrastructureExploits** - Ray, MLflow, Jupyter, BentoML CVEs

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/hackagent.git
cd hackagent
pip install -r requirements.txt  # If exists
```

## Usage

### Quick Scan
```bash
python quick_scan.py --target https://example.com
```

### Full Hunt
```bash
python hunt_target.py --program hackerone/example --scope scope.txt
```

### AI/LLM Testing
```python
from core.ai_techniques import PromptInjectionEngine, MCPSecurityScanner

# Generate prompt injection attacks
attacks = PromptInjectionEngine.get_all_attacks()

# Scan for MCP vulnerabilities
results = MCPSecurityScanner.scan("https://ai-api.example.com")
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          VIPER                                   │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    HACKER MIND                           │   │
│  │  • Phase-based reasoning (Recon→Exploit→Report)         │   │
│  │  • Hypothesis generation from observations               │   │
│  │  • Adaptive payload generation                           │   │
│  │  • WAF detection and bypass strategies                   │   │
│  │  • Attack chain construction                             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              🤖 AI/LLM ATTACK MODULE                     │   │
│  │  • Prompt Injection (147 vectors)                       │   │
│  │  • Jailbreaks (DAN, Developer Mode, Personas)           │   │
│  │  • OWASP MCP Top 10 Security Checks                     │   │
│  │  • ML Infrastructure Exploits                            │   │
│  │  • CHAOS vs ORDER Dual-Agent Exploitation               │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Ethics

**ALWAYS:**
- Read program rules COMPLETELY before testing
- Stay within defined scope
- Report responsibly
- Document everything

**NEVER:**
- Test out-of-scope targets
- Access/exfiltrate user data
- Cause denial of service
- Share vulnerabilities publicly before disclosure

See [ETHICS.md](ETHICS.md) for full legal framework.

## Directory Structure

```
hackagent/
├── README.md            # This file
├── SKILL.md             # Detailed capability docs
├── ETHICS.md            # Legal framework
├── core/
│   ├── hacker_mind.py   # Cognitive engine
│   ├── attack_patterns.py
│   └── ai_techniques.py # AI/LLM attacks (NEW)
├── tools/
│   ├── recon.py
│   ├── http_client.py
│   └── payload_mutator.py
├── labs/                # Practice environments
├── knowledge/           # OWASP, platform rules
└── reports/             # Scan outputs
```

## Sources

AI techniques integrated from:
- [PromptXploit](https://github.com/Neural-alchemy/promptxploit) - LLM Pentesting Framework
- [GhostHacker](https://github.com/itsjwill/ghosthacker) - Adversarial AI Pentester
- [ProtectAI ai-exploits](https://github.com/protectai/ai-exploits) - ML Infrastructure Exploits
- [MCP-Penetration-testing](https://github.com/Mr-Infect/MCP-Penetration-testing) - OWASP MCP Top 10

## License

For authorized security testing only. Use responsibly.

## Author

Open Source Project


