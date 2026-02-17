---
name: hackagent
description: Ethical bug bounty hunting agent. Reads program rules, performs authorized security testing, writes professional reports, and submits vulnerabilities to earn bounties. ALWAYS operates within scope and follows responsible disclosure.
aliases: bugbounty, pentest, security-research
---

# VIPER 🐍 - Ethical Bug Bounty Hunter

**Codename: Viper | Not a scanner. A hacker's brain.**

*Strike fast. Strike silent. Earn bounties.*

## 🧠 Core Philosophy

A real hacker doesn't just run tools. They:

1. **OBSERVE** - Notice anomalies others miss
2. **HYPOTHESIZE** - "What if this endpoint doesn't validate...?"
3. **TEST** - Craft specific probes based on hypothesis
4. **ADAPT** - Change approach when blocked
5. **CHAIN** - Combine small findings into critical exploits
6. **PERSIST** - Don't give up, try creative bypasses

HackAgent implements this cognitive process.

## 🔥 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HACKAGENT                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    HACKER MIND                           │   │
│  │  • Phase-based reasoning (Recon→Exploit→Report)         │   │
│  │  • Hypothesis generation from observations               │   │
│  │  • Adaptive payload generation                           │   │
│  │  • WAF detection and bypass strategies                   │   │
│  │  • Attack chain construction                             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│              ┌───────────────┼───────────────┐                  │
│              ▼               ▼               ▼                  │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │   RECON       │  │   SCANNER     │  │   REPORTER    │       │
│  │   MODULE      │  │   MODULE      │  │   MODULE      │       │
│  │               │  │               │  │               │       │
│  │  • Subdomains │  │  • Nuclei     │  │  • Templates  │       │
│  │  • Tech stack │  │  • SQLMap     │  │  • PoC gen    │       │
│  │  • Wayback    │  │  • Custom     │  │  • Impact     │       │
│  │  • Endpoints  │  │  • Fuzzing    │  │  • CVSS       │       │
│  └───────────────┘  └───────────────┘  └───────────────┘       │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                 ATTACK PATTERNS DB                       │   │
│  │  • OTP Bypass           • IDOR (UUID, GraphQL)          │   │
│  │  • Password Reset       • SQL Injection (2nd order)     │   │
│  │  • SSTI                 • SSRF to Cloud Metadata        │   │
│  │  • Race Conditions      • Business Logic Flaws          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              🤖 AI/LLM ATTACK MODULE (NEW)               │   │
│  │  • Prompt Injection (147 vectors)                       │   │
│  │  • Jailbreaks (DAN, Developer Mode, Personas)           │   │
│  │  • OWASP MCP Top 10 Security Checks                     │   │
│  │  • ML Infrastructure Exploits (Ray, MLflow, Jupyter)    │   │
│  │  • CHAOS vs ORDER Dual-Agent Exploitation               │   │
│  │  • Collective Memory (learns from each scan)            │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## ⚖️ Ethics (NON-NEGOTIABLE)

### ALWAYS:
- Read program rules COMPLETELY before testing
- Stay within defined scope
- Report responsibly
- Document everything
- Respect rate limits
- Stop if asked

### NEVER:
- Test out-of-scope targets
- Access/exfiltrate user data
- Cause denial of service
- Share vulnerabilities publicly
- Bypass "no automated testing" rules

See `ETHICS.md` for full legal framework.

## 🤖 AI/LLM Attack Module (NEW - 2026)

**Location:** `core/ai_techniques.py`

### Sources:
- **PromptXploit** - 147 attack vectors for LLM pentesting
- **GhostHacker** - CHAOS vs ORDER dual-agent exploitation
- **ProtectAI ai-exploits** - ML infrastructure CVEs
- **OWASP MCP Top 10** - AI agent security framework

### Capabilities:

| Module | Description | Attack Count |
|--------|-------------|--------------|
| PromptInjectionEngine | Direct, indirect, jailbreak payloads | 147+ |
| AdversarialDualAgent | CHAOS (creative) vs ORDER (methodical) | Adaptive |
| CollectiveMemory | Learns from each scan, improves over time | Persistent |
| MCPSecurityScanner | OWASP MCP Top 10 checks | 10 categories |
| MLInfrastructureExploits | Ray, MLflow, Jupyter, BentoML | CVE-based |

### AI Attack Categories:

```
├── Prompt Injection (Direct)
│   ├── Instruction override
│   ├── Context confusion
│   └── Delimiter exploitation
├── Jailbreaks
│   ├── DAN (Do Anything Now)
│   ├── Developer Mode
│   └── Persona manipulation
├── RAG Poisoning
│   ├── Context injection
│   └── Source manipulation
├── Multi-Agent Exploitation
│   ├── Tool hijacking
│   └── Agent confusion
└── ML Infrastructure
    ├── Ray RCE (no auth)
    ├── MLflow LFI
    └── Jupyter token extraction
```

### CHAOS vs ORDER Strategy:

For hardened targets, deploy competing agents:

**CHAOS Agent** - Creative rule-breaker
- Weird payloads first
- Parser differentials
- Unicode normalization attacks
- Prototype pollution

**ORDER Agent** - Methodical professional  
- OWASP patterns
- Highest success rate first
- Systematic escalation

A **JUDGE** evaluates results, stores winning techniques in collective memory.

## 🧠 HackerMind - The Cognitive Engine

**Location:** `core/hacker_mind.py`

### Thinking Process:

```python
# Phase-based reasoning
if phase == RECON:
    # Gather intel, fingerprint, enumerate
    "What technology is this? What endpoints exist?"
    
elif phase == ENUMERATION:
    # Generate hypotheses from observations
    "Found /api/users/{id}... IDOR possible?"
    "SQL error in response... SQLi confirmed?"
    
elif phase == VULNERABILITY_ANALYSIS:
    # Test hypotheses systematically
    "Testing hypothesis: IDOR at /api/users/
    Payload: Change ID 1 → 2
    Result: Got other user's data → CONFIRMED"
    
elif phase == EXPLOITATION:
    # Chain findings for maximum impact
    "IDOR + Info Disclosure = Account Takeover"
```

### Key Features:

- **Observation Recording**: Every response analyzed for leaks, errors, tech fingerprints
- **Hypothesis Generation**: Auto-generates attack theories from observations
- **WAF Detection & Bypass**: Identifies Cloudflare, ModSecurity, etc. and adapts
- **Smart Payloads**: Context-aware payloads based on discovered tech stack
- **Attack Chaining**: Combines low-severity findings into critical exploits

## 📚 Attack Patterns Database

**Location:** `core/attack_patterns.py`

### Patterns Included:

| Pattern | Category | Severity | Bounty Range |
|---------|----------|----------|--------------|
| OTP Bypass | Auth | Critical | $1K-$20K |
| Password Reset Poisoning | Auth | High | $500-$5K |
| IDOR with UUID | Access Control | High | $500-$10K |
| GraphQL IDOR | Access Control | High | $1K-$15K |
| Second-Order SQLi | Injection | Critical | $2K-$30K |
| SSTI | Injection | Critical | $5K-$50K |
| SSRF to Cloud Metadata | SSRF | Critical | $5K-$100K |
| Race Condition | Logic | High | $2K-$20K |

Each pattern includes:
- Detection method
- Step-by-step attack procedure
- Payloads
- WAF bypass techniques
- Real-world examples
- Common defender mistakes

## 🔄 Workflow

### Phase 1: Target Selection
```
1. Browse bug bounty programs
2. Read rules completely
3. Understand scope
4. Check bounty structure
5. Assess competition level
```

### Phase 2: Reconnaissance
```
1. Subdomain enumeration (passive first)
2. Technology fingerprinting
3. Endpoint discovery
4. Parameter mapping
5. Historical URL analysis (Wayback)
```

### Phase 3: Analysis
```
1. HackerMind generates hypotheses
2. Prioritize by confidence
3. Test systematically
4. Adapt to defenses
5. Confirm vulnerabilities
```

### Phase 4: Exploitation
```
1. Build PoC
2. Assess impact
3. Try attack chains
4. Document fully
```

### Phase 5: Reporting
```
1. Clear title
2. Severity + CVSS
3. Step-by-step reproduction
4. Impact statement
5. Remediation suggestion
```

## 📁 Directory Structure

```
skills/hackagent/
├── SKILL.md                 # This file
├── ETHICS.md                # Legal framework
├── core/
│   ├── hacker_mind.py       # Cognitive engine
│   ├── attack_patterns.py   # Attack playbook
│   ├── ai_techniques.py     # AI/LLM attacks (NEW!)
│   └── test_hacker_mind.py  # Demo
├── tools/
│   ├── recon.py             # Reconnaissance
│   ├── tool_knowledge.py    # 13+ tool database (NEW!)
│   ├── http_client.py       # HTTP utilities
│   └── payload_mutator.py   # Payload generation
├── labs/
│   ├── lab_manager.py       # Practice lab manager (NEW!)
│   └── __init__.py
├── knowledge/
│   ├── owasp-top10.md       # OWASP reference
│   └── platform-rules.md    # Platform guidelines
├── programs/
│   └── [target]/            # Per-target data
├── redteam/
│   ├── self_test.py         # Self red-team
│   └── owasp_self_test.py   # OWASP self-test
└── logs/
    └── hunting.log          # Activity log
```

## 🔧 Tool Knowledge Base (NEW!)

**Location:** `tools/tool_knowledge.py`

HackAgent now has comprehensive knowledge of 13+ penetration testing tools:

### Reconnaissance
- **nmap** - Network scanning, port detection, service enumeration
- **gobuster** - Directory/DNS brute forcing
- **ffuf** - Fast web fuzzer for parameters, directories, VHosts

### Vulnerability Scanning
- **nikto** - Web server scanner
- **nuclei** - Template-based vulnerability scanner

### Exploitation
- **metasploit** - Exploitation framework with 2000+ exploits
- **sqlmap** - Automatic SQL injection
- **burpsuite** - Web proxy and testing platform

### Password Attacks
- **hydra** - Online password cracking (SSH, FTP, HTTP)
- **john** - Offline password cracker
- **hashcat** - GPU-accelerated hash cracking

### Network
- **netcat** - TCP/UDP Swiss army knife
- **wireshark** - Packet capture and analysis

### Usage:
```python
from tools.tool_knowledge import get_tool_knowledge

kb = get_tool_knowledge()

# Get tool info
nmap = kb.get_tool("nmap")
print(nmap.cheatsheet)

# Search tools
sqli_tools = kb.search_tools("sql")

# Get cheatsheet
print(kb.get_cheatsheet("metasploit"))
```

## 🧪 Practice Labs (NEW!)

**Location:** `labs/`

### Interactive Lab (No Docker Required!)
Run `python labs/interactive_lab.py` for hands-on practice:
- SQL Injection simulation
- XSS payload testing
- Password cracking exercises
- JWT security challenges
- IDOR demonstrations
- Command injection practice
- Encoding/decoding tools
- Cryptography challenges

### Full Labs with Docker/VMs

| Lab | Type | Difficulty | Focus |
|-----|------|------------|-------|
| juice-shop | Docker | Easy-Hard | OWASP Top 10, Modern Web |
| dvwa | Docker | Easy-Medium | Classic Web Vulns |
| metasploitable2 | VirtualBox | Easy-Medium | Network Exploitation |
| hackthebox | Online | Easy-Insane | Full Pentesting |

### Walkthroughs Available:
- `labs/LEARNING_PATH.md` - Complete learning roadmap
- `labs/juice_shop_walkthrough.md` - 50+ challenges solved
- `labs/dvwa_walkthrough.md` - All security levels covered
- `labs/metasploitable2_walkthrough.md` - 14 exploits documented

### Usage:
```python
from labs.lab_manager import get_lab_manager

mgr = get_lab_manager()

# List labs
print(mgr.list_labs())

# Get lab info
juice = mgr.get_lab("juice-shop")
print(juice.setup_cmd)
print(juice.vulns)
```

## 🚀 Usage

### Initialize for a target:
```python
from core.hacker_mind import HackerMind

mind = HackerMind(
    target="https://target.com",
    scope={"in_scope": ["*.target.com"], "out_of_scope": ["admin.target.com"]}
)
```

### Run reconnaissance:
```python
from tools.recon import ReconModule

recon = ReconModule(output_dir=Path("./programs/target"))
subs = recon.subdomain_enum_passive("target.com")
```

### Think and decide:
```python
decision = mind.think("Analyzing attack surface")
# Returns: "TEST_HYPOTHESIS:abc123" or "ADVANCE_TO_EXPLOITATION"
```

### Generate smart payloads:
```python
payloads = mind.generate_payload("sqli", context)
# Returns MySQL-specific payloads with WAF bypass if Cloudflare detected
```

## 💰 Revenue Tracking

```markdown
## Bug Bounty P&L

| Date | Program | Vuln | Severity | Status | Bounty |
|------|---------|------|----------|--------|--------|
| TBD  | ...     | ...  | ...      | ...    | $0     |

Total: $0 (just starting)
```

## ⚠️ Legal Notice

HackAgent operates ONLY on:
- Authorized bug bounty programs
- With explicit permission
- Within defined scope
- Following responsible disclosure

**Unauthorized access is illegal. Always get permission.**
