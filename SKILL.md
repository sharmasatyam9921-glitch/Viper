---
name: hackagent
description: "VIPER 5.0 — Autonomous bug bounty hunting agent with multi-agent architecture, 7-phase recon pipeline, 85+ core modules, 3D dashboard, and self-learning. $0 cost via Claude CLI OAuth."
aliases: bugbounty, pentest, security-research, viper, hack
---

# VIPER 5.0 — Autonomous Bug Bounty Hunter

Multi-agent AI-powered bug bounty bot. Pure Python, $0 cost (Claude CLI OAuth + Ollama), zero Docker required.

## Quick Start

```bash
python viper.py http://target.com --full                # Full hunt (recon → exploit → report)
python viper.py http://target.com --full --stealth 2    # Stealth mode (WAF evasion)
python viper.py http://target.com --full --deep-think   # Deep strategic analysis
python viper_autonomous.py --continuous --interval=60   # Continuous 24/7 hunting
python viper_daemon.py                                   # Daemon mode
python dashboard/server.py                               # Dashboard at localhost:8080
```

## Architecture

### Hunt Pipeline (8 phases)
```
viper.py → ViperCore.full_hunt(target)
  Phase 1: Domain Discovery    — subfinder, crt.sh, DNS resolution
  Phase 2: Passive Intel       — Shodan, URLScan, WHOIS, NVD+Vulners CVEs
  Phase 3: Port Scanning       — naabu, Shodan InternetDB
  Phase 4: HTTP Probing        — httpx, Wappalyzer (3,920 tech fingerprints)
  Phase 5: Resource Enum       — Katana, GAU, Wayback, Arjun, ParamSpider, FFuf, Kiterunner
  Phase 6: Vuln Scanning       — Nuclei, 28 security checks, WAF bypass detection
  Phase 7: MITRE Enrichment    — CVE→CWE→CAPEC (95MB offline DB)
  Phase 8: Manual Attacks      — ReACT loop + Q-learning + Deep Think + multi-agent
  Phase 9: Reporting           — CISO 6-section narrative, HTML, PDF, compliance mapping
```

### Multi-Agent System (v5.0)
```
orchestrator.py → agent_bus.py (asyncio pub/sub, priority queuing)
                       ↓
        ┌──────────────┼──────────────┬──────────────┐
   recon_agent     vuln_agent    exploit_agent   chain_agent
   (discovery)    (hypotheses)    (PoC dev)     (chaining)
        ↓              ↓              ↓              ↓
   subfinder      hacker_mind    fuzzer.py     attack_chain
   wappalyzer     think_engine   scanner.py    cross_correlator
   shodan         react_engine   race_engine   attack_graph
        ↓
   failure_analyzer ←→ evograph.py (self-learning)
        ↓
   finding_validator → reporter.py → bounty_hunter.py → finding_stream.py
```

### ReACT Engine
```
ReACTEngine.reason_and_act(target)
  → RoE enforcement (scope/time/tool/phase)
  → Phase-aware tool enforcement (50+ tools mapped)
  → Deep Think trigger (auto on failures, LLM request, step 1)
  → Todo list (LLM maintains structured work plan)
  → Tool confirmation gate (dangerous tools need approval)
  → Execute → Q-table update → exhaustion detection
```

### LLM Routing ($0 cost)
```
Claude CLI OAuth (free) → LiteLLM API (paid fallback) → Ollama local (free fallback)
```

## Module Inventory

### core/ — 85+ modules
| Category | Key Modules |
|----------|------------|
| **Orchestration** | `orchestrator.py`, `react_engine.py`, `think_engine.py`, `wave_runner.py`, `phase_engine.py` |
| **Multi-Agent** | `agent_bus.py` (pub/sub), `agent_registry.py` (lifecycle), `agent_state.py` (todo/objectives) |
| **Reasoning** | `hacker_mind.py`, `skill_classifier.py` (attack path + CVE extraction), `learned_capabilities.py` |
| **Knowledge Graph** | `graph_engine.py` (Neo4j + SQLite dual), `graph_query.py` (NL→graph), `chain_writer.py` (26 typed findings) |
| **Learning** | `evograph.py` (Q-tables), `failure_analyzer.py` (WAF bypass learning), `cross_target_correlator.py` |
| **Attack** | `fuzzer.py` (genetic), `graphql_fuzzer.py`, `oauth_fuzzer.py` (7 suites), `websocket_fuzzer.py`, `race_engine.py`, `logic_modeler.py` |
| **Validation** | `finding_validator.py` (37 vuln types), `approval_gate.py` (tool confirm), `guardrails.py` (LLM + hard blocklist) |
| **Safety** | `roe_engine.py` (Rules of Engagement), `stealth.py` (4-level WAF evasion), `rate_limiter.py` (token bucket + Gaussian timing) |
| **Compliance** | `compliance_mapper.py` (PCI-DSS/OWASP/HIPAA/SOC2/NIST), `mitre_mapper.py` (CWE→CAPEC→ATT&CK) |
| **Reporting** | `report_narrative.py` (CISO 6-section), `html_reporter.py` (PDF export), `poc_generator.py`, `finding_stream.py` (Discord/Telegram) |
| **Evidence** | `chain_of_custody.py` (SHA-256 + HMAC), `secret_scanner.py` (40+ patterns), `key_rotation.py` |
| **Codefix** | `codefix_engine.py` (tree-sitter ReACT loop), `codefix_tools.py` (11 AST tools) |
| **Infra** | `viper_db.py` (SQLite), `settings_manager.py`, `iana_services.py` (11,473 ports), `notifier.py` (Telegram) |
| **Prompts** | `skill_prompts/sql_injection.py` (7-step SQLMap), `cve_exploit.py`, `brute_force.py`, `phishing.py`, `dos.py` |

### recon/ — 21 modules (7-phase pipeline)
| Module | Purpose |
|--------|---------|
| `pipeline.py` | Orchestrator: domain → passive → ports → http → resources → vuln → mitre |
| `resource_enum.py` | 7 tools: Katana, GAU, Wayback, Arjun, ParamSpider, FFuf, Kiterunner |
| `security_checks.py` | 28 checks: DNS (SPF/DMARC/DNSSEC/zone transfer), auth, ports, app, WAF bypass, rate limiting |
| `wappalyzer.py` | 3,920 technology fingerprints |
| `shodan_enricher.py` | InternetDB (free) + full Shodan API |
| `cve_lookup.py` | NVD + Vulners, 154 CPE mappings |
| `mitre_offline.py` | 95MB offline CVE/CWE/CAPEC database |
| `github_hunt.py` | Org-wide secret hunting (48 patterns + Shannon entropy) |
| `arjun_discovery.py` | Hidden HTTP parameter brute force |
| `anonymity.py` | Tor/SOCKS5 proxy routing |

### agents/ — 6 specialized agents
| Agent | Purpose |
|-------|---------|
| `recon_agent.py` | Autonomous subdomain enum, tech fingerprint, asset discovery |
| `vuln_agent.py` | Tree-of-Thought hypothesis generation (top-5 branches) |
| `exploit_agent.py` | Non-destructive PoC development and validation |
| `chain_agent.py` | Attack chain discovery + cross-target correlation |
| `codefix_agent.py` | Tree-sitter ReACT fix loop + GitHub PR creation |
| `post_exploit.py` | Post-exploitation enumeration |

### tools/ — 14 modules
| Module | Purpose |
|--------|---------|
| `http_client.py` | Async aiohttp, rate limiting, proxy, WAF detection |
| `brute_forcer.py` | 8 protocols: SSH, FTP, HTTP, MySQL, PostgreSQL, Redis, SMB, MSSQL |
| `google_dork.py` | SerpAPI OSINT (18 dork templates per domain) |
| `web_search.py` | SerpAPI + Tavily dual-provider CVE/exploit search |
| `metasploit.py` | MSF subprocess + persistent console |
| `payload_mutator.py` | WAF bypass encoding mutations |

### scanners/ — 4 modules
- `nuclei_scanner.py` — Nuclei + custom template auto-discovery
- `gvm_scanner.py` — GVM/OpenVAS (optional Docker)
- `trufflehog_scanner.py` — TruffleHog git secret scanning

### dashboard/ — Web UI at localhost:8080
- **3D force-graph** knowledge visualization
- **AI chat** with real Claude responses + conversation persistence
- **NLP terminal** — type English, get shell commands. Sandboxed (allowlist-only pentest tools)
- **SSH target proxy** — `!connect user@target` for remote command execution
- **10+ chart types** — CVSS scatter, kill chain funnel, radar, treemap, risk gauge
- **CypherFix** remediation panel with VS Code-style diff viewer
- **30+ REST API endpoints** + SSE streaming

## External Tools

All optional — graceful degradation when missing:
```
nuclei httpx subfinder katana naabu gau ffuf    # Go (~/go/bin/)
arjun paramspider sqlmap xsstrike dirsearch     # Python (pip install)
```

## Data Files

| Path | Size | Content |
|------|------|---------|
| `data/wappalyzer_technologies.json` | 1.3MB | 3,920 tech fingerprints |
| `data/iana_services.csv` | 1.1MB | 11,473 port-service mappings |
| `data/mitre_db/` | 95MB | Offline CVE/CWE/CAPEC (1999-2026) |
| `data/nuclei/custom/` | 4KB | Custom nuclei YAML templates |
| `wordlists/` | 500KB | common.txt, lfi-payloads.txt, burp-parameter-names.txt, etc. |

## State & Runtime

```
state/           — Current session state (viper_state.json)
memory/          — Learned patterns across sessions
knowledge/       — Attack knowledge base
findings/        — Discovered vulnerabilities (JSON)
reports/         — Generated HTML/Markdown reports + PoCs
scopes/          — Platform scope definitions (HackerOne JSON)
models/          — Q-tables + experience data
logs/            — Audit logs
credentials/     — Platform API credentials
programs/        — Target program definitions
```

## Ethical Rules (enforced in code)

1. **Scope enforced** — `roe_engine.py` + `guardrails.py` block out-of-scope targets
2. **No destructive actions** — read-only PoCs, no data modification
3. **Findings verified** — `finding_validator.py` (37 vuln-type behavioral confirmation)
4. **Rate limiting** — `rate_limiter.py` (token bucket + human-like Gaussian timing)
5. **Tool gates** — `approval_gate.py` requires confirmation for dangerous tools (sqlmap, hydra, msfconsole)
6. **Phase enforcement** — `phase_engine.py` blocks exploitation tools during recon phase
7. **Evidence integrity** — `chain_of_custody.py` (SHA-256 hashing + HMAC signing)
8. **Secret redaction** — findings truncated to 8 chars, no full credentials in reports
