# VIPER 5.0

Autonomous bug bounty hunting bot with multi-agent architecture. Pure Python, $0 cost (Claude CLI OAuth + Ollama), zero Docker required.

## Running

```bash
python viper.py http://target.com --full              # Full hunt (recon → exploit → report)
python viper.py http://target.com --full --stealth 2   # Stealth mode
python viper_autonomous.py --continuous --interval=60  # Continuous hunting
python viper_daemon.py                                  # 24/7 daemon
python dashboard/server.py                              # Dashboard at localhost:8080
```

## Directory Structure

```
hackagent/
├── viper.py                  # Main CLI entry point
├── viper_core.py             # Hunt orchestrator (ViperCore class)
├── viper_autonomous.py       # Continuous hunting mode
├── viper_daemon.py           # 24/7 daemon
├── mcp_server.py             # MCP tool server for Clawdbot integration
│
├── core/                     # 85+ modules — brain, engine, graph, agents, tools
│   ├── orchestrator.py       #   Async state machine (init→think→execute→respond)
│   ├── react_engine.py       #   ReACT loop with deep think + todo + RoE + phase enforcement
│   ├── think_engine.py       #   Deep Think structured analysis
│   ├── wave_runner.py        #   Parallel tool execution (asyncio.gather waves)
│   ├── hacker_mind.py        #   Cognitive reasoning: observe→hypothesize→test→adapt
│   ├── phase_engine.py       #   Phase state machine (RECON→SCAN→EXPLOIT) + tool enforcement
│   ├── skill_classifier.py   #   LLM attack path classification with confidence + CVE extraction
│   ├── agent_state.py        #   TodoList, ObjectiveManager, ConversationObjective
│   ├── agent_bus.py          #   Asyncio pub/sub message bus with priority queuing
│   ├── agent_registry.py     #   Agent lifecycle, health checks, least-busy routing
│   ├── approval_gate.py      #   Tool confirmation gate (dangerous tool approval)
│   ├── roe_engine.py         #   Rules of Engagement (scope, time, tool, phase enforcement)
│   ├── graph_engine.py       #   Dual-backend knowledge graph (Neo4j + networkx/SQLite)
│   ├── graph_query.py        #   NL→graph queries
│   ├── chain_writer.py       #   Attack chain persistence + 26 typed findings
│   ├── evograph.py           #   Cross-session Q-learning memory
│   ├── finding_validator.py  #   37 vuln-type behavioral FP filter
│   ├── guardrails.py         #   Target validation (LLM + hard blocklist)
│   ├── stealth.py            #   4-level WAF evasion + fingerprint randomization
│   ├── compliance_mapper.py  #   PCI-DSS/OWASP/HIPAA/SOC2/NIST mapping
│   ├── mitre_mapper.py       #   CWE→CAPEC→ATT&CK (hardcoded + offline DB)
│   ├── rate_limiter.py       #   Token bucket + human-like Gaussian timing
│   ├── key_rotation.py       #   API key round-robin rotation
│   ├── notifier.py           #   Telegram alerts via Clawdbot gateway
│   ├── codefix_engine.py     #   Tree-sitter ReACT fix loop + GitHub PR
│   ├── codefix_tools.py      #   11 code nav tools (symbols, find_def, repo_map)
│   ├── report_narrative.py   #   CISO 6-section report generator
│   ├── html_reporter.py      #   Professional HTML reports + PDF export
│   ├── iana_services.py      #   11,473 port-service mappings
│   ├── viper_db.py           #   SQLite findings/targets/attacks persistence
│   ├── fuzzer.py             #   Mutation + grammar + genetic algorithm fuzzing
│   ├── graphql_fuzzer.py     #   Introspection + depth bomb + alias bomb + injection
│   ├── oauth_fuzzer.py       #   7 OAuth/OIDC test suites (state bypass, PKCE, JWT alg:none)
│   ├── websocket_fuzzer.py   #   WS fuzzing, auth bypass, injection, race conditions
│   ├── race_engine.py        #   Last-byte sync race conditions (Turbo Intruder style)
│   ├── logic_modeler.py      #   Business logic flaw detection (step-skip, price manipulation)
│   ├── scanner.py            #   HTTP fuzzing with rate limiting
│   ├── secret_scanner.py     #   40+ regex + Shannon entropy
│   ├── failure_analyzer.py   #   Learn from failed attacks, WAF detection, bypass suggestions
│   ├── cross_target_correlator.py  #   Same vuln class across multiple targets
│   ├── chain_of_custody.py   #   SHA-256 evidence hashing + HMAC-signed manifests
│   ├── finding_stream.py     #   Real-time notifications (Discord, Telegram, email)
│   ├── poc_generator.py      #   Standalone PoC scripts (Python + curl)
│   └── skill_prompts/        #   Per-attack-type LLM prompts
│       ├── sql_injection.py  #     7-step SQLMap workflow + WAF bypass matrix
│       ├── cve_exploit.py    #     CVE exploitation workflow
│       ├── brute_force.py    #     Credential attack workflow
│       ├── phishing.py       #     Social engineering workflow
│       └── dos.py            #     Denial of service workflow
│
├── recon/                    # 21 modules — 7-phase pipeline
│   ├── pipeline.py           #   Orchestrator: domain→passive→ports→http→resources→vuln→mitre
│   ├── recon_engine.py       #   Subdomain enum + port scanning
│   ├── surface_mapper.py     #   Parameter discovery + API enum + JS analysis
│   ├── web_crawler.py        #   Async BFS crawler
│   ├── resource_enum.py      #   Katana + GAU + Wayback + Arjun + ParamSpider + FFuf + Kiterunner
│   ├── security_checks.py    #   28 checks: DNS/auth/ports/app/WAF bypass/rate limiting
│   ├── wappalyzer.py         #   3,920 tech fingerprints
│   ├── shodan_enricher.py    #   Shodan InternetDB + full API
│   ├── urlscan_enricher.py   #   URLScan.io passive recon
│   ├── whois_lookup.py       #   WHOIS with retry + cache
│   ├── cve_lookup.py         #   NVD + Vulners API, 154 CPE mappings
│   ├── mitre_enricher.py     #   CVE→CWE→CAPEC enrichment
│   ├── mitre_offline.py      #   95MB offline MITRE database
│   ├── github_hunt.py        #   Org-wide GitHub secret hunting (48 patterns)
│   ├── github_secrets.py     #   JS/HTTP secret detection
│   ├── arjun_discovery.py    #   Hidden parameter discovery
│   ├── paramspider_discovery.py  #   Wayback param mining
│   ├── kiterunner_discovery.py   #   API endpoint brute force
│   ├── ffuf_fuzzer.py        #   Directory fuzzing with auto-calibration
│   └── anonymity.py          #   Tor/SOCKS5 proxy routing
│
├── ai/                       # 3 modules
│   ├── model_router.py       #   Claude CLI ($0) → LiteLLM → Ollama fallback chain
│   └── llm_analyzer.py       #   AI-powered vulnerability analysis
│
├── tools/                    # 14 modules
│   ├── http_client.py        #   Async aiohttp with rate limiting + proxy + WAF detection
│   ├── brute_forcer.py       #   8-protocol credential testing (SSH/FTP/HTTP/MySQL/etc.)
│   ├── metasploit.py         #   MSF subprocess interface
│   ├── google_dork.py        #   SerpAPI passive OSINT (18 dork templates)
│   ├── web_search.py         #   SerpAPI + Tavily dual-provider web search
│   ├── payload_mutator.py    #   WAF bypass encoding mutations
│   └── tool_manager.py       #   External tool registry + auto-detect
│
├── scanners/                 # 4 modules
│   ├── nuclei_scanner.py     #   Nuclei + custom template auto-discovery
│   ├── gvm_scanner.py        #   GVM/OpenVAS (optional Docker)
│   └── trufflehog_scanner.py #   TruffleHog git secret scanning
│
├── agents/                   # Specialized autonomous agents
│   ├── recon_agent.py        #   Autonomous recon: subdomain enum, tech fingerprint, discovery
│   ├── vuln_agent.py         #   Tree-of-Thought hypothesis generation (top-5 branches)
│   ├── exploit_agent.py      #   Non-destructive PoC development and validation
│   ├── chain_agent.py        #   Attack chain discovery + cross-target correlation
│   ├── codefix_agent.py      #   Tree-sitter ReACT fix loop + GitHub PR
│   └── post_exploit.py       #   Post-exploitation enumeration
│
├── dashboard/                # Web UI at localhost:8080
│   ├── server.py             #   Python HTTP server, 30+ API endpoints, sandboxed terminal
│   ├── index.html            #   Preact SPA: 3D graph, risk gauge, charts, chat, terminal
│   ├── chat_v2.html          #   AI chat with persistence + agent timeline
│   ├── terminal_v2.html      #   NLP terminal (English→command) + SSH target proxy
│   ├── insights_v2.html      #   10+ chart types (CVSS, kill chain, radar, treemap)
│   └── cypherfix_v2.html     #   Remediation panel with diff viewer
│
├── scope/                    # Scope management
│   ├── scope_manager.py      #   In-scope/out-of-scope tracking + wildcards
│   └── roe_parser.py         #   Rules of Engagement document parser
│
├── data/                     # Static data (126MB)
│   ├── wappalyzer_technologies.json  # 3,920 tech fingerprints
│   ├── iana_services.csv     #   11,473 port-service mappings
│   ├── mitre_db/             #   95MB offline CVE/CWE/CAPEC database
│   └── nuclei/custom/        #   Custom nuclei templates
│
├── state/                    # Runtime state (JSON)
├── memory/                   # Learned patterns across sessions
├── knowledge/                # Attack knowledge base
├── findings/                 # Discovered vulnerabilities
├── reports/                  # Generated HTML/Markdown reports + PoCs
├── scopes/                   # Platform scope definitions (HackerOne JSON)
├── wordlists/                # Fuzzing wordlists (common.txt, lfi-payloads.txt, etc.)
├── models/                   # ML experience data + Q-tables
├── logs/                     # Audit logs
├── credentials/              # Platform API credentials
├── programs/                 # Target program definitions
├── docker/                   # Docker compose (GVM)
├── labs/                     # Interactive practice labs
└── archive/                  # Archived scripts (natas, hunt sessions, old experiments)
```

## Key Architecture

### Hunt Pipeline
```
viper.py → ViperCore.full_hunt(target)
  Phase 1.0: Domain Discovery (subfinder, crt.sh, DNS)
  Phase 1.5: Passive Intel (Shodan, URLScan, WHOIS, CVEs)
  Phase 2.0: Port Scanning (naabu, Shodan InternetDB)
  Phase 3.0: HTTP Probing (httpx, Wappalyzer 3920 techs)
  Phase 4.0: Resource Enum (Katana, GAU, Arjun, ParamSpider, FFuf, Kiterunner)
  Phase 5.0: Vuln Scanning (Nuclei, 28 security checks, WAF bypass)
  Phase 6.0: MITRE Enrichment (CVE→CWE→CAPEC offline)
  Phase 7.0: Manual Attacks (ReACT loop + Q-learning + Deep Think)
  Phase 8.0: Reporting (CISO narrative, HTML, compliance mapping)
```

### Multi-Agent Architecture (v5.0)
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

### ReACT Engine Flow
```
ReACTEngine.reason_and_act(target)
  → RoE enforcement (scope/time/tool/phase check)
  → Phase enforcement (tool must match current phase)
  → Deep Think trigger (auto at step 1, on failures, on LLM request)
  → Todo list management (LLM maintains structured work plan)
  → Tool confirmation gate (dangerous tools need approval)
  → Execute action → update Q-table → check exhaustion
```

### Attack Modules (v5.0)
- **OAuth fuzzer** — 7 test suites: state bypass, redirect manipulation, PKCE, JWT alg:none
- **WebSocket fuzzer** — Auth bypass, injection, race conditions, cross-origin
- **Race engine** — Last-byte sync (Turbo Intruder style), coupon reuse, double-spend
- **Logic modeler** — Business logic mapping, step-skip, price manipulation, privilege escalation
- **Failure analyzer** — WAF detection, bypass suggestions, LLM-powered learning

### LLM Routing ($0 cost)
```
Claude CLI OAuth (free) → LiteLLM API (paid fallback) → Ollama local (free fallback)
```

## External Tools

Installed via Go/pip. All optional with graceful degradation:
```
nuclei httpx subfinder katana naabu gau ffuf    # Go tools (~/go/bin/)
arjun paramspider                                 # pip install
```

## Dashboard

`http://localhost:8080` — Preact SPA with:
- 3D force-graph knowledge visualization
- AI chat (real Claude responses)
- Sandboxed NLP terminal (English→command, SSH target proxy)
- 10+ chart types, risk gauge, kill chain
- CypherFix remediation panel
- 30+ REST API endpoints + SSE streaming

Terminal security: allowlist-only pentest tools, shell metacharacter blocking, no local system access. `!connect user@target` for SSH proxy mode.

## Ethical Rules

1. Only test authorized targets (scope enforced by `roe_engine.py` + `guardrails.py`)
2. No destructive actions — read-only PoCs only
3. Verify every finding before reporting (`finding_validator.py` — 37 vuln-type behavioral checks)
4. Rate limiting enforced (`rate_limiter.py` — token bucket + human timing)
5. Tool confirmation gate for dangerous operations
6. Findings redacted — no PII/credentials in reports
