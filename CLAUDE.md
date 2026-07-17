# VIPER 5.0

Autonomous bug bounty hunting bot with multi-agent architecture. Pure Python, $0 cost (Claude CLI OAuth + Ollama), zero Docker required.

## Running

```bash
python viper.py http://target.com --full              # Full hunt (recon → exploit → report)
python viper.py http://target.com --full --stealth 2   # Stealth mode
python viper.py hack <target> --profile bugbounty       # Swarm HackMode hunt (see core/hack_mode.py)
python viper_daemon.py                                  # 24/7 daemon
python dashboard/launch.py                              # Dashboard: UI :3000 + API :8080 (one command)
python dashboard/launch.py --prod                       # Same, production UI build
python dashboard/server.py                              # Headless API only (:8080)
```

### Operator / triage CLIs

```bash
python viper.py scope pull <h1-handle>   # auto-pull a HackerOne program's scope -> scopes/current_scope.json
python viper.py scope import <csv|burp>   #   (offline) load an exported scope CSV / Burp scope file
python viper.py classes                  # vuln classes VIPER tests; flags gate-confirmed + OOB-capable
python viper.py scorecard [--strict]     # per-class validation-gate precision/recall benchmark
python viper.py verify <findings.json>   # re-confirm saved findings via the gate (no full hunt)
python viper.py evidence verify <manifest> [findings.json] [--key K]   # verify a hunt's tamper-evident custody manifest
python viper.py leads [findings.json]    # group non-submittable leads by why the gate demoted them
python viper.py submissions [hunt_id]    # review gate-confirmed submission drafts
python viper.py outcome <disposition> <findings.json> [--tech t1,t2]   # feed accepted/paid/rejected back into priors (outer learning loop)
python viper.py import <file.har|collection.json> [--host H]   # inspect a HAR/Postman export (endpoints+params; auth values never read)
python viper.py ledger [list|clear]      # cross-hunt duplicate-suppression ledger
python viper.py bola <target> ...        # focused two-account BOLA/IDOR check
python viper.py skills [stats|search|show|select]   # lazy skill catalog (~1,600 skills)
python viper.py mcp [servers|list|call]  # consume external MCP tool servers (gate-filtered)
python viper.py oob [start|demo]         # out-of-band interaction listener (blind-vuln confirmation)
```

Hunt flags worth knowing: `HackMode(..., oob=OOBServer, mcp_plan=[...], bola_config=..., proxy=..., validate=True)`.
`viper.py hack <t> --burp-mcp` auto-builds an mcp_plan against an external Burp MCP
(access-control sweep + Collaborator poll + scanner issues), merged into `--mcp-plan`
and gate-filtered like any `mcp:*` source; two-account BOLA flags arm the sweep.

## Directory Structure

```
hackagent/
├── viper.py                  # Main CLI entry point
├── viper_core.py             # Hunt orchestrator (ViperCore class)
├── viper_daemon.py           # 24/7 daemon (continuous hunting)
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
│   ├── finding_stream.py     #   Telegram + Discord + email alert dispatch (replaces notifier.py)
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
             + swarm recon `openapi` worker: ingests a published OpenAPI 3.x /
             Swagger 2.0 spec (read-only) into real endpoint targets (path-templated,
             query-seeded) + registers every documented param name via
             add_discovered_params, so the confirmed injection/SSRF/access-control
             workers probe the API's ACTUAL routes+params instead of guessing.
             + swarm recon `sourcemap` worker: fetches served .js.map files (only
             HEAD-checked before) and mines them — shape-specific credentials
             (gate-confirmed by the existing _recheck_secrets, reusing its regexes)
             + routes/params recovered from sourcesContent fed to the vuln workers.
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
`ai/model_router.py` is provider-agnostic and runs WITHOUT Claude: set
`VIPER_MODEL=ollama/<model>` (+ `OLLAMA_HOST`) for a local LLM, or `VIPER_MODEL` +
`VIPER_API_BASE` for any OpenAI-compatible endpoint. `VIPER_USE_CLI` auto-detects — it
prefers the free Claude CLI by default but stands down when you point `VIPER_MODEL`/
`VIPER_API_BASE` at another backend (so a stray `claude` binary can't hijack it); set it
explicitly to force either way. The LLM only powers reasoning / report narrative / skill
classification — recon, the swarm workers, and the validation gate call NO LLM, so a hunt
(`viper.py hack`) fully confirms findings even with no LLM configured. `ai/llm_analyzer.py`
routes through the same router (Anthropic-direct only as a last-resort fallback).

## Confirmation & Trust (the core differentiator)

VIPER is FP-averse and human-submits-only: a worker finding is a *candidate*; it
becomes `submittable` ONLY when an INDEPENDENT path re-confirms it. This is what
makes autonomous runs safe to act on.

```
swarm worker (candidate) → swarm_validation.py gate (_reconfirm, fail-closed)
   → validated / submittable / validation_confidence / validation_reason
   → proof_requests (the EXACT confirming request(s), auth-redacted, for repro)
   → chain_recipes.correlate_chains → prioritization → submission_draft (+INDEX.md)
   → chain_of_custody: submittable set SHA-256-hashed (incl. proof_requests) +
     HMAC-signed into a per-hunt <hunt_id>_manifest.json (tamper-evident evidence)
   → submission_ledger (cross-hunt dedup) → human reviews & submits
```

- `core/swarm_validation.py` — the gate. Per-class independent re-tests
  (`_recheck_xss/_sqli/_ssti/_lfi/_cmdi/_secrets/_access_control/_host_header/
  _subdomain_takeover/_crlf/_xxe/_clickjacking/_idor`), two-identity trust for
  BOLA/BFLA/web-cache-deception (provenance-checked, external `source=mcp:*`
  findings can NEVER use a trust short-circuit), and OOB-token confirmation. A
  malformed/un-reproducible finding fails closed to a lead.
- `core/gate_benchmark.py` — `viper.py scorecard`: labeled per-class precision/
  recall. Currently 26 classes at precision 1.00 (0 false positives).
- `core/confirm_gate.py` — reusable ThreeGateConfirmer (baseline→attack→
  differential + reproducibility re-test).
- `core/adversarial_verifier.py` — a REFUTATION pass after the gate: independently
  re-runs the gate's confirmation on each submittable finding and DEMOTES any that
  does not reproduce (transient/flaky — a timing blip, an intermittent 5xx). Only
  ever demotes, so it improves precision on noisy targets but never costs recall on
  a deterministic true positive (a test iterates every scorecard vuln scenario and
  asserts none are demoted). Wired into the hunt; opt out with
  `profile.adversarial_verify = False`.

### Out-of-band (blind-vuln) confirmation — `core/oob/`

The only way to confirm blind SSRF / RCE / XXE / OAST-SQLi / Host-header SSRF.
`OOBServer` mints unique canary tokens, runs HTTP+DNS listeners, and records only
interactions for tokens IT issued (no false confirms from background traffic).
Blind-capable workers (`ssrf`, `command_injection`, `xxe`, `host_header`, `ssti_probe`
— the last fires engine-specific template payloads across Jinja/Twig/Freemarker/Smarty/
ERB under one canary) fire a canary; a callback flips the finding to submittable at the
gate. Before the gate
decides, `HackMode._await_late_oob_callbacks` waits a bounded window (only while
canary tokens are still outstanding) so a LATE callback — arriving just after the
hunt — still rescues a genuine blind vuln instead of it being filed as a lead.

### Confirmed vulnerability classes (gate-verified)

Beyond the injection family (sqli/xss/ssti/lfi/cmdi) and exposures
(secrets/env/git/dir-listing/cors), VIPER confirms: **BOLA + BFLA + IDOR**
(two-account, `core/specialist/{bola,bfla}_engine.py`), **Host Header Injection**
(`host_header.py`), **Subdomain Takeover** (`subdomain_takeover.py`, fingerprint
+ CNAME corroboration), **Web Cache Deception** (`web_cache_deception.py`,
two-identity), **CRLF**, **clickjacking**, **Open Redirect** (CWE-601 — the gate
re-injects a FRESH random attacker host and requires it to be the real redirect
target, absent under a benign control), **GraphQL** introspection / exposed IDE
(independent introspection re-query requiring a genuine __Schema: named queryType +
canonical __TypeKind) and **GraphQL field-level authorization** bypass (`graphql.py`
`graphql_authz` — BOLA/BFLA over GraphQL: opt-in + two-identity, the gate POSTs an
operator-supplied READ-ONLY query and confirms iff the owner's private marker appears in
the OWNER *and* ATTACKER responses' non-null `data` but NOT anonymously; a mutation is
refused and a marker reflected from the query is vetoed, so an authZ error-echo can't
false-confirm; CWE-639), **NoSQL operator-injection auth bypass** (`nosql_injection.py`
`:login` — re-runs the token differential: a bogus credential mints no token, the
operator body does; an $eq-to-bogus control proves it's operator-driven), and **JWT
weak-key forgery** (`jwt.py` `:weak_key` — a cracked key stays a LEAD until an
operator-supplied `jwt_probe_endpoint` proves a forged token is accepted where a
bad-signature control is rejected; opt-in, GET-only, no privilege escalation) and
**JWT RS256->HS256 algorithm confusion** (`jwt.py` `:alg_confusion` — reconstructs the
RSA public key from jwks.json into a PEM via a hand-rolled DER encoder, dependency-free;
forges an HS256 token with that public key as the HMAC secret and confirms via the SAME
opt-in forge-accept probe as weak-key) and **JWT `kid` header injection** (`jwt.py`
`:kid_inject` — a JWT carrying a `kid` (Key ID) header is forgeable when the verifier
resolves `kid` to a key FILE; the gate forges with `alg:HS256`, a path-traversal `kid`
(-> `/dev/null`) and an EMPTY HMAC key and confirms via the SAME opt-in forge-accept probe;
CWE-347, GET-only, no privilege escalation).
and **Response-based SSRF** (`ssrf.py` `ssrf:<param>` — re-runs the read-only metadata
differential: an internal payload must return the service's own body with a credential
VALUE co-occurring with >=1 cloud-metadata marker, or >=2 distinct markers, absent from
a benign baseline; reflected payload stripped + WAF-denial vetoed; blind SSRF stays on
the OOB path), and **LDAP / XPath injection** (`query_injection.py`
`{ldap,xpath}_injection:<param>` — the gate re-runs an in-band engine-error differential:
a grammar-breaker (`*)(uid=*` for LDAP, `'` for XPath) must emit an ENGINE-SPECIFIC error
(`javax.naming`/`LDAPException` — CWE-90; `XPathException`/`xmlXPathEval` — CWE-643) that a
benign control value does NOT, and a control that already errors vetoes it as noise;
read-only, mirrors the sqli error-signature discipline). CSRF is deliberately NOT
gate-confirmed — a tokenless SameSite-less form is only forgeable if the server also lacks
an Origin/Referer or double-submit defence, which is invisible read-only, so it stays an
actionable lead (adversarially confirmed FP vector; same rationale as mass-assignment).
`viper.py classes` lists coverage; `viper.py leads` explains why any non-submittable
finding was demoted. The scorecard measures 26 classes / 29 confirmed scenarios /
precision 1.00 / 0 FP (xxe + crlf are scored offline too — the benchmark patches
those workers' module `fetch`, since their gate recheck re-runs the worker), and
`core/gate_mutations.py` (`python -m core.gate_mutations --strict`)
re-runs every SAFE scenario across confidence thresholds + benign response
perturbations so precision 1.00 is a guarded invariant, not a snapshot.
`python -m core.gate_ci` runs the scorecard (strict on BOTH precision AND recall —
a confirmed class silently dropping to a lead also fails) + the mutation harness as
one check; `.github/workflows/gate.yml` enforces it on every push/PR that touches
`core/` or `tests/`, so the invariant is a merge-gate, not just measured.

Lead-only (read-only) detectors stay leads by design — confirming them would need a
destructive action (an RCE gadget, a server-side write, poisoning a shared cache) or
a browser, so they surface an actionable `viper.py leads` reason instead of a false
auto-submission: **client-side prototype pollution** (`proto_pollution.py`, CWE-1321
— user-input source reaching a prototype-touching JS sink, or a versioned vulnerable
merge lib), **insecure-deserialization surface** (`deser_surface.py`, CWE-502 —
observes serialized-object magic in cookies/params/body, never sends a gadget),
**OAuth/OIDC config** (`oauth_config.py` — reads the `.well-known` discovery doc for
no-PKCE / implicit-flow / `none`-auth), **web-cache-poisoning risk** (`cache_poisoning.py`,
CWE-524 — unkeyed-header reflection into a cacheable response, probed SAFELY with a
per-request cache buster + a benign marker so no shared key is poisoned), and **mass
assignment** (needs a PATCH write). None mutates target state destructively.

### New core modules (since v5.0)

```
core/session_context.py    Per-hunt roles + (role,url)->status reachability matrix
core/authenticated_crawl.py crawl_roles: shallow crawl per operator-supplied role,
                           records per-role reachability (feeds BOLA/BFLA) + surfaces
                           authed-only endpoints/params. HackMode auto-seeds roles from
                           the two-account BOLA config; read-only, discovery only.
                           (GraphQL introspection + the OpenAPI worker likewise seed
                           the injection workers with the API's real field/param names.)
core/browser/              proxy_pipeline (dedup) + session_capture (role-diff) +
                           viper_browser (optional Playwright, graceful degradation)
core/skill_registry.py     Lazy skill catalog (flat token cost) + skill_catalog.py
core/skill_import.py        (build from vendored MITRE + absorb external SKILL.md)
core/mcp/ + mcp_client.py  Dependency-free MCP: own servers + CLIENT to consume
core/mcp_tool_bridge.py     external tool arsenals (output gate-filtered)
core/oob/                  Out-of-band interaction engine (canary/store/listeners)
core/chain_recipes.py      Low→critical escalation correlation (submittable iff
                           every component is submittable)
core/prioritization.py     P1-P4 scoring (submittable + severity + gate confidence)
core/submission_ledger.py  Cross-hunt duplicate suppression
core/hack_mode.py          Swarm HackMode orchestrator (threads OOB + MCP + gate)
core/attack_priors.py      Closes the evograph write->read loop: records each
                           technique's per-hunt outcome and reorders phase dispatch
                           so attacks that historically worked on the target's stack
                           run first. Best-effort; never touches the gate (exploration
                           ORDER only). Disable via profile.learn_priors = False.
                           (react_engine has the sibling loop: evograph.get_reasoning_
                           recall seeds Deep Think with prior high-reward reasoning for
                           the same stack, so the react loop no longer reasons from zero.)
core/gate_mutations.py     Mutation/regression harness: re-runs every SAFE benchmark
                           scenario across confidence thresholds + benign perturbations
                           so precision 1.00 is a guarded invariant (python -m
                           core.gate_mutations --strict).
core/{ops,verify}_cli.py    classes / ledger / leads / verify operator CLIs
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

1. Only test authorized targets (scope enforced by `roe_engine.py` + `guardrails.py`).
   `core/guardrail_hard.py` is a deterministic blocklist (gov/mil/edu/int TLDs + 50+ major
   domains) that fails an un-scoped run closed — a bare `google.com` typo stays refused. For a
   legitimate AUTHORIZED engagement (e.g. a HackerOne program you're enrolled in) it can be
   overridden PER-HOST by a deliberate operator signal: an operator-loaded `--scope` program
   file (marked authoritative; in-scope hosts are allowed) or the `VIPER_AUTHORIZED_TARGETS`
   env allowlist (`host`, `*.wildcard`, or `*`). A target-derived AUTO-scope can NOT authorize
   itself, so the blocklist still catches typos/un-scoped runs; every override is audited
   (`guardrail.authorized_override`). `is_blocked(target, authorized=...)` — the blocklist is
   evaluated before any safe-target heuristic and `_normalize` reduces a URL to its true
   authority host (scheme/userinfo/backslash/IPv6/port can't dodge it).
2. No destructive actions — read-only PoCs only
3. Verify every finding before reporting (`finding_validator.py` — 37 vuln-type behavioral checks)
4. Rate limiting enforced (`rate_limiter.py` — token bucket + human timing). The
   swarm request path (`core/swarm_workers/vuln/_rate_limit.py`) adds per-host
   ADAPTIVE backoff on TWO axes: a target's own 429/503 signals multiplicatively
   throttle its request RATE down (to a 0.5 req/s floor) AND halve its CONCURRENCY
   ceiling (simultaneous in-flight, floor 1), both recovering gradually on sustained
   healthy responses — fast on healthy targets, automatically gentle on fragile ones
   / connection-limited WAFs.
5. Tool confirmation gate for dangerous operations
6. Findings redacted — no PII/credentials in reports
