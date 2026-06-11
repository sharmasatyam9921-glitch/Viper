# VIPER — Competitive Roadmap to Best-in-Class

_Generated 2026-06-11. Goal: a credible, winnable path to making VIPER the strongest
open-source autonomous web/API + LLM-app hunter — judged on **published benchmarks**,
not claims._

## 1. The honest competitive picture

| Tool | Stars | Interface | Benchmark (public) | Breadth | VIPER gap |
| --- | --- | --- | --- | --- | --- |
| **pentest-ai** (0xsteph) | 753 | MCP + CLI | **63.24% Juice Shop (43/68), 0% FP** | 205 tools, 17 agents, AD/cloud/mobile/wireless, OAST | We're behind on breadth + benchmark coverage |
| **claude-bug-bounty** (shuvonsec) | 2.5k | Claude-Code plugin (26 cmds) | none public | 20 Web2 + **10 Web3**, platform reports, hunt-memory | Behind on distribution + Web3 + reporting |
| **Shannon** (KeygraphHQ) | — | white-box | **96% (104/104)** | reads source, real PoCs | Different game (white-box); we're black-box |
| **XBOW** (commercial) | — | SaaS | **#1 HackerOne, 1060+ subs** | enterprise, proven | Not our tier |
| **PentestGPT** + other multi-agent OSS frameworks | 12.5k+ | HITL / multi-agent | academic | advisory / sandboxed | Behind on adoption |
| **VIPER** (this repo) | private | CLI + dashboard + MCP | **4/4 Juice Shop (4 challenges)** | ~7 tools, 12 vuln workers, **20 LLM-app testers** | tiny benchmark, private, narrow tooling |

**Read:** VIPER is **behind** pentest-ai and claude-bug-bounty on benchmark breadth, tool
integration, distribution, and multi-domain coverage. It is **ahead** on engineering rigor
(1184 tests), the chain-planner/world-model architecture, and one genuinely **uncontested
capability: OWASP-LLM/Agentic-Top-10 application security** (`core/ai_hunter/`, 20 testers).

**"Better than everyone" overall is not a short-term reality** (Shannon's 96% is white-box;
XBOW is #1 on HackerOne with $100M+ behind it). The **winnable** position:

> **The best open-source _black-box_ hunter for web + API, and the _definitive_ tool for
> LLM/agentic-application security — both backed by published, reproducible benchmark
> numbers.**

## 2. The universal weakness = VIPER's biggest opportunity

Every agent fails at **business-logic flaws (~70% of critical web vulns)** and the
**lab-to-real gap is brutal** (GPT-4: 87% on described CVEs → 13% realistic → ~0% hard).
This is where LLM *reasoning* + VIPER's `world_model` + `chain_planner` + `logic_modeler`
could actually differentiate — nobody has solved it.

## 3. The roadmap (prioritized by credibility-per-effort)

### Phase 1 — Earn a comparable number (highest leverage)
The 4/4 result is a proof-of-capability, not a market number. Close that first.
- **Expand the Juice Shop suite 4 → full set (~68 graded challenges)** and publish a catch
  rate directly comparable to pentest-ai's 63.24%. Reuse `benchmark/` + the new workers.
- **Run the XBOW 104-set (flag mode)** — `benchmark/suite/xbow/` already adapts to it.
- **Publish a pentest-ai-style scorecard**: catch rate, **FP rate**, OWASP buckets covered,
  vs ZAP/Nuclei baselines, in `benchmark/RESULTS.md`.
- Fix sequential-run reliability (per-hunt fresh target + resource budget) so the headline
  isn't isolated-run-only.

### Phase 2 — Close the capability gaps that cost challenges
Drawn from what the leaders detect and VIPER currently can't:
- **OAST / out-of-band** (interactsh-style) — *the* gap for **blind** SQLi/SSRF/XXE/RCE.
  pentest-ai ships encrypted OAST. Add an OAST collaborator + worker; route through
  `tool_gateway`. Without this, all blind classes are invisible.
- **Authenticated session engine** — `login_sqli` already recovers a JWT; thread it into a
  shared auth context so **IDOR/BOLA/business-logic** workers test as a logged-in user
  across two accounts (the real app-logic depth). Build on `world_model`.
- **New vuln workers**: request smuggling, subdomain takeover, 403/401 bypass, SSRF,
  open-redirect, mass-assignment, CSRF — all vuln-phase, all mock-tested like the existing 12.
- **Business-logic worker** — LLM-reasoned multi-step flows (price manipulation, step-skip,
  coupon reuse) on top of `logic_modeler.py` + the auth engine. This is the differentiator.

### Phase 3 — Tool depth (curated, not 205-for-show)
Research is clear: *specialized chains beat general breadth*. Add high-yield tools through
`core/tool_registry.py` + `tool_gateway`, each with a worker that consumes its output:
sqlmap, dalfox, ffuf (have), katana, gau, nuclei (have), arjun, paramspider. Quality of the
worker that *interprets* the tool matters more than the count.

### Phase 4 — Distribution (how the bounty tools actually win adoption)
claude-bug-bounty (2.5k★) and pentest-ai (MCP) win on **interface + visibility**:
- **First-class Claude-Code plugin**: ship `/recon /hunt /validate /report /autopilot` slash
  commands + skills over the existing `mcp_server.py` — an MCP-native "no API key needed"
  path. This is the format that gets stars and real-bounty users.
- **Go public** with the test suite + RESULTS. VIPER's rigor is its peer-group edge, but only
  if visible.
- **Reporting parity**: SARIF 2.1.0 + JUnit export, CI severity gates, and platform-aware
  templates (HackerOne/Bugcrowd/Intigriti/Immunefi) — `report_exporter.py` is the home.

### Phase 5 — Lean into the uncontested wedge: LLM-application security
Almost no competitor targets OWASP-LLM/Agentic-Top-10. As AI apps proliferate, this is a
growing, **uncontested bounty surface**.
- Make `core/ai_hunter/` (20 testers) the **headline capability**, with its own benchmark
  (a deliberately-vulnerable LLM-app target in `benchmark/`), and a `/hunt-ai` command.
- Web3 parity with claude-bug-bounty: strengthen `web3_auditor.py` toward the 10 smart-
  contract classes (reentrancy, oracle manipulation, flash-loan, access control).

## 4. Sequencing (what to do first)
1. **Full Juice Shop benchmark** (Phase 1) — turns "4/4" into a real, comparable catch rate.
   Highest credibility-per-hour; the harness already exists.
2. **OAST + auth-session engine** (Phase 2) — unlocks the largest class of currently-invisible
   bugs (blind + authenticated), which is what raises the catch rate most.
3. **Claude-Code plugin + go public** (Phase 4) — converts capability into adoption.
4. **Business-logic + LLM-app benchmark** (Phase 2/5) — the durable differentiation.

## 5. What "advanced" means here, concretely
Not "205 tools." It means: **a published catch rate competitive with pentest-ai's 63%, the
only OSS tool with a real LLM-app-security benchmark, an OAST-backed blind-vuln capability,
an authenticated business-logic engine, and a Claude-Code-native distribution** — each claim
backed by a reproducible number in `benchmark/`.
