# PLAN — Function Audit: `ai_techniques`

> Part of [PLAN.md](PLAN.md) Section 2. Generated 2026-06-06. Module: **core/ai_techniques.py**

**Exists:** True  

## Summary

1195-line AI/LLM attack technique library: encoding utilities, prompt-injection payload arsenal (~147 templates), RAG/multi-agent payload sets, a thread-pool "CHAOS vs ORDER" dual-agent runner, a JSON-backed collective memory, an OWASP-MCP-Top-10 config scanner, and ML-infra CVE exploit metadata + a live HTTP endpoint scanner. Nearly all logic is pure data/string generation; the only network action is MLInfrastructureExploitsV2.scan_endpoint (urllib, 10s timeout). The module is imported and re-exported by core/__init__.py (public API), but no live (non-archive) code or test exercises its methods — only archive/old_entry_points and README reference them. Zero test coverage. Main defects: scan_endpoint hits the target with no scope/RoE/guardrail check, two genuinely silent excepts, a synchronous ThreadPoolExecutor.result() that blocks if used in async contexts, save-on-every-technique (unbounded disk I/O), MD5 use, and a README-documented MCPSecurityScanner.scan() method that does not exist (only scan_all).

## Top issues

- scan_endpoint (line 1135) does live network I/O with no scope check
- destructive DROP TABLE payload in _run_order_agent
- silent excepts at lines 782 and 1163
- blocking threadpool .result() unsafe in async; unguarded concurrent file writes

## Scope / safety notes

YES — this module performs a target/network action without a scope or RoE check. MLInfrastructureExploitsV2.scan_endpoint (line 1135-1166) issues a real urllib HTTP GET to a caller-supplied base_url with a 10s timeout and a hard-coded User-Agent ('VIPER-Scanner/1.0'), with no call to guardrails/roe_engine/scope_manager before sending. This is the only direct network call in the file. Additionally, AdversarialDualAgentV2.run_parallel_attack (line 616) and the _run_chaos_agent/_run_order_agent helpers invoke an arbitrary caller-supplied test_fn against payloads (including a destructive 'DROP TABLE' payload at line 699) with no scope/RoE/non-destructive enforcement inside this module — safety depends entirely on the caller. generate_nuclei_templates writes exploit templates to disk but performs no network action. All MCPSecurityScannerV2 checks and the prompt-injection/RAG/multi-agent generators are pure (no network). Recommendation: gate scan_endpoint and run_parallel_attack behind scope_manager/roe_engine validation and remove the destructive SQL payload before any live use.

## Function-by-function table

| File:Line | Function | Purpose | Inputs | Outputs | Side effects | Status | Issues |
|---|---|---|---|---|---|---|---|
| ai_techniques.py:55 | `EncodingEngine.to_base64` | Base64-encode text | `text:str` | `str` | none | UNTESTED | |
| ai_techniques.py:59 | `EncodingEngine.from_base64` | Base64-decode text | `text:str` | `str` | none | UNTESTED | No error handling; raises on bad input/non-utf8 |
| ai_techniques.py:63 | `EncodingEngine.to_rot13` | ROT13 encode | `text:str` | `str` | none | UNTESTED | |
| ai_techniques.py:67 | `EncodingEngine.from_rot13` | ROT13 decode | `text:str` | `str` | none | DEAD-CODE | Never called in repo (no inverse use) |
| ai_techniques.py:71 | `EncodingEngine.to_hex` | Hex-encode text | `text:str` | `str` | none | UNTESTED | |
| ai_techniques.py:75 | `EncodingEngine.to_unicode_escape` | \\uXXXX escape | `text:str` | `str` | none | UNTESTED | Only handles BMP (ord>0xFFFF mis-rendered) |
| ai_techniques.py:79 | `EncodingEngine.to_url_encode` | %XX encode | `text:str` | `str` | none | UNTESTED | `%02x` truncates codepoints >0xFF |
| ai_techniques.py:83 | `EncodingEngine.to_double_url_encode` | %25XX encode | `text:str` | `str` | none | UNTESTED | Same >0xFF truncation |
| ai_techniques.py:87 | `EncodingEngine.to_leetspeak` | Leet substitution | `text:str` | `str` | none | UNTESTED | |
| ai_techniques.py:92 | `EncodingEngine.to_fullwidth` | Fullwidth Unicode | `text:str` | `str` | none | UNTESTED | |
| ai_techniques.py:97 | `EncodingEngine.to_circle_letters` | Circled letters | `text:str` | `str` | none | UNTESTED | |
| ai_techniques.py:223 | `PromptInjectionEngineV2.get_encoding_attacks` | Build encoded payload dicts | `action:str` | `List[Dict]` | none | UNTESTED | `to_hex` listed but no `from`/decode key consistency; pure |
| ai_techniques.py:356 | `PromptInjectionEngineV2.get_all_attacks` | Aggregate all PI payloads | none | `List[Dict]` | none | UNTESTED | Docstring claims 147+; actual count not enforced |
| ai_techniques.py:392 | `PromptInjectionEngineV2.generate_payload` | One formatted payload | `action:str, category:str` | `str` | none | UNTESTED | `.format` raises KeyError if template has other `{..}` tokens (e.g. delimiter `{"role"...}`); uses global `random` (nondeterministic) |
| ai_techniques.py:458 | `RAGPoisoningEngine.get_all_attacks` | Aggregate RAG payloads | none | `List[Dict]` | none | UNTESTED | Pure |
| ai_techniques.py:540 | `MultiAgentExploitEngine.get_all_attacks` | Aggregate multi-agent payloads | none | `List[Dict]` | none | UNTESTED | Pure |
| ai_techniques.py:574 | `AdversarialDualAgentV2.__init__` | Init memory + threadpool | none | none | Creates CollectiveMemoryV2 (reads/loads JSON file); spawns ThreadPoolExecutor(2) | UNTESTED | Executor never shutdown (resource leak; no context mgr / __del__) |
| ai_techniques.py:578 | `AdversarialDualAgentV2.assess_difficulty` | Score defenses→strategy | `target_info:Dict` | `Dict` | none | UNTESTED | Pure |
| ai_techniques.py:616 | `AdversarialDualAgentV2.run_parallel_attack` | Run CHAOS+ORDER via threads | `target, vuln_type, test_fn` | `Dict` | Invokes user `test_fn` (may do network I/O) | UNTESTED | Blocking `.result(timeout=300)`; if called from async def it blocks the loop; `target` arg unused; no scope check before invoking test_fn |
| ai_techniques.py:644 | `AdversarialDualAgentV2._run_chaos_agent` | Run creative payloads | `target, vuln_type, test_fn` | `List[Dict]` | Calls `test_fn` per payload | UNTESTED | `target`/`vuln_type` unused; broad `except Exception` (line 680) swallows all errors into result (acceptable but loses trace) |
| ai_techniques.py:690 | `AdversarialDualAgentV2._run_order_agent` | Run OWASP payloads | `target, vuln_type, test_fn` | `List[Dict]` | Calls `test_fn` per payload | UNTESTED | `target` unused; payload set includes `'; DROP TABLE users--` (destructive if test_fn sends it live — violates non-destructive rule); broad except (732) |
| ai_techniques.py:742 | `AdversarialDualAgentV2._judge_results` | Tally wins, persist winners | `chaos_results, order_results` | `Dict` | Calls `collective_memory.add_technique` → writes JSON file per win | UNTESTED | Disk write per successful technique (unbounded I/O); stats chaos_wins/order_wins never actually incremented |
| ai_techniques.py:774 | `CollectiveMemoryV2.__init__` | Load memory file | `path:str=None` | none | Reads file at default `__file__.parent/collective_memory.json` | UNTESTED | Default path hard-coded relative to module dir (writes into source tree) |
| ai_techniques.py:778 | `CollectiveMemoryV2._load` | Parse JSON or default | none | `Dict` | Reads file | NEEDS-FIX | Silent `except Exception: pass` (line 782-783) hides corruption; `e` bound but unused/unlogged |
| ai_techniques.py:795 | `CollectiveMemoryV2.save` | Write memory JSON | none | none | Overwrites JSON file | UNTESTED | No atomic write/temp-rename (truncation risk on crash); no error handling; concurrent saves from 2 threads = race/corruption |
| ai_techniques.py:798 | `CollectiveMemoryV2.add_technique` | Record winning payload | `result:Dict` | none | Mutates self.memory + calls save() (disk write) | NEEDS-FIX | MD5 for key (weak, collision-prone for dedupe); writes file every call (perf); not thread-safe though called from threadpool judge path; payload truncated to 50 chars may collide |
| ai_techniques.py:816 | `CollectiveMemoryV2.get_recommended` | Top techniques by success rate | `target_stack:str, limit:int` | `List[str]` | none | DEAD-CODE | `target_stack` arg ignored entirely; not called by any live code |
| ai_techniques.py:837 | `MCPSecurityScannerV2.__init__` | Init scanner | none | none | Instantiates PromptInjectionEngineV2 | UNTESTED | `self.results`/`self.prompt_engine` set but never used |
| ai_techniques.py:841 | `MCPSecurityScannerV2.scan_all` | Run MCP01-10 checks | `target_config:Dict` | `Dict` | none (pure config inspection) | UNTESTED | Per-check `except Exception` (874) is broad but records error (ok); no network — purely reads dict |
| ai_techniques.py:883 | `MCPSecurityScannerV2._check_token_management` | MCP01 secret check | `config:Dict` | `Tuple[bool,str]` | none | UNTESTED | Returns secret key NAME in details (not value) — low risk |
| ai_techniques.py:901 | `MCPSecurityScannerV2._check_privilege_escalation` | MCP02 | `config:Dict` | `Tuple[bool,str]` | none | UNTESTED | Pure config heuristic |
| ai_techniques.py:917 | `MCPSecurityScannerV2._check_tool_poisoning` | MCP03 | `config:Dict` | `Tuple[bool,str]` | none | UNTESTED | Pure |
| ai_techniques.py:933 | `MCPSecurityScannerV2._check_supply_chain` | MCP04 | `config:Dict` | `Tuple[bool,str]` | none | UNTESTED | Pure |
| ai_techniques.py:949 | `MCPSecurityScannerV2._check_command_injection` | MCP05 | `config:Dict` | `Tuple[bool,str]` | none | UNTESTED | Pure |
| ai_techniques.py:965 | `MCPSecurityScannerV2._check_prompt_injection` | MCP06 | `config:Dict` | `Tuple[bool,str]` | none | UNTESTED | Pure |
| ai_techniques.py:981 | `MCPSecurityScannerV2._check_auth` | MCP07 | `config:Dict` | `Tuple[bool,str]` | none | UNTESTED | Pure |
| ai_techniques.py:997 | `MCPSecurityScannerV2._check_audit` | MCP08 | `config:Dict` | `Tuple[bool,str]` | none | UNTESTED | Pure |
| ai_techniques.py:1013 | `MCPSecurityScannerV2._check_shadow_servers` | MCP09 | `config:Dict` | `Tuple[bool,str]` | none | UNTESTED | Pure |
| ai_techniques.py:1026 | `MCPSecurityScannerV2._check_context_oversharing` | MCP10 | `config:Dict` | `Tuple[bool,str]` | none | UNTESTED | Pure |
| ai_techniques.py:1120 | `MLInfrastructureExploitsV2.generate_nuclei_templates` | Write nuclei YAML files | `output_dir:Path` | `List[str]` | Creates dir + writes .yaml files to disk | UNTESTED | No error handling on write; overwrites existing files silently |
| ai_techniques.py:1135 | `MLInfrastructureExploitsV2.scan_endpoint` | Live HTTP probe of ML endpoint | `base_url:str, tech:str` | `Dict` | NETWORK: urllib GET to target | NEEDS-FIX | NO scope/RoE/guardrail check before hitting target; bare-ish `except Exception` (1163) swallows all; only GET (never sends exploit_payload, so "scan" is a connectivity check mislabeled); 10s timeout ok; no retry; User-Agent hard-coded "VIPER-Scanner/1.0" (differs from RoE-mandated UA) |
