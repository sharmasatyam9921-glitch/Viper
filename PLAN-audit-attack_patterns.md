# PLAN — Function Audit: `attack_patterns`

> Part of [PLAN.md](PLAN.md) Section 2. Generated 2026-06-06. Module: **core/attack_patterns.py**

**Exists:** True  

## Summary

Static, data-only "hacker's playbook": a hardcoded `PATTERNS` dict of 8 `AttackPattern` dataclass instances (methodology text, payloads, bypass techniques, bounty ranges) plus 4 pure accessor functions and a `__main__` demo. No network, filesystem, subprocess, or target interaction occurs anywhere in the module — it never sends a request or runs a tool; it only returns in-memory dataclass objects. Imports `Severity` from `core/models.py` (verified valid Enum). The module is effectively dead in live code: the only importer of `PATTERNS` is `archive/old_entry_points/agent.py` (archived). The 4 accessor functions have no live callers — `react_engine.py`/`vuln_agent.py` reference a different `self.brain.attack_patterns` dict, not this module. No tests import it. All functions are simple, correct, and side-effect-free; no silent excepts, loops are bounded by the 8-entry dict, no I/O, no secrets, no async. Code quality is OK; the concern is reachability (dead/untested) not defects. One cosmetic typo in payload data ('UUID version Agentlysis' should read 'Analysis', line 160) and one genuinely destructive example payload string ('test'); DROP TABLE users;--', line 249) sitting in a data list — it is never executed by this module but violates the project's non-destructive-payload rule if a consumer ever sent it.

## Top issues

- Module is effectively dead code: PATTERNS imported only by archived agent.py; all 4 accessor functions have no live callers; no tests.
- Line 249 data list contains a destructive payload string "test'); DROP TABLE users;--" — never executed here but violates non-destructive-payload rule if a consumer sends it.
- Line 160 typo 'UUID version Agentlysis' (should be 'Analysis') corrupts playbook text.

## Scope / safety notes

No scope/RoE concern at the module level: this file performs NO network, target, subprocess, or filesystem action. It is pure static data plus in-memory dict accessors; nothing here sends a request or invokes a tool, so a scope/RoE check is not applicable and its absence is not a defect. CAVEAT: the data it stores includes live attack payloads — notably cloud-metadata SSRF URLs (169.254.169.254, metadata.google.internal), SSTI/RCE payloads, and a destructive SQL payload \"test'); DROP TABLE users;--\" (line 249). These are inert strings here, but any downstream consumer that fetches/sends them MUST enforce scope and the non-destructive rule before transmission. The risk is in consumers, not this module.

## Function-by-function table

| File:Line | Function | Purpose | Inputs | Outputs | Side effects | Status | Issues |
|---|---|---|---|---|---|---|---|
| core/attack_patterns.py:15 | `AttackPattern` (dataclass) | Container for one attack methodology (name, OWASP cat, severity, steps, payloads, bypasses, indicators, mistakes, examples, bounty range) | 11 fields via `@dataclass` __init__ | AttackPattern instance | None (pure data) | OK | None |
| core/attack_patterns.py:430 | `get_pattern` | Lookup one pattern by key | `name: str` | `Optional[AttackPattern]` | None | DEAD-CODE | No live caller (only archive/old_entry_points uses module's PATTERNS); not idempotency/etc relevant — pure dict.get |
| core/attack_patterns.py:435 | `get_patterns_by_severity` | Filter patterns by Severity enum | `severity: Severity` | `List[AttackPattern]` | None | UNTESTED | Only called by `__main__` demo (line 463); no live caller, no test. Pattern set bounded (8). OK logic |
| core/attack_patterns.py:440 | `get_patterns_by_category` | Filter by OWASP category substring | `owasp_category: str` | `List[AttackPattern]` | None | DEAD-CODE | No caller anywhere. Uses `in` substring match (intended). No defects |
| core/attack_patterns.py:445 | `search_patterns` | Keyword search over name/desc/steps | `keyword: str` | `List[AttackPattern]` | None | DEAD-CODE | No caller. `str(p.attack_steps)` stringifies list for substring match (works, slightly loose). Bounded loop (8). No defects |
| core/attack_patterns.py:457 | `__main__` block | Print pattern stats when run directly | none (script entry) | stdout prints | Writes to stdout | OK | Demo only; not imported. No issues |
| core/attack_patterns.py:36 | `PATTERNS` (module global dict) | The 8-entry attack-pattern database | n/a (literal) | dict[str, AttackPattern] | Module-level constant, never mutated | OK | Mutable global by type (dict) but treated read-only; no code mutates it, so no race/state risk. Contains destructive example payload `"test'); DROP TABLE users;--"` (line 249) and typo "Agentlysis" (line 160) in data |
