# PLAN — Function Audit: `bounty_hunter`

> Part of [PLAN.md](PLAN.md) Section 2. Generated 2026-06-06. Module: **bounty_hunter**

**Exists:** True  

## Summary

core/bounty_hunter.py (581 lines) is a synchronous bug-bounty orchestration module: program database (5 hardcoded featured programs), submission tracking with JSON persistence, report formatting (HackerOne + generic), duplicate detection, and bounty estimation. Despite the docstring claiming HackerOne/Bugcrowd/Intigriti API integration, there is NO network code at all — `urllib.request` and `ssl` are imported but never used, and no platform API is actually called. The module is purely local: it scores findings, formats reports, and reads/writes two JSON files. No async, so no sync-in-async hazards. Main defects: (1) hardcoded CWD-relative default paths `skills/hackagent/programs` and `skills/hackagent/submissions.json` that break when run from any other directory; (2) zero error handling on all file I/O (load/save can raise/corrupt, no atomic writes -> race/corruption under concurrent access); (3) `list_targets()` is annotated `List[str]` but returns `str`; (4) loose substring scope matching in `is_in_scope`; (5) brittle ad-hoc duplicate-similarity heuristic that can exceed 1.0; (6) `print()` side effects instead of logging.

## Top issues

- Module-wide deception: docstring claims HackerOne/Bugcrowd/Intigriti API integration and imports urllib.request+ssl (L18-19) that are NEVER used — no network/API code exists; check_duplicate and submission tracking are local-only.
- Hardcoded CWD-relative default paths skills/hackagent/programs (L163) and skills/hackagent/submissions.json (L222) break when CWD != repo root.
- No error handling or atomic writes on file I/O (_load L226, _save L243, _save_program L178): malformed/concurrent JSON corrupts state, raises raw exceptions, non-atomic truncate-then-write loses data on crash, no lock -> race.
- Report formatters (L314, L341) index required finding keys directly (KeyError risk) and interpolate raw evidence/payload with NO redaction, violating the project no-PII/secrets-in-reports rule.
- Loose substring scope matching (is_in_scope L63, check_duplicate L486) is over-broad -> false in-scope / false-duplicate results.
- Contract bugs: list_targets (L560) annotated List[str] but returns str; select_target (L412) 'new'/'responsive' strategies unimplemented; _save_program drops severity_payouts/rating (lossy persistence).

## Scope / safety notes

This module performs NO network or target actions at all — no HTTP, no socket, no subprocess, no tool invocation. `urllib.request` and `ssl` are imported (L18-19) but completely unused; the docstring's claim of HackerOne/Bugcrowd/Intigriti API access is not implemented. The only side effects are local filesystem reads/writes (programs dir + submissions.json) and stdout prints. Because it never touches a target, the absence of an explicit scope/RoE gate here is not itself a live-action violation. However: (1) is_in_scope (L50) and find_programs_for_target (L199) are the in-scope decision helpers other modules may rely on, and their loose substring matching (L63) could wrongly classify an out-of-scope asset as in-scope, indirectly enabling a scope breach upstream; (2) report formatters emit raw finding evidence/payload with no redaction, which can leak sensitive data into generated reports (a reporting-rule violation, not a scope one). No scope check is needed inside this module's own execution, but the scope-matching logic it exposes should be hardened since callers trust it.

## Function-by-function table

| File:Line | Function | Purpose | Inputs | Outputs | Side effects | Status | Issues |
|-----------|----------|---------|--------|---------|--------------|--------|--------|
| bounty_hunter.py:50 | `BountyProgram.is_in_scope` | Check if target string is in program scope | `self, target: str` | `bool` | none | NEEDS-FIX | Loose substring match: `scope in target` (L63) matches any substring, e.g. scope `meta.com` matches `notmeta.com.evil.com`; out-of-scope check at L55 strips only `*.` prefix and uses substring `in`, over-broad; no path/port awareness |
| bounty_hunter.py:80 | `Submission.to_dict` | Serialize submission to dict | `self` | `dict` | none | OK | |
| bounty_hunter.py:162 | `ProgramDatabase.__init__` | Init program DB, ensure dir, load featured | `self, programs_dir: Path = None` | `None` | `mkdir(parents,exist_ok)` on disk | NEEDS-FIX | Hardcoded CWD-relative default `Path("skills/hackagent/programs")` (L163) breaks when CWD != repo root; mkdir not wrapped (perm errors propagate raw) |
| bounty_hunter.py:168 | `ProgramDatabase._load_featured` | Register 5 hardcoded featured programs | `self` | `None` | mutates `self.programs` | OK | |
| bounty_hunter.py:173 | `ProgramDatabase.add_program` | Add program + persist | `self, program: BountyProgram` | `None` | writes JSON file | OK | (inherits _save_program I/O risk) |
| bounty_hunter.py:178 | `ProgramDatabase._save_program` | Write program JSON to disk | `self, program: BountyProgram` | `None` | `mkdir` + `open(w)` write | NEEDS-FIX | No try/except, no atomic write/tmp-rename; partial write corrupts file on crash; no concurrency lock; drops `severity_payouts`/`rating`/`response_time` fields (lossy persistence) |
| bounty_hunter.py:195 | `ProgramDatabase.get_program` | Lookup program by handle | `self, handle: str` | `Optional[BountyProgram]` | none | OK | |
| bounty_hunter.py:199 | `ProgramDatabase.find_programs_for_target` | List programs with target in scope | `self, target: str` | `List[BountyProgram]` | none | OK | Inherits loose matching from is_in_scope; bounded by program count |
| bounty_hunter.py:207 | `ProgramDatabase.get_high_value_programs` | Programs w/ critical payout >= min | `self, min_payout: int = 5000` | `List[BountyProgram]` (sorted) | none | OK | |
| bounty_hunter.py:221 | `SubmissionTracker.__init__` | Init tracker, load submissions | `self, data_file: Path = None` | `None` | reads file via _load | NEEDS-FIX | Hardcoded CWD-relative default `Path("skills/hackagent/submissions.json")` (L222) |
| bounty_hunter.py:226 | `SubmissionTracker._load` | Load submissions from JSON | `self` | `None` | reads file, mutates list | NEEDS-FIX | No try/except: malformed JSON / missing keys raise (KeyError on s["program"] etc.); no schema validation; corrupt file aborts init |
| bounty_hunter.py:243 | `SubmissionTracker._save` | Persist submissions + stats | `self` | `None` | `open(w)` overwrite file | NEEDS-FIX | No try/except; non-atomic overwrite (truncate-then-write) corrupts on crash; no lock -> race if concurrent callers; recomputes stats each save |
| bounty_hunter.py:251 | `SubmissionTracker.add_submission` | Append + save | `self, submission: Submission` | `None` | writes file | OK | (inherits _save risk) |
| bounty_hunter.py:256 | `SubmissionTracker.update_status` | Update status/bounty by title | `self, title, status, bounty=0` | `None` | writes file | NEEDS-FIX | Matches by exact title (first match only, `break`); no idempotency key; silent no-op if title not found; duplicate titles update only first |
| bounty_hunter.py:266 | `SubmissionTracker.get_stats` | Compute submission stats | `self` | `dict` | none | OK | `avg_bounty` divides by `accepted` (guarded >0); fine |
| bounty_hunter.py:283 | `SubmissionTracker.get_pnl_report` | Markdown P&L report | `self` | `str` | none | OK | Slices to 10 recent; bounded |
| bounty_hunter.py:314 | `ReportFormatter.hackerone_format` | Build HackerOne report text | `finding: dict, program: BountyProgram` | `str` | none | NEEDS-FIX | Direct `finding['title']/['severity']/['target']/['description']/['evidence']` indexing -> KeyError if absent; `program` param unused; raw finding fields interpolated into report with no redaction (rules require PII/secret redaction) |
| bounty_hunter.py:341 | `ReportFormatter.generic_format` | Build generic report text | `finding: dict` | `str` | none | NEEDS-FIX | Same required-key KeyError risk on title/severity/target/description/evidence; no redaction of evidence/payload |
| bounty_hunter.py:391 | `BountyEstimate.to_dict` | Serialize estimate | `self` | `dict` | none | OK | |
| bounty_hunter.py:408 | `BountyHunter.__init__` | Wire ProgramDatabase + SubmissionTracker | `self` | `None` | triggers dir create + file load | OK | (inherits hardcoded-path defaults) |
| bounty_hunter.py:412 | `BountyHunter.select_target` | Pick program by strategy | `self, strategy: str = "high_value"` | `Optional[BountyProgram]` | none | NEEDS-FIX | Only "high_value" branch real; "new"/"responsive" strategies documented but unimplemented (fall through to arbitrary first program); returns first element regardless |
| bounty_hunter.py:430 | `BountyHunter.prepare_submission` | Route to platform formatter | `self, finding: dict, program: BountyProgram` | `str` | none | OK | (inherits formatter KeyError risk) |
| bounty_hunter.py:436 | `BountyHunter.track_submission` | Create + record submission | `self, program, title, severity, url=""` | `None` | writes file, `print()` | NEEDS-FIX | `print()` side effect instead of logger (L446); no return of created object; uses `datetime.now()` (naive, no tz) |
| bounty_hunter.py:448 | `BountyHunter.get_earnings_report` | Proxy to P&L report | `self` | `str` | none | OK | |
| bounty_hunter.py:452 | `BountyHunter.check_duplicate` | Heuristic duplicate detection | `self, finding: dict` | `DuplicateCheckResult` | none | NEEDS-FIX | Ad-hoc similarity can exceed 1.0 (overlap up to 1.0 + 0.2 + 0.3); `submission.program.lower() in target` is loose substring; thresholds magic numbers; O(n) over all submissions (bounded but unindexed); purely local — does NOT query platform for real dupes despite docstring intent |
| bounty_hunter.py:512 | `BountyHunter.estimate_bounty` | Estimate bounty range | `self, finding: dict` | `BountyEstimate` | none | OK | Hardcoded multipliers/confidence are heuristic but functional; uses first matching program only |
| bounty_hunter.py:560 | `BountyHunter.list_targets` | Markdown listing of programs | `self` | declared `List[str]`, actually `str` | none | NEEDS-FIX | Return-type annotation mismatch: returns `"\n".join(...)` -> `str`, not `List[str]` (L560 vs L571) |
| bounty_hunter.py:575 | `__main__` block | CLI demo: print targets + P&L | (none) | exit | `print()` to stdout; triggers DB/file init | UNTESTED | Side-effecting on import-as-script: creates dirs/loads files; only exercised when run directly |
