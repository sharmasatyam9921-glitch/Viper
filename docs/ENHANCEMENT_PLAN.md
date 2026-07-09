# VIPER Enhancement Plan

Grounded in the current codebase (gate at **22 confirmed classes / precision 1.00 / 0 FP**,
measured on the scorecard, guarded by the mutation harness + reproducibility refuter).
Every item below is checked against the code so we don't re-propose what's already built.

**Invariants that gate every item:** (1) never regress precision 1.00 — a new class either
gets an independent read-only/OOB recheck or ships as a confidence-capped **lead**;
(2) non-destructive only — no target-state mutation, no account creation, no unauthorized
live third-party scan; (3) confirmation is read-only, out-of-band, or operator-session.

---

## Already built (do not re-propose)

Gate confirms: injection family (sqli/xss/ssti/lfi/cmdi), exposures (secrets/env/git/
dir-listing/cors), BOLA/BFLA/IDOR, host-header, subdomain-takeover, web-cache-deception,
CRLF, clickjacking, cloud-exposure, open-redirect, graphql, nosql-login, jwt (weak-key +
RS256→HS256 alg-confusion), response-based SSRF. • Mutation/regression harness •
reproducibility refuter • evograph inner learning loop + reasoning recall • OpenAPI /
GraphQL-schema / authenticated-per-role / source-map discovery • per-host adaptive rate
backoff • late-OOB-callback rescue • proof-requests + accurate CVSS + signed
chain-of-custody manifest + `viper.py leads`. Lead-only read-only detectors:
proto-pollution, deser-surface, oauth-config, cache-poisoning, mass-assignment, csrf.

---

## Phase 1 — Now (small, self-contained, high-leverage, FP-safe)

### 1.1 Wire `coverage_critic` to drive a follow-up round ✅ DONE
`core/coverage_critic.py` computed what a hunt *missed* but nothing consumed it.
`HackMode._run_coverage_round` (teardown, before the gate) now re-probes the critic's
discovered-but-untested surface in one bounded vuln round; new findings still flow through
the gate. Opt out with `profile.coverage_followup = False`. FP-safe (exploration only).

### 1.2 `viper.py evidence verify <manifest> [findings.json] [--key K]` ✅ DONE
`core/evidence_cli.py` re-hashes each finding (incl. its `proof_requests`) against the
manifest's recorded hashes (tamper check, no key needed) and, with `--key`, verifies the
HMAC signature. `core/chain_of_custody.py` gained a shared `hash_finding` (one source of
truth for recording + verifying). Read-only; exit 0 iff integrity is confirmed.

### 1.3 Calibrated confidence surface ✅ DONE
`core/gate_benchmark.py:class_scenario_counts()` tallies each class's labeled scorecard
scenarios (cheap — no execution). `submission_draft._gate_assurance` renders a "Gate
assurance" line citing "precision 1.00 across N labeled scenarios (M adversarial safe
cases), 0 FP — guarded by the mutation harness", quantifying trust beyond a bare number.

---

## Phase 2 — Next (new confirmable coverage, still FP-safe & non-destructive)

### 2.1 Blind SSTI via OOB canary ✅ DONE
`ssti_probe.py` now fires an OOB canary (first 6 params) with engine-specific template
payloads (Jinja/Twig/Freemarker/Smarty/ERB) added to `canary.py`; `fire_oob` was extended
to fire a LIST of payload keys under one canary. A backend callback flips it to submittable
via the existing `oob_token` gate path — zero new gate logic, same read-only-`curl`-to-our-
canary shape as blind cmdi. Confirmed end-to-end in test_oob_workers.

### 2.2 Email / SMTP header injection (CWE-93 sibling of CRLF)
A `to`/`subject`/`name` param that splits into an extra email header. Confirm read-only via a
response-reflected header differential (like CRLF) **or** OOB when a mail-callback canary is
configured; otherwise a lead. Effort: medium.

### 2.3 LDAP / XPath injection (in-band differential)
Error/boolean differential on `*`/`)(` (LDAP) and `' or '1'='1` (XPath) with a benign control,
mirroring the sqli recheck shape. Read-only. Ships as a lead until the differential is proven.
Effort: medium.

### 2.4 Outer learning loop — feed submission outcomes back to priors ✅ DONE
`viper.py outcome <disposition> <findings.json> [--tech t1,t2]` (`core/outcome_cli.py`)
logs the disposition in the ledger (`SubmissionLedger.set_disposition`) and feeds a
reward-weighted signal into the priors (`AttackPriors.record_outcome`: paid 3.0 > accepted
2.0 > triaged 1.5 > duplicate/informative 0.5 > rejected 0.0), so classes that actually pay
out on a stack rank first next time. Ordering only — never touches the gate.

---

## Phase 3 — Discovery depth & reliability

- **JS-bundle deep mining** — beyond source maps: parse minified bundles for `fetch('/api/…')`
  / route tables / inline secrets when no `.map` is served. (`core/swarm_workers/recon/`.)
- **Postman collection / HAR import** — turn an operator-exported HAR/Postman file into endpoint
  + param + header targets (read-only, operator-supplied). High signal for authed APIs.
- **Resumable-state completeness** — persist findings + `proof_requests` + the evidence manifest
  across `--resume` so a resumed hunt keeps its confirmed set and custody chain.
- **Calibrated per-host concurrency** — extend the adaptive rate limiter to also learn a safe
  concurrency ceiling per host, not just RPS.

---

## Phase 4 — Later (larger; each needs careful FP/scope review)

- **OAuth/OIDC flow flaws** — the read-only `.well-known` config detector exists as a lead; the
  *active* flow test (redirect-uri wildcard, missing PKCE/state) needs an operator test-client
  and dual-flow reproducibility before it could be more than a lead.
- **Web-cache *poisoning*** (vs. the confirmed *deception*) — only safe if confirmed with an
  ephemeral, per-request cache-buster that never poisons a shared key; currently a lead.
- **Adversarial review in CI** — run `gate_mutations --strict` + a scheduled refutation pass on
  every gate change so precision 1.00 is enforced pre-merge, not just measured.

---

## Explicitly out of scope (safety/rule boundaries — do NOT build)

- Automated **account creation** (temp-mail signup) — prohibited; two-account BOLA uses
  operator-supplied sessions.
- Any **destructive** confirmation — RCE gadget execution, server-side writes (mass-assignment
  stays a lead), poisoning a shared cache, stored-XSS beaconing that fires in victims' browsers.
- **Timing-only** auto-submission for RCE/smuggling/race — structurally vetoed; stays a lead.
- Live scanning of third-party production without a verifiable operator trigger.

---

## Suggested sequencing

**Sprint 1 (Phase 1):** 1.1 coverage-critic wiring → 1.2 evidence-verify CLI → 1.3 calibrated
confidence. All small, FP-safe, offline-testable; each ships green with the mutation harness.

**Sprint 2 (Phase 2):** 2.1 blind-SSTI OOB (best single new class) → 2.4 outer learning loop →
2.2/2.3 the two injection siblings. Each new submittable path gets an adversarial-refutation
review before it ships (the pattern used for every gate branch this cycle).

Everything is measured on `python -m core.gate_benchmark --strict` and guarded by
`python -m core.gate_mutations --strict`; a new confirmable class isn't "done" until it has a
labeled vuln+safe scorecard row at precision 1.00.
