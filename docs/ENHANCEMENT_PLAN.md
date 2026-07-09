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

### 1.1 Wire `coverage_critic` to drive a follow-up round
`core/coverage_critic.py` computes what a hunt *missed* (untested params, unrun techniques,
unverified claims) — but **nothing consumes its output** (verified: no non-test importer).
Feed `critique(findings, ran_techniques)` into the HackMode iteration loop so a gap it names
becomes the next round's targeted dispatch (bounded by the depth budget). Turns a dead
analysis into an autonomy multiplier. FP-safe (drives *exploration*, never the gate).
**Files:** `core/hack_mode.py` (iteration loop), `core/coverage_critic.py`. Effort: small.

### 1.2 `viper.py evidence verify <manifest> [findings.json]`
The hunt now writes a signed `<hunt_id>_manifest.json`, but there's no CLI to **verify** it.
Add a command that (a) checks the HMAC signature and (b) re-hashes each finding (incl. its
`proof_requests`) and reports any mismatch — making the chain-of-custody actionable for a
triager. Pure read-only. **Files:** `core/verify_cli.py` or `core/ops_cli.py`, `viper.py`.
Effort: small.

### 1.3 Calibrated confidence surface
Map the gate's per-class `validation_confidence` to the scorecard's *observed* precision so
a report can say "this class has been 1.00 across N labeled scenarios" instead of a bare
number. Read-only reporting; no gate behavior change. **Files:** `core/gate_benchmark.py`
(export per-class stats), `core/report_narrative.py` / `submission_draft.py`. Effort: small.

---

## Phase 2 — Next (new confirmable coverage, still FP-safe & non-destructive)

### 2.1 Blind SSTI via OOB canary  ★ highest-value new class
`core/swarm_workers/vuln/ssti_probe.py` is reflection-only — **no `fire_oob`** (verified).
The whole OOB path already exists end-to-end (canary templates in `core/oob/canary.py`, the
`fire_oob` pattern used by sqli/xxe/ssrf/cmdi, and the gate's `oob_token` confirmation). Add
an OOB phase: inject a canary-URL SSTI payload per candidate param and attach `oob_token`; a
callback flips it to submittable via the *existing* gate path — **zero new gate logic**.
Blind SSTI (async/email/log template rendering) is currently invisible and is critical-sev.
FP-safe (per-run canary; a token that never calls back stays a lead). Effort: medium.

### 2.2 Email / SMTP header injection (CWE-93 sibling of CRLF)
A `to`/`subject`/`name` param that splits into an extra email header. Confirm read-only via a
response-reflected header differential (like CRLF) **or** OOB when a mail-callback canary is
configured; otherwise a lead. Effort: medium.

### 2.3 LDAP / XPath injection (in-band differential)
Error/boolean differential on `*`/`)(` (LDAP) and `' or '1'='1` (XPath) with a benign control,
mirroring the sqli recheck shape. Read-only. Ships as a lead until the differential is proven.
Effort: medium.

### 2.4 Outer learning loop — feed submission outcomes back to priors
Today evograph records per-hunt *technique* outcomes (inner loop). There's **no** loop from
**submitted → accepted/paid/duplicate** back into the priors. When the operator marks a draft's
disposition (via `viper.py submissions` / the ledger), reweight `attack_priors` so classes that
actually *pay out* on a stack rank higher. Closes the outermost feedback loop. FP-safe (ordering
only). **Files:** `core/submission_ledger.py`, `core/attack_priors.py`. Effort: medium.

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
