# VIPER Benchmark Results

Two live suites: **Juice Shop** (unauthenticated app-logic) and **DVWA**
(authenticated). Pipeline: **hack** (swarm HackMode).

| Suite | Target | Mode | Result |
| --- | --- | --- | --- |
| Juice Shop | `bkimminich/juice-shop` | unauthenticated | **4/4** (each isolated) |
| DVWA `low` | `vulnerables/web-dvwa` | **authenticated** (`--auth-setup dvwa`) | **4/4** (one full run) |

---

## Juice Shop — OWASP app-logic suite

Suite: `suite/local.json` · Budget: 3–4 min/challenge · fresh container per challenge

### Headline

| Challenge | Class | Start | Now |
| --- | --- | --- | --- |
| `juice_login_sqli` | sql_injection / auth_bypass | ❌ MISS | ✅ **SOLVE** |
| `juice_search_xss` | xss | ❌ MISS | ✅ **SOLVE** |
| `juice_access_control` | idor / access_control | ❌ MISS | ✅ **SOLVE** |
| `juice_info_disclosure` | info_disclosure | ❌ MISS | ✅ **SOLVE** |

**0/4 → 4/4** (each verified in an isolated run). The full sequential run scores
**3/4**; the one miss is the *last* container in the sequence timing out under
cumulative host load (it solves standalone — a benchmark-host artifact, not a
capability gap). Reproduce a single challenge clean with:

```bash
python benchmark/run_benchmark.py --suite suite/local.json \
    --only juice_info_disclosure --mode hack --time 4
```

## What each solve required (benchmark-driven fixes)

Every fix below was found by running VIPER against the live target, reading the
actual findings, and probing the real app — not by guessing.

1. **Recon target handling** — explicit `host:port` targets were dropped /
   probed on the wrong port; `httpx` was shadowed by a pip package. The whole
   pipeline returned "0 alive hosts" against `127.0.0.1:4000`.
2. **Wayback flood** — the worker queried web.archive.org for `127.0.0.1`, got
   500 internet-wide "localhost" URLs, and emitted each as a finding → 500
   vuln-probe assets that starved the vuln phase (0 vuln findings in a
   525-finding run). Now skips non-public hosts and surfaces only interesting
   paths.
3. **Secrets worker** — probed `/styles.css/ftp` (asset-relative) instead of
   the site root `/ftp`. Made exposure paths origin-relative → detects Juice
   Shop's `/ftp` listing. *(info_disclosure)*
4. **`login_sqli` (new vuln-phase worker)** — JSON + form login bypass via
   `' OR 1=1--`, confirmed by a JWT-in-200 with a bogus-cred baseline.
   *(login SQLi)*
5. **`broken_access_control` (new vuln-phase worker)** — GETs curated
   should-be-protected endpoints; flags 200-with-data as missing authorization.
   Verified 5 live findings (`/api/Feedbacks`, `/api/Quantitys`,
   `/rest/admin/application-*`, …). *(access control)*
6. **XSS** — already capable; unblocked once the wayback flood stopped
   starving the vuln phase. *(reflected XSS)*

## Running notes

- **One fresh target per hunt** is the correct model (matches real engagements:
  one target per run). Booting 4 heavy containers in sequence on a laptop can
  starve the tail hunt; a single shared container can crash under repeated
  aggressive hunting. Use `--external-url` against a sturdy pre-running target
  for a fast multi-challenge pass; otherwise run challenges with `--only`.
- All capability is covered by unit tests (mock-based, no network) so the logic
  is verified in CI without Docker; the live runs confirm end-to-end.

---

## DVWA — authenticated suite

Suite: `suite/dvwa.json` · Budget: 2 min/challenge · one shared container, logged in once.
DVWA gates every vulnerable page behind a login + per-request CSRF token, so this
suite proves VIPER hunting **as a logged-in user** — where IDOR/BOLA/business-logic
bugs (and most real bounties) actually live.

| Challenge | Class | Endpoint | Result |
| --- | --- | --- | --- |
| `dvwa_sqli` | sql_injection | `/vulnerabilities/sqli/?id=` | ✅ **SOLVE** |
| `dvwa_xss_reflected` | xss | `/vulnerabilities/xss_r/?name=` | ✅ **SOLVE** |
| `dvwa_sqli_blind` | sql_injection | `/vulnerabilities/sqli_blind/?id=` | ✅ **SOLVE** |
| `dvwa_lfi` | lfi | `/vulnerabilities/fi/?page=` | ✅ **SOLVE** |

**4/4 in one full authenticated sequential run.** LFI was the last to flip: the
worker, auth, and the discovered `?page=` endpoint were all correct, but a blind
workers×assets manifest cross-product starved the LFI-vs-`/fi/?page=` combo under
the time budget. The fix (commit `4d9f9cd`) routes param-injection workers to
param-bearing endpoints and dedupes near-duplicate endpoints, so high-yield combos
run in budget — flipping LFI MISS→SOLVE and the suite to 4/4.

### How the auth works
`harness/dvwa.py` runs DVWA's setup once against a fresh container — create-db →
login (`admin`/`password`, DVWA's public default) → security=low — and captures the
session cookie. `--auth-setup dvwa` threads that cookie into every hunt via
`viper.py hack --cookie`, so the vuln workers reach the gated `/vulnerabilities/*`
pages. Run it:

```bash
docker run -d --rm -p 4030:80 vulnerables/web-dvwa
python benchmark/run_benchmark.py --suite suite/dvwa.json --mode hack \
    --auth-setup dvwa --auth-base http://127.0.0.1:4030 --time 2
```

### Coverage note
The four challenges are the GET-based classes VIPER's non-destructive workers
confirm. DVWA's command-injection and file-upload are POST-form; the current
GET-based `command_injection` worker doesn't cover them — a known, honest gap.

---

## VIPER vs other tools (honest comparison)

Direct cross-tool benchmarking is hard: each tool publishes numbers on a
*different* substrate with *different* scoring. The only fully apples-to-apples
comparison would be running every tool on the same suite — which nobody has done
publicly. So this table separates **what VIPER verified on this machine** from
**competitors' published/self-reported numbers**, and is explicit about substrate.

| Tool | Benchmark | Score | Source | Notes |
| --- | --- | --- | --- | --- |
| **VIPER** | Juice Shop — 4 curated app-logic challenges | **4/4** | verified here (live) | narrow: proves specific classes, *not* a broad catch-rate |
| **VIPER** | DVWA `low` — 4 authenticated challenges | **4/4** | verified here (live, one run) | sqli, xss, lfi, blind-sqli — logged-in hunting |
| pentest-ai (`0xsteph`) | Juice Shop — **full 68-challenge set** | ~63% (43/68) | project self-report | same app, far broader suite |
| XBOW | XBOW validation-benchmarks (104 CTF apps) | ~75–77% | vendor + DEF CON | also **#1 on HackerOne US** (real bounties) |
| Shannon | white-box (source access) | ~96% | vendor | different category — has the code |

### The honest read
- **VIPER's "4/4" is not comparable to pentest-ai's 63% or XBOW's 75%.** Those are
  broad catch-rates over 68–104 challenges; VIPER's is 4 hand-picked classes it can
  do non-destructively. On the *same app* (Juice Shop), pentest-ai has a published
  43/68 — VIPER's broad catch-rate there is currently **unknown** (not yet run on all 68).
- **What VIPER genuinely has:** verified, reproducible, $0 (Claude CLI + Ollama),
  authenticated hunting, 22 vuln workers across the OWASP classes, a curated
  128-payload library with a weaponization safety gate, and a *differentiated*
  LLM-application hunter (`core/ai_hunter`, 20 testers) that the web-focused
  competitors don't target.
- **What VIPER lacks to claim a competitive number:** a broad catch-rate. The real
  apples-to-apples test is the **full Juice Shop 68-challenge set** (to compare
  head-to-head with pentest-ai) and/or the **XBOW 104 validation-benchmarks** (the
  `benchmark/suite/xbow/` adapter exists for this). Until those run, VIPER's claim is
  "these specific classes work, verified" — not "beats tool X."

### To produce a real head-to-head number
1. Expand `suite/local.json` to the full Juice Shop challenge set (or import the
   official solve-checker), run `--mode hack`, publish the X/68.
2. Generate the XBOW suite (`benchmark/suite/xbow/gen_xbow_suite.py`) and run the 104.
That converts "capability proven" into a number that sits next to 63% / 75% honestly.
