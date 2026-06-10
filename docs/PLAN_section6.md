## SECTION 6 — Internal Lab for Safe Method Testing

### 6.0 Purpose & relationship to what already exists

VIPER already has two of the three pieces this section needs, and we build **on**
them rather than around them:

- **`benchmark/`** — a working scoring harness. `benchmark/harness/targets.py`
  (`TargetManager`) brings docker / docker-compose / external targets up, health-polls
  them, and tears them down. `benchmark/harness/runner.py` (`ViperRunner`) runs a real
  `viper.py` subprocess per challenge in isolation. `benchmark/harness/scorer.py`
  (`score()`) grades the run in `flag` or `vuln_class` mode against a `Challenge` spec.
  `benchmark/run_benchmark.py` loads a suite (e.g. `benchmark/suite/local.json`),
  runs each challenge, and writes a JSON+MD scorecard (overall + per-category solve rate).
- **`labs/`** — practice content: `labs/lab_manager.py` (`LabManager` already knows
  Juice Shop / DVWA / Metasploitable), `labs/interactive_lab.py`, walkthroughs, and
  `labs/ctf_challenges/`.

What is **missing** and what Section 6 adds:

1. An **always-on, network-isolated docker-compose vuln stack** (Section 6.1) — a
   superset of `labs/lab_manager.py`'s single-container labs, run together on one
   isolated bridge with **no egress**.
2. A **lab-runner that evaluates a *new attack pattern*** (not just "does VIPER work"):
   it scores TP-rate / FP-rate / time-to-first-finding and **promotes** the pattern only
   if it beats a threshold (Section 6.2). It reuses `harness/scorer.py` as its ground-truth
   oracle — no second scorer.
3. **Shadow mode** (Section 6.3): a candidate pattern runs *alongside* production hunts on
   authorized targets, emitting findings to a shadow log only, never to verdicts/reports,
   until it earns trust.
4. **Hard network-isolation enforcement** (Section 6.4): lab containers are unreachable
   from the normal hunting path, and during a lab run the hunting interface cannot reach
   arbitrary internet hosts.

> **New code lives under `benchmark/lab/` and a new suite `benchmark/suite/lab.json`.**
> No existing benchmark file is duplicated; `targets.py`, `runner.py`, `scorer.py`,
> `models.py` are imported as-is.

---

### 6.1 The isolated vulnerable-app stack (docker-compose)

A single compose file stands up five intentionally-vulnerable targets on **one private
bridge network with `internal: true`** (Docker creates no default route / no NAT to the
host's uplink, so containers have **no egress** to the internet). The lab-runner reaches
them only from a dedicated runner container attached to the same internal network.

**File:** `benchmark/lab/docker-compose.lab.yml`

```yaml
# benchmark/lab/docker-compose.lab.yml
# Intentionally-vulnerable app stack for safe attack-pattern testing.
# All app services sit ONLY on the `labnet` bridge, which is `internal: true`
# => no NAT, no default gateway, no internet egress. They are NOT published to
# the host (no `ports:`), so they are unreachable from VIPER's normal hunting
# interface. The only thing that can talk to them is the `runner` container,
# which is attached to labnet and acts as the test driver.
name: viper-lab

networks:
  labnet:
    driver: bridge
    internal: true            # <-- KILLS EGRESS: no route off this bridge
    ipam:
      config:
        - subnet: 172.31.0.0/24
    driver_opts:
      com.docker.network.bridge.enable_icc: "true"
      com.docker.network.bridge.enable_ip_masquerade: "false"   # belt-and-braces

services:
  dvwa:
    image: vulnerables/web-dvwa
    networks: { labnet: { aliases: [dvwa.lab] } }
    environment: { MYSQL_PASS: "lab" }
    restart: "no"
    # NO ports: — not reachable from host

  juiceshop:
    image: bkimminich/juice-shop
    networks: { labnet: { aliases: [juiceshop.lab] } }
    environment: { NODE_ENV: unsafe }
    restart: "no"

  webgoat:
    image: webgoat/webgoat
    networks: { labnet: { aliases: [webgoat.lab] } }
    restart: "no"

  vulnapi:
    # Vulnerable REST + GraphQL API (BOLA/IDOR, mass-assignment, GraphQL
    # introspection + injection). VAmPI covers REST; DVGA covers GraphQL.
    image: erev0s/vampi:latest
    networks: { labnet: { aliases: [vulnapi.lab] } }
    environment: { vulnerable: "1" }
    restart: "no"

  graphql:
    image: dolevf/dvga:latest          # Damn Vulnerable GraphQL Application
    networks: { labnet: { aliases: [graphql.lab] } }
    environment: { WEB_HOST: 0.0.0.0 }
    restart: "no"

  ssooidc:
    # SAML / OAuth2 / OIDC playground for auth-flow attack patterns
    # (alg:none, state/PKCE bypass, SAML signature wrapping, redirect_uri abuse).
    image: ghcr.io/dexidp/dex:latest    # OIDC provider; SP = oauth-playground below
    networks: { labnet: { aliases: [oidc.lab] } }
    command: ["dex", "serve", "/etc/dex/config.lab.yaml"]
    volumes:
      - ./dex/config.lab.yaml:/etc/dex/config.lab.yaml:ro
    restart: "no"

  samlsp:
    image: ghcr.io/oauth2-proxy/oauth2-proxy:latest
    networks: { labnet: { aliases: [samlsp.lab] } }
    command: ["--http-address=0.0.0.0:4180", "--upstream=http://juiceshop.lab:3000",
              "--provider=oidc", "--oidc-issuer-url=http://oidc.lab:5556",
              "--email-domain=*", "--cookie-secret=lab-cookie-secret-0001",
              "--client-id=lab", "--client-secret=labsecret",
              "--redirect-url=http://samlsp.lab:4180/oauth2/callback"]
    depends_on: [ssooidc]
    restart: "no"

  # The ONLY container with a route into labnet AND a controllable egress policy.
  # It runs the lab-runner (Section 6.2). It does NOT publish ports either.
  runner:
    build: ./runner            # benchmark/lab/runner/Dockerfile (python + viper + iptables)
    networks: { labnet: {} }
    volumes:
      - ../..:/viper:ro                       # VIPER source, read-only
      - ./results:/viper/benchmark/lab/results
    environment:
      VIPER_LAB_MODE: "1"                      # runtime flag, see 6.4
    cap_add: [NET_ADMIN]                       # to install the egress firewall in 6.4
    entrypoint: ["python", "/viper/benchmark/lab/lab_runner.py"]
    restart: "no"
```

Service hostnames (`dvwa.lab`, `juiceshop.lab`, `webgoat.lab`, `vulnapi.lab`,
`graphql.lab`, `samlsp.lab`) resolve **only inside `labnet`** via Docker DNS. Nothing is
published to the host, so from the operator's machine / VIPER's normal hunting interface
these targets simply do not exist on any reachable port. (Coverage cross-check:
`labs/lab_manager.py` lists the same DVWA/Juice Shop classes — this stack is the
multi-app, networked, egress-free version of that catalog.)

**Companion suite:** `benchmark/suite/lab.json` (same `Challenge` schema the existing
harness already parses in `benchmark/harness/models.py::Challenge.from_dict`). Because the
apps are long-lived on `labnet`, every challenge uses `target.type = "external"` pointing
at the in-network hostname:

```jsonc
// benchmark/suite/lab.json  (excerpt — same schema as benchmark/suite/local.json)
{
  "name": "viper-internal-lab",
  "description": "Isolated multi-app vuln stack on labnet (internal:true, no egress).",
  "challenges": [
    { "id": "dvwa_sqli", "category": "injection", "mode": "vuln_class",
      "target": { "type": "external", "url": "http://dvwa.lab",        "health_path": "/login.php" },
      "expect": { "vuln_types": ["sql_injection"], "min_severity": "medium" } },
    { "id": "juice_xss", "category": "xss", "mode": "vuln_class",
      "target": { "type": "external", "url": "http://juiceshop.lab:3000" },
      "expect": { "vuln_types": ["xss"] } },
    { "id": "vulnapi_idor", "category": "access_control", "mode": "vuln_class",
      "target": { "type": "external", "url": "http://vulnapi.lab:5000" },
      "expect": { "vuln_types": ["idor", "access_control"] } },
    { "id": "dvga_introspection", "category": "graphql", "mode": "vuln_class",
      "target": { "type": "external", "url": "http://graphql.lab:5013" },
      "expect": { "vuln_types": ["graphql"] } },
    { "id": "oidc_alg_none", "category": "auth", "mode": "vuln_class",
      "target": { "type": "external", "url": "http://samlsp.lab:4180" },
      "expect": { "vuln_types": ["jwt", "auth_bypass"] } }
    // ... plus negative/control challenges, see 6.2
  ]
}
```

---

### 6.2 The lab-runner: score a *new attack pattern*, promote only if it beats threshold

The existing `run_benchmark.py` answers "how good is VIPER as-is". The lab-runner answers a
different question: **"is this *specific new attack pattern* a net improvement, or does it
add false positives?"** It does that by running the lab suite **twice** — once with the
pattern off (baseline) and once with it on (candidate) — and diffing.

**File:** `benchmark/lab/lab_runner.py`

It **reuses the existing harness as its oracle** — it does not reimplement scoring:

```python
# benchmark/lab/lab_runner.py  (key wiring — abbreviated)
from harness.models  import Challenge, Score            # existing dataclasses
from harness.runner  import ViperRunner                 # existing subprocess runner
from harness.scorer  import score as score_run          # existing TP oracle
from harness.targets import TargetManager               # existing up/down (no-op for external)
```

**Ground truth.** Each challenge in `benchmark/suite/lab.json` declares the vuln class that
*does* exist at that endpoint (`expect.vuln_types`). We also add **control / negative
challenges** — endpoints on the same apps that are **known-clean** for a given class
(e.g. a static `/about` page tagged `expect.vuln_types: []`). These are what make FP-rate
measurable: any finding the candidate reports against a negative challenge for the class
under test is a **false positive**.

**Metrics computed per pattern** (over the suite):

| Metric | Definition (using `score_run()` verdicts) |
| --- | --- |
| **TP-rate** | `solved_positive / total_positive` — fraction of known-vulnerable challenges the candidate now solves. |
| **FP-rate** | `fp_findings / negative_challenges` — findings of the pattern's class raised on known-clean controls. |
| **TTFF** | time-to-first-finding: seconds from run start to the first matching finding (parsed from the per-challenge `--output` JSON timestamps / `RunResult.duration_s`). |
| **ΔTP / ΔFP** | candidate minus baseline — isolates *this pattern's* contribution, not VIPER's. |

```python
# Promotion gate — a candidate is promoted iff ALL hold (defaults; tunable in lab.json meta):
PROMOTE = (
    cand.tp_rate            >= 0.60 and          # solves >=60% of its positive cases
    cand.fp_rate            <= 0.10 and          # <=10% false positives on controls
    (cand.tp_rate - base.tp_rate) >= 0.05 and    # adds >=5pp TP over baseline
    (cand.fp_rate - base.fp_rate) <= 0.02 and    # adds <=2pp FP over baseline
    cand.ttff_median_s      <= base.ttff_median_s * 1.5   # not pathologically slower
)
```

**How a "new attack pattern" is plugged in.** A pattern is a `core/skill_prompts/<name>.py`
module (the registry in `core/skill_prompts/__init__.py`) and/or an EvoGraph-stored
heuristic (`core/evograph.py`). The runner toggles it via a forwarded VIPER flag so the
*same* `ViperRunner` runs both arms:

```
baseline  : python viper.py http://dvwa.lab --full --no-guardrail --output b.json \
                   --disable-pattern <name>
candidate : python viper.py http://dvwa.lab --full --no-guardrail --output c.json \
                   --enable-pattern <name>
```

(These two flags — `--enable-pattern` / `--disable-pattern` — are the only new viper.py
CLI surface this section requires; they map to including/excluding the module in the
`core.skill_prompts` dispatch and gating the EvoGraph heuristic by name.)

**CLI** (mirrors `run_benchmark.py`'s argument style so it's instantly familiar):

```bash
python benchmark/lab/lab_runner.py \
    --suite benchmark/suite/lab.json \
    --pattern saml_sig_wrapping \      # the new attack pattern under test
    --time 8 \                          # minutes/challenge, forwarded to viper --time
    --promote-on-pass                   # if gate passes, mark trusted (see below)
```

**Output.** The runner writes a scorecard in the *same shape* `run_benchmark.py` produces
(`benchmark/lab/results/labcard_<ts>.{json,md}`) plus a `promotion` block
(`{pattern, decision: promote|reject|shadow, tp, fp, ttff, delta_tp, delta_fp}`).

**Promotion target — `pattern_registry.json`.** The decision is persisted to
`benchmark/lab/pattern_registry.json`, the single source of truth for a pattern's trust
tier:

```jsonc
{
  "saml_sig_wrapping": {
    "tier": "trusted",          // candidate -> shadow -> trusted
    "promoted_utc": "20260606_...",
    "lab_tp": 0.83, "lab_fp": 0.04, "ttff_median_s": 41.2,
    "scorecard": "benchmark/lab/results/labcard_20260606_....json"
  }
}
```

VIPER reads this registry at startup: `tier:"trusted"` patterns contribute to verdicts
normally; `tier:"shadow"` patterns run but are quarantined (Section 6.3); `tier:"candidate"`
patterns only ever run inside the lab. **A pattern can never reach production verdicts
without a lab scorecard that beat the gate.**

---

### 6.3 Shadow mode — run new patterns next to production, but never let them vote

The lab proves a pattern works on *known* bugs. Shadow mode proves it behaves on *real,
authorized* traffic **before** it's allowed to influence anything. A `tier:"shadow"`
pattern runs inside ordinary hunts on authorized in-scope targets but is fully
quarantined.

**Wiring (in `core/react_engine.py` / `core/finding_validator.py`):**

- When a finding is produced by a pattern whose registry tier is `shadow`, it is tagged
  `shadow=True` and routed to a **separate sink**: `findings/shadow/<target>/<ts>.jsonl`
  via `core/audit_logger.py`. It is **excluded** from:
  - the verdict set that `finding_validator.py` returns,
  - the report (`core/report_narrative.py`, `core/html_reporter.py`),
  - notifications (`core/finding_stream.py`),
  - the EvoGraph reward update used for production Q-learning.
- A shadow finding **cannot trigger a tool the production path wouldn't already run** — it
  is observe-only; it re-evaluates traffic the trusted patterns already generated, so it
  adds **zero** extra requests to the authorized target (no scope/rate-limit impact, per
  `.claude/rules/scope.md`).

**Earning trust from shadow data.** Shadow findings are graded out-of-band against the
operator's eventual ground truth (triage outcome, or a later trusted-pattern confirmation).
A nightly job (`benchmark/lab/shadow_promote.py`) computes the shadow TP/FP-rate over the
accumulated `findings/shadow/` corpus using the **same metric definitions as 6.2**, and
promotes `shadow -> trusted` only when it clears a stricter live gate (e.g. `fp_rate <=
0.05` over `>= 30` shadow observations). Until then, production verdicts are byte-for-byte
unaffected by the candidate's presence.

```
candidate ──(lab gate 6.2 passes)──► shadow ──(live gate 6.3 passes)──► trusted
   │ lab only          │ runs in prod, quarantined        │ counts toward verdicts
```

This gives a safe, reversible rollout: a regression is caught in the lab; a real-world
mismatch is caught in shadow; neither can corrupt a live report.

---

### 6.4 Network-isolation enforcement (the hard guarantees)

Two invariants must hold **technically**, not by convention:

> **(I1)** Lab containers are **unreachable** from VIPER's normal hunting interface.
> **(I2)** During a lab run, the hunting interface **cannot reach arbitrary internet hosts**.

**(I1) Lab unreachable from normal hunting — enforced by Docker network topology.**

- `labnet` is `internal: true` and `enable_ip_masquerade: "false"` → the bridge has **no
  NAT, no default gateway**. Containers on it cannot route off-bridge, and nothing off the
  bridge has a route in.
- **No `ports:` mappings** on any app service → nothing is bound on the host. The normal
  hunting path (a VIPER process on the host targeting `http://<real-target>`) has no host
  port and no route to `172.31.0.0/24`, so `dvwa.lab` et al. are simply not addressable.
  Resolution of `*.lab` names only works via Docker's embedded DNS *inside* `labnet`.
- The only container bridging in is `runner`, and it too publishes no ports — it is driven
  by `docker compose run`, not by a network socket from the host.

**(I2) Hunting interface can't reach the internet during a lab run — enforced 3 ways
(defense in depth):**

1. **Runtime mode flag.** The `runner` container sets `VIPER_LAB_MODE=1` (and the lab-runner
   exports it into every `viper.py` subprocess). VIPER reads this at startup in
   `viper_core.py` / `tools/http_client.py`: when set, the HTTP client's allowlist is
   collapsed to **`labnet` hostnames + RFC1918 only**; any request to a public IP / external
   host is refused before a socket is opened. This is the same chokepoint
   `.claude/rules/scope.md` and `core/guardrails.py` already use — we add a lab predicate,
   not a new path.

2. **Egress firewall inside `runner` (kernel-enforced).** Because the app services live on
   `internal: true labnet`, they already can't egress. The `runner` *could* in principle have
   a second interface, so on entry it installs a default-deny egress policy scoped to the lab
   subnet (it holds `cap_add: NET_ADMIN`):

   ```bash
   # benchmark/lab/runner/egress_lockdown.sh — run by lab_runner.py at startup when VIPER_LAB_MODE=1
   iptables -P OUTPUT DROP
   iptables -A OUTPUT -o lo -j ACCEPT
   iptables -A OUTPUT -d 172.31.0.0/24 -j ACCEPT     # labnet apps only
   iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.11 -j ACCEPT  # docker embedded DNS
   # everything else (public internet) is dropped at the kernel
   ```

   With `OUTPUT DROP` as default, even a bug that bypasses the application-layer allowlist (I2.1)
   cannot put a packet on the public internet — the kernel drops it.

3. **`--no-egress` precondition check.** `lab_runner.py` refuses to start the suite unless it
   can confirm both: (a) `VIPER_LAB_MODE=1` is exported, and (b) a probe to a known public
   host (e.g. `http://1.1.1.1`) from inside `runner` **fails closed**. If the probe *succeeds*,
   the lab is mis-isolated and the runner aborts with a non-zero exit before touching VIPER —
   so a misconfigured network can never silently let a lab run reach the internet.

**Why both (I1) and (I2) matter together.** (I1) stops a normal hunt from accidentally
attacking a lab app (which would pollute real findings). (I2) stops a lab run — which may be
exercising an unvetted, possibly aggressive new pattern — from ever touching a real internet
host. The `VIPER_LAB_MODE` flag is the single switch that flips the process between the two
regimes; the `iptables` policy and the fail-closed probe are the kernel-level backstops that
make the guarantee hold even if application code is buggy.

---

### 6.5 Operator workflow (end to end)

```bash
# 1. Bring up the isolated stack (no egress, nothing published).
docker compose -f benchmark/lab/docker-compose.lab.yml up -d \
    dvwa juiceshop webgoat vulnapi graphql ssooidc samlsp

# 2. Test a new attack pattern against the lab; promote only if it beats the gate.
docker compose -f benchmark/lab/docker-compose.lab.yml run --rm runner \
    python /viper/benchmark/lab/lab_runner.py \
      --suite benchmark/suite/lab.json --pattern saml_sig_wrapping \
      --time 8 --promote-on-pass
#   -> writes benchmark/lab/results/labcard_<ts>.{json,md}
#   -> updates benchmark/lab/pattern_registry.json: tier candidate -> shadow (if gate passed)

# 3. The pattern now runs in SHADOW during real hunts (quarantined sink), e.g.:
python viper.py http://authorized-target.com --full
#   -> shadow findings land in findings/shadow/, excluded from verdicts/report

# 4. Nightly shadow promotion graduates shadow -> trusted once live gate clears.
python benchmark/lab/shadow_promote.py        # cron/daemon-driven

# 5. Tear the lab down (also removes the internal bridge).
docker compose -f benchmark/lab/docker-compose.lab.yml down -v
```

### 6.6 New files this section introduces (none overwrite existing code)

| Path | Role |
| --- | --- |
| `benchmark/lab/docker-compose.lab.yml` | Isolated 5-app vuln stack on `internal:true labnet`. |
| `benchmark/suite/lab.json` | Lab challenges + negative controls (existing `Challenge` schema). |
| `benchmark/lab/lab_runner.py` | Pattern evaluator: TP/FP/TTFF + promotion gate; reuses `harness/{runner,scorer,targets,models}.py`. |
| `benchmark/lab/pattern_registry.json` | Trust tiers: candidate → shadow → trusted. |
| `benchmark/lab/shadow_promote.py` | Nightly shadow→trusted promotion from `findings/shadow/`. |
| `benchmark/lab/runner/Dockerfile` | Runner image (python + viper + iptables, `NET_ADMIN`). |
| `benchmark/lab/runner/egress_lockdown.sh` | Kernel-level default-deny egress for lab runs. |
| `benchmark/lab/dex/config.lab.yaml` | OIDC provider config for the SAML/OAuth playground. |

**Reused unchanged:** `benchmark/harness/targets.py`, `benchmark/harness/runner.py`,
`benchmark/harness/scorer.py`, `benchmark/harness/models.py`, `benchmark/run_benchmark.py`,
`labs/lab_manager.py`, `core/skill_prompts/__init__.py`, `core/evograph.py`,
`core/audit_logger.py`, `core/finding_validator.py`, `tools/http_client.py`.
