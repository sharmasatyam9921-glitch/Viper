# VIPER Benchmark Harness

Runs VIPER against a suite of challenge targets, scores each run, and emits an
XBOW-style scorecard (overall solve rate + per-category breakdown). This is the
**adversarial** benchmark — it measures whether VIPER actually *finds* things — as
opposed to `tests/test_benchmark.py`, which only checks that subsystems import.

> Why this exists: VIPER's gap isn't features, it's *validation*. A published
> solve rate on a public challenge set is what makes "VIPER vs. tool X" a number
> instead of an opinion.

## TL;DR

```bash
# Self-driving local run (boots its own Juice Shop containers via Docker):
python benchmark/run_benchmark.py --suite suite/local.json --time 10

# XBOW-comparable flag-capture run (see suite/xbow/README.md to generate):
python benchmark/run_benchmark.py --suite suite/xbow/xbow_generated.json --time 15

# See what a suite would do without starting anything:
python benchmark/run_benchmark.py --suite suite/local.json --dry-run
```

Requirements: Docker + `docker compose` (for dockerized targets), Python 3.11+.
No third-party Python deps — the harness uses only the stdlib (intentionally, so
it runs anywhere VIPER does; `pyyaml` is **not** required).

## How it works

```
run_benchmark.py  (orchestrator)
  load suite JSON ─► for each challenge:
        TargetManager.start()      bring target up (docker run / compose / external) + health-poll
        ViperRunner.run()          subprocess: python viper.py <url> --full --no-guardrail
                                   --output <tmp.json> --time N   (hard-killed if it overruns)
        scorer.score()             grade the run (flag mode | vuln_class mode)
        TargetManager.stop()       tear the target down
  aggregate ─► results/scorecard_<ts>.{json,md}   (solve rate + per-category)
```

Each challenge runs in its own process with its own `--output` file, so scoring is
isolated per challenge and never depends on a shared findings DB.

## Scoring modes

| Mode | Solved when… | Use for |
| --- | --- | --- |
| `flag` | the flag string / `flag_regex` appears in VIPER's artifacts (findings JSON, stdout, stderr) | XBOW-comparable capture-the-flag sets |
| `vuln_class` | VIPER reports a finding whose vuln type matches an expected class (synonym-aware), optionally gated by `url_contains` + `min_severity` | graded apps (Juice Shop, DVWA) with no single flag |

`vuln_class` matching is synonym-aware: a spec asking for `sql_injection` also
matches VIPER labels like `sqli`, `sqli_union`, `blind_sql` (see
`harness/scorer.py:SYNONYMS`). Add classes/synonyms there as VIPER's labels evolve.

## Suite spec schema

```jsonc
{
  "name": "my-suite",
  "challenges": [
    {
      "id": "unique_id",                 // required
      "name": "human label",
      "category": "injection",           // for the per-category breakdown
      "difficulty": "easy|medium|hard",
      "mode": "flag" | "vuln_class",
      "target": {
        "type": "external" | "docker_image" | "docker_compose",
        "url": "http://localhost:4000",  // base URL VIPER attacks
        // docker_image:
        "image": "bkimminich/juice-shop", "container_port": 3000, "host_port": 4000,
        "env": { "KEY": "val" }, "run_args": ["--cap-add=..."],
        // docker_compose:
        "compose_dir": "/path", "compose_file": "/path/docker-compose.yml", "service": "web",
        // health:
        "health_path": "/", "health_timeout": 180
      },
      "expect": {                        // vuln_class mode
        "vuln_types": ["sql_injection", "auth_bypass"],
        "url_contains": "/login",        // optional
        "min_severity": "medium"         // optional: info|low|medium|high|critical
      },
      "flag": "FLAG{exact}",             // flag mode (exact), OR
      "flag_regex": "FLAG\\{[^}]+\\}",   // flag mode (randomized)
      "viper_args": ["--stealth", "2"],  // extra args appended to this challenge's viper.py call
      "tags": ["owasp-a03"]
    }
  ]
}
```

## CLI

```
python benchmark/run_benchmark.py [options]
  --suite PATH        suite JSON (relative to benchmark/ or absolute)   [suite/local.json]
  --time N            minutes budget per challenge (-> viper --time)     [10]
  --only a,b,c        run only these challenge ids
  --skip a,b,c        exclude these challenge ids
  --out DIR           scorecard output dir                               [results]
  --python PATH       interpreter used to launch viper.py                [current]
  --viper-arg ARG     extra arg forwarded to viper.py (repeatable)
  --keep-targets      don't tear targets down (debugging)
  --dry-run           list challenges and exit; start/run nothing
```

## Layout

```
benchmark/
├── README.md              ← you are here
├── run_benchmark.py       orchestrator + scorecard writer
├── harness/
│   ├── models.py          Challenge / Target / Expect / RunResult / Score dataclasses
│   ├── targets.py         TargetManager: external | docker_image | docker_compose + health poll
│   ├── runner.py          ViperRunner: isolated viper.py subprocess, per-challenge timeout/kill
│   └── scorer.py          flag mode + vuln_class (synonym-aware) scoring
├── suite/
│   ├── local.json         self-driving Juice Shop suite (vuln_class)
│   └── xbow/              adapter for XBOW validation-benchmarks (flag, XBOW-comparable)
│       ├── README.md
│       ├── gen_xbow_suite.py
│       └── example.json
└── results/               scorecards (gitignored)
```

## Honest-comparison checklist

- Match `--time` to the competitor's reported per-challenge budget.
- Run each suite 2–3× and report the spread — LLM-driven runs vary.
- For flag mode, confirm VIPER actually *prints* the flag on a known-solvable
  challenge before trusting a 0% (a reporting gap reads as a miss).
- State your config (budget, VIPER version, model routing) next to the number.
```
