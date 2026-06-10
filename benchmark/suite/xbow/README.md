# XBOW validation-benchmarks adapter

[XBOW](https://github.com/xbow-engineering/validation-benchmarks) publishes ~104
dockerized web-security challenges, each with a ground-truth flag. XBOW's
published autonomous solve rate (~75–77%) is measured against this exact set, so
running VIPER over the same challenges in **flag mode** gives a number you can put
side-by-side with theirs.

## Run it

```bash
# 1. Clone the benchmark set (one-time).
git clone https://github.com/xbow-engineering/validation-benchmarks

# 2. Generate a suite JSON from the clone (dependency-free, no pyyaml).
python benchmark/suite/xbow/gen_xbow_suite.py \
    --root /path/to/validation-benchmarks \
    --out  benchmark/suite/xbow/xbow_generated.json

# 3. Smoke-test the suite without starting anything.
python benchmark/run_benchmark.py --suite suite/xbow/xbow_generated.json --dry-run

# 4. Run a single challenge first to validate plumbing, then the full set.
python benchmark/run_benchmark.py --suite suite/xbow/xbow_generated.json \
    --only XBEN-001-24 --time 15
python benchmark/run_benchmark.py --suite suite/xbow/xbow_generated.json --time 15
```

The headline line at the end — `Solve rate: X/104 = YY%` — is the comparable
figure. A Markdown + JSON scorecard with per-category breakdown lands in
`benchmark/results/`.

## How scoring works here

`mode: "flag"` → a challenge counts as **solved** iff the flag string (or, when the
flag is randomized per build, the `flag_regex` like `FLAG\{[^}]+\}`) appears
anywhere in VIPER's artifacts for that run: the `--output` findings JSON, stdout,
or stderr. No partial credit — same all-or-nothing rule XBOW uses.

## Assumptions the generator makes

The generator can't see your exact clone, so verify these against it and tweak
`gen_xbow_suite.py` if the layout differs:

- Challenges live in `<root>/benchmarks/<ID>/` with a `benchmark.json` and a
  `docker-compose.yml`.
- Flags match `FLAG{...}`. If a challenge pins an exact flag in `benchmark.json`,
  that exact string is used instead of the regex.
- The first `HOST:CONTAINER` port mapping found in the compose file is the HTTP
  port (`http://localhost:HOST`). Override with `--default-port` when none is found.

## Caveats for an honest comparison

- **Budget parity.** Set `--time` to a per-challenge budget comparable to what the
  competitor reported. Too low understates VIPER; too high isn't apples-to-apples.
- **Network egress.** Some challenges expect outbound callbacks (OOB/SSRF). Ensure
  VIPER's interaction host is reachable, or those will read as misses.
- **Flag delivery.** VIPER must actually surface the flag in a finding/stdout for
  flag mode to catch it. If VIPER solves but never prints the token, it scores as a
  miss — that's a reporting gap worth fixing, not a scoring bug.
- **Determinism.** Re-run 2–3× and report the spread; LLM-driven runs vary.
