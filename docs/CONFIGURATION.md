# VIPER Configuration & Operations

All runtime configuration is centralized in [`core/config.py`](../core/config.py)
(`ViperConfig`, loaded once via `get_config()`). Values come from environment
variables (and a `.env` file at the repo root; real env always wins). This page
is the single reference for the knobs and the dashboard security model.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `VIPER_PROJECT_ROOT` | repo root | Base dir for derived paths |
| `VIPER_DATA_DIR` | `<root>/data` | SQLite DBs + static data |
| `VIPER_STATE_DIR` | `<root>/state` | Runtime state + hunt logs |
| `VIPER_LOGS_DIR` | `<root>/logs` | Log output dir |
| `VIPER_REPORTS_DIR` | `<root>/reports` | Generated reports |
| `VIPER_DB_PATH` | `<data>/viper.db` | Findings/targets/attacks DB |
| `VIPER_EVOGRAPH_DB` | `<data>/evograph.db` | Cross-session learning DB |
| `VIPER_HUNTS_DIR` | `<state>/hunts` | Per-hunt audit logs |
| `VIPER_BIND_HOST` | `127.0.0.1` | Dashboard API bind host |
| `VIPER_PORT` | `8080` | Dashboard API port |
| `VIPER_UI_PORT` | `3000` | Next.js UI port |
| `VIPER_DASHBOARD_TOKEN` | _(empty)_ | Dashboard auth token (see below) |
| `VIPER_WEBAPP_ORIGINS` | _(empty)_ | Extra allowed CORS origins (csv) |
| `VIPER_HTTP_TIMEOUT` | `30.0` | Default outbound HTTP timeout (s) |
| `VIPER_DB_TIMEOUT` | `10.0` | SQLite busy timeout (s) |
| `VIPER_MAX_WORKERS` | `12` | Max concurrent swarm workers |
| `VIPER_HTTP_MAX_CONCURRENT` | `10` | HTTP batch fan-out |
| `VIPER_RATE_LIMIT_RPS` | `2.0` | Default per-host request rate |
| `VIPER_LOG_LEVEL` | `INFO` | Root log level |
| `VIPER_LOG_JSON` | `false` | Emit structured JSON logs |

Invalid values fail loudly at startup (`ConfigError`) rather than silently
falling back — e.g. a non-numeric `VIPER_PORT`.

## Dashboard authentication

The dashboard control plane (`dashboard/server.py`) can launch hunts and run a
sandboxed terminal, so its exposure is gated:

| Bind | Token set? | Result |
| --- | --- | --- |
| `127.0.0.1` (default) | no | **Open** — local-dev convenience, unchanged |
| any | **yes** | **Auth required** on every `/api` (Bearer header *or* `viper_token` cookie) |
| `0.0.0.0` / public | no | **Locked** — all `/api` requests denied (fail closed), loud startup warning |

- `/api/health` is always reachable (liveness probes).
- The browser UI sends the token automatically when present: set
  `NEXT_PUBLIC_VIPER_DASHBOARD_TOKEN` at build time, or
  `localStorage.setItem("viper-token", "<token>")` at runtime.
- API clients send `Authorization: Bearer <token>`.
- Security headers (`X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`) are set on every response.

**Production:** never expose the dashboard publicly without a token. Prefer a
reverse proxy (TLS + auth) in front of it; WebSocket/SSE authenticate via the
`viper_token` cookie (same-origin).

## Observability

`configure_logging()` ([`core/logging_setup.py`](../core/logging_setup.py)) is
called by every entrypoint. With `VIPER_LOG_JSON=1` each line is one JSON object
carrying a `hunt_id` that matches the `audit.jsonl` rows, so a log shipper can
join logs to the audit trail. Human format surfaces `(h=<hunt_id>)` inline
during a hunt. `--log-level` / `--log-json` flags on `viper.py hack` override.

## Egress control

Outbound actions routed through [`core/tool_gateway.py`](../core/tool_gateway.py)
(`gateway.http` / `gateway.run_subprocess`) are scope-checked (fail closed),
rate-limited, timeout-bounded, and audited. A hunt installs an `EgressContext`
automatically; with no context installed the gateway is permissive (lab/CTF /
owned boxes). Worker HTTP additionally enforces the scope guard directly.
