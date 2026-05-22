#!/bin/sh
# VIPER 6.0 — container entrypoint
#
# Dispatches based on the first arg or MODE env:
#   api      → dashboard HTTP + WebSocket server on :8080 (default)
#   worker   → swarm worker daemon (subscribes to phase queues)
#   daemon   → 24/7 continuous hunter
#   hack     → one-shot HackMode run; remaining args forwarded
#   shell    → exec /bin/bash (debug)
#   <other>  → exec the args verbatim (escape hatch)
#
# Examples:
#   docker run viper:latest                              # api mode
#   docker run -e MODE=worker viper:latest               # worker mode
#   docker run viper:latest hack https://example.com     # one-shot hunt
set -eu

# Precedence: explicit MODE env var > first positional arg > default "api".
# This way `docker run -e MODE=worker image` does the right thing even when
# the image's CMD is `["api"]`, and `docker run image hack <target>` still
# works as a one-shot override.
#
# If the first positional arg matches the *resolved* MODE, we still shift it
# off so it isn't re-passed to the underlying command (e.g. argparse would
# reject a stray "worker" positional).
if [ "$#" -gt 0 ]; then
    case "$1" in
        api|worker|daemon|hack|shell|--help|-h)
            if [ -z "${MODE:-}" ] || [ "${MODE}" = "$1" ]; then
                MODE="$1"
                shift
            fi
            ;;
    esac
fi

MODE="${MODE:-api}"

cd /app

echo "[entrypoint] VIPER 6.0 starting in mode=${MODE}"
echo "[entrypoint] REDIS_URL=${REDIS_URL:-<unset, asyncio bus>}"
echo "[entrypoint] python=$(python --version 2>&1)"

case "${MODE}" in
    api)
        exec python -u dashboard/server.py "$@"
        ;;

    worker)
        exec python -u -m core.swarm_worker_daemon "$@"
        ;;

    daemon)
        exec python -u viper_daemon.py "$@"
        ;;

    hack)
        # One-shot HackMode run — useful for `docker run --rm viper hack <target>`
        exec python -u viper.py hack "$@"
        ;;

    shell)
        exec /bin/bash
        ;;

    --help|-h)
        echo "Usage: docker run [-e MODE=<mode>] viper:latest [args...]"
        echo "  MODE=api      → dashboard/server.py  (default)"
        echo "  MODE=worker   → swarm worker daemon  (REDIS_URL recommended)"
        echo "  MODE=daemon   → viper_daemon.py     (24/7 hunter)"
        echo "  MODE=hack     → viper.py hack <target>  (one-shot run)"
        exit 0
        ;;

    *)
        # Escape hatch — run whatever the user gave us
        exec python -u "${MODE}" "$@"
        ;;
esac
