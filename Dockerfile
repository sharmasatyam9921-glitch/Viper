# syntax=docker/dockerfile:1.7
# ──────────────────────────────────────────────────────────────────────────
# VIPER 6.0 — multi-role Python backend image
#
# Single image used in three roles based on the MODE env var:
#   MODE=api      → `python dashboard/server.py` (default; exposes 8080)
#   MODE=worker   → `python -m core.swarm_worker_daemon`  (swarm worker pool)
#   MODE=daemon   → `python viper_daemon.py`             (24/7 hunter)
#
# Stage 1: tools — fetches Go-based pentest CLIs.
# Stage 2: runtime — slim Python + tools copied in + non-root user.
# ──────────────────────────────────────────────────────────────────────────

FROM golang:1.24-bookworm AS tools

ENV CGO_ENABLED=1 \
    GOFLAGS="-trimpath" \
    GOOS=linux \
    GOTOOLCHAIN=auto \
    GOBIN=/out/bin

RUN mkdir -p /out/bin

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git build-essential libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery + community pentest CLIs.
# Each install is best-effort: VIPER degrades gracefully if a tool is absent.
RUN set -eux; \
    for pkg in \
        github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
        github.com/projectdiscovery/httpx/cmd/httpx@latest \
        github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
        github.com/projectdiscovery/katana/cmd/katana@latest \
        github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
        github.com/lc/gau/v2/cmd/gau@latest \
        github.com/ffuf/ffuf/v2@latest \
        github.com/hakluke/hakrawler@latest \
        github.com/d3mondev/puredns/v2@latest \
        github.com/assetnote/kiterunner/cmd/kr@latest \
        github.com/BishopFox/jsluice/cmd/jsluice@latest \
    ; do \
        echo "==> installing $pkg" ; \
        go install -v "$pkg" || echo "WARN: failed to install $pkg (continuing)" ; \
    done ; \
    ls -1 /out/bin/

# ──────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="VIPER 6.0" \
      org.opencontainers.image.description="Autonomous bug-bounty + CTF hunting bot with XBOW-style swarm" \
      org.opencontainers.image.source="https://github.com/viper-ashborn/viper" \
      org.opencontainers.image.licenses="MIT"

ARG VIPER_USER=viper
ARG VIPER_UID=1000
ARG VIPER_GID=1000

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIPER_HOME=/app \
    PATH="/opt/go-tools/bin:${PATH}" \
    DEBIAN_FRONTEND=noninteractive

# Runtime OS deps (also needed for some lxml/cryptography wheels)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        git \
        jq \
        libpcap0.8 \
        libxml2 \
        libxslt1.1 \
        nmap \
        masscan \
        netcat-openbsd \
        wget \
        whois \
    && rm -rf /var/lib/apt/lists/*

# Copy Go pentest tools from builder stage
COPY --from=tools /out/bin/ /opt/go-tools/bin/

# Non-root user
RUN groupadd --gid ${VIPER_GID} ${VIPER_USER} \
 && useradd --create-home --uid ${VIPER_UID} --gid ${VIPER_GID} --shell /bin/bash ${VIPER_USER}

WORKDIR ${VIPER_HOME}

# Python deps — cached layer
COPY --chown=${VIPER_USER}:${VIPER_USER} requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir \
        redis>=5.0.0 \
        hiredis>=2.3.0 \
        sqlmap

# Source — broken into layers for cache locality
COPY --chown=${VIPER_USER}:${VIPER_USER} core/                ./core/
COPY --chown=${VIPER_USER}:${VIPER_USER} recon/               ./recon/
COPY --chown=${VIPER_USER}:${VIPER_USER} tools/               ./tools/
COPY --chown=${VIPER_USER}:${VIPER_USER} scanners/            ./scanners/
COPY --chown=${VIPER_USER}:${VIPER_USER} agents/              ./agents/
COPY --chown=${VIPER_USER}:${VIPER_USER} ai/                  ./ai/
COPY --chown=${VIPER_USER}:${VIPER_USER} scope/               ./scope/
COPY --chown=${VIPER_USER}:${VIPER_USER} dashboard/           ./dashboard/
COPY --chown=${VIPER_USER}:${VIPER_USER} \
        viper.py viper_core.py viper_daemon.py \
        viper_submit_queue.py mcp_server.py \
        ./

# State dirs the app writes to (volume-mounted in compose)
RUN mkdir -p data logs reports state findings models knowledge credentials \
 && chown -R ${VIPER_USER}:${VIPER_USER} ${VIPER_HOME}

# Nuclei templates (best-effort; runs offline-safe if upstream is down)
USER ${VIPER_USER}
RUN /opt/go-tools/bin/nuclei -update-templates -silent 2>/dev/null || true

# Entrypoint dispatches on MODE env
COPY --chown=${VIPER_USER}:${VIPER_USER} docker/entrypoint.sh /entrypoint.sh
USER root
RUN chmod +x /entrypoint.sh
USER ${VIPER_USER}

EXPOSE 8080

# /api/status returns dashboard health JSON
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8080/api/status || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["api"]
