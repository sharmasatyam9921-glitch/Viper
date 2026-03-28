FROM python:3.12-slim

LABEL maintainer="viper-ashborn"
LABEL description="VIPER 5.0 — Autonomous Bug Bounty Hunting Agent"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONUTF8=1

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget unzip nmap masscan dnsutils whois \
    libpcap-dev build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Go tools (subfinder, httpx, nuclei, katana, naabu, gau, ffuf, hakrawler, puredns)
ENV GOPATH=/root/go
ENV PATH="${PATH}:/usr/local/go/bin:/root/go/bin"
RUN wget -q https://go.dev/dl/go1.22.5.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/lc/gau/v2/cmd/gau@latest \
    && go install -v github.com/ffuf/ffuf/v2@latest \
    && go install -v github.com/hakluke/hakrawler@latest \
    && go install -v github.com/d3mondev/puredns/v2@latest \
    && go install -v github.com/assetnote/kiterunner/cmd/kr@latest

# Python deps
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# SQLMap
RUN pip install --no-cache-dir sqlmap

# jsluice (Go tool for JS analysis)
RUN go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest

# Copy VIPER source
COPY . .

# Nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Dashboard port
EXPOSE 8080

# Default: full hunt mode
ENTRYPOINT ["python", "viper.py"]
CMD ["--help"]
