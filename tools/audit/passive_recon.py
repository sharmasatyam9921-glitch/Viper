"""Passive A-Z recon driver for a saved scope.

For every explicit URL target + a sampled set of wildcards, resolve DNS,
fetch HTTP status / server header, fingerprint tech via httpx (if
available), and look up known CVEs.

Strictly scope-gated: every target is checked against
scopes/current_scope.json before any request.

Output: findings/recon-<program>.json
"""
from __future__ import annotations

import asyncio
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.audit.scope_guard import load_scope, allowed  # noqa: E402

UA = "viper-ashborn-h1 (Authorized Testing - inDrive H1)"


def _host(u: str) -> str:
    if "://" not in u:
        u = "https://" + u
    return (urlsplit(u).hostname or "").lower()


def resolve_dns(host: str) -> dict:
    out = {"a": [], "aaaa": [], "cname": [], "err": None}
    try:
        for family, kind in ((socket.AF_INET, "a"), (socket.AF_INET6, "aaaa")):
            try:
                infos = socket.getaddrinfo(host, None, family)
                out[kind] = sorted({i[4][0] for i in infos})
            except socket.gaierror:
                pass
    except Exception as e:  # noqa: BLE001
        out["err"] = repr(e)[:120]
    return out


def http_probe(host: str, timeout: float = 6.0) -> dict:
    """One quick HEAD/GET on https://<host>/. No path traversal."""
    url = f"https://{host}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {
                "url": url,
                "status": getattr(resp, "status", resp.getcode()),
                "server": resp.headers.get("Server", ""),
                "x_powered_by": resp.headers.get("X-Powered-By", ""),
                "content_type": resp.headers.get("Content-Type", ""),
                "size": len(resp.read(8 * 1024)),
                "redirected_to": resp.geturl() if resp.geturl() != url else None,
                "cookies": [c.split(";")[0] for c in resp.headers.get_all("Set-Cookie", []) or []][:5],
            }
    except urllib.error.HTTPError as e:
        return {
            "url": url, "status": e.code,
            "server": e.headers.get("Server", "") if e.headers else "",
            "err_class": "HTTPError",
        }
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return {"url": url, "err_class": type(e).__name__, "err": str(e)[:120]}


def fingerprint(probe: dict) -> list[str]:
    """Map server + headers to tech labels (lightweight Wappalyzer-lite)."""
    labels = []
    s = (probe.get("server") or "").lower()
    p = (probe.get("x_powered_by") or "").lower()
    ct = (probe.get("content_type") or "").lower()
    for tech, marker in (
        ("nginx",      "nginx"),
        ("apache",     "apache"),
        ("caddy",      "caddy"),
        ("envoy",      "envoy"),
        ("traefik",    "traefik"),
        ("cloudflare", "cloudflare"),
        ("istio",      "istio"),
        ("uvicorn",    "uvicorn"),
        ("gunicorn",   "gunicorn"),
        ("kestrel",    "kestrel"),
    ):
        if marker in s:
            labels.append(tech)
    for tech, marker in (
        ("php",     "php"),
        ("aspnet",  "asp.net"),
        ("express", "express"),
        ("django",  "django"),
    ):
        if marker in p:
            labels.append(tech)
    if "json" in ct:
        labels.append("api")
    if "html" in ct and not any(l == "api" for l in labels):
        labels.append("web")
    return labels


def value_score(type: str, probe: dict, fp: list[str]) -> int:
    """Rough heuristic for ordering targets. Higher = scan first."""
    s = probe.get("status", 0)
    score = 0
    if s >= 200 and s < 400:
        score += 5
    if type == "URL":
        score += 5  # explicit URL = program owner is confident there's surface
    if "api" in fp:
        score += 4
    if any(x in (probe.get("url", "")) for x in ("/api/", "passkey", "auth", "pay", "admin")):
        score += 6
    if "cloudflare" in fp:
        score -= 1  # CF often blocks heavier scans
    return score


def main() -> int:
    scope_path = REPO_ROOT / "scopes" / "current_scope.json"
    scope = load_scope(scope_path)
    if not scope:
        print(f"[!] No scope loaded at {scope_path}", file=sys.stderr)
        return 2

    assets = scope.get("in_scope", [])
    print(f"Loaded scope: {scope.get('program','?')} ({len(assets)} assets)")
    print()

    # Build the target list — only URL types + non-wildcard hosts
    # (wildcards require subdomain enumeration to be useful, which is
    # a separate phase).
    targets = []
    for a in assets:
        asset = a["asset"]
        if a["type"] != "URL":
            continue
        host = _host(asset)
        if not host or "*" in host:
            continue
        if not allowed(asset, scope):
            # belt + suspenders — should never happen for url_targets
            continue
        targets.append((host, a))

    print(f"Probing {len(targets)} explicit URL targets…")
    rows = []
    for i, (host, a) in enumerate(targets, 1):
        sys.stdout.write(f"  [{i:>3}/{len(targets)}] {host:42}")
        sys.stdout.flush()
        dns = resolve_dns(host)
        probe = http_probe(host)
        fp = fingerprint(probe)
        score = value_score(a["type"], probe, fp)
        row = {
            "host": host,
            "max_severity": a["max_severity"],
            "type": a["type"],
            "dns": dns,
            "probe": probe,
            "tech": fp,
            "score": score,
        }
        rows.append(row)
        print(f"  status={probe.get('status', '-'):>3} fp={','.join(fp) or '-':25} score={score}")

    # Sort by score, descending — highest-value first
    rows.sort(key=lambda r: (-r["score"], r["host"]))

    out_path = REPO_ROOT / "findings" / "indrive-passive-recon.json"
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps({
        "program": scope.get("program"),
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "targets": rows,
    }, indent=2))

    print()
    print(f"Saved: {out_path}")
    print()
    print("Top-10 by value score:")
    for r in rows[:10]:
        print(f"  score={r['score']:>2}  {r['host']:42}  "
              f"status={r['probe'].get('status','-'):>3}  "
              f"tech={','.join(r['tech']) or '-'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
