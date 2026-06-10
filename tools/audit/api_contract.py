"""Phase 5 — API contract audit.

For every ``useApi<T>(...)`` / ``apiGet<T>(...)`` / ``apiPost<T>(...)`` call
site in the Next.js webapp, GET the endpoint against the running backend
and verify the response shape matches the TypeScript generic.

Detects the "expects array, got object" wrapping mismatches that have
crashed the dashboard before (overview, cypherfix, projects, targets).

Writes:
  findings/api-contract.json    machine-readable list of mismatches
  findings/api-contract.md      human report
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FE = ROOT / "dashboard" / "webapp" / "src"
BACKEND = "http://127.0.0.1:8080"

CALL_PATTERNS = (
    # useApi<T>("key", "/api/...", interval)
    re.compile(
        r'useApi<\s*([^>]+?)\s*>\(\s*[\'"][^\'"]*[\'"]\s*,\s*[\'"](/api/[^\'"]+)[\'"]'
    ),
    # apiGet<T>("/api/...")
    re.compile(r'apiGet<\s*([^>]+?)\s*>\(\s*[`\'"]([^`\'"]*/api/[^`\'"]+)'),
    # apiPost<T>("/api/...", body)
    re.compile(r'apiPost<\s*([^>]+?)\s*>\(\s*[`\'"]([^`\'"]*/api/[^`\'"]+)'),
)


def find_calls() -> list[dict]:
    out = []
    for tsx in list(FE.rglob("*.tsx")) + list(FE.rglob("*.ts")):
        body = tsx.read_text(encoding="utf-8", errors="replace")
        rel = tsx.relative_to(ROOT).as_posix()
        for pat in CALL_PATTERNS:
            for m in pat.finditer(body):
                expects = m.group(1).strip().replace("\n", " ")
                path = m.group(2).strip()
                # Strip template-literal interp
                if "${" in path:
                    continue
                kind = "POST" if "apiPost" in pat.pattern else "GET"
                out.append({
                    "file": rel, "kind": kind,
                    "path": path, "expects": expects,
                })
    return out


def probe(path: str) -> tuple[bool, object | None, str]:
    """Returns (ok, parsed_json, error)."""
    try:
        req = urllib.request.Request(
            BACKEND + path,
            headers={"Origin": "http://localhost:3000"},
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            return True, json.loads(r.read().decode()), ""
    except urllib.error.HTTPError as e:
        return False, None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return False, None, type(e).__name__


def classify(expects: str, payload: object) -> tuple[str, str]:
    """Return ('ok' | 'mismatch' | 'defensive', detail)."""
    is_array = isinstance(payload, list)
    is_object = isinstance(payload, dict)
    expects_array = "[]" in expects and "|" not in expects
    expects_object = ("[]" not in expects) and "|" not in expects
    is_union = "|" in expects

    if is_union:
        return ("defensive", f"accepts both shapes: {expects}")
    if expects_array and is_array:
        return ("ok", "array→array")
    if expects_object and is_object:
        return ("ok", "object→object")
    if expects_array and is_object:
        return ("mismatch", "expects array but backend returns object")
    if expects_object and is_array:
        return ("mismatch", "expects object but backend returns array")
    return ("ok", "")


def main() -> int:
    calls = find_calls()
    # Dedupe by (kind, path)
    unique = {}
    for c in calls:
        path = c["path"].split("?")[0]
        unique.setdefault((c["kind"], path), []).append(c)

    rows = []
    for (kind, path), seen in sorted(unique.items()):
        first = seen[0]
        if kind == "POST":
            rows.append({
                "kind": kind, "path": path, "expects": first["expects"],
                "status": "skip", "detail": "POST body — not auto-probed",
                "files": [s["file"] for s in seen],
            })
            continue
        ok, payload, err = probe(path)
        if not ok:
            rows.append({
                "kind": kind, "path": path, "expects": first["expects"],
                "status": "unreachable", "detail": err,
                "files": [s["file"] for s in seen],
            })
            continue
        status, detail = classify(first["expects"], payload)
        rows.append({
            "kind": kind, "path": path, "expects": first["expects"],
            "status": status, "detail": detail,
            "files": [s["file"] for s in seen],
        })

    out = ROOT / "findings" / "api-contract.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2))

    counts = {"ok": 0, "mismatch": 0, "defensive": 0,
              "unreachable": 0, "skip": 0}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    md = ["# API Contract Audit\n",
          f"- total: {len(rows)} unique endpoints\n",
          f"- ok: {counts['ok']}\n",
          f"- defensive (handles both shapes): {counts['defensive']}\n",
          f"- mismatch: {counts['mismatch']}\n",
          f"- unreachable: {counts['unreachable']}\n",
          f"- skipped (POST): {counts['skip']}\n\n"]
    if counts["mismatch"]:
        md.append("## Mismatches\n\n")
        for r in rows:
            if r["status"] == "mismatch":
                md.append(f"- **`{r['path']}`** — {r['detail']}\n")
                md.append(f"  - expects: `{r['expects']}`\n")
                for f in r["files"]:
                    md.append(f"  - call site: {f}\n")
                md.append("\n")
    if counts["unreachable"]:
        md.append("## Unreachable\n\n")
        for r in rows:
            if r["status"] == "unreachable":
                md.append(f"- `{r['path']}` — {r['detail']}\n")
    (ROOT / "findings" / "api-contract.md").write_text("".join(md))

    print(f"Audited {len(rows)} endpoints")
    for s in ("ok", "defensive", "mismatch", "unreachable", "skip"):
        print(f"  {s}: {counts[s]}")
    if counts["mismatch"]:
        print("\nMismatches:")
        for r in rows:
            if r["status"] == "mismatch":
                print(f"  {r['path']} :: {r['detail']} :: {r['files'][0]}")
    return 0 if counts["mismatch"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
