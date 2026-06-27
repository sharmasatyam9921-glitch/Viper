"""Derive PII-free class priors from a local corpus of disclosed vulnerability
reports (per-class prevalence + attack-pattern mix), emitting
business_logic_priors.json. AGGREGATES ONLY — case counts and attack-pattern
distributions; never the case payloads (which can carry leaked credentials). The
raw corpus stays local; only the derived statistics are committed.

    python -m core.selfimprove.derive_business_logic_priors <corpus_dir> [out.json]

`corpus_dir` holds one markdown file per vuln class, each listing disclosed cases.
"""
from __future__ import annotations

import json
import math
import re
import sys
from pathlib import Path

# corpus category -> (VIPER class prefix, inherent criticality weight 0-1)
_CLASS_MAP = {
    "sql-injection": ("sqli", 1.0),
    "command-execution": ("command_injection", 1.0),
    "rce": ("rce", 1.0),
    "file-upload": ("file_upload", 0.9),
    "unauthorized-access": ("access_control", 0.8),
    "weak-password": ("auth_bypass", 0.8),
    "ssrf": ("ssrf", 0.8),
    "file-traversal": ("lfi", 0.75),
    "xxe": ("xxe", 0.75),
    "logic-flaws": ("business_logic", 0.7),
    "info-disclosure": ("secrets", 0.55),
    "xss": ("xss", 0.5),
    "csrf": ("csrf", 0.45),
    "misconfig": ("cors", 0.4),
}
# attack-pattern labels (corpus is zh) -> english tag (taxonomy only, no content)
_PATTERN_MAP = {
    "越权": "privilege_escalation", "绕过": "auth_bypass", "泄露": "info_disclosure",
    "执行": "code_execution", "注入": "injection", "上传": "file_upload",
    "未授权": "unauthorized_access", "遍历": "path_traversal", "伪造": "request_forgery",
}
# a disclosed-case id marker (e.g. <source>-20YY-NNN) — matched generically so no
# corpus/source name is hardcoded; only used to COUNT cases, never to keep the id.
_CASE_RE = re.compile(r"\b[a-z][a-z0-9]{2,}-20\d{2}-\d")
_PAT_LINE = re.compile(r"\s+([一-鿿]{2,6}):\s*(\d+)")


def derive(corpus_dir: str) -> dict:
    root = Path(corpus_dir)
    classes: dict = {}
    counts: dict = {}
    for f in sorted(root.glob("*.md")):
        cat = f.stem
        if cat not in _CLASS_MAP:
            continue
        vclass, crit = _CLASS_MAP[cat]
        n = 0
        patterns: dict = {}
        with f.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if _CASE_RE.search(line):
                    n += 1
                m = _PAT_LINE.match(line)
                if m and m.group(1) in _PATTERN_MAP:
                    tag = _PATTERN_MAP[m.group(1)]
                    patterns[tag] = patterns.get(tag, 0) + int(m.group(2))
        counts[vclass] = counts.get(vclass, 0) + n
        # keep the richer attack-pattern mix + max criticality across merged cats
        prev = classes.get(vclass, {"attack_patterns": {}, "criticality": 0.0})
        for k, v in patterns.items():
            prev["attack_patterns"][k] = prev["attack_patterns"].get(k, 0) + v
        prev["criticality"] = max(prev["criticality"], crit)
        classes[vclass] = prev

    total = sum(counts.values()) or 1
    log_max = math.log1p(max(counts.values()) or 1)
    out_classes = {}
    for vclass, info in classes.items():
        cases = counts[vclass]
        # log-scaled prevalence so a 24k-case class doesn't 100x a 200-case one
        prevalence = round(math.log1p(cases) / log_max, 3) if log_max else 0.0
        out_classes[vclass] = {
            "cases": cases,
            "share": round(cases / total, 4),
            "prevalence": prevalence,                 # 0-1, log-scaled frequency
            "criticality": round(info["criticality"], 2),
            "impact_prior": round(prevalence * info["criticality"], 3),
            "attack_patterns": dict(sorted(info["attack_patterns"].items(),
                                           key=lambda kv: -kv[1])),
        }
    return {
        "description": "Per-class priors derived from a corpus of disclosed "
                       "business-logic / web vulnerability reports. Aggregates only "
                       "(case counts + attack-pattern taxonomy); no payloads/PII. "
                       "impact_prior = log-prevalence x inherent criticality, used "
                       "by core.prioritization to rank findings by historical impact.",
        "total_cases": total,
        "classes": out_classes,
    }


def main(argv):
    if not argv:
        print("usage: python -m core.selfimprove.derive_business_logic_priors "
              "<corpus_dir> [out.json]")
        return 1
    out = derive(argv[0])
    dest = Path(argv[1]) if len(argv) > 1 else (
        Path(__file__).parent / "business_logic_priors.json")
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=True), encoding="utf-8")
    print(f"wrote {dest}: {len(out['classes'])} classes, "
          f"{out['total_cases']} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
