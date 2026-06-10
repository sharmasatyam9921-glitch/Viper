#!/usr/bin/env python3
"""A stand-in for viper.py that honors the same CLI contract the harness relies on.

Used by run_selftest.py to exercise the orchestrator end-to-end without a real
10-minute hunt or a Docker target. It parses the same flags the runner passes
(`--output`, `--time`, target URL) plus a test-only `--selftest-emit MODE` that
decides what to "find", so one suite can produce a hit, a flag, and a miss.
"""

import json
import sys


def _arg(flag, default=None):
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return default


def main():
    out = _arg("--output")
    mode = _arg("--selftest-emit", "sqli")
    # argv[0]=stub path, argv[1]=target url (first non-flag after the script).
    target = next((a for a in sys.argv[1:] if not a.startswith("-")), "http://unknown")

    findings = []
    if mode == "sqli":
        findings = [{
            "vuln_type": "sqli_union", "severity": "high", "confidence": 0.92,
            "url": f"{target}/rest/user/login", "title": "SQL injection in login",
            "evidence": "' OR 1=1-- returned all rows", "payload": "' OR 1=1--",
        }]
    elif mode == "flag":
        findings = [{
            "vuln_type": "info_disclosure", "severity": "medium", "confidence": 0.8,
            "url": f"{target}/ftp", "title": "Exposed file",
            "evidence": "captured token FLAG{selftest_0xCAFE}", "payload": "",
        }]
    elif mode == "nothing":
        findings = []

    result = {
        "target": target,
        "findings": findings,
        "status": "completed",
    }
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)

    # Mirror VIPER's habit of printing a summary line; flag mode prints the token
    # to stdout too so the scorer's stdout path is exercised.
    print(f"[stub] target={target} mode={mode} findings={len(findings)}")
    if mode == "flag":
        print("[stub] FLAG{selftest_0xCAFE}")
    print("[stub] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
