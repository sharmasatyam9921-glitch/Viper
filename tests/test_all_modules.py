#!/usr/bin/env python3
"""VIPER Module Test Report — tests all 10 new improvements + 4 skill prompts."""

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def main():
    results = []
    total_start = time.time()

    # 1. JS Secret Scanner
    print("Testing 1/10: JS Secret Scanner...")
    t = time.time()
    try:
        from recon.js_scanner import JSSecretScanner
        scanner = JSSecretScanner()
        pattern_count = len(scanner.PATTERNS) if hasattr(scanner, "PATTERNS") else 0
        secrets = await scanner.scan_url("http://localhost:9999/")
        results.append(("JS Secret Scanner", "PASS", int((time.time()-t)*1000),
                        f"{pattern_count} patterns, {len(secrets)} secrets on test page"))
    except Exception as e:
        results.append(("JS Secret Scanner", "FAIL", int((time.time()-t)*1000), str(e)))

    # 2. Auth Scanner
    print("Testing 2/10: Auth Scanner...")
    t = time.time()
    try:
        from core.auth_scanner import AuthScanner
        auth = AuthScanner()
        await auth.login_bearer("test-token-123")
        headers = auth.get_auth_headers()
        await auth.login_cookie({"session": "abc123"})
        cookies = auth.get_auth_cookies()
        results.append(("Auth Scanner", "PASS", int((time.time()-t)*1000),
                        f"Bearer={'Authorization' in headers}, Cookie={'session' in cookies}"))
    except Exception as e:
        results.append(("Auth Scanner", "FAIL", int((time.time()-t)*1000), str(e)))

    # 3. Chain Escalator
    print("Testing 3/10: Chain Escalator...")
    t = time.time()
    try:
        from core.chain_escalator import ChainEscalator
        esc = ChainEscalator()
        chain_defs = len(esc.CHAINS) if hasattr(esc, "CHAINS") else 0
        findings = [
            {"vuln_type": "cors_misconfiguration", "severity": "medium", "url": "http://t"},
            {"vuln_type": "csrf_token_leak", "severity": "medium", "url": "http://t"},
            {"vuln_type": "xss_reflected", "severity": "medium", "url": "http://t"},
            {"vuln_type": "ssti_basic", "severity": "high", "url": "http://t"},
            {"vuln_type": "ssrf_basic", "severity": "high", "url": "http://t"},
        ]
        chains = esc.analyze(findings)
        names = [c.chain_name if hasattr(c, "chain_name") else c.get("chain_name") for c in chains]
        results.append(("Chain Escalator", "PASS", int((time.time()-t)*1000),
                        f"{chain_defs} defined, {len(chains)} detected: {names}"))
    except Exception as e:
        results.append(("Chain Escalator", "FAIL", int((time.time()-t)*1000), str(e)))

    # 4. Bounty Optimizer
    print("Testing 4/10: Bounty Optimizer...")
    t = time.time()
    try:
        from core.bounty_optimizer import BountyOptimizer
        opt = BountyOptimizer()
        programs = [
            {"name": "meesho", "bounty_range": [50, 5000], "response_efficiency": 98, "in_scope": list(range(7))},
            {"name": "shopify", "bounty_range": [500, 30000], "response_efficiency": 85, "in_scope": list(range(20))},
            {"name": "small_co", "bounty_range": [0, 100], "response_efficiency": 30, "in_scope": ["a"]},
        ]
        ranked = opt.rank_targets(programs)
        scores = [(p["name"], round(p["roi_score"], 1)) for p in ranked]
        results.append(("Bounty Optimizer", "PASS", int((time.time()-t)*1000),
                        f"Rankings: {scores}"))
    except Exception as e:
        results.append(("Bounty Optimizer", "FAIL", int((time.time()-t)*1000), str(e)))

    # 5. Template Generator
    print("Testing 5/10: Nuclei Template Generator...")
    t = time.time()
    try:
        from core.template_generator import NucleiTemplateGenerator
        gen = NucleiTemplateGenerator()
        templates = await gen.generate_for_target(
            target_url="http://localhost:9999",
            technologies=["python", "flask", "nginx"],
            endpoints=["/search", "/users", "/view"],
            parameters={"/search": ["q"], "/users": ["id"], "/view": ["file"]},
        )
        results.append(("Template Generator", "PASS", int((time.time()-t)*1000),
                        f"{len(templates)} templates for 3 endpoints + 3 technologies"))
    except Exception as e:
        results.append(("Template Generator", "FAIL", int((time.time()-t)*1000), str(e)))

    # 6. Auto-Submit Pipeline
    print("Testing 6/10: Auto-Submit Pipeline...")
    t = time.time()
    try:
        from core.auto_submit import AutoSubmitPipeline
        tracker = "state/submission_tracker.json"
        if os.path.exists(tracker):
            os.remove(tracker)
        pipeline = AutoSubmitPipeline()
        findings = [
            {"vuln_type": "sqli_error", "severity": "high", "confidence": 0.85,
             "url": "http://test/users?id=1", "payload": "'", "marker": "SQL syntax"},
            {"vuln_type": "xss_reflected", "severity": "medium", "confidence": 0.90,
             "url": "http://test/search?q=x", "payload": "<script>alert(1)</script>"},
        ]
        rpt = await pipeline.process_findings(findings, "test_bbp", {})
        count = len(rpt) if isinstance(rpt, list) else len(rpt.get("pending", rpt.get("submissions", [])))
        results.append(("Auto-Submit Pipeline", "PASS", int((time.time()-t)*1000),
                        f"{count} reports from {len(findings)} findings"))
    except Exception as e:
        results.append(("Auto-Submit Pipeline", "FAIL", int((time.time()-t)*1000), str(e)))

    # 7. Parallel Hunter
    print("Testing 7/10: Parallel Hunter...")
    t = time.time()
    try:
        from core.parallel_hunter import ParallelHunter
        hunter = ParallelHunter(max_concurrent=3)
        has_hunt = hasattr(hunter, "hunt_all")
        results.append(("Parallel Hunter", "PASS", int((time.time()-t)*1000),
                        f"max_concurrent=3, hunt_all={has_hunt}"))
    except Exception as e:
        results.append(("Parallel Hunter", "FAIL", int((time.time()-t)*1000), str(e)))

    # 8. Training Mode
    print("Testing 8/10: Training Mode...")
    t = time.time()
    try:
        from core.training_mode import TrainingMode, TRAINING_TARGETS
        trainer = TrainingMode()
        expected = TRAINING_TARGETS["local_vuln_server"]["expected_vulns"]
        results.append(("Training Mode", "PASS", int((time.time()-t)*1000),
                        f"{len(TRAINING_TARGETS)} targets, {len(expected)} expected vulns"))
    except Exception as e:
        results.append(("Training Mode", "FAIL", int((time.time()-t)*1000), str(e)))

    # 9. Skill Prompts
    print("Testing 9/10: Skill Prompts...")
    t = time.time()
    try:
        from core.skill_prompts import get_skill_prompt
        skill_types = ["sql_injection", "api_security", "xss_exploitation",
                       "ssrf_exploitation", "xss", "jwt_exploitation", "graphql_exploitation"]
        loaded = {}
        for st in skill_types:
            prompt = get_skill_prompt(st)
            if prompt:
                loaded[st] = len(prompt)
        results.append(("Skill Prompts", "PASS", int((time.time()-t)*1000),
                        f"{len(loaded)}/{len(skill_types)} loaded, total {sum(loaded.values())} chars"))
    except Exception as e:
        results.append(("Skill Prompts", "FAIL", int((time.time()-t)*1000), str(e)))

    # 10. Playwright Tool
    print("Testing 10/10: Playwright Tool...")
    t = time.time()
    try:
        from tools.playwright_tool import PlaywrightTool
        available = PlaywrightTool.is_available()
        pw = PlaywrightTool()
        methods = [m for m in ["bypass_waf", "navigate", "verify_xss", "verify_csrf",
                               "capture_auth_flow", "extract_spa_content"] if hasattr(pw, m)]
        results.append(("Playwright Tool", "PASS", int((time.time()-t)*1000),
                        f"installed={available}, methods={methods}"))
    except Exception as e:
        results.append(("Playwright Tool", "FAIL", int((time.time()-t)*1000), str(e)))

    # ══════════════════════════════════════════════════
    # REPORT
    # ══════════════════════════════════════════════════
    total_ms = int((time.time() - total_start) * 1000)
    passed = sum(1 for r in results if r[1] == "PASS")
    failed = sum(1 for r in results if r[1] == "FAIL")

    print()
    print("=" * 72)
    print("  VIPER MODULE TEST REPORT")
    print("=" * 72)
    print()
    for i, (name, status, ms, details) in enumerate(results, 1):
        icon = "PASS" if status == "PASS" else "FAIL"
        print(f"  {i:2d}. [{icon}] {name:30s} ({ms}ms)")
        print(f"      {details}")
        print()
    print("-" * 72)
    print(f"  Total: {passed} passed, {failed} failed | {total_ms}ms")
    print("=" * 72)


if __name__ == "__main__":
    asyncio.run(main())
