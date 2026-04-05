#!/usr/bin/env python3
"""
VIPER 4.0 — AI-Powered Autonomous Bug Bounty Scanner
Usage:
    python viper.py <target_url>                    # Quick hunt (5 min)
    python viper.py <target_url> --full             # Full hunt (30 min)
    python viper.py <target_url> --full --time 15   # Full hunt (15 min)
    python viper.py <target_url> --scope scope.json # With scope file
    python viper.py <target_url> --roe engage.pdf   # Auto-scope from RoE document
    python viper.py <target_url> --report-html      # Generate HTML report
    python viper.py <target_url> --waves 3          # Parallel multi-strategy (3 waves)
    python viper.py <target_url> --secrets          # Enable GitHub secret scanning
    python viper.py <target_url> --stealth 2        # WAF evasion (0-3)
    python viper.py <target_url> --gvm              # Enable GVM/OpenVAS network scanning
    python viper.py <target_url> --bruteforce       # Enable brute-force engine
    python viper.py <target_url> --metasploit       # Enable Metasploit integration
    python viper.py <target_url> --codefix          # Generate remediation suggestions
    python viper.py <target_url> --post-exploit     # Enable post-exploitation analysis
    python viper.py <target_url> --graph            # Build attack graph
    python viper.py --dashboard-only                # Launch dashboard only
    python viper.py <target_url> --dashboard        # Hunt + live dashboard
    python viper.py --setup                         # Run setup wizard
    python viper.py <target_url> --interactive         # Approval-gated mode
    python viper.py <target_url> --deep-think          # Strategic analysis before attacks
    python viper.py <target_url> --triage              # Run triage on findings
    python viper.py <target_url> --codefix /path/repo  # Auto-fix vulnerabilities + GitHub PR
    python viper.py <target_url> --report-ciso         # CISO-quality narrative report
    python viper.py <target_url> --tor                 # Route through Tor
    python viper.py <target_url> --shodan              # Shodan InternetDB enrichment
    python viper.py <target_url> --kali                # Use Docker Kali sandbox
    python viper.py <target_url> --skill cve_exploit   # Force attack classification
    python viper.py <target_url> --no-guardrail        # Skip target guardrails (lab mode)
    python viper.py --export project.zip               # Export project data
    python viper.py --import project.zip               # Import project data
    python viper.py --triage                           # Triage existing findings (no scan)
"""
import asyncio, sys, os, argparse, json

# Load .env if exists
env_file = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(env_file):
    for line in open(env_file):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

sys.path.insert(0, os.path.dirname(__file__))


def main():
    parser = argparse.ArgumentParser(description="VIPER 4.0 — AI Bug Bounty Scanner")
    parser.add_argument("target", nargs="?", help="Target URL to scan")
    parser.add_argument("--full", action="store_true", help="Full hunt (recon+surface+nuclei+manual)")
    parser.add_argument("--time", type=int, default=None, help="Time budget in minutes (default: 5 quick, 30 full)")
    parser.add_argument("--scope", help="Path to scope JSON file")
    parser.add_argument("--setup", action="store_true", help="Run setup wizard")
    parser.add_argument("--output", help="Output file for results (JSON)")
    parser.add_argument("--dashboard", action="store_true", help="Launch web dashboard alongside hunt")
    parser.add_argument("--dashboard-port", type=int, default=8080, help="Dashboard port (default: 8080)")
    parser.add_argument("--dashboard-only", action="store_true", help="Launch dashboard only (blocks)")
    parser.add_argument("--secrets", action="store_true", help="Enable GitHub secret scanning phase")
    parser.add_argument("--roe", help="Path to Rules of Engagement document (PDF/TXT/MD)")
    parser.add_argument("--report-html", action="store_true", help="Generate HTML report (auto-enabled in --full mode)")
    parser.add_argument("--waves", type=int, default=1, help="Number of parallel hunt waves (1=normal, 3=parallel)")
    parser.add_argument("--stealth", type=int, default=0, help="Stealth level 0-3 (0=off, 1=basic, 2=moderate, 3=paranoid)")
    parser.add_argument("--gvm", action="store_true", help="Enable GVM/OpenVAS network-layer vulnerability scanning")
    parser.add_argument("--bruteforce", action="store_true", help="Enable brute-force engine (credential testing, dir enum)")
    parser.add_argument("--metasploit", action="store_true", help="Enable Metasploit exploit integration")
    parser.add_argument("--codefix", action="store_true", help="Generate code remediation suggestions post-hunt")
    parser.add_argument("--post-exploit", action="store_true", help="Enable post-exploitation analysis")
    parser.add_argument("--graph", action="store_true", help="Build attack graph during hunt (default: on)")
    # VIPER 4.0 new flags
    parser.add_argument("--interactive", action="store_true", help="Approval-gated mode (confirm before exploitation)")
    parser.add_argument("--deep-think", action="store_true", help="Enable strategic analysis before attacks")
    parser.add_argument("--triage", action="store_true", help="Run vulnerability triage on existing findings")
    parser.add_argument("--codefix-repo", help="Path to repository for auto-fix (generates patches + optional PR)")
    parser.add_argument("--report-ciso", action="store_true", help="Generate CISO-quality narrative report")
    parser.add_argument("--tor", action="store_true", help="Route traffic through Tor (requires Tor running)")
    parser.add_argument("--shodan", action="store_true", help="Enable Shodan InternetDB enrichment (free, no key)")
    parser.add_argument("--kali", action="store_true", help="Use Docker Kali sandbox for tool execution")
    parser.add_argument("--skill", help="Force attack classification (cve_exploit, brute_force, phishing, dos)")
    parser.add_argument("--no-guardrail", action="store_true", help="Skip target guardrails (for lab/CTF use)")
    parser.add_argument("--auth-url", help="Login page URL for authenticated scanning")
    parser.add_argument("--auth-user", help="Username for authenticated scanning")
    parser.add_argument("--auth-pass", help="Password for authenticated scanning")
    parser.add_argument("--auth-token", help="Bearer token for authenticated scanning")
    parser.add_argument("--export", help="Export project data to ZIP file")
    parser.add_argument("--import-zip", dest="import_zip", help="Import project data from ZIP file")
    parser.add_argument("--project", default="default", help="Project ID for multi-project support")
    parser.add_argument("--targets", help="File with target URLs (one per line) for parallel hunting")
    parser.add_argument("--max-concurrent", type=int, default=3, help="Max concurrent targets for --targets mode (default: 3)")
    parser.add_argument("--preflight-only", action="store_true", help="Run preflight checks and exit")
    parser.add_argument("--skip-preflight", action="store_true", help="Skip preflight checks")
    parser.add_argument("--proxy", type=str, default=None, help="HTTP proxy (e.g., http://127.0.0.1:8081 for Burp Suite)")
    # Training mode
    parser.add_argument("--train", action="store_true", help="Run training mode against local vuln server")
    parser.add_argument("--train-iterations", type=int, default=3, help="Training iterations (default: 3)")
    parser.add_argument("--train-minutes", type=int, default=8, help="Minutes per training iteration (default: 8)")
    parser.add_argument("--train-port", type=int, default=9999, help="Port for training vuln server (default: 9999)")
    args = parser.parse_args()

    # ── Preflight checks ──
    if not args.skip_preflight:
        from core.preflight import run_preflight
        ok, report = run_preflight()
        report.print_report()
        if args.preflight_only:
            sys.exit(0 if ok else 1)
        if not ok:
            print("❌ Critical preflight failures. Use --skip-preflight to bypass.")
            sys.exit(1)

    if args.dashboard_only:
        from dashboard.server import main as dashboard_main
        dashboard_main()
        return

    if args.dashboard:
        from dashboard.server import start_dashboard
        start_dashboard(port=args.dashboard_port)
        print(f"Dashboard: http://localhost:{args.dashboard_port}")

    if args.setup:
        import install
        install.main()
        return

    # VIPER 4.0: Standalone commands
    if args.export:
        from core.graph_engine import GraphEngine
        from core.report_exporter import ReportExporter
        g = GraphEngine(project_id=args.project)
        exporter = ReportExporter(graph_engine=g)
        path = exporter.export_zip(args.export)
        print(f"Exported to {path}")
        g.close()
        return

    if args.import_zip:
        from core.graph_engine import GraphEngine
        from core.report_exporter import ReportExporter
        g = GraphEngine(project_id=args.project)
        exporter = ReportExporter(graph_engine=g)
        stats = exporter.import_zip(args.import_zip)
        print(f"Imported: {stats}")
        g.close()
        return

    # Training mode (no target needed)
    if args.train:
        from core.training_mode import TrainingMode
        trainer = TrainingMode()
        report = asyncio.run(trainer.train(
            target_name="local_vuln_server",
            iterations=args.train_iterations,
            minutes_per_run=args.train_minutes,
            port=args.train_port,
        ))
        if args.output:
            with open(args.output, "w") as fh:
                json.dump(report.to_dict(), fh, indent=2, default=str)
            print(f"\nTraining results saved to {args.output}")
        return

    # Triage-only mode (no target needed)
    if args.triage and not args.target:
        from core.graph_engine import GraphEngine
        from core.triage_engine import TriageEngine
        g = GraphEngine(project_id=args.project)
        te = TriageEngine(g)
        remediations = te.triage_sync()
        print(f"\nTriage Results: {len(remediations)} remediation items")
        for r in remediations:
            sev = r.severity.upper() if hasattr(r, 'severity') else r.get('severity', '?').upper()
            title = r.title if hasattr(r, 'title') else r.get('title', '?')
            print(f"  [{sev}] {title}")
        g.close()
        return

    # ── Parallel multi-target mode ──
    if args.targets:
        from core.parallel_hunter import ParallelHunter
        targets = ParallelHunter.load_targets_file(args.targets)
        if not targets:
            print(f"No targets found in {args.targets}")
            return
        minutes = args.time or (15 if args.full else 5)
        hunter = ParallelHunter(max_concurrent=args.max_concurrent)
        print(f"VIPER 5.0 | Parallel Hunt: {len(targets)} targets | "
              f"Max concurrent: {args.max_concurrent} | "
              f"Mode: {'full' if args.full else 'quick'} | Time: {minutes}min/target")
        print("-" * 60)
        results = asyncio.run(hunter.hunt_all(
            targets, minutes_per_target=minutes,
            scope_file=args.scope, full=args.full,
            stealth=args.stealth,
        ))
        summary = hunter.get_summary()
        print(f"\n{'='*60}")
        print(f"Parallel Hunt Complete")
        print(f"  Targets: {summary['completed']} completed, {summary['failed']} failed")
        print(f"  Total findings: {summary['total_findings']}")
        sev = summary['severity_counts']
        print(f"  Severity: {sev['critical']}C / {sev['high']}H / {sev['medium']}M / {sev['low']}L")
        print(f"  Elapsed: {summary['elapsed_minutes']:.1f} min")
        for target_url, res in results.items():
            status = res.get('status', '?')
            fc = res.get('findings_count', 0)
            elapsed = res.get('elapsed_seconds', 0)
            err = f" — {res['error']}" if res.get('error') else ""
            print(f"    [{status}] {target_url}: {fc} findings ({elapsed:.0f}s){err}")
        if args.output:
            with open(args.output, "w") as fh:
                json.dump(results, fh, indent=2, default=str)
            print(f"\nResults saved to {args.output}")
        return

    if not args.target:
        parser.print_help()
        return

    minutes = args.time or (30 if args.full else 5)

    # Load scope from RoE document or scope JSON
    scope = None
    if args.roe:
        from scope.roe_parser import RoEParser
        parser_roe = RoEParser(verbose=True)
        scope, rules = parser_roe.parse_file(args.roe)
        print(f"Loaded RoE: {len(scope.in_scope)} in-scope, {len(scope.out_of_scope)} out-of-scope assets")
    elif args.scope:
        from scope.scope_manager import BugBountyScope
        scope = BugBountyScope.from_dict(json.loads(open(args.scope).read()))

    asyncio.run(run_hunt(args.target, args.full, minutes, scope, args.output,
                         secrets=args.secrets, waves=args.waves, report_html=args.report_html,
                         stealth=args.stealth, gvm=args.gvm,
                         bruteforce=args.bruteforce, metasploit=args.metasploit,
                         codefix=args.codefix, post_exploit=getattr(args, 'post_exploit', False),
                         graph=args.graph,
                         interactive=args.interactive, deep_think=args.deep_think,
                         triage=args.triage, codefix_repo=args.codefix_repo,
                         report_ciso=args.report_ciso, tor=args.tor,
                         shodan=args.shodan, kali=args.kali, skill=args.skill,
                         no_guardrail=args.no_guardrail, project=args.project,
                         auth_url=args.auth_url, auth_user=args.auth_user,
                         auth_pass=args.auth_pass, auth_token=args.auth_token,
                         proxy=args.proxy))


async def run_hunt(target, full, minutes, scope, output_file, secrets=False, waves=1,
                   report_html=False, stealth=0, gvm=False,
                   bruteforce=False, metasploit=False, codefix=False,
                   post_exploit=False, graph=False,
                   # VIPER 4.0 params
                   interactive=False, deep_think=False, triage=False,
                   codefix_repo=None, report_ciso=False, tor=False,
                   shodan=False, kali=False, skill=None, no_guardrail=False,
                   project="default",
                   # VIPER 5.0 auth params
                   auth_url=None, auth_user=None, auth_pass=None, auth_token=None,
                   proxy=None):
    # ── VIPER 4.0: Initialize new engines ──
    from core.graph_engine import GraphEngine
    from core.chain_writer import ChainWriter
    graph_engine = GraphEngine(project_id=project)
    chain_writer = ChainWriter(graph_engine)

    # Guardrail check (unless --no-guardrail)
    if not no_guardrail:
        try:
            from core.guardrail_hard import is_blocked
            blocked, reason = is_blocked(target)
            if blocked:
                print(f"\n[GUARDRAIL] Target blocked: {reason}")
                print("Use --no-guardrail for lab/CTF targets")
                graph_engine.close()
                return
        except ImportError:
            pass

    # Tor proxy
    tor_ctx = None
    if tor:
        try:
            from recon.anonymity import TorProxy
            tor_ctx = TorProxy()
            tor_ctx.__enter__()
            print(f"[TOR] Routing through Tor (exit IP: {tor_ctx.get_exit_ip()})")
        except Exception as e:
            print(f"[TOR] Failed: {e}")

    # Wave Runner mode: parallel multi-strategy hunting
    if waves > 1:
        from core.wave_runner import WaveRunner
        runner = WaveRunner(num_waves=waves, max_minutes_per_wave=minutes)
        print(f"VIPER 4.0 | Target: {target} | Mode: WAVE RUNNER ({waves} waves) | Time: {minutes}min/wave")
        print("-" * 60)
        wave_result = await runner.run(target, scope=scope, full=full)
        result = wave_result.to_dict()

        # Generate HTML report for wave results if requested
        if report_html or full:
            try:
                from core.html_reporter import generate_report, save_report
                html = await generate_report(result["findings"], target, {"elapsed_seconds": wave_result.elapsed_seconds, "phases": {}})
                path = save_report(html)
                result["html_report_file"] = str(path)
                print(f"HTML report: {path}")
            except Exception as e:
                print(f"HTML report failed: {e}")
    else:
        from viper_core import ViperCore

        viper = ViperCore()

        # Set proxy (e.g., Burp Suite at 127.0.0.1:8081)
        if proxy:
            if hasattr(viper, 'http_client') and viper.http_client:
                viper.http_client.proxy = proxy
            viper.log(f"[Proxy] Routing traffic through {proxy}")

        # Disable secret scanner unless --secrets flag is set
        if not secrets:
            viper.secret_scanner = None

        # Set stealth level if specified
        if stealth > 0:
            viper.set_stealth_level(stealth)

        # Disable GVM scanner unless --gvm flag is set
        if not gvm:
            viper.gvm_scanner = None

        # Disable brute_forcer unless --bruteforce
        if not bruteforce and hasattr(viper, 'brute_forcer'):
            viper.brute_forcer = None

        # Disable metasploit unless --metasploit
        if not metasploit and hasattr(viper, 'metasploit'):
            viper.metasploit = None

        # ── Authenticated scanning ──
        if auth_token and viper.auth_scanner:
            await viper.auth_scanner.login_bearer(auth_token)
            print(f"[AUTH] Bearer token set for authenticated scanning")
        elif auth_url and auth_user and auth_pass and viper.auth_scanner:
            ok = await viper.auth_scanner.login_form(auth_url, auth_user, auth_pass)
            if ok:
                print(f"[AUTH] Logged in via {auth_url} ({len(viper.auth_scanner.cookies)} cookies)")
            else:
                print(f"[AUTH] Login failed at {auth_url} — proceeding without auth")

        # ── FLAG 5: --kali → Kali sandbox ──
        if kali:
            import shutil
            if shutil.which("docker"):
                print("[KALI] Docker detected — Kali sandbox enabled")
                viper.kali_sandbox = True
            else:
                print("[KALI] WARNING: Docker not found — continuing without Kali sandbox")
                viper.kali_sandbox = False
        else:
            viper.kali_sandbox = False

        # ── FLAG 4: --shodan → Shodan enrichment ──
        if shodan:
            try:
                shodan_key = os.environ.get("SHODAN_API_KEY", "")
                if shodan_key:
                    import importlib
                    shodan_mod = importlib.import_module("shodan")
                    api = shodan_mod.Shodan(shodan_key)
                    from urllib.parse import urlparse
                    host = urlparse(target).hostname or target
                    info = api.host(host)
                    ports = info.get("ports", [])
                    vulns = info.get("vulns", [])
                    print(f"[SHODAN] Host: {host} | Ports: {ports} | Vulns: {vulns}")
                else:
                    # Use free InternetDB (no key needed)
                    from urllib.parse import urlparse
                    import socket
                    host = urlparse(target).hostname or target
                    try:
                        ip = socket.gethostbyname(host)
                        import aiohttp as _aio
                        async with _aio.ClientSession() as _s:
                            async with _s.get(f"https://internetdb.shodan.io/{ip}") as resp:
                                if resp.status == 200:
                                    data = await resp.json()
                                    print(f"[SHODAN/InternetDB] IP: {ip} | Ports: {data.get('ports', [])} | Vulns: {data.get('vulns', [])}")
                                else:
                                    print(f"[SHODAN/InternetDB] No data for {ip}")
                    except Exception as e:
                        print(f"[SHODAN] InternetDB lookup failed: {e}")
            except Exception as e:
                print(f"[SHODAN] Enrichment failed: {e}")

        # ── FLAG 3: --skill → SkillClassifier ──
        skill_classification = None
        if skill:
            try:
                from core.skill_classifier import SkillClassifier
                sc = SkillClassifier()
                skill_classification = asyncio.get_event_loop().run_until_complete(
                    sc.classify(skill)
                )
                print(f"[SKILL] Classified: {skill_classification.attack_path_type} "
                      f"(phase={skill_classification.required_phase}, "
                      f"confidence={skill_classification.confidence:.0%})")
            except Exception as e:
                print(f"[SKILL] Classification failed: {e}")

        # ── FLAG 2: --deep-think → ThinkEngine ──
        deep_think_result = None
        if deep_think:
            try:
                from core.think_engine import ThinkEngine
                te = ThinkEngine()
                context = {
                    "target": target,
                    "current_phase": "recon",
                    "iteration": 0,
                    "max_iterations": 50,
                    "attack_path_type": skill_classification.attack_path_type if skill_classification else "cve_exploit",
                    "trace": [],
                    "todo": [],
                }
                deep_think_result = await te.think(context)
                decision = deep_think_result.get("_decision", {})
                print(f"[DEEP-THINK] {decision.get('thought', 'Strategic analysis complete')}")
            except Exception as e:
                print(f"[DEEP-THINK] Analysis failed: {e}")

        # ── FLAG 1: --interactive → ApprovalGate ──
        if interactive:
            try:
                from core.approval_gate import ApprovalGate
                gate = ApprovalGate(auto_approve=False)
                decision, modification = gate.check_phase_transition(
                    'recon', 'exploit', interactive=True
                )
                if decision == 'abort':
                    print("[INTERACTIVE] User aborted — skipping hunt for this target")
                    chain_writer.shutdown()
                    graph_engine.close()
                    if tor_ctx:
                        try:
                            tor_ctx.__exit__(None, None, None)
                        except Exception:
                            pass
                    return
                elif decision == 'modify':
                    print(f"[INTERACTIVE] User modified phase transition: {modification}")
            except Exception as e:
                print(f"[INTERACTIVE] Approval gate failed: {e}")

        react_status = "ReACT+LLM" if viper._react_engine else "Q-learning"
        extras = []
        if stealth > 0:
            extras.append(f"Stealth:{stealth}")
        if gvm:
            extras.append("GVM")
        if secrets:
            extras.append("Secrets")
        if bruteforce:
            extras.append("BruteForce")
        if metasploit:
            extras.append("Metasploit")
        if codefix:
            extras.append("CodeFix")
        if post_exploit:
            extras.append("PostExploit")
        if graph:
            extras.append("Graph")
        if interactive:
            extras.append("Interactive")
        if deep_think:
            extras.append("DeepThink")
        if tor:
            extras.append("Tor")
        if shodan:
            extras.append("Shodan")
        if kali:
            extras.append("Kali")
        if skill:
            extras.append(f"Skill:{skill}")
        if triage:
            extras.append("Triage")
        if report_ciso:
            extras.append("CISO-Report")
        extra_str = f" | {', '.join(extras)}" if extras else ""

        print(f"VIPER 4.0 | Target: {target} | Mode: {'full' if full else 'quick'} | Time: {minutes}min | Engine: {react_status}{extra_str}")
        print("-" * 60)

        if full:
            result = await viper.full_hunt(target_url=target, scope=scope, max_minutes=minutes)
        else:
            import aiohttp
            async with aiohttp.ClientSession() as viper.session:
                result = await viper.hunt(target, max_minutes=minutes,
                                          enable_bruteforce=bruteforce,
                                          enable_metasploit=metasploit,
                                          enable_codefix=codefix,
                                          enable_post_exploit=post_exploit,
                                          enable_graph=graph)

        # Standalone HTML report if --report-html but not --full (full_hunt already generates one)
        if report_html and not full and result:
            try:
                from core.html_reporter import generate_report, save_report
                html = await generate_report(result.get("findings", []), target, result)
                path = save_report(html)
                result["html_report_file"] = str(path)
                print(f"HTML report: {path}")
            except Exception as e:
                print(f"HTML report failed: {e}")

    if result:
        findings = result.get("findings", [])
        print(f"\nFindings: {len(findings)}")
        for f in findings:
            sev = f.get("severity", "?").upper()
            vtype = f.get("vuln_type", f.get("attack", "?"))
            conf = f.get("confidence", 0)
            url = f.get("url", "")[:70]
            print(f"  [{sev}] {vtype} ({conf:.0%}) -- {url}")

        if output_file:
            with open(output_file, "w") as fh:
                json.dump(result, fh, indent=2, default=str)
            print(f"\nResults saved to {output_file}")
    else:
        print("No results.")

    # ── VIPER 4.0: Post-hunt features ──

    # Populate graph from results
    if result:
        try:
            graph_engine.populate_from_findings(target, result.get("findings", []))
            graph_engine.save()
        except Exception as e:
            print(f"[Graph] Save failed: {e}")

    # Triage
    if triage and result:
        try:
            from core.triage_engine import TriageEngine
            te = TriageEngine(graph_engine)
            remediations = te.triage_sync()
            print(f"\nTriage: {len(remediations)} remediation items")
            for r in remediations[:10]:
                sev = r.severity.upper() if hasattr(r, 'severity') else r.get('severity', '?').upper()
                title = r.title if hasattr(r, 'title') else r.get('title', '?')
                print(f"  [{sev}] {title}")
        except Exception as e:
            print(f"[Triage] Failed: {e}")

    # CodeFix
    if codefix_repo and result:
        try:
            from core.codefix_engine import CodeFixEngine
            cfe = CodeFixEngine()
            fixes = asyncio.get_event_loop().run_until_complete(
                cfe.fix_findings(result.get("findings", []), codefix_repo)
            )
            print(f"\nCodeFix: {len(fixes)} fixes generated")
            for fix in fixes:
                print(f"  {fix.get('status', '?')}: {fix.get('finding_id', '?')}")
        except Exception as e:
            print(f"[CodeFix] Failed: {e}")

    # CISO Report
    if report_ciso and result:
        try:
            from core.report_narrative import ReportNarrative
            from core.report_exporter import ReportExporter
            rn = ReportNarrative(graph_engine=graph_engine)
            narratives = rn.generate_sync(result)
            exporter = ReportExporter(graph_engine=graph_engine)
            report_path = exporter.generate_html_report(narratives, result)
            print(f"\nCISO Report: {report_path}")
        except Exception as e:
            print(f"[CISO Report] Failed: {e}")

    # Cleanup
    if tor_ctx:
        try:
            tor_ctx.__exit__(None, None, None)
        except Exception:
            pass

    chain_writer.shutdown()
    graph_engine.close()


if __name__ == "__main__":
    main()
