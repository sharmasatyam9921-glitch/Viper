"""
VIPER Hunt Phases — standalone async functions extracted from ViperCore.full_hunt.

Each function takes explicit parameters (no `self`), returns a dict of results,
and can be called from the thin ViperCore.full_hunt orchestrator.
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Type aliases for callables passed in from ViperCore
# ---------------------------------------------------------------------------
LogFn = Callable[..., None]  # log_fn(msg, level="INFO")


# =========================================================================
# Phase 1.5: Recon Pipeline
# =========================================================================

async def phase_pipeline(
    target: Any,
    recon_budget_seconds: float,
    graph_engine: Any,
    session: Any,
    settings: dict,
    log_fn: LogFn,
    *,
    pipeline_cls: type | None = None,
) -> dict:
    """Run the recon pipeline (domain discovery, passive intel, ports, HTTP).

    Args:
        target: Target dataclass instance.
        recon_budget_seconds: Max seconds for the pipeline.
        graph_engine: GraphEngine instance (or None).
        session: aiohttp.ClientSession.
        settings: VIPER settings dict.
        log_fn: Logging callable.
        pipeline_cls: ReconPipeline class (passed to avoid import at module level).

    Returns:
        Dict with ``pipeline`` key containing pipeline results, plus any
        technologies / subdomains merged into *target* in-place.
    """
    if pipeline_cls is None:
        return {}

    log_fn("\n=== Phase 1.5: Recon Pipeline ===")
    result: dict = {}
    try:
        pipeline = pipeline_cls(
            graph_engine=graph_engine,
            session=session,
            settings=settings,
        )
        budget = min(recon_budget_seconds * 0.5, 300)  # max 5 min
        recon_results = await asyncio.wait_for(
            pipeline.run(target, timeout_minutes=budget / 60),
            timeout=budget,
        )
        if recon_results.endpoints:
            log_fn(f"[Pipeline] Discovered {len(recon_results.endpoints)} endpoints")
        if recon_results.technologies:
            _pipeline_techs: Set[str] = set()
            for url_techs in recon_results.technologies.values():
                for t in url_techs:
                    if isinstance(t, dict) and t.get("name"):
                        _pipeline_techs.add(t["name"])
                    elif isinstance(t, str) and t:
                        _pipeline_techs.add(t)
            if _pipeline_techs:
                target.technologies.update(_pipeline_techs)
            log_fn(
                f"[Pipeline] Fingerprinted {len(_pipeline_techs)} technologies: "
                f"{', '.join(sorted(_pipeline_techs)[:5])}"
            )
        if recon_results.subdomains:
            target.subdomains = (
                target.subdomains | recon_results.subdomains
                if hasattr(target, "subdomains") and target.subdomains
                else recon_results.subdomains
            )
        result["pipeline"] = recon_results.to_dict()
    except asyncio.TimeoutError:
        log_fn("[Pipeline] Timed out, falling back to standard recon", "WARN")
    except Exception as e:
        log_fn(f"[Pipeline] Error: {e}", "WARN")
    return result


# =========================================================================
# Phase 2: Reconnaissance
# =========================================================================

async def phase_recon(
    target_url: str,
    domain: str,
    target: Any,
    recon_engine: Any,
    graph_engine: Any,
    wappalyzer: Any,
    recon_budget_minutes: float,
    log_fn: LogFn,
) -> dict:
    """Run subdomain enumeration, port scanning, tech fingerprinting.

    Mutates *target* in-place (subdomains, open_ports, technologies).

    Returns:
        Dict with ``recon`` key containing recon results dict.
    """
    if recon_engine is None:
        return {}

    log_fn("\n=== Phase 2: Reconnaissance ===")
    result: dict = {}
    try:
        recon_result = await asyncio.wait_for(
            recon_engine.full_recon(
                domain,
                subdomain_enum=True,
                port_scan=True,
                tech_fingerprint=True,
                dns_enum=True,
            ),
            timeout=recon_budget_minutes * 60,
        )
        # Merge subdomains (don't overwrite pipeline results)
        target.subdomains = (target.subdomains or set()) | recon_result.subdomains
        target.open_ports = recon_result.open_ports
        target.technologies.update(
            tech
            for url_tech in recon_result.technologies.values()
            for tech in url_tech.get("technologies", [])
        )
        # Merge wappalyzer_techs (List[Dict] with "name" key)
        if hasattr(recon_result, "wappalyzer_techs") and recon_result.wappalyzer_techs:
            names: Set[str] = set()
            for t in recon_result.wappalyzer_techs:
                if isinstance(t, dict) and t.get("name"):
                    names.add(t["name"])
                elif isinstance(t, str) and t:
                    names.add(t)
            if names:
                target.technologies.update(names)
                log_fn(
                    f"  [Wappalyzer] Merged {len(names)} techs: "
                    f"{', '.join(sorted(names)[:5])}",
                    "INFO",
                )
        result["recon"] = recon_result.to_dict()

        # Wappalyzer additional tech detection on recon body/header data
        if wappalyzer:
            try:
                for url_key, tech_data in recon_result.technologies.items():
                    body_content = tech_data.get("body", "")
                    hdrs = tech_data.get("headers", {})
                    if body_content or hdrs:
                        wap_techs = wappalyzer.analyze(body_content, hdrs)
                        if wap_techs:
                            target.technologies.update(wap_techs)
                            log_fn(f"  [Wappalyzer] Detected on {url_key}: {wap_techs}")
            except Exception:
                pass

        # Populate knowledge graph from recon
        if graph_engine and recon_result:
            try:
                recon_dict = {
                    "subdomains": list(recon_result.subdomains),
                    "ports": [
                        {"ip": host, "port": port}
                        for host, ports in recon_result.open_ports.items()
                        for port in ports
                    ],
                    "technologies": list(recon_result.technologies.keys()),
                    "urls": list(recon_result.live_hosts),
                }
                graph_engine.populate_from_recon(domain, recon_dict)
            except Exception as e:
                log_fn(f"[GraphEngine] Recon population failed: {e}", "WARN")
    except asyncio.TimeoutError:
        log_fn(f"Recon timed out after {recon_budget_minutes:.1f} min", "WARN")
    except Exception as e:
        log_fn(f"Recon error: {e}", "ERROR")
    return result


# =========================================================================
# Phase 2.5: Secret Scanning
# =========================================================================

async def phase_secrets(
    target_url: str,
    domain: str,
    secret_scanner: Any,
    session: Any,
    log_fn: LogFn,
) -> dict:
    """Scan for leaked secrets (GitHub, JS files, etc.).

    Returns:
        Dict with ``secrets`` phase info and ``findings`` list of dicts.
    """
    if secret_scanner is None:
        return {}

    log_fn("\n=== Phase 2.5: Secret Scanning ===")
    result: dict = {"findings": [], "phase": {}}
    try:
        secret_findings = await asyncio.wait_for(
            secret_scanner.scan_target(domain, session=session),
            timeout=120,
        )
        result["findings"] = [sf.to_dict() for sf in secret_findings]
        result["phase"] = {
            "findings_count": len(secret_findings),
            "summary": secret_scanner.summary(),
        }
    except asyncio.TimeoutError:
        log_fn("Secret scanning timed out", "WARN")
    except Exception as e:
        log_fn(f"Secret scanning error: {e}", "ERROR")
    return result


# =========================================================================
# Phase 3: Surface Mapping
# =========================================================================

async def phase_surface(
    target_url: str,
    domain: str,
    target: Any,
    surface_mapper: Any,
    db: Any,
    surface_budget_minutes: float,
    session_start_iso: str,
    log_fn: LogFn,
) -> dict:
    """Map attack surface: parameters, API endpoints, JS analysis.

    Mutates *target* in-place (parameters, js_endpoints, api_endpoints, endpoints).

    Returns:
        Dict with ``surface`` phase info and ``findings`` list of JS secret dicts.
    """
    if surface_mapper is None:
        return {}

    log_fn("\n=== Phase 3: Surface Mapping ===")
    result: dict = {"findings": [], "phase": {}}
    try:
        surface_result = await asyncio.wait_for(
            surface_mapper.map_surface(target_url, crawl_depth=2, max_pages=30),
            timeout=surface_budget_minutes * 60,
        )
        target.parameters.update(
            p for params in surface_result.url_parameters.values() for p in params
        )
        target.js_endpoints = surface_result.js_endpoints
        target.api_endpoints = surface_result.api_endpoints
        target.endpoints.update(surface_result.api_endpoints)
        # Preserve URL→parameter mapping for targeted fuzzing
        for url, params in surface_result.url_parameters.items():
            clean = url.split("?")[0].rstrip("/")
            if clean:
                target.endpoints.add(clean)
                target.url_parameters[clean] = list(params)
        result["phase"] = surface_result.to_dict()

        # Deduplicate JS secrets
        seen_secrets: Set[tuple] = set()
        for secret in surface_result.js_secrets:
            src_url = secret.get("source", "")
            pattern = secret.get("pattern", "")
            key = (src_url, pattern)
            if key in seen_secrets:
                continue
            seen_secrets.add(key)
            finding_dict = {
                "type": "js_secret",
                "vuln_type": "js_secret",
                "severity": "high",
                "confidence": 0.75,
                "url": src_url,
                "details": secret,
            }
            result["findings"].append(finding_dict)
            if db:
                try:
                    tid = db.add_target(target_url, domain)
                    dup, _ = db.is_duplicate(
                        tid, "js_secret", src_url,
                        secret.get("value", ""),
                        session_start=session_start_iso,
                    )
                    if not dup:
                        db.add_finding(
                            target_id=tid,
                            vuln_type="js_secret",
                            severity="high",
                            title=f"Potential secret in JS: {secret.get('pattern', 'unknown')[:50]}",
                            url=src_url,
                            payload=secret.get("value", "")[:200],
                            evidence=json.dumps(secret),
                            confidence=0.75,
                            validated=False,
                        )
                except Exception as e:
                    log_fn(f"Failed to save JS secret to DB: {e}", "WARN")
    except asyncio.TimeoutError:
        log_fn(f"Surface mapping timed out after {surface_budget_minutes:.1f} min", "WARN")
    except Exception as e:
        log_fn(f"Surface mapping error: {e}", "ERROR")
    return result


# =========================================================================
# Phase 4: Nuclei Scanning
# =========================================================================

async def phase_nuclei(
    target_url: str,
    domain: str,
    target: Any,
    nuclei_scanner: Any,
    db: Any,
    mitre_enricher: Any,
    metrics: dict,
    nuclei_budget_minutes: float,
    log_fn: LogFn,
) -> dict:
    """Run Nuclei vulnerability scanner.

    Mutates *target* in-place (nuclei_findings, vulns_found).

    Returns:
        Dict with ``nuclei`` phase info, ``nuclei_findings`` list, and
        ``findings`` list of enriched finding dicts.
    """
    if nuclei_scanner is None or not nuclei_scanner.nuclei_path:
        return {}

    log_fn("\n=== Phase 4: Nuclei Scanning ===")
    result: dict = {"findings": [], "nuclei_findings": [], "phase": {}}
    try:
        nuclei_result = await asyncio.wait_for(
            nuclei_scanner.quick_scan(target_url),
            timeout=nuclei_budget_minutes * 60,
        )
        target.nuclei_findings = [f.to_dict() for f in nuclei_result.findings]
        result["nuclei_findings"] = target.nuclei_findings
        result["phase"] = nuclei_result.to_dict()

        for nf in nuclei_result.findings:
            vuln_type = nuclei_scanner._categorize_finding(nf)
            nuclei_finding = {
                "type": vuln_type,
                "attack": vuln_type,
                "vuln_type": vuln_type,
                "severity": nf.severity.lower(),
                "url": nf.matched_at,
                "payload": nf.template_id,
                "details": f"Nuclei: {nf.template_name} ({nf.template_id})",
                "source": "nuclei",
                "validated": True,
                "confidence": 0.85,
                "template_id": nf.template_id,
            }
            result["findings"].append(nuclei_finding)
            target.vulns_found.append(nuclei_finding)
            metrics["total_findings"] = metrics.get("total_findings", 0) + 1

            if db:
                try:
                    tid = db.add_target(target_url, domain)
                    db.add_finding(
                        target_id=tid,
                        vuln_type=vuln_type,
                        severity=nf.severity.lower(),
                        title=f"Nuclei: {nf.template_name}",
                        url=nf.matched_at,
                        payload=nf.template_id,
                        evidence=nf.curl_command or "",
                        confidence=0.85,
                        validated=True,
                    )
                except Exception:
                    pass

        log_fn(f"  Nuclei: {len(nuclei_result.findings)} findings wired to main list")

        # MITRE enrichment for nuclei findings
        if mitre_enricher and nuclei_result.findings:
            for finding in result["findings"]:
                if finding.get("source") == "nuclei":
                    cves = finding.get("cves", [])
                    for cve_id in cves:
                        enrichment = mitre_enricher.enrich_cve(cve_id)
                        if enrichment and enrichment.get("cwes"):
                            finding["mitre_enrichment"] = enrichment
    except asyncio.TimeoutError:
        log_fn(f"Nuclei timed out after {nuclei_budget_minutes:.1f} min", "WARN")
    except Exception as e:
        log_fn(f"Nuclei scan error: {e}", "ERROR")
    return result


# =========================================================================
# Phase 4b: GVM/OpenVAS Network Scan
# =========================================================================

async def phase_gvm(
    target_url: str,
    domain: str,
    target: Any,
    gvm_scanner: Any,
    db: Any,
    metrics: dict,
    end_time: datetime,
    log_fn: LogFn,
) -> dict:
    """Run GVM/OpenVAS network scan (optional).

    Mutates *target* in-place (vulns_found).

    Returns:
        Dict with ``gvm`` phase info and ``findings`` list.
    """
    if gvm_scanner is None:
        return {}

    log_fn("\n=== Phase 4b: GVM/OpenVAS Network Scan ===")
    result: dict = {"findings": [], "phase": {}}
    try:
        if await gvm_scanner.is_available():
            gvm_budget = min(
                30, max(5, (end_time - datetime.now()).total_seconds() / 60 * 0.3)
            )
            gvm_result = await asyncio.wait_for(
                gvm_scanner.quick_network_scan(domain),
                timeout=gvm_budget * 60,
            )
            result["phase"] = gvm_result.to_dict()
            for gf in gvm_result.findings:
                if gf.severity >= 4.0:  # medium+
                    vf = gf.to_viper_finding()
                    result["findings"].append(vf)
                    target.vulns_found.append(vf)
                    metrics["total_findings"] = metrics.get("total_findings", 0) + 1
                    if db:
                        try:
                            tid = db.add_target(target_url, domain)
                            db.add_finding(
                                target_id=tid,
                                vuln_type=vf["vuln_type"],
                                severity=vf["severity"],
                                title=f"OpenVAS: {gf.name}",
                                url=f"{gf.host}:{gf.port}",
                                payload=gf.oid,
                                evidence=gf.description[:500],
                                confidence=vf["confidence"],
                                validated=True,
                            )
                        except Exception:
                            pass
            log_fn(
                f"  GVM: {len(gvm_result.findings)} findings "
                f"({sum(1 for f in gvm_result.findings if f.severity >= 7.0)} high+)"
            )
        else:
            log_fn("  GVM not available — skipping network scan", "INFO")
    except asyncio.TimeoutError:
        log_fn("GVM scan timed out", "WARN")
    except Exception as e:
        log_fn(f"GVM scan error: {e}", "ERROR")
    return result


# =========================================================================
# Phase 5: Manual Attacks (orchestrator guidance + hunt)
# =========================================================================

async def phase_manual_attacks(
    target_url: str,
    target: Any,
    orchestrator: Any,
    phase_engine: Any,
    hunt_fn: Callable,
    react_engine: Any,
    manual_minutes: float,
    log_fn: LogFn,
) -> dict:
    """Run orchestrator strategic guidance and manual VIPER attacks.

    Args:
        hunt_fn: Bound ``ViperCore.hunt`` method.
        react_engine: ReACTEngine instance for trace extraction.

    Returns:
        Dict with ``manual`` phase results and optional ``react_trace``.
    """
    result: dict = {}

    # Orchestrator strategic guidance
    if orchestrator:
        try:
            tech_list = list(target.technologies) if target.technologies else []
            objective = f"Security test {target_url} (tech: {', '.join(tech_list[:5])})"
            guidance = await orchestrator.invoke(target_url, objective)
            if guidance:
                log_fn(f"  [Orchestrator] Strategic guidance: {str(guidance)[:200]}")
        except Exception as e:
            log_fn(f"  [Orchestrator] Guidance failed: {e}")

    # Advance phase engine to EXPLOIT
    if phase_engine:
        try:
            while phase_engine.current_phase not in ("EXPLOIT", "POST_EXPLOIT"):
                phase_engine.advance_phase(
                    "completing prior phases before manual attacks"
                )
            log_fn(f"  [PhaseEngine] Advanced to {phase_engine.current_phase}")
        except Exception as _pe:
            log_fn(f"  [PhaseEngine] Advance failed: {_pe}", "DEBUG")

    manual_minutes = max(3.0, manual_minutes)
    log_fn(f"\n=== Phase 5: Manual Attacks ({manual_minutes:.1f} min) ===")
    manual_result = await hunt_fn(target_url, max_minutes=int(manual_minutes))
    result["manual"] = manual_result

    # Merge technologies detected during manual hunt
    if manual_result.get("technologies"):
        target.technologies.update(manual_result["technologies"])

    # Extract ReACT reasoning trace
    if react_engine and react_engine.traces:
        latest_trace = react_engine.traces[-1]
        result["react_trace"] = latest_trace.to_dict()
        log_fn(
            f"  ReACT trace: {len(latest_trace.steps)} steps, "
            f"LLM-guided={sum(1 for s in latest_trace.steps if s.llm_used)}"
        )
    return result


# =========================================================================
# Phase 6: LLM Analysis
# =========================================================================

async def phase_llm_analysis(
    target_url: str,
    target: Any,
    findings: List[dict],
    llm_analyzer: Any,
    log_fn: LogFn,
) -> dict:
    """Run LLM-assisted triage and next-attack recommendations.

    Returns:
        Dict with ``llm_recommended_attacks`` if any.
    """
    if llm_analyzer is None or not findings:
        return {}

    log_fn("\n=== Phase 6: LLM Analysis ===")
    result: dict = {}
    try:
        if llm_analyzer.has_direct_api:
            log_fn("  Using direct Claude API for analysis")
            for finding in findings[:5]:
                if finding.get("severity") in ["critical", "high"]:
                    triage = await llm_analyzer.triage_finding_direct(finding)
                    if triage:
                        finding["llm_triage"] = triage
                        log_fn(f"  LLM triage: {triage.get('reasoning', '')[:100]}")
            next_attacks = await llm_analyzer.decide_next_attack(
                {"url": target_url, "technologies": list(target.technologies)},
                list(target.attacks_tried.keys()),
                findings[:10],
            )
            if next_attacks:
                result["llm_recommended_attacks"] = next_attacks
                log_fn(f"  LLM recommends: {next_attacks}")
        else:
            log_fn("  No direct API — queuing for main agent")
            for finding in findings[:5]:
                if finding.get("severity") in ["critical", "high"]:
                    await llm_analyzer.triage_finding(finding, target_url)
            await llm_analyzer.get_next_vectors(
                target_url,
                list(target.technologies),
                findings,
                list(target.attacks_tried.keys()),
            )
    except Exception as e:
        log_fn(f"LLM analysis error: {e}", "ERROR")
    return result


# =========================================================================
# Post-hunt: Compliance enrichment, graph save, reporting
# =========================================================================

async def phase_finalize(
    target_url: str,
    domain: str,
    target: Any,
    results: dict,
    start_time: datetime,
    graph_engine: Any,
    db: Any,
    stealth: Any,
    metrics: dict,
    http_client: Any,
    log_fn: LogFn,
    generate_full_report_fn: Callable,
    save_state_fn: Callable,
    *,
    enrich_compliance_fn: Callable | None = None,
    compliance_available: bool = False,
    html_reporter_available: bool = False,
    generate_html_report_fn: Callable | None = None,
    save_html_report_fn: Callable | None = None,
) -> dict:
    """Post-hunt finalization: compliance enrichment, graph persistence, reports.

    Mutates *results* in-place (adds elapsed_seconds, report files, etc.).

    Returns:
        Dict with ``report_file`` and optional ``html_report_file``.
    """
    out: dict = {}

    # Compliance enrichment
    if compliance_available and enrich_compliance_fn:
        for finding in results.get("findings", []):
            enrich_compliance_fn(finding)

    # Save findings to graph
    if graph_engine:
        try:
            all_findings = results.get("findings", [])
            graph_engine.populate_from_findings(domain, all_findings)
            graph_engine.save()
        except Exception as e:
            log_fn(f"[GraphEngine] Finding save failed: {e}", "WARN")

    # Timing
    elapsed = (datetime.now() - start_time).total_seconds()
    results["elapsed_seconds"] = elapsed
    results["access_level"] = target.access_level

    # Text report
    report_file = generate_full_report_fn(target, results, elapsed)
    results["report_file"] = str(report_file)
    out["report_file"] = str(report_file)

    # HTML report
    if html_reporter_available and generate_html_report_fn and save_html_report_fn:
        try:
            router = None
            try:
                from ai.model_router import ModelRouter

                router = ModelRouter()
                if not router.is_available:
                    router = None
            except Exception:
                pass
            html_content = await generate_html_report_fn(
                findings=results.get("findings", []),
                target=target_url,
                metadata=results,
                model_router=router,
            )
            dom = urllib.parse.urlparse(target_url).netloc.replace(":", "_")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            html_file = save_html_report_fn(
                html_content, f"viper_full_{dom}_{ts}.html"
            )
            results["html_report_file"] = str(html_file)
            out["html_report_file"] = str(html_file)
            log_fn(f"HTML report: {html_file}")
        except Exception as e:
            log_fn(f"HTML report generation failed: {e}", "WARN")

    # Close HTTP client
    if http_client:
        await http_client.close()

    # Summary log
    log_fn("\n=== Hunt Complete ===")
    log_fn(f"Duration: {elapsed:.1f}s")
    log_fn(
        f"Findings: {len(results['findings'])} "
        f"({metrics.get('validated_findings', 0)} validated)"
    )
    log_fn(f"False positives caught: {metrics.get('false_positives_caught', 0)}")
    log_fn(f"Nuclei: {len(results.get('nuclei_findings', []))}")
    if "gvm" in results.get("phases", {}):
        gvm_phase = results["phases"]["gvm"]
        log_fn(f"GVM/OpenVAS: {gvm_phase.get('total_findings', 0)} findings")
    if stealth:
        stats = stealth.get_stats()
        if stats["level_value"] > 0:
            log_fn(
                f"Stealth: {stats['level']} | WAFs: {stats['detected_wafs']} "
                f"| Blocked: {stats['blocked_domains']}"
            )
    log_fn(f"Report: {report_file}")

    if db:
        log_fn(f"DB stats: {db.stats()}")

    save_state_fn()

    return out


# =========================================================================
# Phase 3.5: Custom Nuclei Template Generation
# =========================================================================

async def phase_generate_templates(
    target_url: str,
    target: Any,
    nuclei_scanner: Any,
    log_fn: LogFn,
) -> dict:
    """Generate custom Nuclei templates based on discovered surface.

    Uses NucleiTemplateGenerator to create templates tailored to the
    target's tech stack and discovered parameters. Saves them to disk
    and registers them with the Nuclei scanner for Phase 4.

    Returns:
        Dict with ``phase`` info (template count, directory).
    """
    result: dict = {"phase": {}}

    # Need both tech data and nuclei scanner to be useful
    if nuclei_scanner is None:
        return result

    technologies = list(getattr(target, "technologies", []))
    endpoints = list(getattr(target, "endpoints", set()))
    url_parameters = getattr(target, "url_parameters", {})

    # Skip if no surface data to work with
    if not technologies and not url_parameters:
        log_fn("  Template gen: skipped (no tech/param data from surface mapping)")
        return result

    log_fn("\n=== Phase 3.5: Custom Template Generation ===")
    try:
        from core.template_generator import NucleiTemplateGenerator

        generator = NucleiTemplateGenerator()
        templates = await generator.generate_for_target(
            target_url=target_url,
            technologies=technologies,
            endpoints=endpoints,
            parameters=url_parameters,
        )

        if templates:
            saved_paths = generator.save_templates(templates)
            output_dir = str(generator.output_dir)

            # Register the generated template directory with nuclei scanner
            if hasattr(nuclei_scanner, "_custom_template_dirs"):
                gen_dir = Path(output_dir)
                if gen_dir not in nuclei_scanner._custom_template_dirs:
                    nuclei_scanner._custom_template_dirs.append(gen_dir)
                    # Re-discover templates so they appear in the catalog
                    if hasattr(nuclei_scanner, "_discover_and_log_templates"):
                        nuclei_scanner._discover_and_log_templates()

            result["phase"] = {
                "templates_generated": len(templates),
                "templates_dir": output_dir,
                "saved_files": [str(p) for p in saved_paths],
            }
            log_fn(
                f"  Generated {len(templates)} custom templates → {output_dir}"
            )
        else:
            log_fn("  Template gen: no templates produced")

    except Exception as e:
        log_fn(f"  Template generation error: {e}", "WARN")

    return result


# =========================================================================
# Post-hunt: Chain Escalation
# =========================================================================

async def phase_chain_escalation(
    findings: List[dict],
    log_fn: LogFn,
) -> dict:
    """Analyze findings for chainable vulnerabilities.

    Detects combinations of low/medium-severity findings that constitute
    higher-severity attack paths (e.g., CORS + CSRF = Account Takeover).

    Returns:
        Dict with ``findings`` list (escalated chain findings) and
        ``chains`` list (chain metadata).
    """
    result: dict = {"findings": [], "chains": []}

    if not findings:
        return result

    try:
        from core.chain_escalator import ChainEscalator

        escalator = ChainEscalator()
        chains = escalator.analyze(findings)

        if chains:
            log_fn(f"\n=== Chain Escalation: {len(chains)} chains detected ===")
            for chain in chains:
                log_fn(
                    f"  [{chain.escalated_severity.upper()}] "
                    f"{chain.chain_name}: {chain.escalated_impact[:80]}"
                )
                result["findings"].append(chain.to_finding())
                result["chains"].append(chain.to_dict())
        else:
            log_fn("  Chain escalation: no combinable vulnerabilities found")

    except Exception as e:
        log_fn(f"  Chain escalation error: {e}", "WARN")

    return result
