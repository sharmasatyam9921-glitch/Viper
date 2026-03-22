#!/usr/bin/env python3
"""
VIPER 4.0 Phase 6 — Report Exporter (ZIP backup/restore + HTML report).

Generates self-contained, professional HTML pentest reports with:
- Cover page, table of contents, 6 narrative sections
- Findings table with severity badges and CVSS chart (inline SVG)
- MITRE ATT&CK mapping table, attack chain visualization
- Technology inventory, appendix
- Dark/light theme, print-ready CSS

Also handles full project backup/restore as ZIP archives.

Stdlib only. No external dependencies.
"""

import html as html_mod
import json
import logging
import os
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.report_exporter")

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# ══════════════════════════════════════════════════════════════════════
# SEVERITY HELPERS
# ══════════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#3498db",
    "info": "#95a5a6",
}


class ReportExporter:
    """Export VIPER projects as ZIP and generate professional HTML reports."""

    def __init__(self, graph_engine=None):
        """
        Args:
            graph_engine: Optional GraphEngine for extracting graph data
                          during ZIP export.
        """
        self.graph_engine = graph_engine

    # ==================================================================
    # ZIP EXPORT / IMPORT
    # ==================================================================

    def export_zip(self, output_path: str, include_reports: bool = True) -> str:
        """
        Export full project as ZIP.

        Contents:
        - graph_data.json (all nodes + edges)
        - findings.json (all findings)
        - settings.json (project settings)
        - reports/ (HTML reports if any)
        - attack_chains.json
        - scan_metadata.json

        Returns path to created ZIP.
        """
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(str(output), "w", zipfile.ZIP_DEFLATED) as zf:
            # Graph data
            if self.graph_engine is not None:
                graph_data = self._extract_graph_data()
                zf.writestr(
                    "graph_data.json",
                    json.dumps(graph_data, indent=2, default=str),
                )

                # Findings
                findings = self._extract_findings()
                zf.writestr(
                    "findings.json",
                    json.dumps(findings, indent=2, default=str),
                )

                # Attack chains
                chains = self._extract_attack_chains()
                zf.writestr(
                    "attack_chains.json",
                    json.dumps(chains, indent=2, default=str),
                )

            # Scan metadata
            metadata = {
                "export_date": datetime.now().isoformat(),
                "viper_version": "4.0",
                "export_type": "full_project",
            }
            zf.writestr(
                "scan_metadata.json",
                json.dumps(metadata, indent=2),
            )

            # Settings (if a settings file exists)
            settings_path = Path(__file__).parent.parent / "settings.json"
            if settings_path.exists():
                zf.write(str(settings_path), "settings.json")

            # Include existing HTML reports
            if include_reports and REPORTS_DIR.exists():
                for report_file in REPORTS_DIR.glob("*.html"):
                    zf.write(
                        str(report_file),
                        f"reports/{report_file.name}",
                    )

        logger.info(f"Project exported to {output}")
        return str(output)

    def import_zip(self, zip_path: str) -> dict:
        """
        Import project from ZIP, restore graph + findings.

        Returns {nodes_imported, edges_imported, findings_imported}.
        """
        stats = {"nodes_imported": 0, "edges_imported": 0, "findings_imported": 0}

        zpath = Path(zip_path)
        if not zpath.exists():
            raise FileNotFoundError(f"ZIP not found: {zip_path}")

        with zipfile.ZipFile(str(zpath), "r") as zf:
            names = zf.namelist()

            # Restore graph data
            if "graph_data.json" in names and self.graph_engine is not None:
                raw = json.loads(zf.read("graph_data.json"))
                nodes = raw.get("nodes", [])
                edges = raw.get("edges", [])
                stats["nodes_imported"] = self._restore_nodes(nodes)
                stats["edges_imported"] = self._restore_edges(edges)

            # Restore findings
            if "findings.json" in names:
                findings = json.loads(zf.read("findings.json"))
                stats["findings_imported"] = len(findings)
                if self.graph_engine is not None:
                    self._restore_findings(findings)

            # Restore reports
            for name in names:
                if name.startswith("reports/") and name.endswith(".html"):
                    REPORTS_DIR.mkdir(exist_ok=True)
                    target = REPORTS_DIR / Path(name).name
                    target.write_bytes(zf.read(name))

            # Restore settings
            if "settings.json" in names:
                settings_dest = Path(__file__).parent.parent / "settings.json"
                settings_dest.write_bytes(zf.read("settings.json"))

        logger.info(f"Imported from {zip_path}: {stats}")
        return stats

    # ==================================================================
    # HTML REPORT GENERATION
    # ==================================================================

    def generate_html_report(
        self,
        narratives: dict,
        scan_data: dict,
        output_path: str = None,
    ) -> str:
        """
        Generate professional HTML report.

        Args:
            narratives: Dict with 6 narrative sections from ReportNarrative.
            scan_data: Raw scan data dict.
            output_path: Optional output file path. Auto-generated if None.

        Returns path to HTML file.
        """
        target = scan_data.get("target", "unknown")
        vulns = scan_data.get("vulnerabilities", [])
        technologies = scan_data.get("technologies", [])
        mitre = scan_data.get("mitre_mappings", [])
        chains = scan_data.get("attack_chains", [])
        scan_date = scan_data.get("scan_date", datetime.now().isoformat())
        scan_duration = scan_data.get("scan_duration", "N/A")

        # Build findings table
        findings_table = self._render_findings_table(vulns)
        cvss_chart = self._render_cvss_chart(vulns)
        mitre_table = self._render_mitre_table(mitre)
        chain_svg = self._render_attack_chain_svg(chains)
        tech_table = self._render_tech_table(technologies)

        # Section HTML
        sections_html = ""
        section_titles = {
            "executive_summary": "Executive Summary",
            "scope_narrative": "Scope and Methodology",
            "risk_narrative": "Risk Analysis",
            "findings_narrative": "Detailed Findings",
            "attack_surface_narrative": "Attack Surface Analysis",
            "recommendations_narrative": "Remediation Recommendations",
        }

        toc_items = ""
        for i, (key, title) in enumerate(section_titles.items(), 1):
            anchor = key.replace("_", "-")
            text = narratives.get(key, "Section content not generated.")
            # Convert newlines to paragraphs
            paragraphs = [
                f"<p>{html_mod.escape(p.strip())}</p>"
                for p in text.split("\n\n") if p.strip()
            ]
            if not paragraphs:
                paragraphs = [f"<p>{html_mod.escape(text)}</p>"]
            body = "\n".join(paragraphs)

            sections_html += f"""
            <section id="{anchor}" class="report-section">
                <h2>{i}. {html_mod.escape(title)}</h2>
                {body}
            </section>
            """

            toc_items += f'<li><a href="#{anchor}">{i}. {html_mod.escape(title)}</a></li>\n'

        # Severity summary counts
        sev_counts = {}
        for v in vulns:
            s = (v.get("severity") or "info").lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        sev_badges_html = " ".join(
            f'<span class="sev-badge sev-{s}">{s.upper()}: {c}</span>'
            for s, c in sorted(sev_counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9))
        )

        report_html = _HTML_TEMPLATE.format(
            target=html_mod.escape(str(target)),
            scan_date=html_mod.escape(str(scan_date)[:10]),
            scan_duration=html_mod.escape(str(scan_duration)),
            total_findings=len(vulns),
            severity_badges=sev_badges_html,
            toc_items=toc_items,
            sections=sections_html,
            findings_table=findings_table,
            cvss_chart=cvss_chart,
            mitre_table=mitre_table,
            chain_svg=chain_svg,
            tech_table=tech_table,
            generation_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            css=_CSS,
        )

        if output_path is None:
            safe_target = "".join(
                c if c.isalnum() or c in ".-_" else "_"
                for c in str(target)
            )
            filename = f"viper_report_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            output_path = str(REPORTS_DIR / filename)

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(report_html, encoding="utf-8")
        logger.info(f"HTML report generated: {output_path}")
        return output_path

    # ------------------------------------------------------------------
    # SVG / HTML Renderers
    # ------------------------------------------------------------------

    def _render_cvss_chart(self, findings: list) -> str:
        """Generate inline SVG bar chart for CVSS score distribution."""
        if not findings:
            return '<p class="no-data">No CVSS data available.</p>'

        # Bucket scores into ranges
        buckets = {
            "0-1": 0, "1-2": 0, "2-3": 0, "3-4": 0, "4-5": 0,
            "5-6": 0, "6-7": 0, "7-8": 0, "8-9": 0, "9-10": 0,
        }
        bucket_keys = list(buckets.keys())

        for v in findings:
            score = v.get("cvss", v.get("cvss_score", 0))
            try:
                score = float(score)
            except (ValueError, TypeError):
                continue
            idx = min(int(score), 9)
            key = bucket_keys[idx]
            buckets[key] += 1

        max_count = max(buckets.values()) or 1
        chart_width = 500
        chart_height = 200
        bar_width = 40
        gap = 10
        x_offset = 50
        y_offset = 20

        bars = ""
        labels = ""
        for i, (label, count) in enumerate(buckets.items()):
            bar_height = int((count / max_count) * (chart_height - 40)) if count else 0
            x = x_offset + i * (bar_width + gap)
            y = chart_height - bar_height - y_offset

            # Color by severity range
            if i >= 9:
                color = SEVERITY_COLORS["critical"]
            elif i >= 7:
                color = SEVERITY_COLORS["high"]
            elif i >= 4:
                color = SEVERITY_COLORS["medium"]
            else:
                color = SEVERITY_COLORS["low"]

            bars += (
                f'<rect x="{x}" y="{y}" width="{bar_width}" '
                f'height="{bar_height}" fill="{color}" rx="3"/>\n'
            )
            if count > 0:
                bars += (
                    f'<text x="{x + bar_width // 2}" y="{y - 4}" '
                    f'text-anchor="middle" class="chart-count">{count}</text>\n'
                )
            labels += (
                f'<text x="{x + bar_width // 2}" y="{chart_height - 4}" '
                f'text-anchor="middle" class="chart-label">{label}</text>\n'
            )

        return f"""
        <div class="chart-container">
            <h3>CVSS Score Distribution</h3>
            <svg width="{chart_width + 20}" height="{chart_height + 10}"
                 xmlns="http://www.w3.org/2000/svg" class="cvss-chart">
                <line x1="{x_offset}" y1="{y_offset}"
                      x2="{x_offset}" y2="{chart_height - y_offset}"
                      stroke="var(--text-muted)" stroke-width="1"/>
                <line x1="{x_offset}" y1="{chart_height - y_offset}"
                      x2="{chart_width}" y2="{chart_height - y_offset}"
                      stroke="var(--text-muted)" stroke-width="1"/>
                {bars}
                {labels}
            </svg>
        </div>
        """

    def _render_severity_badges(self, severity: str) -> str:
        """Generate colored HTML badge for severity level."""
        sev = (severity or "info").lower()
        color = SEVERITY_COLORS.get(sev, "#95a5a6")
        return f'<span class="sev-badge" style="background:{color}">{html_mod.escape(sev.upper())}</span>'

    def _render_mitre_table(self, mitre_data: list) -> str:
        """Generate HTML table for MITRE ATT&CK mappings."""
        if not mitre_data:
            return '<p class="no-data">No MITRE ATT&CK mappings available.</p>'

        rows = ""
        for m in mitre_data:
            tid = html_mod.escape(str(m.get("technique_id", "")))
            tname = html_mod.escape(str(m.get("technique_name", "")))
            tactic = html_mod.escape(str(m.get("tactic", "")))
            finding = html_mod.escape(str(m.get("finding", "")))
            rows += f"""
            <tr>
                <td><code>{tid}</code></td>
                <td>{tname}</td>
                <td>{tactic}</td>
                <td>{finding}</td>
            </tr>
            """

        return f"""
        <div class="table-container">
            <h3>MITRE ATT&CK Mapping</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Technique ID</th>
                        <th>Technique Name</th>
                        <th>Tactic</th>
                        <th>Related Finding</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        """

    def _render_findings_table(self, vulns: list) -> str:
        """Generate HTML table of all findings with severity badges."""
        if not vulns:
            return '<p class="no-data">No findings to display.</p>'

        # Sort by severity
        sorted_vulns = sorted(
            vulns,
            key=lambda v: SEVERITY_ORDER.get(
                (v.get("severity") or "info").lower(), 9
            ),
        )

        rows = ""
        for v in sorted_vulns:
            name = html_mod.escape(str(v.get("name", "Unnamed")))
            sev = (v.get("severity") or "info").lower()
            badge = self._render_severity_badges(sev)
            cvss = v.get("cvss", v.get("cvss_score", "N/A"))
            cve = html_mod.escape(str(v.get("cve_id", v.get("cve", ""))))
            target = html_mod.escape(str(v.get("target", "")))
            cwe = html_mod.escape(str(v.get("cwe", "")))

            rows += f"""
            <tr>
                <td>{name}</td>
                <td>{badge}</td>
                <td>{cvss}</td>
                <td><code>{cve}</code></td>
                <td>{cwe}</td>
                <td>{target}</td>
            </tr>
            """

        return f"""
        <div class="table-container">
            <h3>Findings Summary Table</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Finding</th>
                        <th>Severity</th>
                        <th>CVSS</th>
                        <th>CVE</th>
                        <th>CWE</th>
                        <th>Target</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        """

    def _render_attack_chain_svg(self, chains: list) -> str:
        """Generate inline SVG visualization of attack chains."""
        if not chains:
            return '<p class="no-data">No attack chains identified.</p>'

        svg_blocks = ""
        y_pos = 10

        for chain in chains[:5]:  # Cap at 5 chains for readability
            name = html_mod.escape(str(chain.get("name", "Unnamed Chain")))
            severity = (chain.get("severity") or "medium").lower()
            color = SEVERITY_COLORS.get(severity, "#95a5a6")
            steps = chain.get("steps", [])

            # Chain title
            svg_blocks += (
                f'<text x="10" y="{y_pos + 16}" class="chain-title" '
                f'fill="{color}">{name}</text>\n'
            )
            y_pos += 30

            # Steps as connected boxes
            x_pos = 20
            for i, step in enumerate(steps[:8]):  # Cap steps
                step_text = html_mod.escape(str(step)[:30])
                box_w = max(len(step_text) * 7, 80)

                svg_blocks += (
                    f'<rect x="{x_pos}" y="{y_pos}" width="{box_w}" height="28" '
                    f'rx="4" fill="var(--bg-card)" stroke="{color}" stroke-width="1.5"/>\n'
                    f'<text x="{x_pos + 8}" y="{y_pos + 18}" '
                    f'class="chain-step">{step_text}</text>\n'
                )

                if i < len(steps) - 1 and i < 7:
                    arrow_x = x_pos + box_w
                    svg_blocks += (
                        f'<line x1="{arrow_x}" y1="{y_pos + 14}" '
                        f'x2="{arrow_x + 20}" y2="{y_pos + 14}" '
                        f'stroke="{color}" stroke-width="1.5" '
                        f'marker-end="url(#arrow-{severity})"/>\n'
                    )
                    x_pos += box_w + 25
                else:
                    x_pos += box_w + 10

            y_pos += 45

        total_width = 900
        total_height = y_pos + 10

        # Arrow markers for each severity color
        markers = ""
        for sev, col in SEVERITY_COLORS.items():
            markers += (
                f'<marker id="arrow-{sev}" markerWidth="8" markerHeight="6" '
                f'refX="8" refY="3" orient="auto">'
                f'<polygon points="0 0, 8 3, 0 6" fill="{col}"/></marker>\n'
            )

        return f"""
        <div class="chart-container">
            <h3>Attack Chain Visualization</h3>
            <svg width="{total_width}" height="{total_height}"
                 xmlns="http://www.w3.org/2000/svg" class="chain-svg">
                <defs>{markers}</defs>
                {svg_blocks}
            </svg>
        </div>
        """

    def _render_tech_table(self, technologies: list) -> str:
        """Generate technology inventory table."""
        if not technologies:
            return '<p class="no-data">No technologies detected.</p>'

        rows = ""
        for t in technologies:
            name = html_mod.escape(str(t.get("name", "")))
            version = html_mod.escape(str(t.get("version", "N/A")))
            cve_count = t.get("cve_count", 0)
            category = html_mod.escape(str(t.get("category", "")))

            cve_class = ""
            if cve_count > 5:
                cve_class = ' class="danger"'
            elif cve_count > 0:
                cve_class = ' class="warning"'

            rows += f"""
            <tr>
                <td>{name}</td>
                <td><code>{version}</code></td>
                <td{cve_class}>{cve_count}</td>
                <td>{category}</td>
            </tr>
            """

        return f"""
        <div class="table-container">
            <h3>Technology Inventory</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Technology</th>
                        <th>Version</th>
                        <th>Known CVEs</th>
                        <th>Category</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        """

    # ------------------------------------------------------------------
    # Graph helpers (safe if graph_engine is None)
    # ------------------------------------------------------------------

    def _extract_graph_data(self) -> dict:
        """Extract all nodes and edges from graph engine."""
        if self.graph_engine is None:
            return {"nodes": [], "edges": []}
        try:
            nodes = []
            edges = []
            if hasattr(self.graph_engine, "get_all_nodes"):
                nodes = self.graph_engine.get_all_nodes()
            if hasattr(self.graph_engine, "get_all_edges"):
                edges = self.graph_engine.get_all_edges()
            return {"nodes": nodes, "edges": edges}
        except Exception as e:
            logger.error(f"Failed to extract graph data: {e}")
            return {"nodes": [], "edges": []}

    def _extract_findings(self) -> list:
        """Extract all findings from graph engine."""
        if self.graph_engine is None:
            return []
        try:
            if hasattr(self.graph_engine, "get_findings"):
                return self.graph_engine.get_findings()
            return []
        except Exception as e:
            logger.error(f"Failed to extract findings: {e}")
            return []

    def _extract_attack_chains(self) -> list:
        """Extract attack chains from graph engine."""
        if self.graph_engine is None:
            return []
        try:
            if hasattr(self.graph_engine, "get_attack_chains"):
                return self.graph_engine.get_attack_chains()
            return []
        except Exception as e:
            logger.error(f"Failed to extract attack chains: {e}")
            return []

    def _restore_nodes(self, nodes: list) -> int:
        """Restore nodes into graph engine. Returns count imported."""
        count = 0
        if self.graph_engine is None:
            return 0
        for node in nodes:
            try:
                node_type = node.get("type", "Unknown")
                props = {k: v for k, v in node.items() if k != "type"}
                if hasattr(self.graph_engine, "add_node"):
                    self.graph_engine.add_node(node_type, **props)
                    count += 1
            except Exception as e:
                logger.warning(f"Failed to restore node: {e}")
        return count

    def _restore_edges(self, edges: list) -> int:
        """Restore edges into graph engine. Returns count imported."""
        count = 0
        if self.graph_engine is None:
            return 0
        for edge in edges:
            try:
                if hasattr(self.graph_engine, "add_edge"):
                    self.graph_engine.add_edge(
                        edge.get("source", ""),
                        edge.get("target", ""),
                        edge.get("relationship", "RELATED_TO"),
                        **{k: v for k, v in edge.items()
                           if k not in ("source", "target", "relationship")},
                    )
                    count += 1
            except Exception as e:
                logger.warning(f"Failed to restore edge: {e}")
        return count

    def _restore_findings(self, findings: list) -> None:
        """Restore findings into graph engine."""
        for f in findings:
            try:
                if hasattr(self.graph_engine, "add_node"):
                    self.graph_engine.add_node("Vulnerability", **f)
            except Exception as e:
                logger.warning(f"Failed to restore finding: {e}")


# ══════════════════════════════════════════════════════════════════════
# HTML TEMPLATE + CSS
# ══════════════════════════════════════════════════════════════════════

_CSS = """
:root {{
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-card: #1c2333;
    --bg-hover: #22293a;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --text-muted: #484f58;
    --border: #30363d;
    --accent: #58a6ff;
    --accent-dark: #1f6feb;
    --critical: #e74c3c;
    --high: #e67e22;
    --medium: #f1c40f;
    --low: #3498db;
    --info: #95a5a6;
}}

@media (prefers-color-scheme: light) {{
    :root {{
        --bg-primary: #ffffff;
        --bg-secondary: #f6f8fa;
        --bg-card: #ffffff;
        --bg-hover: #f3f4f6;
        --text-primary: #1f2937;
        --text-secondary: #4b5563;
        --text-muted: #9ca3af;
        --border: #d1d5db;
        --accent: #2563eb;
        --accent-dark: #1d4ed8;
    }}
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.7;
    font-size: 15px;
}}

.report-container {{
    max-width: 1000px;
    margin: 0 auto;
    padding: 40px 60px;
}}

/* Cover page */
.cover-page {{
    text-align: center;
    padding: 80px 0;
    border-bottom: 3px solid var(--accent);
    margin-bottom: 40px;
    page-break-after: always;
}}
.cover-page h1 {{
    font-size: 2.4em;
    font-weight: 700;
    color: var(--accent);
    margin-bottom: 8px;
    letter-spacing: -0.5px;
}}
.cover-title {{
    font-size: 1.6em;
    font-weight: 300;
    color: var(--text-secondary);
    margin-bottom: 30px;
}}
.cover-meta {{
    font-size: 0.95em;
    color: var(--text-secondary);
    line-height: 2;
}}
.cover-classification {{
    display: inline-block;
    margin-top: 30px;
    padding: 6px 24px;
    border: 2px solid var(--critical);
    color: var(--critical);
    font-weight: 700;
    font-size: 0.85em;
    letter-spacing: 2px;
    text-transform: uppercase;
}}
.severity-summary {{
    margin-top: 24px;
}}

/* TOC */
.toc {{
    margin-bottom: 40px;
    padding: 24px 32px;
    background: var(--bg-secondary);
    border-radius: 8px;
    border: 1px solid var(--border);
    page-break-after: always;
}}
.toc h2 {{
    font-size: 1.3em;
    color: var(--accent);
    margin-bottom: 12px;
}}
.toc ul {{
    list-style: none;
}}
.toc li {{
    padding: 6px 0;
    border-bottom: 1px solid var(--border);
}}
.toc li:last-child {{ border-bottom: none; }}
.toc a {{
    color: var(--text-primary);
    text-decoration: none;
    font-size: 0.95em;
}}
.toc a:hover {{ color: var(--accent); }}

/* Sections */
.report-section {{
    margin-bottom: 48px;
    page-break-inside: avoid;
}}
.report-section h2 {{
    font-size: 1.5em;
    color: var(--accent);
    border-bottom: 2px solid var(--border);
    padding-bottom: 8px;
    margin-bottom: 20px;
}}
.report-section p {{
    margin-bottom: 14px;
    text-align: justify;
}}

/* Tables */
.table-container {{
    margin: 24px 0;
    overflow-x: auto;
}}
.table-container h3 {{
    font-size: 1.1em;
    color: var(--text-secondary);
    margin-bottom: 12px;
}}
.data-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88em;
}}
.data-table th {{
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-weight: 600;
    text-align: left;
    padding: 10px 12px;
    border-bottom: 2px solid var(--border);
    text-transform: uppercase;
    font-size: 0.85em;
    letter-spacing: 0.5px;
}}
.data-table td {{
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}}
.data-table tr:hover td {{
    background: var(--bg-hover);
}}
.data-table td.danger {{ color: var(--critical); font-weight: 600; }}
.data-table td.warning {{ color: var(--high); font-weight: 600; }}
.data-table code {{
    background: var(--bg-secondary);
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 0.9em;
}}

/* Severity badges */
.sev-badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 0.75em;
    font-weight: 700;
    color: #fff;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
.sev-critical {{ background: var(--critical); }}
.sev-high {{ background: var(--high); }}
.sev-medium {{ background: var(--medium); color: #1a1a2e; }}
.sev-low {{ background: var(--low); }}
.sev-info {{ background: var(--info); }}

/* Charts */
.chart-container {{
    margin: 24px 0;
    padding: 20px;
    background: var(--bg-secondary);
    border-radius: 8px;
    border: 1px solid var(--border);
}}
.chart-container h3 {{
    font-size: 1.1em;
    color: var(--text-secondary);
    margin-bottom: 16px;
}}
.chart-count {{
    fill: var(--text-primary);
    font-size: 11px;
    font-weight: 600;
}}
.chart-label {{
    fill: var(--text-secondary);
    font-size: 10px;
}}
.chain-title {{
    font-size: 13px;
    font-weight: 700;
}}
.chain-step {{
    fill: var(--text-primary);
    font-size: 11px;
}}
.chain-svg {{
    overflow-x: auto;
}}

.no-data {{
    color: var(--text-muted);
    font-style: italic;
    padding: 12px 0;
}}

/* Appendix */
.appendix {{
    margin-top: 48px;
    padding-top: 24px;
    border-top: 2px solid var(--border);
}}
.appendix h2 {{
    font-size: 1.3em;
    color: var(--accent);
    margin-bottom: 16px;
}}
.appendix h3 {{
    font-size: 1em;
    color: var(--text-secondary);
    margin-top: 16px;
    margin-bottom: 8px;
}}
.appendix p {{
    font-size: 0.9em;
    color: var(--text-secondary);
}}

/* Footer */
.report-footer {{
    margin-top: 60px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
    text-align: center;
    font-size: 0.8em;
    color: var(--text-muted);
}}

/* Print styles */
@media print {{
    body {{
        background: #fff;
        color: #000;
        font-size: 11pt;
    }}
    .report-container {{
        max-width: 100%;
        padding: 20px;
    }}
    .cover-page {{
        padding: 60px 0;
    }}
    .cover-page h1 {{
        color: #1a1a2e;
    }}
    .report-section h2 {{
        color: #1a1a2e;
    }}
    .chart-container, .table-container {{
        background: #f9f9f9;
        border: 1px solid #ddd;
    }}
    .data-table th {{
        background: #f0f0f0;
        color: #333;
    }}
    .data-table td {{
        border-color: #ddd;
    }}
    .sev-badge {{
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}
    .toc {{
        background: #f9f9f9;
        border: 1px solid #ddd;
    }}
    .toc a {{ color: #000; }}
    a {{ color: inherit; text-decoration: none; }}
    .report-footer {{ color: #999; }}
    svg rect, svg line, svg text, svg polygon {{
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}
}}
"""

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIPER Security Assessment - {target}</title>
    <style>{css}</style>
</head>
<body>
<div class="report-container">

    <!-- Cover Page -->
    <div class="cover-page">
        <h1>VIPER</h1>
        <div class="cover-title">Security Assessment Report</div>
        <div class="cover-meta">
            <div><strong>Target:</strong> {target}</div>
            <div><strong>Assessment Date:</strong> {scan_date}</div>
            <div><strong>Duration:</strong> {scan_duration}</div>
            <div><strong>Total Findings:</strong> {total_findings}</div>
        </div>
        <div class="severity-summary">{severity_badges}</div>
        <div class="cover-classification">CONFIDENTIAL</div>
    </div>

    <!-- Table of Contents -->
    <div class="toc">
        <h2>Table of Contents</h2>
        <ul>
            {toc_items}
            <li><a href="#findings-table">7. Findings Summary Table</a></li>
            <li><a href="#cvss-distribution">8. CVSS Distribution</a></li>
            <li><a href="#mitre-mapping">9. MITRE ATT&CK Mapping</a></li>
            <li><a href="#attack-chains">10. Attack Chain Visualization</a></li>
            <li><a href="#tech-inventory">11. Technology Inventory</a></li>
            <li><a href="#appendix">Appendix: Methodology and Tools</a></li>
        </ul>
    </div>

    <!-- Narrative Sections -->
    {sections}

    <!-- Data Sections -->
    <section id="findings-table" class="report-section">
        <h2>7. Findings Summary Table</h2>
        {findings_table}
    </section>

    <section id="cvss-distribution" class="report-section">
        <h2>8. CVSS Score Distribution</h2>
        {cvss_chart}
    </section>

    <section id="mitre-mapping" class="report-section">
        <h2>9. MITRE ATT&CK Mapping</h2>
        {mitre_table}
    </section>

    <section id="attack-chains" class="report-section">
        <h2>10. Attack Chain Visualization</h2>
        {chain_svg}
    </section>

    <section id="tech-inventory" class="report-section">
        <h2>11. Technology Inventory</h2>
        {tech_table}
    </section>

    <!-- Appendix -->
    <div id="appendix" class="appendix">
        <h2>Appendix: Methodology and Tools</h2>

        <h3>Assessment Methodology</h3>
        <p>This assessment was conducted using VIPER 4.0, an autonomous security assessment
        platform that combines automated reconnaissance, vulnerability correlation, exploit
        validation, and AI-driven analysis. The methodology follows a multi-phase approach:
        (1) automated asset discovery and fingerprinting, (2) vulnerability identification
        through CVE correlation and active scanning, (3) exploit validation and attack chain
        construction, (4) AI-assisted risk analysis and report generation.</p>

        <h3>Tools and Techniques</h3>
        <p>VIPER integrates subdomain enumeration, DNS resolution, port scanning, web crawling,
        technology fingerprinting, CVE database correlation, MITRE ATT&CK mapping, and
        graph-based attack path analysis. All findings are validated through multiple
        verification methods to minimize false positives.</p>

        <h3>Classification</h3>
        <p>This report is classified as CONFIDENTIAL and is intended solely for the
        authorized recipients. Distribution, reproduction, or disclosure of this report
        or its contents to unauthorized parties is prohibited.</p>

        <h3>Disclaimer</h3>
        <p>This assessment represents a point-in-time snapshot of the target's security
        posture. New vulnerabilities may be discovered after the assessment date.
        Regular reassessment is recommended to maintain an accurate understanding
        of organizational risk.</p>
    </div>

    <div class="report-footer">
        Generated by VIPER 4.0 Security Assessment Platform | {generation_date}
    </div>

</div>
</body>
</html>
"""
