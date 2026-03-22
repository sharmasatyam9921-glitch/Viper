#!/usr/bin/env python3
"""
VIPER MCP Server - Bug Bounty Tools via Model Context Protocol

Tools exposed:
- recon: Subdomain enumeration, port scanning
- scan: Vulnerability scanning with nuclei
- exploit: Test specific vulnerabilities
- report: Generate findings report
"""

import subprocess
import json
import os
from datetime import datetime
from pathlib import Path
from mcp.server.fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP("VIPER", json_response=True)

HACKAGENT_DIR = Path(__file__).parent
REPORTS_DIR = HACKAGENT_DIR / "reports"
RECON_OUTPUT = HACKAGENT_DIR / "recon_output"

REPORTS_DIR.mkdir(exist_ok=True)
RECON_OUTPUT.mkdir(exist_ok=True)


@mcp.tool()
def subdomain_enum(domain: str) -> dict:
    """
    Enumerate subdomains for a target domain using subfinder.
    
    Args:
        domain: Target domain (e.g., example.com)
    
    Returns:
        List of discovered subdomains
    """
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=120
        )
        subdomains = [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]
        
        # Save to file
        output_file = RECON_OUTPUT / f"{domain}_subdomains.txt"
        output_file.write_text("\n".join(subdomains))
        
        return {
            "domain": domain,
            "count": len(subdomains),
            "subdomains": subdomains[:50],  # Limit response size
            "full_list": str(output_file)
        }
    except subprocess.TimeoutExpired:
        return {"error": "Timeout - domain may have too many subdomains"}
    except FileNotFoundError:
        return {"error": "subfinder not installed"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def port_scan(target: str, ports: str = "80,443,8080,8443") -> dict:
    """
    Scan ports on a target using naabu.
    
    Args:
        target: Target IP or hostname
        ports: Comma-separated ports or range (default: common web ports)
    
    Returns:
        Open ports found
    """
    try:
        result = subprocess.run(
            ["naabu", "-host", target, "-p", ports, "-silent"],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        open_ports = []
        for line in result.stdout.strip().split("\n"):
            if ":" in line:
                open_ports.append(line.strip())
        
        return {
            "target": target,
            "ports_scanned": ports,
            "open": open_ports
        }
    except subprocess.TimeoutExpired:
        return {"error": "Scan timeout"}
    except FileNotFoundError:
        return {"error": "naabu not installed"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def nuclei_scan(target: str, templates: str = "cves,vulnerabilities") -> dict:
    """
    Run nuclei vulnerability scanner on a target.
    
    Args:
        target: Target URL (e.g., https://example.com)
        templates: Template categories to use (cves, vulnerabilities, exposures, etc.)
    
    Returns:
        Vulnerabilities found
    """
    try:
        output_file = HACKAGENT_DIR / "nuclei_output" / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_file.parent.mkdir(exist_ok=True)
        
        result = subprocess.run(
            [
                "nuclei",
                "-u", target,
                "-t", templates,
                "-json-export", str(output_file),
                "-silent"
            ],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        findings = []
        if output_file.exists():
            with open(output_file) as f:
                for line in f:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        
        return {
            "target": target,
            "templates": templates,
            "findings_count": len(findings),
            "findings": findings[:20],  # Limit response
            "full_report": str(output_file)
        }
    except subprocess.TimeoutExpired:
        return {"error": "Scan timeout (5 min limit)"}
    except FileNotFoundError:
        return {"error": "nuclei not installed"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def http_probe(targets: list[str]) -> dict:
    """
    Probe targets to find live HTTP services using httpx.
    
    Args:
        targets: List of domains/IPs to probe
    
    Returns:
        Live HTTP endpoints with status codes
    """
    try:
        # Write targets to temp file
        temp_file = RECON_OUTPUT / "probe_targets.txt"
        temp_file.write_text("\n".join(targets))
        
        result = subprocess.run(
            ["httpx", "-l", str(temp_file), "-silent", "-status-code", "-title"],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        live = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                live.append(line.strip())
        
        return {
            "probed": len(targets),
            "live_count": len(live),
            "live": live
        }
    except subprocess.TimeoutExpired:
        return {"error": "Probe timeout"}
    except FileNotFoundError:
        return {"error": "httpx not installed"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def crawl_urls(target: str, depth: int = 2) -> dict:
    """
    Crawl a target to discover URLs using katana.
    
    Args:
        target: Target URL to crawl
        depth: Crawl depth (default: 2)
    
    Returns:
        Discovered URLs
    """
    try:
        result = subprocess.run(
            ["katana", "-u", target, "-d", str(depth), "-silent"],
            capture_output=True,
            text=True,
            timeout=180
        )
        
        urls = [u.strip() for u in result.stdout.strip().split("\n") if u.strip()]
        
        # Save crawl results
        output_file = RECON_OUTPUT / f"crawl_{target.replace('://', '_').replace('/', '_')}.txt"
        output_file.write_text("\n".join(urls))
        
        return {
            "target": target,
            "depth": depth,
            "urls_found": len(urls),
            "urls": urls[:100],  # Limit response
            "full_list": str(output_file)
        }
    except subprocess.TimeoutExpired:
        return {"error": "Crawl timeout"}
    except FileNotFoundError:
        return {"error": "katana not installed"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def test_sqli(url: str, param: str) -> dict:
    """
    Test a URL parameter for SQL injection.
    
    Args:
        url: Target URL with parameter (e.g., https://example.com/page?id=1)
        param: Parameter name to test
    
    Returns:
        SQLi test results
    """
    payloads = [
        "' OR '1'='1",
        "1' OR '1'='1' --",
        "1 OR 1=1",
        "' UNION SELECT NULL--",
        "1' AND SLEEP(5)--"
    ]
    
    results = []
    import httpx
    
    for payload in payloads:
        try:
            test_url = url.replace(f"{param}=", f"{param}={payload}")
            resp = httpx.get(test_url, timeout=10, follow_redirects=True)
            
            # Basic heuristics
            indicators = {
                "error_based": any(x in resp.text.lower() for x in ["sql", "syntax", "mysql", "postgresql", "oracle"]),
                "status_code": resp.status_code,
                "response_length": len(resp.text)
            }
            
            results.append({
                "payload": payload,
                **indicators
            })
        except Exception as e:
            results.append({"payload": payload, "error": str(e)})
    
    return {
        "url": url,
        "param": param,
        "tests": results
    }


@mcp.tool()
def test_xss(url: str, param: str) -> dict:
    """
    Test a URL parameter for XSS vulnerabilities.
    
    Args:
        url: Target URL with parameter
        param: Parameter name to test
    
    Returns:
        XSS test results
    """
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)"
    ]
    
    results = []
    import httpx
    
    for payload in payloads:
        try:
            test_url = url.replace(f"{param}=", f"{param}={payload}")
            resp = httpx.get(test_url, timeout=10, follow_redirects=True)
            
            # Check if payload reflected
            reflected = payload in resp.text or payload.replace("<", "&lt;") in resp.text
            
            results.append({
                "payload": payload,
                "reflected": reflected,
                "encoded": payload.replace("<", "&lt;") in resp.text,
                "status_code": resp.status_code
            })
        except Exception as e:
            results.append({"payload": payload, "error": str(e)})
    
    return {
        "url": url,
        "param": param,
        "tests": results
    }


@mcp.tool()
def generate_report(target: str, findings: list[dict]) -> dict:
    """
    Generate a bug bounty report from findings.
    
    Args:
        target: Target name/domain
        findings: List of vulnerability findings
    
    Returns:
        Report path and summary
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = REPORTS_DIR / f"{target.replace('.', '_')}_{timestamp}.md"
    
    report = f"""# Bug Bounty Report: {target}
Generated: {datetime.now().isoformat()}

## Summary
- Total Findings: {len(findings)}
- Critical: {sum(1 for f in findings if f.get('severity') == 'critical')}
- High: {sum(1 for f in findings if f.get('severity') == 'high')}
- Medium: {sum(1 for f in findings if f.get('severity') == 'medium')}
- Low: {sum(1 for f in findings if f.get('severity') == 'low')}

## Findings

"""
    
    for i, finding in enumerate(findings, 1):
        report += f"""### {i}. {finding.get('title', 'Untitled')}
- **Severity**: {finding.get('severity', 'Unknown')}
- **Type**: {finding.get('type', 'Unknown')}
- **URL**: {finding.get('url', 'N/A')}

**Description**:
{finding.get('description', 'No description provided.')}

**Steps to Reproduce**:
{finding.get('steps', 'N/A')}

**Impact**:
{finding.get('impact', 'N/A')}

---

"""
    
    report_file.write_text(report)
    
    return {
        "target": target,
        "report_path": str(report_file),
        "findings_count": len(findings)
    }


@mcp.resource("viper://status")
def get_status() -> str:
    """Get VIPER server status and available tools."""
    tools = [
        "subdomain_enum - Enumerate subdomains",
        "port_scan - Scan ports on target",
        "nuclei_scan - Run vulnerability scanner",
        "http_probe - Find live HTTP services",
        "crawl_urls - Discover URLs",
        "test_sqli - Test for SQL injection",
        "test_xss - Test for XSS",
        "generate_report - Generate report"
    ]
    return f"VIPER MCP Server - Active\n\nTools:\n" + "\n".join(f"- {t}" for t in tools)


@mcp.resource("viper://reports/{name}")
def get_report(name: str) -> str:
    """Get a specific report by name."""
    report_file = REPORTS_DIR / name
    if report_file.exists():
        return report_file.read_text()
    return f"Report not found: {name}"


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--http":
        import uvicorn
        print("Starting VIPER MCP Server on http://127.0.0.1:8890/mcp", file=sys.stderr)
        uvicorn.run(mcp.streamable_http_app(), host="127.0.0.1", port=8890)
    else:
        # Default: stdio transport (for Claude Code, etc.)
        mcp.run()
