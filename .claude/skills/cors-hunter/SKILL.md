# SKILL: CORS Vulnerability Hunter

This skill (`cors-hunter`) is designed to autonomously identify, verify, and document Cross-Origin Resource Sharing (CORS) misconfigurations.

## 1. Skill Overview

### 1.1 Purpose
- To perform comprehensive analysis of CORS policies on target applications.
- To detect common and complex CORS misconfigurations (e.g., wildcard origins, null origin reflection, regex bypasses).
- To verify exploitability with Proof of Concept (PoC) generation.
- To integrate findings directly into the VIPER reporting workflow.

### 1.2 Invocation
- **Auto-Invoked**: Automatically triggered by `/project:hunt` when a target is identified as a web application or API endpoint.
- **Manual Invocation**: Can be triggered manually for focused testing:
  ```bash
  /skill:cors-hunter --target="https://api.example.com"
  /skill:cors-hunter --findings-dir="findings/potential_cors/"
  ```

## 2. Methodology

### 2.1 Enumeration of Endpoints
- **Action**: Utilizes `tools/recon/endpoint_discover.py` to find potential API endpoints.
- **Technique**: Leverages Spidering, JavaScript parsing, and wordlist-based directory enumeration.

### 2.2 CORS Policy Probing
- **Action**: Sends a series of crafted HTTP requests to target endpoints with various `Origin` headers.
- **Probe Types**:
  - Null Origin (`Origin: null`)
  - Reflective Origin (`Origin: <requested_origin>`)
  - Whitelisted Domains with typo (`Origin: example.com.evil.com`)
  - Regex Bypass attempts (e.g., `example.com%evil.com`)
  - Credentials-allowed checks (`Access-Control-Allow-Credentials: true`)
  - Custom Methods (`Access-Control-Request-Method: PUT`, `DELETE`)
  - Custom Headers (`Access-Control-Request-Headers: X-Custom-Header`)

### 2.3 Response Analysis
- **Action**: Parses HTTP responses for `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Allow-Methods`, and `Access-Control-Allow-Headers` headers.
- **Detection Logic**: Identifies misconfigurations based on:
  - `Access-Control-Allow-Origin: *` (wildcard)
  - `Access-Control-Allow-Origin: null`
  - Reflection of arbitrary `Origin` headers
  - Misconfigured regex matching
  - Credential exposure with wide origin policies

### 2.4 Exploitability Verification
- **Action**: For each detected misconfiguration, generates and executes a minimal Proof of Concept (PoC) to confirm exploitability.
- **PoC Generation**: Creates a simple HTML page with JavaScript to make a cross-origin request.
- **Confirmation**: Verifies if sensitive information can be exfiltrated or unauthorized actions performed.

## 3. Findings & Reporting

### 3.1 Structured Findings
- **Output**: Generates a detailed JSON finding for each confirmed CORS vulnerability.
- **Fields**: Vulnerability type, affected endpoint, vulnerable origin, reproduction steps (cURL, JS PoC), actual and expected CORS headers, business impact, CVSS score.
- **Storage**: Findings stored in `findings/cors_vulnerabilities/`.

### 3.2 Evidence Collection
- **Action**: Automatically captures screenshots of successful PoC execution.
- **Action**: Records relevant HTTP traffic logs (request/response).

### 3.3 Integration
- **Seamless**: Automatically integrates with `/project:submit` and `/project:report` commands.
- **Data Flow**: Populates the finding with all necessary data for direct submission.

## 4. Ethical & Safety Guidelines

### 4.1 Non-Destructive
- **Rule**: All probes and PoCs are strictly read-only and designed not to impact target functionality.
- **Action**: Avoids any methods that could modify server-side state.

### 4.2 Rate Limiting
- **Rule**: Adheres to the rate limiting rules defined in `rules/recon.md` and `settings.json`.
- **Action**: Implements dynamic delays between requests to prevent service disruption.

### 4.3 Scope Compliance
- **Rule**: Only probes targets that are explicitly defined as in-scope in `scopes/current_scope.json`.
- **Action**: Pre-flight checks ensure target is authorized before any active probing.

## 5. Components

- **`viper_cors_hunter.py`**: Main script for orchestrating CORS detection and verification.
- **`cors_analyzer.py`**: Core logic for parsing headers and identifying misconfigurations.
- **`poc_generator.py`**: Generates minimal JavaScript/HTML PoC files.
- **`http_client.py`**: Reused from `tools/` for making HTTP requests.

## 6. Future Enhancements

- Advanced DOM-based CORS detection.
- Integration with browser automation for complex client-side scenarios.
- Machine learning models for identifying subtle CORS bypasses.
- Support for pre-flight request analysis for OPTIONS method vulnerabilities.

---

*This skill provides robust, automated CORS vulnerability hunting with a strong emphasis on ethical hacking and accurate reporting.*