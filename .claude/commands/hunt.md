# /project:hunt - Start Bug Bounty Hunt

Start a new bug bounty hunting session against a specified target.

## Usage

```bash
/project:hunt --target="example.com" [options]
```

## Parameters

- `--target` (required): Primary target domain or URL
- `--program`: Bug bounty program name (hackerone, yogosha, etc.)
- `--intensity`: Scan intensity (passive, moderate, aggressive)
- `--scope-file`: Custom scope file path
- `--modules`: Specific modules to run (cors,gql,auth,secrets)
- `--output`: Output directory for results
- `--notification`: Enable real-time notifications

## Examples

### Basic Hunt
```bash
/project:hunt --target="api.example.com"
```

### Full Program Hunt
```bash
/project:hunt --target="example.com" --program="hackerone/example" --intensity="aggressive"
```

### Focused Hunt
```bash
/project:hunt --target="app.example.com" --modules="cors,gql" --output="results/example-cors"
```

## What It Does

1. **Scope Validation**
   - Validates target is in authorized scope
   - Loads program-specific restrictions
   - Checks exclusion lists

2. **Reconnaissance Phase**
   - Subdomain enumeration (passive & active)
   - Technology fingerprinting
   - API endpoint discovery
   - Asset mapping

3. **Vulnerability Discovery**
   - CORS misconfiguration testing
   - GraphQL introspection attempts
   - Authentication bypass testing
   - Business logic flaw detection

4. **PoC Development**
   - Vulnerability validation
   - Clean exploitation proof
   - Impact assessment
   - Evidence collection

## Output Structure

```
findings/
├── {target}_hunt_{timestamp}/
│   ├── recon/
│   │   ├── subdomains.txt
│   │   ├── technologies.json
│   │   └── endpoints.json
│   ├── vulnerabilities/
│   │   ├── cors_findings.json
│   │   ├── gql_introspection.json
│   │   └── auth_bypasses.json
│   ├── evidence/
│   │   ├── screenshots/
│   │   └── traffic_logs/
│   └── summary_report.md
```

## Safety Features

- **Automatic Scope Checking**: Verifies every target against authorized scope
- **Rate Limiting**: Respects target infrastructure limits
- **Non-Destructive Testing**: No data modification or deletion
- **Ethical Boundaries**: Follows responsible disclosure practices

## Integration Points

- **State Management**: Updates `viper_state.json` with hunt progress
- **Notification System**: Real-time Discord/Telegram alerts for findings
- **Report Generation**: Auto-generates submission-ready reports
- **Submission Tracking**: Links findings to platform submission status

## Prerequisites

- Valid `.env` file with API credentials
- Current scope file in `scopes/` directory
- Required tools installed (nuclei, subfinder, etc.)
- Network connectivity to target (within scope)

## Error Handling

- **Out of Scope**: Automatically rejects unauthorized targets
- **Network Issues**: Implements retry logic with exponential backoff
- **Tool Failures**: Graceful degradation and alternative approaches
- **Rate Limiting**: Automatic delay adjustment and respectful scanning

---

*This command initiates comprehensive but ethical bug bounty hunting. All activities are logged and auditable.*