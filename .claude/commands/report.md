# /project:report - Generate Bug Bounty Report

Generate a professional bug bounty report for a given finding or set of findings.

## Usage

```bash
/project:report --finding="xss_reflected_456.json" [options]
```

## Parameters

- `--finding` (required for single report): Path to a specific finding file
- `--findings-dir`: Directory containing multiple finding files for a consolidated report
- `--platform`: Target platform for report formatting (hackerone, yogosha, pdf, markdown)
- `--output`: Output file path for the generated report (default: `reports/{finding_id}.pdf`)
- `--template`: Custom report template file path
- `--include-evidence`: Include all available evidence (screenshots, traffic logs, PoC code)
- `--redact-sensitive`: Automatically redact sensitive information from evidence
- `--cvss-version`: Specify CVSS version for scoring (3.0, 3.1, 4.0)

## Examples

### Single Finding Report (HackerOne Markdown)
```bash
/project:report --finding="findings/cors_api_example_com.json" --platform="hackerone" --output="reports/hackerone_cors_report.md"
```

### Consolidated Program Report (PDF)
```bash
/project:report --findings-dir="findings/example_program_hunt/" --platform="pdf" --output="reports/example_program_summary.pdf" --include-evidence=true
```

### Custom Template Report
```bash
/project:report --finding="findings/sqli_auth_bypass.json" --template="templates/internal_report.tpl" --output="reports/internal_sqli_report.docx"
```

## What It Does

1. **Data Aggregation**
   - Loads vulnerability details, impact, and reproduction steps
   - Gathers associated evidence (screenshots, traffic logs, PoC code)
   - Retrieves program-specific details and asset information
   - Fetches historical data from submission tracker for context

2. **Content Generation**
   - Uses AI to articulate complex technical details clearly
   - Structures report according to platform best practices
   - Automatically calculates and applies CVSS scores
   - Generates executive summary and technical details sections

3. **Formatting & Export**
   - Formats report for chosen platform (Markdown for HackerOne, PDF for clients)
   - Embeds evidence securely and efficiently
   - Applies redaction rules for sensitive data
   - Exports report to specified output path

## Report Sections (Typical)

### Executive Summary
- High-level overview of the vulnerability
- Business impact assessment
- Remediation priority

### Vulnerability Details
- Vulnerability Type (e.g., CORS Misconfiguration, SQL Injection)
- Affected Asset(s)
- CWE and CVSS scores
- Detailed technical description

### Reproduction Steps (with Evidence)
- Step-by-step instructions to reproduce
- Screenshots, video links, or traffic logs as proof
- PoC code snippets

### Impact Analysis
- Potential consequences of exploitation
- Risk assessment for the organization
- Real-world attack scenarios

### Remediation Recommendations
- Specific, actionable advice for developers
- Best practices to prevent similar issues
- References to security standards and guidelines

### Reference Information
- Program details
- Researcher information (viper-ashborn)
- Discovery date and time
- Tools used

## Platform-Specific Output

### HackerOne Markdown
- Follows HackerOne report template structure
- Uses appropriate markdown for formatting
- Embeds images as direct links (if hosted)
- Focuses on clear, concise reproduction steps

### PDF for Clients
- Professional layout with company branding (if configured)
- High-resolution evidence embedding
- Printable format for offline review
- More formal language and structure

### Yogosha Markdown
- Adapts to Yogosha's report format
- Includes specific fields for Yogosha platform
- Supports multi-language output if enabled
- Emphasizes clear severity and impact

## Evidence Management

- **Automatic Embedding**: Inserts screenshots and logs directly
- **Redaction**: Automatically blurs or removes IPs, session tokens, PII
- **Hosting**: Can optionally upload evidence to secure storage and link
- **Versioning**: Links to specific versions of evidence for auditability

## Quality Assurance

- **AI Review**: Checks report for clarity, completeness, and grammar
- **CVSS Validation**: Ensures scores are accurate and justified
- **Ethical Review**: Confirms no sensitive data exposure
- **Format Compliance**: Verifies adherence to platform guidelines
- **Readability Score**: Optimizes for easy understanding by developers

## Integration with Workflow

- **Post-Submission**: Can be run automatically after `/project:submit`
- **Draft Generation**: Supports generating drafts for manual review
- **Version Control**: Reports can be version-controlled in `reports/`
- **Notification**: Alerts on report generation completion

---

*This command ensures high-quality, professional reports for effective bug bounty communication and remediation.*