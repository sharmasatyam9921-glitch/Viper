# /project:verify - Verify Existing Findings

Verify that existing vulnerability findings are still exploitable and haven't been patched.

## Usage

```bash
/project:verify [options]
```

## Parameters

- `--finding`: Verify specific finding by ID or file path
- `--all`: Verify all findings in the findings directory
- `--platform`: Filter by platform (hackerone, yogosha, etc.)
- `--status`: Filter by submission status (pending, triaged, resolved)
- `--age`: Maximum finding age in days (default: 30)
- `--output`: Output verification report to file
- `--fix-attempts`: Number of retry attempts (default: 3)

## Examples

### Verify Specific Finding
```bash
/project:verify --finding="cors_api_example_com.json"
```

### Verify All Unresolved
```bash
/project:verify --all --status="pending,triaged"
```

### Verify Recent Findings
```bash
/project:verify --all --age=7 --output="verification_report.json"
```

### Platform-Specific Verification
```bash
/project:verify --platform="hackerone" --status="triaged"
```

## What It Does

1. **Finding Analysis**
   - Loads vulnerability details and exploitation steps
   - Extracts target information and attack vectors
   - Reviews original evidence and PoC code
   - Checks submission status on platforms

2. **Live Verification**
   - Re-executes original exploitation steps
   - Tests current vulnerability state
   - Captures new evidence if still exploitable
   - Compares results with original findings

3. **Status Assessment**
   - Determines if vulnerability is still present
   - Identifies partial fixes or workarounds
   - Detects complete remediation
   - Flags new security measures

4. **Report Generation**
   - Creates comprehensive verification report
   - Updates finding files with current status
   - Generates evidence comparison
   - Provides remediation recommendations

## Verification Process

### CORS Vulnerabilities
```python
# Example verification flow
1. Check current CORS policy
2. Test with original exploit payload
3. Verify cross-origin request behavior
4. Compare with baseline evidence
5. Document any changes detected
```

### GraphQL Introspection
```python
# Introspection verification
1. Send introspection query to endpoint
2. Compare schema with original discovery
3. Test field-level permissions
4. Verify mutation capabilities
5. Check for new security headers
```

### Authentication Bypasses
```python
# Auth bypass verification
1. Attempt original bypass technique
2. Test alternative authentication paths
3. Verify session handling behavior
4. Check for new authentication controls
5. Test privilege escalation paths
```

## Verification Statuses

### Still Vulnerable
- Original vulnerability remains exploitable
- No security measures detected
- PoC executes successfully
- Evidence matches original findings

### Partially Fixed
- Some protections implemented
- Vulnerability partially mitigated
- Alternative attack vectors exist
- Workarounds still possible

### Fixed
- Vulnerability completely remediated
- Proper security controls implemented
- All attack vectors blocked
- No bypass techniques available

### Changed
- Target infrastructure modified
- Different vulnerability class present
- Original technique ineffective
- New investigation required

## Output Format

### JSON Report
```json
{
  "verification_id": "verify_20241201_143022",
  "timestamp": "2024-12-01T14:30:22Z",
  "findings_verified": 15,
  "results": [
    {
      "finding_id": "viper_cors_001",
      "original_date": "2024-11-15T10:00:00Z",
      "verification_status": "still_vulnerable",
      "confidence": 0.95,
      "evidence_updated": true,
      "changes_detected": [],
      "verification_details": {
        "exploit_successful": true,
        "response_time": 0.234,
        "new_evidence": ["cors_still_present.png"]
      }
    }
  ],
  "summary": {
    "still_vulnerable": 8,
    "partially_fixed": 3,
    "fixed": 3,
    "verification_failed": 1
  }
}
```

### Markdown Report
```markdown
# Vulnerability Verification Report
**Generated:** 2024-12-01 14:30:22
**Findings Checked:** 15

## Summary
- 🔴 Still Vulnerable: 8
- 🟡 Partially Fixed: 3  
- 🟢 Fixed: 3
- ⚠️ Verification Failed: 1

## Detailed Results
### CORS-001: api.example.com CORS Misconfiguration
- **Status:** Still Vulnerable
- **Confidence:** 95%
- **Last Verified:** 2024-12-01 14:30:22
- **Changes:** None detected
```

## Integration Features

### Platform Sync
- Updates submission status from platforms
- Sync comments and triager feedback  
- Track bounty awards and timeline
- Monitor resolution verification

### Evidence Management
- Archives original evidence for comparison
- Captures new verification evidence
- Maintains evidence history timeline
- Provides side-by-side comparisons

### Notification System
- Alerts when vulnerabilities are fixed
- Notifies about partial mitigations
- Reports verification failures
- Sends weekly verification summaries

## Automation Features

### Scheduled Verification
```bash
# Weekly verification of active findings
/project:verify --all --status="pending,triaged" --auto-schedule="weekly"
```

### Continuous Monitoring
```python
# Monitor specific high-value targets
continuous_verify = {
    "targets": ["api.example.com", "admin.target.com"],
    "interval": "daily",
    "alert_on": ["fixed", "changed"]
}
```

## Safety Considerations

- **Non-Destructive**: All verification attempts are read-only
- **Rate Limited**: Respects target rate limits and timeouts
- **Scope Aware**: Only verifies in-scope targets
- **Ethical**: Follows responsible disclosure guidelines

---

*This command ensures finding accuracy and tracks vulnerability lifecycle for comprehensive bounty management.*