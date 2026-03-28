# /project:submit - Submit Bug Bounty Finding

Submit a verified vulnerability finding to the appropriate bug bounty platform.

## Usage

```bash
/project:submit --finding="cors_finding_123.json" [options]
```

## Parameters

- `--finding` (required): Path to vulnerability finding file
- `--platform`: Target platform (hackerone, yogosha, intigriti)
- `--program`: Specific program ID or handle
- `--severity`: Override CVSS severity (low, medium, high, critical)
- `--draft`: Create draft submission for review
- `--auto-submit`: Skip confirmation and submit immediately
- `--attach-evidence`: Include all evidence files

## Examples

### Standard Submission
```bash
/project:submit --finding="findings/cors_api_example_com.json" --platform="hackerone"
```

### Draft for Review
```bash
/project:submit --finding="findings/gql_introspection.json" --platform="hackerone" --draft=true
```

### Critical Finding
```bash
/project:submit --finding="findings/auth_bypass_critical.json" --platform="hackerone" --severity="critical" --auto-submit=true
```

## What It Does

1. **Validation Phase**
   - Verifies finding file format and completeness
   - Validates all required evidence is present
   - Checks CVSS scoring and impact assessment
   - Ensures reproduction steps are clear

2. **Platform Preparation**
   - Formats report for target platform
   - Optimizes evidence files (compression, redaction)
   - Generates platform-specific metadata
   - Calculates bounty estimate ranges

3. **Submission Process**
   - Creates report on target platform
   - Uploads evidence files and screenshots
   - Sets appropriate severity and impact ratings
   - Adds reproduction timeline and PoC details

4. **Tracking & Follow-up**
   - Updates submission tracker database
   - Sets up monitoring for response notifications
   - Schedules follow-up reminders
   - Logs submission metrics

## Finding File Format

Required fields in the finding JSON:

```json
{
  "id": "viper_cors_001_20241201",
  "vulnerability_type": "CORS Misconfiguration",
  "target": {
    "domain": "api.example.com",
    "endpoint": "/api/v1/user/profile"
  },
  "severity": {
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    "score": 8.6,
    "rating": "high"
  },
  "description": "Wildcard CORS policy allows unauthorized cross-origin requests",
  "impact": "Complete account takeover via malicious websites",
  "reproduction": [
    "1. Navigate to malicious website",
    "2. Site makes CORS request to api.example.com/api/v1/user/profile",
    "3. Response includes sensitive user data due to wildcard policy"
  ],
  "evidence": {
    "screenshots": ["cors_request.png", "response_data.png"],
    "traffic_logs": ["burp_requests.xml"],
    "poc_code": ["exploit.html", "poc_server.py"]
  },
  "remediation": "Replace wildcard (*) with specific allowed origins",
  "discovery_date": "2024-12-01T15:30:00Z",
  "verified": true,
  "platform_data": {
    "hackerone": {
      "program_handle": "example",
      "asset_type": "api"
    }
  }
}
```

## Platform-Specific Features

### HackerOne
- Automatic asset mapping to program scope
- CVSS 3.1 scoring integration
- Evidence upload with automated compression
- Real-time submission status tracking

### Yogosha
- European GDPR compliance checks
- Multi-language report support
- Platform-specific severity mappings
- Integration with researcher profile

### Intigriti
- Researcher profile verification
- Automated bounty range estimation
- Platform-specific evidence requirements
- Integration with submission guidelines

## Quality Checks

Before submission, the system validates:

- **Completeness**: All required fields and evidence present
- **Accuracy**: CVSS scoring matches vulnerability impact  
- **Clarity**: Reproduction steps are detailed and testable
- **Ethics**: No sensitive data exposed in evidence
- **Scope**: Target confirmed as in-scope for program

## Submission Tracking

The system maintains detailed tracking in `state/submission_tracker.json`:

```json
{
  "submissions": [
    {
      "id": "viper_cors_001_20241201",
      "platform": "hackerone",
      "submission_id": "H1-123456",
      "status": "triaged",
      "submitted_at": "2024-12-01T16:00:00Z",
      "last_update": "2024-12-02T09:30:00Z",
      "bounty_awarded": null,
      "follow_ups": [
        {
          "date": "2024-12-02T09:30:00Z",
          "type": "status_change",
          "details": "Moved to triaged status"
        }
      ]
    }
  ]
}
```

## Error Handling

- **Invalid Finding**: Clear validation errors with fix suggestions
- **Platform Issues**: Retry logic with exponential backoff
- **Authentication Failures**: Credential validation and refresh
- **Rate Limiting**: Queue submissions and respect platform limits

## Security Features

- **Credential Protection**: API keys stored securely and rotated
- **Evidence Sanitization**: Removes sensitive data from uploads
- **Audit Logging**: Complete submission history for compliance
- **Access Control**: Submission rights based on researcher verification

---

*This command handles professional vulnerability submissions with platform-specific optimizations and comprehensive tracking.*