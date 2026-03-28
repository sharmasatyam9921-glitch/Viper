# SKILL: Vulnerability Submission

Auto-invoked when preparing and submitting findings to bug bounty platforms.

## Invocation
- Triggered by `/project:submit`
- Auto-triggered when a finding is marked `verified: true`

## Submission Checklist

Before submitting, validate ALL of:
- [ ] Finding file exists with all required fields
- [ ] `verified: true` in finding JSON
- [ ] CVSS score calculated and justified
- [ ] Reproduction steps are step-by-step and tested
- [ ] Evidence attached (screenshots, traffic logs, PoC code)
- [ ] Target confirmed in-scope via `scopes/current_scope.json`
- [ ] No sensitive PII exposed in evidence files

## Platform Flows

### HackerOne
1. Load `HACKERONE_API_TOKEN` from env
2. Validate program handle exists and is active
3. Map finding to HackerOne asset type
4. POST to `https://api.hackerone.com/v1/hackers/reports`
5. Upload evidence files to report
6. Record `report_id` in `state/submission_tracker.json`

### Yogosha
1. Load `YOGOSHA_API_TOKEN` from env
2. Find matching program by domain
3. Format report in Yogosha schema
4. Submit via Yogosha API
5. Record submission ID

## Submission Tracker Update

After every submission, append to `state/submission_tracker.json`:
```json
{
  "finding_id": "...",
  "platform": "hackerone",
  "report_id": "H1-XXXXXX",
  "submitted_at": "ISO timestamp",
  "status": "new",
  "bounty": null
}
```

## Ethics Gate

**HARD STOP** if any of these are true:
- Target not in `scopes/current_scope.json`
- Finding not marked verified
- Evidence contains unredacted PII
- CVSS score is missing

Never bypass these checks. No exceptions.
