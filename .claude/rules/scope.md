# VIPER Rules: Scope & Ethical Hacking

These rules define the boundaries and ethical considerations for all VIPER's bug bounty hunting activities. Strict adherence is mandatory.

## 1. Stay In Scope (Absolutely Critical)

### 1.1 Authorized Targets Only
- **Rule**: Only engage with targets explicitly listed in the current program scope (`scopes/current_scope.json`).
- **Violation**: Testing any domain, subdomain, IP address, or application not explicitly authorized.
- **Consequence**: Immediate cessation of activity, potential ban from program, legal action.
- **Action**: Always cross-reference `scopes/current_scope.json` before initiating any active reconnaissance or scanning.

### 1.2 Subdomain Scope
- **Rule**: If `*.example.com` is in scope, only subdomains of `example.com` are allowed. Top-level domains (`example.com`) should also be explicitly listed.
- **Clarification**: `staging.example.com` is in scope, `example.net` is NOT.
- **Action**: Use recon tools with strict scope filtering; manually verify discovered subdomains.

### 1.3 Exclusion Lists
- **Rule**: Respect all explicit exclusion lists. These targets are strictly out of bounds, even if they appear related to in-scope assets.
- **Examples**: QA environments, test systems, third-party services, employee-only portals, deprecated applications.
- **Action**: Load `scopes/current_scope.json` exclusions into all scanning and probing tools.

### 1.4 Out-of-Scope Assets
- **Rule**: Assets like internal IP ranges, physical infrastructure, social engineering targets, and unsupported services are always out of scope unless explicitly mentioned.
- **Clarification**: Focus solely on the web application layer unless authorized for network/mobile.

## 2. Ethical Hacking Constraints

### 2.1 Non-Destructive Actions (Absolutely Critical)
- **Rule**: Never perform any action that could lead to data loss, service degradation, system instability, or denial of service.
- **Violation**: Deleting records, corrupting databases, overwhelming servers, generating excessive traffic.
- **Consequence**: Immediate cessation of activity, reporting to platform/client, potential legal action.
- **Action**: Design all payloads and tests to be read-only or have minimal, reversible impact. If in doubt, do not execute.

### 2.2 Respect Rate Limits
- **Rule**: Implement respectful rate limiting for all automated tools and active reconnaissance.
- **Guideline**: Do not exceed typical user traffic patterns. Avoid bursting requests.
- **Action**: Configure tools like Nuclei, HttpX, and custom scripts with `rate-limit` parameters. Implement dynamic delays and backoff strategies.

### 2.3 No Sensitive Data Access/Disclosure
- **Rule**: If sensitive data (PII, credentials, financial data, confidential business information) is accidentally accessed, immediately cease activity, document, and report it without further access or storage.
- **Action**: Do not download, store, or share sensitive data. Redact from all evidence (screenshots, logs).

### 2.4 No Social Engineering or Phishing
- **Rule**: Never attempt any form of social engineering (e.g., impersonation, pretexting) or phishing attacks (e.g., fake login pages) against employees, users, or third parties.
- **Action**: VIPER's scope is purely technical vulnerability assessment, not human element exploitation.

### 2.5 No Unauthorized Escalation
- **Rule**: Do not attempt to pivot into internal networks or other systems that are not explicitly in scope, even if an initial vulnerability allows it.
- **Action**: If a critical vulnerability allows unauthorized access, document it and stop at the minimum proof required.

### 2.6 Always Verify PoC
- **Rule**: Before reporting, every vulnerability must be independently verified to be reproducible and have a clear Proof of Concept (PoC).
- **Action**: Run `viper_verify.py` or equivalent manual steps to reconfirm the finding.

### 2.7 Responsible Disclosure
- **Rule**: Follow the disclosure policy of each bug bounty program. Do not publicly disclose vulnerabilities without explicit permission.
- **Action**: Submit findings through the official platform channels. Await their triage and disclosure process.

## 3. Reporting Out-of-Scope Findings

- **Rule**: If a critical vulnerability is discovered on a clearly out-of-scope asset, do NOT exploit it. Document the discovery and, if possible, ethically notify the affected party or the bug bounty program administrators (who may choose to forward it).
- **Action**: Prioritize communication over exploitation for out-of-scope but critical findings. Do not submit to the bug bounty platform unless explicitly advised.

## Enforcement

- All VIPER modules (scanners, tools, reporting) are designed to enforce these rules.
- Deviations are immediately flagged and require human override with explicit justification.
- Automatic audit trails record all actions for compliance checks.

---

*These rules are paramount to maintaining trust, ethical standards, and legal compliance in bug bounty hunting.*