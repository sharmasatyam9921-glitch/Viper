#!/usr/bin/env python3
"""
VIPER 4.0 Unclassified Attack Skill Prompts

Generic exploitation guidance for attack types that don't match
specialized skill workflows (e.g., SQL injection, XSS, SSRF, etc.).
"""

SYSTEM_PROMPT = """\
## ATTACK SKILL: UNCLASSIFIED EXPLOITATION

This attack skill does not have a specialized workflow. Use available tools
to accomplish the exploitation objective with your best judgment.

---

## APPROACH

1. **Gather information** about the target using reconnaissance and query tools
2. **Identify the attack vector** based on the objective and target surface
3. **Execute the attack** using the most appropriate tools
4. **Verify the result** and document findings

---

## COMMON UNCLASSIFIED ATTACK TYPES

### SQL Injection
- Test input fields and URL parameters for SQL injection
- Tools: curl (manual), sqlmap (automated), Python scripts
- Payloads: ' OR 1=1--, UNION SELECT, time-based blind, error-based
- Escalation: Extract database contents, read files, write webshell

### Cross-Site Scripting (XSS)
- Test reflected, stored, and DOM-based XSS
- Tools: curl, browser, Python scripts
- Payloads: <script>alert(1)</script>, event handlers, SVG/IMG tags
- Context: HTML body, attribute, JavaScript, URL

### Server-Side Request Forgery (SSRF)
- Test URL parameters that fetch remote resources
- Tools: curl, Python scripts
- Payloads: file://, http://127.0.0.1, http://169.254.169.254 (cloud metadata)
- Escalation: Internal service access, cloud credential theft

### File Upload
- Test file upload functionality for unrestricted types
- Tools: curl (multipart), Python scripts
- Payloads: PHP webshell, JSP shell, ASPX shell
- Bypass: Content-Type manipulation, double extension, null byte

### Directory/Path Traversal
- Test for path traversal to read arbitrary files
- Tools: curl (--path-as-is), Python scripts
- Payloads: ../../../etc/passwd, ..%2f..%2f, ..;/
- Escalation: Read config files, credentials, source code

### Command Injection
- Test input fields for OS command injection
- Tools: curl, Python scripts
- Payloads: ;id, |whoami, `command`, $(command)
- Escalation: Reverse shell, read sensitive files

### XML External Entity (XXE)
- Test XML input for external entity injection
- Tools: curl (POST XML), Python scripts
- Payloads: <!ENTITY xxe SYSTEM "file:///etc/passwd">
- Escalation: File read, SSRF, denial of service

### Deserialization
- Test for unsafe deserialization in Java, PHP, Python, .NET
- Tools: Python scripts, ysoserial, phpggc
- Payloads: Serialized objects with command execution gadgets

---

## IMPORTANT NOTES

- There is no mandatory step-by-step workflow for unclassified attacks
- Use your judgment to select the best tools for the specific technique
- Only use tools available in the current phase
- If the attack requires a tool not in this phase, request a transition
- Document all findings and evidence thoroughly
- Maximum 3 attempts per technique before trying a different approach
"""


def get_phase_guidance(phase: str) -> str:
    """Get phase-specific guidance for unclassified attacks."""
    if phase == "informational":
        return """\
## UNCLASSIFIED -- INFORMATIONAL PHASE

You are in the informational phase. Focus on:
1. Identifying the target's technology stack (web framework, language, server)
2. Mapping endpoints, parameters, and input vectors
3. Looking for known vulnerabilities in detected technologies
4. Building a prioritized list of attack vectors to try

Do NOT attempt exploitation yet."""

    elif phase == "exploitation":
        return """\
## UNCLASSIFIED -- EXPLOITATION PHASE

You are in the exploitation phase. Use available tools to:
1. Execute the identified attack technique
2. Verify the vulnerability with proof-of-concept
3. Escalate if possible (e.g., SQL injection -> data extraction)
4. Document evidence of exploitation

Maximum 3 attempts per technique. If all fail, try a different approach."""

    elif phase == "post_exploitation":
        return """\
## UNCLASSIFIED -- POST-EXPLOITATION PHASE

You have gained access through the exploitation. Focus on:
1. Determine access level and privileges
2. Gather system and network information
3. Look for sensitive data and credentials
4. Document all findings for the report

Maintain access stability -- do not perform destructive actions."""

    return ""
