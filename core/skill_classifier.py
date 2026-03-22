#!/usr/bin/env python3
"""
VIPER 4.0 Attack Skill Classifier

LLM-based intent routing that classifies user objectives into attack skill types
and required phases. Falls back to keyword matching when no LLM is available.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, List, Optional

logger = logging.getLogger("viper.skill_classifier")


# ---------------------------------------------------------------------------
# Classification result
# ---------------------------------------------------------------------------

@dataclass
class AttackPathClassification:
    """Result of classifying a penetration testing objective."""
    required_phase: str = "informational"        # "informational" | "exploitation"
    attack_path_type: str = "cve_exploit"         # skill type or "<term>-unclassified"
    confidence: float = 0.5
    reasoning: str = ""
    detected_service: Optional[str] = None       # ssh, ftp, mysql, etc.
    target_host: Optional[str] = None
    target_port: Optional[int] = None
    target_cves: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "required_phase": self.required_phase,
            "attack_path_type": self.attack_path_type,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "detected_service": self.detected_service,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "target_cves": self.target_cves,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AttackPathClassification":
        return cls(
            required_phase=d.get("required_phase", "informational"),
            attack_path_type=d.get("attack_path_type", "cve_exploit"),
            confidence=float(d.get("confidence", 0.5)),
            reasoning=d.get("reasoning", ""),
            detected_service=d.get("detected_service"),
            target_host=d.get("target_host"),
            target_port=d.get("target_port") if d.get("target_port") is not None else None,
            target_cves=d.get("target_cves", []),
        )


# ---------------------------------------------------------------------------
# Skill sections for LLM prompt building
# ---------------------------------------------------------------------------

_CVE_EXPLOIT_SECTION = """### cve_exploit -- CVE Exploitation
- Exploit known CVE vulnerabilities directly against a service
- Keywords: CVE-XXXX, exploit, RCE, vulnerability, pwn, hack, metasploit
"""

_BRUTE_FORCE_SECTION = """### brute_force_credential_guess
- Password guessing / credential attacks against login services (SSH, FTP, MySQL, RDP, SMB, etc.)
- Keywords: brute force, crack password, dictionary attack, wordlist, password spray, credential attack
"""

_PHISHING_SECTION = """### phishing_social_engineering
- Attack where a target user must execute, open, click, or install something (payload, document, link)
- Includes: payloads, document-based payloads, web delivery, email delivery, handler setup
- Key distinction: target user runs artifact on THEIR machine (vs cve_exploit which hits a service directly)
- Keywords: payload, reverse shell, msfvenom, phishing, document payload, handler
"""

_DOS_SECTION = """### denial_of_service
- Attacks that DISRUPT service availability rather than gaining access or stealing data
- Includes: DoS modules, flooding, slowloris, resource exhaustion, crash exploits
- Key distinction: goal is DISRUPTION/CRASH/UNAVAILABILITY
- Keywords: dos, denial of service, crash, disrupt, slowloris, flood, exhaust, stress test, overwhelm
"""

_UNCLASSIFIED_SECTION = """### <descriptive_term>-unclassified
- ANY exploitation request that does NOT clearly fit the enabled attack skills above
- The agent has no specialized workflow for these -- uses available tools generically
- Key distinction from phishing: the attacker directly interacts with a SERVICE/APPLICATION
  - "Try SQL injection on the web app" -> unclassified (attacker sends input to a web service)
  - "Generate a reverse shell payload" -> phishing (attacker creates file for target to execute)
- Format: `<term>-unclassified` where term is 1-4 lowercase words joined by underscores
- Examples: "sql_injection-unclassified", "ssrf-unclassified", "xss-unclassified",
  "file_upload-unclassified", "directory_traversal-unclassified"
"""

_BUILTIN_SKILL_MAP = {
    "cve_exploit": _CVE_EXPLOIT_SECTION,
    "brute_force_credential_guess": _BRUTE_FORCE_SECTION,
    "phishing_social_engineering": _PHISHING_SECTION,
    "denial_of_service": _DOS_SECTION,
}

_PRIORITY_INSTRUCTIONS = {
    "phishing_social_engineering": """\
   {letter}. **phishing_social_engineering** (highest priority):
      - Is the request asking to GENERATE, CREATE, or SET UP a payload, malicious file, reverse shell, or delivery server?
      - Will the output be something a target user must execute, open, click, or install?
      - Does it mention msfvenom, handler, multi/handler, web delivery, encoding for AV evasion?
      - If YES -> "phishing_social_engineering" """,

    "brute_force_credential_guess": """\
   {letter}. **brute_force_credential_guess**:
      - Does the request mention password guessing, brute force, credential attacks, wordlists, or dictionary attacks?
      - Does it target a login service with credential-based attack?
      - If YES -> "brute_force_credential_guess" """,

    "cve_exploit": """\
   {letter}. **cve_exploit**:
      - Does the request mention a specific CVE ID or exploit module to use DIRECTLY against a service?
      - Does it describe exploiting a service vulnerability where NO target user interaction is needed?
      - If YES -> "cve_exploit" """,

    "denial_of_service": """\
   {letter}. **denial_of_service**:
      - Is the goal to DISRUPT, CRASH, or make a service UNAVAILABLE (not to gain access)?
      - Does it mention DoS, denial of service, flooding, slowloris, stress test?
      - If YES -> "denial_of_service" """,
}


def _build_classification_prompt(objective: str, enabled_skills: Optional[set] = None) -> str:
    """Build a dynamic classification prompt based on enabled skills."""
    if enabled_skills is None:
        enabled_skills = set(_BUILTIN_SKILL_MAP.keys())

    parts = [
        "You are classifying a penetration testing request to determine:\n"
        "1. The required PHASE (informational vs exploitation)\n"
        "2. The ATTACK SKILL TYPE (for exploitation requests only)\n"
    ]

    # Phase types
    parts.append("""## Phase Types

### informational
- Reconnaissance, OSINT, information gathering
- Scanning and enumeration without exploitation
- Examples: "What vulnerabilities exist?", "Show me open ports", "Scan the network"

### exploitation
- Active exploitation of vulnerabilities
- Brute force / credential attacks
- Generating payloads, reverse shells, or delivery mechanisms
- Any request involving gaining unauthorized access
- Examples: "Exploit CVE-2021-41773", "Brute force SSH", "Try SQL injection"
""")

    # Attack skill types
    parts.append("## Attack Skill Types (ONLY for exploitation phase)\n")

    skill_order = ["phishing_social_engineering", "brute_force_credential_guess",
                   "cve_exploit", "denial_of_service"]
    for skill_id in skill_order:
        if skill_id in enabled_skills:
            parts.append(_BUILTIN_SKILL_MAP[skill_id])

    parts.append(_UNCLASSIFIED_SECTION)

    # User request
    parts.append(f"## User Request\n{objective}\n")

    # Classification instructions
    parts.append("## Instructions\nClassify the user's request:\n")
    parts.append("1. First determine the REQUIRED PHASE:\n"
                 '   - Reconnaissance/information gathering -> "informational"\n'
                 '   - Active attack/exploitation -> "exploitation"\n')

    parts.append("2. If exploitation, determine the ATTACK SKILL TYPE using this priority order:")

    letter = ord("a")
    for skill_id in skill_order:
        if skill_id in enabled_skills and skill_id in _PRIORITY_INSTRUCTIONS:
            parts.append(_PRIORITY_INSTRUCTIONS[skill_id].format(letter=chr(letter)))
            letter += 1

    parts.append(f"   {chr(letter)}. **<descriptive_term>-unclassified**:\n"
                 "      - Does the request describe a specific attack technique against a service?\n"
                 '      - If YES -> "<descriptive_term>-unclassified"')
    letter += 1

    default_type = "cve_exploit" if "cve_exploit" in enabled_skills else "<descriptive_term>-unclassified"
    parts.append(f'   {chr(letter)}. Default to "{default_type}" if truly unclear\n')

    parts.append('3. If informational, set attack_path_type to "cve_exploit" (default, won\'t be used)\n')

    parts.append("4. Extract TARGET HINTS from the request (best-effort):\n"
                 '   - target_host: IP or hostname mentioned. null if none.\n'
                 '   - target_port: port number mentioned. null if none.\n'
                 '   - target_cves: list of CVE IDs mentioned. Empty list if none.\n')

    # Valid types for JSON schema
    valid_types = []
    for skill_id in skill_order:
        if skill_id in enabled_skills:
            valid_types.append(f'"{skill_id}"')
    valid_types.append('"<descriptive_term>-unclassified"')

    parts.append(f"""Output valid JSON:

```json
{{
  "required_phase": "informational" | "exploitation",
  "attack_path_type": {' | '.join(valid_types)},
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation",
  "detected_service": "ssh" | "ftp" | "mysql" | "http" | null,
  "target_host": "10.0.0.5" | null,
  "target_port": 8080 | null,
  "target_cves": ["CVE-2021-41773"] | []
}}
```

Notes:
- For unclassified paths, the term MUST be lowercase snake_case followed by "-unclassified"
- detected_service should only be set for brute_force_credential_guess
- confidence: 0.9+ if intent is very clear, 0.6-0.8 if ambiguous""")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Keyword-based fallback classifier (no LLM)
# ---------------------------------------------------------------------------

# CVE pattern
_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

# IP/host extraction
_IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_HOST_RE = re.compile(r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b')
_PORT_RE = re.compile(r'\bport\s*(\d{1,5})\b|\b:(\d{1,5})\b', re.IGNORECASE)

# Informational keywords
_INFORMATIONAL_KW = [
    "scan", "enumerate", "recon", "reconnaissance", "discover", "fingerprint",
    "what vulnerabilities", "what services", "show me", "list", "query",
    "open ports", "running services", "technologies", "osint", "information gathering",
    "what is running", "detect", "identify",
]

# Exploitation keywords by skill type
_SKILL_KEYWORDS = {
    "phishing_social_engineering": [
        "payload", "reverse shell", "msfvenom", "phishing", "social engineering",
        "malicious document", "handler", "multi/handler", "web delivery",
        "hta", "macro", "dropper", "backdoor", "trojan",
    ],
    "brute_force_credential_guess": [
        "brute force", "brute-force", "bruteforce", "crack password", "dictionary attack",
        "wordlist", "password spray", "credential", "hydra", "password guess",
        "login attack", "password attack",
    ],
    "denial_of_service": [
        "dos", "ddos", "denial of service", "denial-of-service",
        "slowloris", "flood", "crash", "disrupt", "stress test",
        "take down", "knock offline", "overwhelm", "exhaust",
    ],
}

# Unclassified attack keywords -> term mapping
_UNCLASSIFIED_KEYWORDS = {
    "sql_injection": ["sql injection", "sqli", "sqlmap", "union select", "' or 1=1"],
    "xss": ["xss", "cross-site scripting", "cross site scripting", "script injection"],
    "ssrf": ["ssrf", "server-side request forgery", "server side request forgery"],
    "file_upload": ["file upload", "upload shell", "web shell upload", "upload a shell"],
    "directory_traversal": ["directory traversal", "path traversal", "lfi", "rfi",
                            "local file inclusion", "remote file inclusion", "../"],
    "command_injection": ["command injection", "cmd injection", "os injection", "rce"],
    "xxe": ["xxe", "xml external entity"],
    "deserialization": ["deserialization", "deserialize", "pickle", "unserialize"],
    "privilege_escalation": ["privilege escalation", "privesc", "priv esc", "escalate privileges"],
    "ldap_injection": ["ldap injection", "ldap"],
    "ssti": ["ssti", "server-side template injection", "template injection"],
}

# Service detection keywords
_SERVICE_KEYWORDS = {
    "ssh": ["ssh", "openssh", "port 22"],
    "ftp": ["ftp", "port 21", "vsftpd"],
    "mysql": ["mysql", "port 3306", "mariadb"],
    "mssql": ["mssql", "port 1433", "sql server"],
    "postgres": ["postgres", "postgresql", "port 5432"],
    "smb": ["smb", "samba", "port 445", "port 139"],
    "rdp": ["rdp", "remote desktop", "port 3389"],
    "vnc": ["vnc", "port 5900"],
    "telnet": ["telnet", "port 23"],
    "tomcat": ["tomcat", "port 8080"],
    "http": ["http", "web server", "web app", "web application", "port 80", "port 443"],
}


def _keyword_classify(objective: str) -> AttackPathClassification:
    """Classify an objective using keyword matching (no LLM fallback)."""
    obj_lower = objective.lower()

    # Extract target hints
    cves = _CVE_RE.findall(objective)
    ip_match = _IP_RE.search(objective)
    host_match = _HOST_RE.search(objective)
    port_match = _PORT_RE.search(objective)

    target_host = ip_match.group(1) if ip_match else (host_match.group(1) if host_match else None)
    target_port = None
    if port_match:
        port_str = port_match.group(1) or port_match.group(2)
        try:
            target_port = int(port_str)
        except (ValueError, TypeError):
            pass

    # Detect service
    detected_service = None
    for service, keywords in _SERVICE_KEYWORDS.items():
        if any(kw in obj_lower for kw in keywords):
            detected_service = service
            break

    # Check for informational phase
    is_informational = False
    for kw in _INFORMATIONAL_KW:
        if kw in obj_lower:
            is_informational = True
            break

    # If CVE mentioned, it's exploitation unless explicitly scanning
    has_cve = len(cves) > 0
    is_exploit_intent = any(
        w in obj_lower for w in [
            "exploit", "pwn", "hack", "attack", "break", "compromise",
            "gain access", "get shell", "pop", "own", "penetrate",
        ]
    )

    # Check each skill type by keyword
    for skill_type, keywords in _SKILL_KEYWORDS.items():
        if any(kw in obj_lower for kw in keywords):
            return AttackPathClassification(
                required_phase="exploitation",
                attack_path_type=skill_type,
                confidence=0.75,
                reasoning=f"Keyword match for {skill_type}",
                detected_service=detected_service if skill_type == "brute_force_credential_guess" else None,
                target_host=target_host,
                target_port=target_port,
                target_cves=cves,
            )

    # Check unclassified attack types
    for term, keywords in _UNCLASSIFIED_KEYWORDS.items():
        if any(kw in obj_lower for kw in keywords):
            return AttackPathClassification(
                required_phase="exploitation",
                attack_path_type=f"{term}-unclassified",
                confidence=0.7,
                reasoning=f"Keyword match for {term}",
                target_host=target_host,
                target_port=target_port,
                target_cves=cves,
            )

    # CVE mentioned -> cve_exploit
    if has_cve:
        phase = "informational" if is_informational and not is_exploit_intent else "exploitation"
        return AttackPathClassification(
            required_phase=phase,
            attack_path_type="cve_exploit",
            confidence=0.8,
            reasoning="CVE ID detected in objective",
            target_host=target_host,
            target_port=target_port,
            target_cves=cves,
        )

    # Generic exploitation intent
    if is_exploit_intent:
        return AttackPathClassification(
            required_phase="exploitation",
            attack_path_type="cve_exploit",
            confidence=0.5,
            reasoning="Generic exploitation intent detected",
            target_host=target_host,
            target_port=target_port,
            target_cves=cves,
        )

    # Default: informational
    return AttackPathClassification(
        required_phase="informational",
        attack_path_type="cve_exploit",
        confidence=0.6,
        reasoning="No clear exploitation intent -- defaulting to informational",
        target_host=target_host,
        target_port=target_port,
        target_cves=cves,
    )


def _extract_json(text: str) -> Optional[dict]:
    """Extract first JSON object from LLM response text."""
    try:
        return json.loads(text.strip())
    except (json.JSONDecodeError, ValueError):
        pass
    # Find JSON block in markdown code fence
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass
    # Find bare JSON object
    match = re.search(r'\{[^{}]*"required_phase"[^{}]*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            pass
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def classify_attack(
    objective: str,
    model_router: Any = None,
    enabled_skills: Optional[set] = None,
) -> AttackPathClassification:
    """Classify a penetration testing objective into attack skill type and phase.

    Args:
        objective: The user's penetration testing request/objective.
        model_router: VIPER ModelRouter instance (optional). If None, uses keyword fallback.
        enabled_skills: Set of enabled skill IDs (optional). Defaults to all built-in skills.

    Returns:
        AttackPathClassification with the determined phase, skill type, and metadata.
    """
    if not objective or not objective.strip():
        return AttackPathClassification(
            required_phase="informational",
            attack_path_type="cve_exploit",
            confidence=0.0,
            reasoning="Empty objective",
        )

    # No LLM -> keyword fallback
    if model_router is None:
        logger.info("No LLM available, using keyword classifier")
        result = _keyword_classify(objective)
        logger.info("Keyword classification: phase=%s, type=%s, confidence=%.2f",
                     result.required_phase, result.attack_path_type, result.confidence)
        return result

    # Build prompt and ask LLM
    prompt = _build_classification_prompt(objective, enabled_skills)

    for attempt in range(3):
        try:
            response = await model_router.generate(
                prompt=prompt,
                system_prompt="You are a penetration testing request classifier. Output only valid JSON.",
                max_tokens=512,
                temperature=0.0,
            )

            text = response.text if hasattr(response, "text") else str(response)
            parsed = _extract_json(text)

            if parsed:
                result = AttackPathClassification.from_dict(parsed)
                # Validate target_port is int or None
                if result.target_port is not None:
                    try:
                        result.target_port = int(result.target_port)
                    except (ValueError, TypeError):
                        result.target_port = None
                logger.info("LLM classification: phase=%s, type=%s, confidence=%.2f",
                             result.required_phase, result.attack_path_type, result.confidence)
                return result

            logger.warning("Classification attempt %d: no JSON in response", attempt + 1)

        except Exception as e:
            logger.warning("Classification attempt %d error: %s", attempt + 1, e)

    # LLM failed -- fall back to keywords
    logger.warning("LLM classification failed after 3 attempts, falling back to keywords")
    return _keyword_classify(objective)


# ---------------------------------------------------------------------------
# Compatibility wrapper class for Phase 3 API consumers
# ---------------------------------------------------------------------------

class SkillClassifier:
    """Wrapper providing a simple ``classify(user_input)`` interface."""

    def __init__(self, model_router=None):
        self.router = model_router

    async def classify(
        self, user_input: str, context: Optional[Any] = None
    ) -> AttackPathClassification:
        """Classify *user_input* into an :class:`AttackPathClassification`.

        Uses the LLM via *model_router* when available, otherwise falls back
        to keyword matching.
        """
        return await classify_attack(user_input, model_router=self.router)
