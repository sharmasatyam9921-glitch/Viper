"""Linux privilege escalation workflow prompt.

Used after initial foothold on a Linux box (low-priv shell, web shell,
SSH as low-priv user, etc.). Outputs structured enumeration + escalation
plan; engine cross-references findings with pentest/gtfobins_db and
pentest/kernel_exploits_db.
"""

LINUX_PRIVESC_PROMPT = """\
You have a low-priv shell on a Linux box. Goal: get root.
Work this checklist top-down. STOP at the first viable escalation; don't
chain unnecessarily.

## 1. System fingerprint (cheap, fast)
```
id; whoami; groups
uname -a; cat /etc/os-release
hostname; hostnamectl 2>/dev/null
arch
```
Note kernel version and distro — feed to `kernel_exploits_db.lookup_linux()`.

## 2. Sudo configuration (highest yield)
```
sudo -l
```
For every entry returned, look up the binary in `gtfobins_db.lookup(bin)`:
- NOPASSWD entries → instant escalation if any matches GTFObins
- Even with password: if you have the user's password from foothold,
  same applies.

Common one-shots from sudo -l:
- `vim`, `less`, `more`, `find`, `awk`, `nmap` → all in GTFOBins
- `apt`, `apt-get` → APT::Update::Pre-Invoke arbitrary command
- `tcpdump` → -z postrotate-command runs as root
- `LD_PRELOAD` env_keep → load malicious .so

## 3. SUID / SGID binaries
```
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```
Filter out the standard set (passwd, su, sudo, ping, mount, etc.).
Anything unusual → check GTFOBins.

## 4. Linux capabilities
```
getcap -r / 2>/dev/null
```
Notable caps:
- `cap_setuid+ep` on python/perl/ruby → instant root
- `cap_net_raw+ep` on tcpdump → packet capture (may have other binaries)
- `cap_dac_read_search+ep` → read any file (incl. /etc/shadow)

## 5. Cron jobs + timers
```
cat /etc/crontab
ls -la /etc/cron.* /var/spool/cron/ 2>/dev/null
systemctl list-timers --all
```
Look for: world-writable scripts, PATH abuse (relative `./script.sh`),
wildcards in `tar`/`rsync`/`chown` commands.

## 6. Writable services / paths
```
ls -la /etc/systemd/system/
find / -writable -type f 2>/dev/null | grep -v /proc | grep -v /sys
```
Look for: writable service unit files, writable scripts referenced from
root-owned services.

## 7. Active sessions / pspy
- `who`, `w`, `last`
- `ps auxf` — what is root running? Long-lived processes?
- If pspy is available (or you can drop it): watch for cron-fired jobs.

## 8. Credentials hunting
```
grep -r -i -E "(password|passwd|pwd|secret|api_key|token)" /home /var/www /opt 2>/dev/null
ls -la /home/*/.ssh/
cat /home/*/.bash_history /root/.bash_history 2>/dev/null
find / -name "config.php" -o -name "database.yml" -o -name ".env" 2>/dev/null
```
Backup files: `*.bak`, `*~`, `*.old`, `*.swp`.

## 9. Database creds
- MySQL: `cat /etc/mysql/debian.cnf` (debian-sys-maint user, often root)
- PostgreSQL: `peer` auth from `postgres` user (if you become postgres)
- MongoDB: `mongo --eval "db.adminCommand('listUsers')"` if no auth

## 10. Kernel exploit (last resort, can crash box)
Cross-reference uname output with `kernel_exploits_db.lookup_linux(version)`.
Notable:
- 4.4.0-* (Ubuntu 16.04) → DirtyCOW (CVE-2016-5195)
- 5.8.0+ → DirtyPipe (CVE-2022-0847) [< 5.16.11]
- 5.10.* → CVE-2022-32250 (netfilter)
- 6.x older → CVE-2023-32233 (nftables)

WARN before running any kernel exploit. Always require approval gate.

## Output for each step
Return JSON like:
{
  "step": "1-10",
  "command": "<exact command>",
  "raw_output": "<truncated to 4KB>",
  "findings": [
    {"type": "sudo_nopasswd", "binary": "vim", "escalation": "<gtfobins one-liner>"}
  ],
  "next": "execute-escalation" | "next-step" | "abort"
}

## Hard constraints
- NO destructive ops without approval (no `rm -rf`, no truncating logs).
- NO persistence (no SSH key drop, no cronjob install) without approval.
- Kernel exploits require explicit approval — they crash boxes.
- Do not exfil files larger than 1 MB without approval.
"""
