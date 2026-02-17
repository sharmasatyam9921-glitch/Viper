#!/usr/bin/env python3
"""
HackAgent Lab Manager - Practice lab environments
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum


class LabType(Enum):
    DOCKER = "docker"
    VIRTUALBOX = "virtualbox"
    ONLINE = "online"


@dataclass
class PracticeLab:
    name: str
    lab_type: LabType
    description: str
    setup_cmd: str
    default_ip: str
    ports: List[int]
    vulns: List[str]


class LabManager:
    def __init__(self):
        self.labs = {
            "juice-shop": PracticeLab(
                name="OWASP Juice Shop",
                lab_type=LabType.DOCKER,
                description="Modern vulnerable web app - OWASP Top 10",
                setup_cmd="docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop",
                default_ip="127.0.0.1",
                ports=[3000],
                vulns=["SQLi", "XSS", "Broken Auth", "IDOR", "XXE"]
            ),
            "dvwa": PracticeLab(
                name="Damn Vulnerable Web App",
                lab_type=LabType.DOCKER,
                description="Classic vulnerable web app for learning",
                setup_cmd="docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa",
                default_ip="127.0.0.1",
                ports=[80],
                vulns=["SQLi", "XSS", "Command Injection", "File Upload", "LFI"]
            ),
            "metasploitable2": PracticeLab(
                name="Metasploitable 2",
                lab_type=LabType.VIRTUALBOX,
                description="Vulnerable Linux VM for Metasploit practice",
                setup_cmd="Download from sourceforge, import to VirtualBox",
                default_ip="10.0.0.1",
                ports=[21, 22, 23, 80, 445, 3306, 5432],
                vulns=["vsftpd backdoor", "Samba", "distcc", "PostgreSQL", "IRC backdoor"]
            ),
            "hackthebox": PracticeLab(
                name="HackTheBox",
                lab_type=LabType.ONLINE,
                description="Online penetration testing labs",
                setup_cmd="sudo openvpn your-config.ovpn",
                default_ip="10.10.10.x",
                ports=[],
                vulns=["Varies by machine"]
            ),
        }
    
    def list_labs(self):
        return list(self.labs.keys())
    
    def get_lab(self, name):
        return self.labs.get(name)


def get_lab_manager():
    return LabManager()


if __name__ == "__main__":
    m = get_lab_manager()
    print(f"Labs: {m.list_labs()}")
    for name, lab in m.labs.items():
        print(f"  {name}: {lab.name}")

