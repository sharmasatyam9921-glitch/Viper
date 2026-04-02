#!/usr/bin/env python3
"""
VIPER Learned Capabilities
===========================
Learned capabilities from analyzing failures.
"""

import sys
sys.path.insert(0, str(__file__).replace('learned_capabilities.py', ''))
from agentic_viper import Tools

class LearnedCapabilities:
    """Capabilities VIPER learned from training"""

    # Learned: directory_browse

    def browse_directory(self, base_url, path, auth):
        """Browse a directory for files"""
        url = f"{base_url.rstrip('/')}/{path.strip('/')}/"
        status, body, _ = Tools.http_get(url, auth=auth)
        if status == 200:
            links = Tools.extract_from_html(body).get("links", [])
            # Filter out parent links
            files = [l for l in links if l and not l.startswith('?') and l != '../']
            for f in files:
                file_url = url + f
                s, b, _ = Tools.http_get(file_url, auth=auth)
                pwd = Tools.extract_password(b, auth[1] if auth else "")
                if pwd:
                    return {"success": True, "file": f, "password": pwd}
        return {"success": False}

