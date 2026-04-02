#!/usr/bin/env python3
"""Compatibility shim.

Historically there are multiple VIPER entry scripts (viper.py, viper_core.py,
viper_autonomous.py, viper_agent.py, etc.).

This file is the new single entrypoint for crons and human use.
"""

import sys
from pathlib import Path

# Ensure repo root is on sys.path when executed as a script.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skills.hackagent.viper_entrypoint import main


if __name__ == "__main__":
    raise SystemExit(main())
