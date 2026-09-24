"""
CyberRisk-Guidewire-Connector (CRGC)
Root Workspace Runner / Delegation Script
Allows running the CLI demonstration directly from the workspace root 'D:\\New folder'.
"""

import os
import sys
from pathlib import Path

# Add cyber-risk-platform to python path
pkg_dir = Path(__file__).resolve().parent / "cyber-risk-platform"
sys.path.insert(0, str(pkg_dir))
os.chdir(str(pkg_dir))

# Execute main demo
from run_demo import main
import asyncio

if __name__ == "__main__":
    asyncio.run(main())
