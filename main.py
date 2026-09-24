"""
CyberRisk-Guidewire-Connector (CRGC)
Root Workspace ASGI Entrypoint
Allows launching Uvicorn directly from the workspace root 'D:\\New folder'.
"""

import os
import sys
from pathlib import Path

# Add cyber-risk-platform directory to sys.path
pkg_dir = Path(__file__).resolve().parent / "cyber-risk-platform"
if str(pkg_dir) not in sys.path:
    sys.path.insert(0, str(pkg_dir))

os.chdir(str(pkg_dir))

# Expose FastAPI application instance
from app.main import app

if __name__ == "__main__":
    import uvicorn
    from config.settings import get_settings
    settings = get_settings()
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=settings.debug)
