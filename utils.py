"""
Module overview:
- Purpose: Provide high-level description of this module.
- Important classes/functions are documented inline.
"""

import asyncio
from datetime import datetime
import subprocess
import sys
import shutil
import hashlib
from pathlib import Path
import zipfile
from typing import Dict, List, Optional

from google.genai.errors import ClientError, ServerError
from datetime import datetime

GRAY='\033[0;30m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'

def print_message(color: str, level:str, msg: str = ""):
    """Print a colored message with a level tag."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f'{GRAY}[{timestamp}] {color}[{level}]{NC} {msg}')

def require_executable(name_or_path: str, friendly: str):
    """Ensure that an executable exists in PATH."""
    exe = shutil.which(name_or_path)
    if exe is None:
        print_message(RED, "ERROR", f"'{friendly}' not found in PATH (command: {name_or_path}).")
        sys.exit(1)
    return exe

def is_valid_apk(p: Path) -> bool:
    """
    Is valid apk.
    
    Args:
        p: Description.
    
    Returns:
        Any: Description.
    """
    if not p.is_file() or p.suffix.lower() != ".apk":
        return False
    try:
        with zipfile.ZipFile(p, "r") as zf:
            if "AndroidManifest.xml" not in set(zf.namelist()):
                return False
        return True
    except Exception:
        return False

def handle_model_errors(e):
    """Centralised error handler for model API calls."""
    if isinstance(e, ClientError):
        if hasattr(e, "code") and e.code == 429:
            print_message(RED, "ClientError", f"Quota exceeded or rate limit hit.\n{e.message}\nTry again later.")
        else:
            print_message(RED, "ERROR", f"ClientError during model call: {e}")
    elif isinstance(e, ServerError):
        if hasattr(e, "code") and e.code >= 503:
            print_message(RED, "ServerError", f"Server error occurred. {e.message}")
        else:
            print_message(RED, "ERROR", f"ServerError during model call: {e}")
    else:
        print_message(RED, "ERROR", f"Unexpected error during vuln detection: {e}")
        raise e

    # keep pipeline safe
    sys.exit(1)
    
def run_async(coro):
    """Run an async coroutine safely even if no loop exists or was closed."""
    try:
        return asyncio.run(coro)
    except RuntimeError as e:
        if "event loop is closed" in str(e) or "no current event loop" in str(e):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(coro)
            loop.close()
            return result
        raise