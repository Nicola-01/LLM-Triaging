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
from CrashSummary import Crashes

from google.genai.errors import ClientError, ServerError

GRAY='\033[0;30m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'

def print_message(color: str, level:str, msg: str):
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

def extract_so_files(apk: Path, workdir: Path) -> List[Path]:
    """Extract .so files from the APK into workdir/lib/<abi>/. Return the list of paths."""
    so_paths: List[Path] = []
    with zipfile.ZipFile(apk, "r") as zf:
        for name in zf.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                out_path = workdir / name
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(name) as src, open(out_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                so_paths.append(out_path)
    so_paths.sort(key=lambda p: (0 if "arm64-v8a" in str(p) else 1, str(p)))
    return so_paths


def find_relevant_libs(so_paths: List[Path], crashes: Crashes, debug: bool = False) -> Dict[Path, List[str]]:
    """
    Given a list of .so files, return those that implement JNI methods,
    preferring specific ABIs in the following order:
        arm64-v8a > armeabi-v7a > armeabi > arm* > x86_64 > x86 > any other.
    """
    relevant_libs_map: Dict[Path, List[str]] = {}

    nm = shutil.which("nm") or shutil.which("llvm-nm")
    if not nm:
        print_message(RED, "ERROR", "Neither 'nm' nor 'llvm-nm' command is available in PATH.")
        print_message(YELLOW, "WARN", "Returning all .so files without filtering.")
        return so_paths

    # Group libs by ABI (directory name under /lib/)
    abi_groups: Dict[str, List[Path]] = {}
    for so in so_paths:
        abi = so.parent.name
        abi_groups.setdefault(abi, []).append(so)

    # Define ABI preference order
    abi_preference = [
        "arm64-v8a",
        "armeabi-v7a",
        "armeabi",
        "arm",
        "x86_64",
        "x86"
    ]

    # Select the best available ABI group
    selected_abi = None
    for abi in abi_preference:
        if abi in abi_groups:
            selected_abi = abi
            break
    if not selected_abi:
        # fallback: pick any remaining ABI folder
        selected_abi = next(iter(abi_groups.keys()), None)

    if debug:
        print_message(CYAN, "DEBUG", f"Selected ABI: {selected_abi}")

    selected_libs = abi_groups.get(selected_abi, [])
    
    JNI_List = [entry.JNIBridgeMethod for entry in crashes if entry.JNIBridgeMethod]
    stackTracesList = [entry.StackTrace for entry in crashes]
    
    # Join JNI_List and stackTracesList into a single list of unique method names
    methodList = set()
    for jni in JNI_List:
        methodList.add(jni)
    for stack in stackTracesList:
        for line in stack:
            methodList.add(line)

    # Filter selected libs by JNI symbol presence
    for so in selected_libs:
        try:
            nm_out = subprocess.check_output([nm, "-D", str(so)], text=True, stderr=subprocess.DEVNULL)
            symbols = set(line.split()[-1] for line in nm_out.splitlines() if line and not line.startswith("U "))
            
            matched = [m for m in methodList if any(m in s for s in symbols)]
            if matched:
                relevant_libs_map.setdefault(so, []).extend(matched)
                
        except Exception:
            continue
        
    # if debug:
    #     for lib, methods in relevant_libs_map.items():
    #         print_message(CYAN, "DEBUG", f"Lib: {lib}, Methods: {methods}")

    return relevant_libs_map

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
        print_message(RED, "ERROR", f"Unexpected error during assessment: {e}")
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