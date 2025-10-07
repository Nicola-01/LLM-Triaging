"""
Module overview:
- Purpose: Provide high-level description of this module.
- Important classes/functions are documented inline.
"""

import subprocess
import sys
import shutil
import hashlib
from pathlib import Path
import zipfile
from typing import List, Optional

RED='\033[0;31m'                                                   
YELLOW='\033[0;33m'                                                                                                                          
GREEN='\033[0;32m'                                                                                                                           
NC='\033[0m'                                                                                                                                 
BLUE='\033[0;34m'         # Blue                                      
PURPLE='\033[0;35m'       # Purple                                                                                                           
CYAN='\033[0;36m'         # Cyan 

def print_message(color: str, level:str, msg: str):
    """Print a colored message with a level tag."""
    print(f'{color}[{level}]{NC} {msg}')

def require_executable(name_or_path: str, friendly: str):
    """Ensure that an executable exists in PATH."""
    exe = shutil.which(name_or_path)
    if exe is None:
        print_message(RED, "ERROR", f"'{friendly}' not found in PATH (command: {name_or_path}).")
        sys.exit(1)
    return exe

def sha256_file(path: Path) -> str:
    """Compute sha256 of a file."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


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


def find_relevant_libs(so_paths: List[Path], jniBridgeMethod: List[str], debug: bool = False) -> List[Path]:
    """
    Given a list of .so files, return those that implement JNI methods.
    """
    relevant_libs: List[Path] = []
    
    nm = shutil.which("nm") or shutil.which("llvm-nm") 
    if not nm:
        print_message(RED, "ERROR", "Neither 'nm' nor 'llvm-nm' command is available in PATH.")
        print_message(YELLOW, "WARN", "Returning all .so files without filtering.")
        return so_paths
    
    for so in so_paths:
        try:
            nm_out = subprocess.check_output([nm, "-D", str(so)], text=True, stderr=subprocess.DEVNULL)
            symbols = set(line.split()[-1] for line in nm_out.splitlines() if line and not line.startswith("U "))
            if any(jni in symbols for jni in jniBridgeMethod):
                relevant_libs.append(so)
        except Exception:
            continue
        
    return relevant_libs