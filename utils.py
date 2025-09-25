import sys
import shutil
import hashlib
from pathlib import Path

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
