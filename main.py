#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
import zipfile
import shutil
import subprocess
import textwrap
from jadx_automation import *

RED='\033[0;31m'                                                   
YELLOW='\033[0;33m'                                                                                                                          
GREEN='\033[0;32m'                                                                                                                           
NC='\033[0m'                                                                                                                                 
BLUE='\033[0;34m'         # Blue                                      
PURPLE='\033[0;35m'       # Purple                                                                                                           
CYAN='\033[0;36m'         # Cyan 


def print_message(color: str, level:str, msg: str):
    print(f'{color}[{level}]{NC} {msg}')

def is_valid_apk(p: Path) -> bool:
    """Check if the given file is a valid APK (extension, ZIP, has AndroidManifest.xml)."""
    if not p.is_file():
        return False
    if p.suffix.lower() != ".apk":
        return False
    try:
        with zipfile.ZipFile(p, "r") as zf:
            zf.testzip()  # ensure ZIP is valid
            names = set(zf.namelist())
            if "AndroidManifest.xml" not in names:
                return False
        return True
    except zipfile.BadZipFile:
        return False
    except Exception:
        return False

def require_executable(name_or_path: str, friendly: str):
    """Ensure that an executable exists in PATH."""
    exe = shutil.which(name_or_path)
    if exe is None:
        print_message(RED, "ERROR", f"'{friendly}' not found in PATH (command: {name_or_path}).")
        sys.exit(1)
    return exe

def parse_args():
    parser = argparse.ArgumentParser(
        description="Open an APK with jadx-gui and query gemini-cli (MCP Jadx) using a text file."
    )
    parser.add_argument("apk_path", type=Path, help="Path to the APK file")
    parser.add_argument("file", type=Path, help="Path to the .txt file containing the prompt")
    parser.add_argument("--jadx", default="jadx-gui",
                        help="Command to run Jadx GUI (default: 'jadx-gui')")
    parser.add_argument("--gemini", default="gemini",
                        help="Gemini CLI command (default: 'gemini-cli')")
    parser.add_argument("--workspace", default=None,
                        help="Optional workspace/project argument for gemini-cli")
    parser.add_argument("--no-open-jadx", action="store_true",
                        help="Skip opening Jadx GUI, only query gemini-cli")
    return parser.parse_args()

def main():
    args = parse_args()

    # Validate APK
    if not is_valid_apk(args.apk_path):
        sys.exit("Error: the specified file is not a valid APK.")

    # Validate prompt file
    if not args.file.is_file():
        sys.exit("Error: the prompt file does not exist.")

    start_jadx_gui(args.apk_path, args.jadx)

    gemini_cmd = require_executable(args.gemini, "gemini-cli")
    query_gemini_cli(gemini_cmd, "what is the app name of the app in the jadx-gui window?")
    query_gemini_cli(gemini_cmd, "what is the app size in the jadx-gui window?")

if __name__ == "__main__":
    main()
