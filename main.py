#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
import zipfile
from utils import *
from jadx_automation import *
from ghidra_automation import *


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

def main_jadx():
    args = parse_args()

    # Validate APK
    if not is_valid_apk(args.apk_path):
        sys.exit("Error: the specified file is not a valid APK.")

    # Validate prompt file
    if not args.file.is_file():
        sys.exit("Error: the file does not exist.")

    start_jadx_gui(args.apk_path, args.jadx)

    gemini_cmd = require_executable(args.gemini, "gemini-cli")
    query_gemini_cli(gemini_cmd, "what is the app name of the app in the jadx-gui window?")
    query_gemini_cli(gemini_cmd, "what is the app size in the jadx-gui window?")
    
def main_ghidra():
    ghidra_init_project("/home/nicola/Desktop/Tesi/test", "MyProject3", "/home/nicola/Desktop/Tesi/test/libmylib.so")
    open_ghidra_project("/home/nicola/Desktop/Tesi/test", "MyProject3")
    gemini_cmd = require_executable("gemini", "gemini-cli")
    query_gemini_cli(gemini_cmd, "What are the methods in libmylib.so using ghidra mcp?")

if __name__ == "__main__":
    main_ghidra()
