#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path
import time
import zipfile
from utils import *
from MCPs.jadxMCP import *
from jadx_helper_functions import *


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
        description="APK file to analise, using the output file from droidot"
    )
    parser.add_argument("apk_path", type=Path, help="Path to the APK file")
    parser.add_argument("droidot_file", type=Path, help="Path to the .txt file")

    parser.add_argument(
        "--jadx",
        type=str,
        default="jadx-gui",  # assuming it's in PATH
        help="Path to the jadx-gui executable (default: 'jadx-gui' in PATH)",
    )

    return parser.parse_args()

def main_jadx():
    args = parse_args()

    # Validate APK
    if not is_valid_apk(args.apk_path):
        sys.exit("Error: the specified file is not a valid APK.")

    # Validate prompt file
    if not args.droidot_file.is_file():
        sys.exit("Error: the file does not exist.")

    start_jadx_gui(args.apk_path, args.jadx)

    # Wait a bit for jadx to open

    print_message(GREEN, "OK", "Prompting the LLM...")
    print_message(BLUE, "NOTE", "This may take a while depending on the LLM and the complexity of the task.")
    asyncio.run(test_jadx())
    print_message(GREEN, "OK", "Done.")

if __name__ == "__main__":
    main_jadx()
