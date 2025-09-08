import subprocess
import sys
import textwrap
from utils import *

def start_jadx_gui(apk_path: str, jadx_cmd: str):
    print_message(CYAN, "INFO", "Opening APK with Jadx GUI...")
    jadx_cmd = require_executable(jadx_cmd, "jadx-gui")
    try:
        subprocess.Popen([jadx_cmd, str(apk_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print_message(GREEN, "OK", f"Opened '{apk_path}' with {jadx_cmd}.")
    except Exception as e:
        sys.exit(f"Error opening Jadx GUI: {e}")

def gemini_response_parser(output: str) -> str:
    """Clean gemini-cli output and return only the relevant response."""
    lines = output.splitlines()
    cleaned = []
    for line in lines:
        if "Loaded cached credentials." in line:
            continue
        if not line.strip():
            continue
        cleaned.append(line)
    return "\n".join(cleaned)

def query_gemini_cli(gemini_cmd: str, prompt_text: str, workspace: str = None):
    # Build gemini-cli command
    cmd = [gemini_cmd, "-p", prompt_text]
    if workspace:
        cmd.extend(["--workspace", workspace])

    # print_message(CYAN, "INFO", "Querying gemini-cli with the provided prompt...")
    try:
        print_message(BLUE, "QUERY", prompt_text)
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,  # capture stdout and stderr
            text=True             # decode as str
        )
        # Parse and clean response
        parsed = gemini_response_parser(result.stdout)
        print_message(PURPLE, "Response", parsed)
        # print_message(GREEN, "OK", "gemini-cli completed successfully.")
    except FileNotFoundError:
        sys.exit("Error: gemini-cli not found.")
    except subprocess.CalledProcessError as e:
        msg = textwrap.dedent(f"""\
        Error while running gemini-cli (exit code {e.returncode}).
        Command: {' '.join(cmd)}
        """)
        sys.exit(msg)