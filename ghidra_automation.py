import os
import subprocess
import sys
import textwrap
from pathlib import Path
from utils import *

SUPPORTED_GHIDRA_EXTS = {
    ".so", ".elf", ".bin", ".o", ".a",       # ELF / raw
    ".exe", ".dll", ".sys", ".ocx", ".drv",  # PE
    ".dylib", ".mach", ".macho",             # Mach-O
    ".dex", ".jar", ".class", ".aar"         # JVM/Android (Ghidra can import some)
}

def is_supported_ghidra_input(p: Path) -> bool:
    """Basic check for file existence and a known extension type Ghidra can import."""
    return p.is_file() and p.suffix.lower() in SUPPORTED_GHIDRA_EXTS

def ghidra_init_project(project_dir: str, project_name: str, file_to_import: str, ghidra_headless_cmd: str = "analyzeHeadless"):
    """
    Initialize a Ghidra project directory if it doesn't exist.
    - project_dir: path to the directory where the project will be created
    - project_name: name of the Ghidra project
    """
    proj_dir = Path(project_dir)
    if not proj_dir.exists():
        try:
            proj_dir.mkdir(parents=True, exist_ok=True)
            print_message(GREEN, "OK", f"Created Ghidra project directory: '{project_dir}'")
        except Exception as e:
            sys.exit(f"Error creating project directory '{project_dir}': {e}")
    else:
        print_message(CYAN, "INFO", f"Ghidra project directory already exists: '{project_dir}'")
    
    
    gpr_path = os.path.join(project_dir, f"{project_name}.gpr")

    if os.path.exists(gpr_path):
        print_message(CYAN, "INFO", f"Project '{project_name}' already exists at {gpr_path}, skipping import.")
        return
    ghidra_headless = require_executable(ghidra_headless_cmd, "analyzeHeadless")
    try:
        # Launch detached and silence output
        subprocess.Popen(
            [ghidra_headless, str(project_dir), project_name, "-import", str(file_to_import)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print_message(GREEN, "OK", f"File '{file_to_import}' imported in  {project_dir + "/" + project_name}.")
    except Exception as e:
        sys.exit(f"Error opening Ghidra GUI: {e}")


"""
ghidra /home/nicola/Desktop/Tesi/test/Test1.gpr
"""

def open_ghidra_project(project_dir: str, project_name: str, ghidra_cmd: str = "ghidra"):

    path = Path(project_dir) / f"{project_name}.gpr"
    if not path.is_file():
        print_message(RED, "ERROR", f"Ghidra project file '{path}' does not exist.")
        sys.exit(1)

    print_message(CYAN, "INFO", "Opening input with Ghidra GUI...")
    ghidra_exe = require_executable(ghidra_cmd, "ghidra")
    try:
        # Launch detached and silence output
        subprocess.Popen(
            [ghidra_exe, str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print_message(GREEN, "OK", f"Opened '{path}' with {ghidra_exe}.")
    except Exception as e:
        sys.exit(f"Error opening Ghidra GUI: {e}")

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
    return "\\n".join(cleaned)

def query_gemini_cli(gemini_cmd: str, prompt_text: str, workspace: str | None = None):
    """
    Send a prompt to gemini-cli (which can leverage an MCP for Ghidra, if configured).
    Prints a cleaned response via print_message.
    """
    cmd = [gemini_cmd, "-p", prompt_text]
    if workspace:
        cmd.extend(["--workspace", workspace])

    try:
        print_message(BLUE, "QUERY", prompt_text)
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True
        )
        parsed = gemini_response_parser(result.stdout)
        print_message(PURPLE, "Response", parsed)
    except FileNotFoundError:
        sys.exit("Error: gemini-cli not found.")
    except subprocess.CalledProcessError as e:
        msg = textwrap.dedent(f"""\
        Error while running gemini-cli (exit code {e.returncode}).
        Command: {' '.join(cmd)}
        Stdout:
        {e.stdout}
        Stderr:
        {e.stderr}
        """)
        sys.exit(msg)
