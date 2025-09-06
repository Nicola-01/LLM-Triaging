import subprocess
import sys
import textwrap
from pathlib import Path
from main import print_message, require_executable, RED, GREEN, CYAN, BLUE, PURPLE, NC

SUPPORTED_GHIDRA_EXTS = {
    ".so", ".elf", ".bin", ".o", ".a",       # ELF / raw
    ".exe", ".dll", ".sys", ".ocx", ".drv",  # PE
    ".dylib", ".mach", ".macho",             # Mach-O
    ".dex", ".jar", ".class", ".aar",        # JVM/Android (Ghidra can import some)
    ".apk"                                   # APK (Ghidra can import, but better for native libs/.dex)
}

def is_supported_ghidra_input(p: Path) -> bool:
    """Basic check for file existence and a known extension type Ghidra can import."""
    return p.is_file() and p.suffix.lower() in SUPPORTED_GHIDRA_EXTS

def start_ghidra_gui(input_path: str, ghidra_cmd: str = "ghidraRun"):
    """
    Open a binary in Ghidra GUI.
    - input_path: path to the binary (e.g., .so, .exe, .elf, .dex, .apk)
    - ghidra_cmd: launcher command for Ghidra GUI (default 'ghidraRun').
      On some installs it could be an absolute path like '/opt/ghidra/ghidraRun'.
    """
    path = Path(input_path)
    if not is_supported_ghidra_input(path):
        print_message(RED, "ERROR", f"Unsupported or missing input for Ghidra: '{input_path}'")
        sys.exit(1)

    print_message(CYAN, "INFO", "Opening input with Ghidra GUI...")
    ghidra_exe = require_executable(ghidra_cmd, "ghidraRun")
    try:
        # Launch detached and silence output
        subprocess.Popen(
            [ghidra_exe, str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print_message(GREEN, "OK", f"Opened '{input_path}' with {ghidra_exe}.")
    except Exception as e:
        sys.exit(f"Error opening Ghidra GUI: {e}")

def analyze_headless(project_dir: str,
                     project_name: str,
                     import_path: str,
                     ghidra_headless_cmd: str = "analyzeHeadless",
                     extra_args: list[str] | None = None):
    """
    Run Ghidra headless analysis.
    - project_dir: directory for the Ghidra project (will be created if missing)
    - project_name: name of the Ghidra project
    - import_path: file to import/analyze
    - ghidra_headless_cmd: analyzeHeadless launcher (default 'analyzeHeadless')
    - extra_args: additional CLI args, e.g. ['-scriptPath', '/path/to/scripts', '-postScript', 'MyScript.java', 'arg1', 'arg2']
    """
    proj_dir = Path(project_dir)
    proj_dir.mkdir(parents=True, exist_ok=True)

    import_file = Path(import_path)
    if not import_file.is_file():
        print_message(RED, "ERROR", f"Input file not found for headless analyze: '{import_path}'")
        sys.exit(1)

    ghidra_headless = require_executable(ghidra_headless_cmd, "analyzeHeadless")

    cmd = [ghidra_headless, str(proj_dir), project_name, "-import", str(import_file)]
    if extra_args:
        cmd.extend(extra_args)

    print_message(CYAN, "INFO", f"Running Ghidra headless analyze: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True
        )
        # Show condensed output to the user (optional)
        out = result.stdout.strip()
        if out:
            print_message(PURPLE, "Ghidra", out if len(out) < 1000 else out[:1000] + "\n... [truncated]")
        print_message(GREEN, "OK", "Headless analysis completed.")
    except subprocess.CalledProcessError as e:
        msg = textwrap.dedent(f"""\
        Error during headless analysis (exit code {e.returncode}).
        Command: {' '.join(cmd)}
        Stdout:
        {e.stdout}
        Stderr:
        {e.stderr}
        """)
        sys.exit(msg)

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
