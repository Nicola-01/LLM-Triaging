import subprocess
import time
import pyautogui
pyautogui.FAILSAFE= True
import os
import shlex
import atexit
import signal
from utils import *


ghidraCLI_cmd = require_executable("ghidra-cli", "ghidra-cli")
wmctrl_cmd = require_executable("wmctrl", "wmctrl")

def _cleanup():
    """Cleanup routine called on normal program exit."""
    try:
        # if you stored the window ID, use it here (otherwise closeGhidraGUI searches for the window)
        closeGhidraGUI()
    except Exception as e:
        # do not interrupt the exit if cleanup fails
        print(f"Warning: failed to close Ghidra cleanly: {e}", file=sys.stderr)

def _signal_handler(signum, frame):
    """Handles SIGINT, SIGTERM, etc., and triggers cleanup."""
    _cleanup()
    # re-send the signal to the process to terminate with the same exit code (optional)
    sys.exit(128 + (signum if isinstance(signum, int) else 0))

    
# register cleanup function to be executed on normal program exit
atexit.register(_cleanup)

# catch common termination signals and trigger the cleanup
for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(s, _signal_handler)


def _run_cmd(cmd: str, shell: bool = False, debug: bool = False, timeout_s: float = None) -> subprocess.CompletedProcess:
    """
    Run a command and return CompletedProcess. Logs debug if enabled.
    If timeout_s is provided and the process runs longer, it will be terminated and TimeoutExpired will be raised.
    
    :param cmd: command string to run
    :param shell: whether to run via shell=True
    :param debug: whether to print debug logs
    :param timeout_s: optional timeout in seconds
    :return: CompletedProcess object if successful
    :raises: subprocess.TimeoutExpired if the process did not complete within timeout_s
    """
    if debug:
        print_message(CYAN, "DEBUG", f"Running command: {cmd}  (timeout={timeout_s})")
    try:
        if shell:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout_s)
        else:
            args = shlex.split(cmd)
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout_s)
        return result
    except subprocess.TimeoutExpired as e:
        print_message(RED, "ERROR", f"Command timed out after {timeout_s} s: {cmd}")
        raise

def _list_windows() -> str:
    """
    Returns the output of `wmctrl -l` as a string.
    """
    cp = _run_cmd(f"{wmctrl_cmd} -l", shell=True)
    return cp.stdout

def _find_window_line(title_substring: str, debug = False) -> str:
    """
    Searches the wmctrl -l output for a window whose title contains title_substring.
    Returns the full line if found, else returns empty string.
    """
    out = _list_windows()
    for line in out.splitlines():
        if title_substring in line:
            if debug:
                print_message(CYAN, "DEBUG", f"Found window line: {line}")
            return line
    return ""

def openGhidraGUI(import_files: list, timeout = 45, debug = False):
    """
    Launches Ghidra via ghidra-cli with the given import_files list.
    Then sends Tab, Tab, Down to the GUI.
    If an existing Ghidra window is found (title contains “Ghidra:”), exits to avoid duplicates.
    """
    # check for existing Ghidra windows
    if _find_window_line("Ghidra:"):
        print_message(YELLOW, "WARNING", "An existing Ghidra window was found. Closing it..")
        closeGhidraGUI(debug=debug)

    # build command
    cmd = f"{ghidraCLI_cmd} -n"
    for f in import_files:
        cmd += f" -i {shlex.quote(f)}"
        
    print_message(GREEN, "INFO", "Launching Ghidra GUI...")
    if debug:
        print_message(CYAN, "DEBUG", f"Importing: {import_files}")
    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        process.communicate(timeout=timeout) 
    except Exception as e:
        print_message(RED, "ERROR", f"Failed to launch Ghidra CLI: {e}")
        return None
        
    process.wait()
    if process.returncode != 0:
        print_message(RED, "ERROR", f"ghidra-cli exited with code {process.returncode}")
        return None

    counter = 0
    while True:
        # small pause to allow GUI to appear
        time.sleep(5)
        counter = counter + 1
        if _find_window_line("Ghidra:"):
            break
        if counter > 5: 
            print_message(YELLOW, "WARNING", "Could not detect Ghidra window after launch")
            return None

    # send the keypresses
    pyautogui.press('tab')
    pyautogui.press('tab')
    pyautogui.press('down')

    # capture the resulting window line
    window_line = _find_window_line("Ghidra:")
    if window_line:
        # parse window ID
        win_id = window_line.split()[0]
        return win_id
    else:
        print_message(YELLOW, "WARNING", "Could not detect Ghidra window after launch")
        return None

def openGhidraFile(import_files: list, select_file: str, debug = False):
    """
    Within an existing Ghidra GUI, selects the given file.
    import_files: the list of all imported files (alphabetical)
    select_file: the file you want to select (must be in import_files)
    Raises if Ghidra window not found.
    """
    # find window
    if not _find_window_line("Ghidra:"):
        print_message(RED, "ERROR", "No Ghidra GUI window found. Cannot select file.")
        return

    # bring to front
    print_message(GREEN, "INFO", "Bringing Ghidra GUI to foreground")
    _run_cmd(f"{wmctrl_cmd} -a \"Ghidra:\"", shell=True)
    time.sleep(1)

    # sort files and find position (1-based)
    files_sorted = sorted(import_files)
    try:
        idx = files_sorted.index(select_file) + 1
    except ValueError:
        print_message(RED, "ERROR", f"select_file {select_file} not in import_files list")
        return
    
    if debug:
        print_message(CYAN, "DEBUG", f"Selecting file '{select_file}' at position {idx}")
    for _ in range(idx):
        pyautogui.press('down')
        time.sleep(0.1)
    pyautogui.press('enter')
    time.sleep(2)

def closeGhidraFile(file: str, debug = False):
    """
    Closes the specific file window within Ghidra by locating its window ID via wmctrl and issuing a close.
    """
    # read windows
    out = _list_windows()
    target_line = None
    for line in out.splitlines():
        if f":/{file}" in line:
            target_line = line
            break
    if not target_line:
        print_message(YELLOW, "WARNING", f"No window line found for file '{file}'")
        return
    win_id = target_line.split()[0]
    if debug:
        print_message(CYAN, "INFO", f"Closing window ID {win_id} for file '{file}'")
    _run_cmd(f"{wmctrl_cmd} -i -c {win_id}", shell=True)

def closeGhidraGUI(debug = False):
    """
    Closes the entire Ghidra GUI window (first one found with title “Ghidra:”).
    """
    line = _find_window_line("Ghidra:")
    if not line:
        return
    win_id = line.split()[0]
    print_message(GREEN, "INFO", f"Closing Ghidra GUI..")
    _run_cmd(f"{wmctrl_cmd} -i -c {win_id}", shell=True)