"""
Module overview:
- Purpose: Provide high-level description of this module.
- Important classes/functions are documented inline.
"""

from utils import *
import subprocess
import os
import sys
import signal
import time
import atexit
import threading
import re

JADX_PROC = None
JADX_READY = threading.Event()
JADX_READY_RE = re.compile(r"JADX AI MCP Plugin HTTP Server Started", re.IGNORECASE)


def _reader_thread(stream, debug: bool = False):
    """Read Jadx output line by line and set the readiness event when the server is started."""
    try:
        for line in iter(stream.readline, ""):
            # Optional: forward logs to your console
            # print(line, end='', flush=True)
            if debug:
                print_message(GREEN, "DEBUG-JADX", line.strip())
            if JADX_READY_RE.search(line):
                JADX_READY.set()
    finally:
        try:
            stream.close()
        except Exception:
            pass


def kill_jadx():
    """Terminate Jadx process group gracefully, fallback to SIGKILL if needed."""
    global JADX_PROC
    if not JADX_PROC:
        return
    try:
        if JADX_PROC.poll() is None:
            os.killpg(JADX_PROC.pid, signal.SIGTERM)
            try:
                JADX_PROC.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(JADX_PROC.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        JADX_PROC = None


def _install_signal_handlers():
    """Ensure Jadx is killed if the Python script receives SIGINT or SIGTERM."""

    def _handler(signum, frame):
        kill_jadx()
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, _handler)


def start_jadx_gui(apk_path: str, jadx_cmd: str = "jadx-gui", timeout_sec: int = 45, debug: bool = False):
    """Start Jadx GUI, wait until the MCP HTTP server is ready, then return."""
    print_message(CYAN, "INFO", "Opening APK with Jadx GUI...")
    jadx_cmd = require_executable(jadx_cmd, "jadx-gui")
    if debug:
        print_message(GREEN, "DEBUG", f"Using Jadx command: {jadx_cmd}")
        print_message(GREEN, "DEBUG", f"Opening APK: {apk_path}")

    global JADX_PROC
    try:
        # Pipe stdout/stderr so we can monitor readiness messages
        JADX_PROC = subprocess.Popen(
            [jadx_cmd, str(apk_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,  # decode stream as text
            bufsize=1,  # line-buffered
            preexec_fn=os.setsid,  # start a new process group (Unix)
            close_fds=True,
        )
        atexit.register(kill_jadx)
        _install_signal_handlers()

        # Start a background thread to read log lines
        t = threading.Thread(
            target=_reader_thread, args=(JADX_PROC.stdout, debug,), daemon=True
        )
        t.start()

        # Wait until Jadx reports that the MCP server has started
        if not JADX_READY.wait(timeout=timeout_sec):
            print_message(
                RED,
                "ERROR",
                f"JADX did not report MCP server startup within {timeout_sec}s. Make sure no instances of JADX are open.",
            )
            kill_jadx()
            sys.exit(1)

        print_message(CYAN, "INFO", "JADX MCP is ready: the MCP HTTP server has started.")

    except Exception as e:
        print_message(RED, "ERROR", f"Failed to open Jadx GUI: {e}")
        kill_jadx()
        sys.exit(1)