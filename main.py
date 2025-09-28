#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nicola MCP Orchestrator - Crash to Vulnerability Assessment

Usage:
  python3 main.py APP.apk crash.txt [-m MODEL] [-o report.json] [-d] [--verbose] [--headless]

Environment (required):
  - LLM_API_KEY
  - JADX_MCP_DIR (directory containing `jadx_mcp_server.py`)
  - GHIDRA_INSTALL_DIR (e.g., /snap/ghidra/current/ghidra_11.4_PUBLIC)

What it does:
  1) Validates the APK and parses the crash report (.txt).
  2) Optionally opens Jadx GUI to make the project available to the Jadx MCP server.
  3) Starts the Jadx MCP server and extracts app metadata.
  4) Extracts .so files from the APK, picks those relevant to the crash (via nm/strings heuristics).
  5) Starts the Ghidra MCP server on the relevant .so files.
  6) Asks the LLM (with both MCP toolsets) to assess whether the crash likely indicates a real vulnerability.
  7) Prints a human-readable summary and saves a JSON report.

All prompts and key steps are commented in English.
"""

TOOL_VERSION = "0.1"

import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field
from datetime import datetime, timezone

from CrashSummary import Crashes
from MCPs.vulnAssessment import AnalysisResult, AnalysisResults, mcp_vuln_assessment
from utils import *
from jadx_helper_functions import start_jadx_gui
from MCPs.jadxMCP import AppMetadata, get_jadx_metadata

# ---------- Data models for JSON output ----------
class ToolInfo(BaseModel):
    model_name: Optional[str] = None
    timestamp_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat(timespec="seconds") + "Z")
    apk_path: Optional[str] = None
    apk_sha256: Optional[str] = None
    version: Optional[str] = None          
    notes: Optional[str] = None

class AnalysisBlock(BaseModel):
    tool: Optional[ToolInfo] = None
    app: Optional[AppMetadata] = None
    analysisResults: List[AnalysisResult] = Field(default_factory=list)
    
class AnalysisEnvelope(BaseModel):
    """Top-level wrapper to nest results under 'analysis' and attach metadata."""
    analysis: AnalysisBlock


    def to_json(self, *, indent: int = 2, exclude_none: bool = True, ensure_ascii: bool = False,) -> str:
        """
        Serialize the whole envelope to JSON.
        """
        data = self.model_dump(mode="python", exclude_none=exclude_none)
        return json.dumps(data, indent=indent, ensure_ascii=ensure_ascii)

    def to_json_file(self, path: Path, *, indent: int = 2, exclude_none: bool = True, ensure_ascii: bool = False, encoding: str = "utf-8",) -> None:
        path.write_text(
            self.to_json(indent=indent, exclude_none=exclude_none, ensure_ascii=ensure_ascii),
            encoding=encoding,
        )

# ---------- APK helpers ----------

def is_valid_apk(p: Path) -> bool:
    """Check if the given file is a valid APK (extension, ZIP, has AndroidManifest.xml)."""
    if not p.is_file() or p.suffix.lower() != ".apk":
        return False
    try:
        with zipfile.ZipFile(p, "r") as zf:
            zf.testzip()  # ensure ZIP is valid
            if "AndroidManifest.xml" not in set(zf.namelist()):
                return False
        return True
    except Exception:
        return False

def extract_so_files(apk: Path, workdir: Path) -> List[Path]:
    """
    Extract .so files from the APK into workdir/lib/<abi>/.
    Returns list of extracted file paths (preferring arm64-v8a first).
    """
    so_paths: List[Path] = []
    with zipfile.ZipFile(apk, "r") as zf:
        for name in zf.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                out_path = workdir / name
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(name) as src, open(out_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                so_paths.append(out_path)
    # Prefer arm64-v8a ordering
    so_paths.sort(key=lambda p: (0 if "arm64-v8a" in str(p) else 1, str(p)))
    return so_paths

def find_relevant_libs(so_paths: List[Path], jniBridgeMethod: List[str], debug: bool = False) -> List[Path]:
    """

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

# ---------- Argument parsing ----------
def parse_args():
    p = argparse.ArgumentParser(description="APK + crash report -> vulnerability assessment via Jadx/Ghidra MCP")
    p.add_argument("apk", type=Path, help="Path to the APK file")
    p.add_argument("crash_txt", type=Path, help="Path to the crash report .txt")
    p.add_argument("-m", "--model-name", type=str, default=os.getenv("LLM_MODEL_NAME", "gemini-2.5-flash"), help="LLM model name (default: env LLM_MODEL_NAME or gemini-2.5-flash)")
    p.add_argument("-o", "--json-out", type=Path, default=Path("report.json"), help="Path to save JSON report")
    p.add_argument("--timeout", type=int, default=120, help="Timeout (seconds) for MCP servers")
    # p.add_argument("--headless", action="store_true", help="Do NOT open Jadx GUI (requires that Jadx MCP can operate headlessly)")
    p.add_argument("-d", "--debug", action="store_true", help="Enable verbose debug logs")
    p.add_argument("-v", "--verbose", action="store_true", help="Echo system/user prompts and model outputs")
    return p.parse_args()

# ---------- Orchestration ----------

async def run_assessment(apk: Path, crash_txt: Path, args) -> None:
    """
        Orchestrate the end-to-end vulnerability assessment for a single APK + crash report.

    High-level flow:
      1) Validate inputs (APK and crash text file).
      2) Optionally start Jadx GUI (unless --headless) so the Jadx MCP can access the open project.
      3) Parse the crash report into a structured summary (entries, JNI methods, native function tokens).
      4) Query Jadx MCP to extract app metadata (package, app label, SDKs, versions).
      5) Extract .so files from the APK and heuristically select the most relevant ones using nm/strings
         against the tokens seen in the crash (JNI/native symbols).
      6) Start Ghidra MCP for the selected native libraries and Jadx MCP for the Java side.
      7) Ask the LLM (via a joint Agent using both MCP toolsets) to decide whether the crash is likely
         caused by a real vulnerability; collect a structured JSON (VulnAssessment).
      8) Enrich the result with APK path/sha256, JNI/native lists, and app metadata fields.

    Parameters
    ----------
    apk : pathlib.Path
        Path to the target APK.
    crash_txt : pathlib.Path
        Path to the crash report (.txt) for a single JNI-driven crash.
    args : argparse.Namespace

    Returns
    -------
    VulnAssessment
        Structured decision:
          - is_vulnerability (bool)
          - confidence (float in [0, 1])
          - reasons (List[str])
          - app/package/SDK/version fields (when available)
          - apk_path/apk_sha256, jni_methods, native_functions
    """
    
    if not is_valid_apk(apk):
        print_message(RED, "ERROR", f"Invalid APK: {apk}")
        sys.exit(1)
    if not crash_txt.is_file():
        print_message(RED, "ERROR", f"Crash file not found: {crash_txt}")
        sys.exit(1)

    start_jadx_gui(str(apk), "jadx-gui", debug=args.debug)
    # Extract metadata via Jadx MCP
    appMetadata = await get_jadx_metadata(model_name=args.model_name, verbose=args.verbose)      

    # Parse crash report
    crashes = Crashes(crash_txt)
        
    # print(crashes[0])
    # print(crashes[1])
    # print(crashes[2])
        
    # Prepare native libs via APK extraction
    print_message(BLUE, "INFO", f"Extracting .so files from APK: {apk}")
    with tempfile.TemporaryDirectory(prefix="apk_so_") as td:
        workdir = Path(td)
        so_paths = extract_so_files(apk, workdir)
        if args.debug:
            for pth in so_paths:
                print_message(GREEN, "SO", f"found {pth}")
        relevant = find_relevant_libs(so_paths, jniBridgeMethod=crashes.get_JNIBridgeMethods(), debug=args.debug) or so_paths[:3]  # fallback to top few
        if not relevant:
            print_message(YELLOW, "WARN", "No relevant libs identified; proceeding with all .so files.")
            relevant = so_paths
        if args.debug:
            for pth in relevant:
                print_message(GREEN, "SELECTED", f"{pth}")
                
                    
        print_message(BLUE, "INFO", f"Starting vulnerability assessment for {len(crashes)} crash entries...")
        analysisResults : AnalysisResults = await mcp_vuln_assessment(model_name=args.model_name, files=[str(p) for p in relevant], crashes=crashes, relevant=relevant, timeout=args.timeout, verbose=args.verbose)
        
    tool = ToolInfo(model_name=args.model_name, apk_path=str(apk), version=TOOL_VERSION)
    envelope = AnalysisEnvelope(
        analysis=AnalysisBlock(app=appMetadata, analysisResults=analysisResults, tool=tool)
    )
    envelope.to_json_file(Path("analysis_report.json"))
    

def main():
    args = parse_args()
    
    if args.model_name:
        # Make the model available to get_agent() via env for consistency.
        os.environ["LLM_MODEL_NAME"] = args.model_name
    if args.debug:
        print_message(GREEN, "DEBUG", f"Using LLM model: {os.getenv('LLM_MODEL_NAME', 'gemini-2.5-flash')}")

    # --- Check required env vars ---
    
    # export LLM_API_KEY="your-api-key"
    if not os.getenv("LLM_API_KEY"):
        print_message(RED, "ERROR", "Environment variable 'LLM_API_KEY' is not set.")
        sys.exit()
    if args.debug:
        print_message(GREEN, "DEBUG", f"Using LLM API key: {os.getenv('LLM_API_KEY')[:8]}...")
        
    # export JADX_MCP_DIR="/path/to/jadx-mcp-server"
    if not os.getenv("JADX_MCP_DIR"):
        print_message(RED, "ERROR", "Environment variable 'JADX_MCP_DIR' is not set.")
        sys.exit(1)
    if args.debug:
        print_message(GREEN, "DEBUG", f"Using Jadx MCP dir: {os.getenv('JADX_MCP_DIR')}")
        
    # export GHIDRA_INSTALL_DIR="/snap/ghidra/current/ghidra_11.4_PUBLIC"
    if not os.getenv("GHIDRA_INSTALL_DIR"):
        print_message(RED, "ERROR", "Environment variable 'GHIDRA_INSTALL_DIR' is not set.")
        sys.exit(1)
    if args.debug:
        print_message(GREEN, "DEBUG", f"Using Ghidra install dir: {os.getenv('GHIDRA_INSTALL_DIR')}")
        
    # --- Run the assessment ---

    asyncio.run(run_assessment(args.apk, args.crash_txt, args))


if __name__ == "__main__":
    main()
