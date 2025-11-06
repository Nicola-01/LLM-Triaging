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

TOOL_VERSION = "1.0"


import argparse
import asyncio
import json
import os
import sys
import tempfile
import re

from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field, field_serializer
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial

from CrashSummary import Crashes
from MCPs.vulnAssessment import AnalysisResult, AnalysisResults, mcp_vuln_assessment
from utils import *
from jadx_helper_functions import kill_jadx, start_jadx_gui
from MCPs.jadxMCP import AppMetadata, get_jadx_metadata


# Matches case folders like: fname-signature@cs_number-io_matching_possibility
_CASE_DIR_RE = re.compile(r"^[\w.-]+@[\w*-]+@[\d-]+$")

# ---------- Data models for JSON output ----------
class ToolInfo(BaseModel):
    """Information about the tool and environment used for the assessment."""
    model_name: Optional[str] = None
    # timestamp_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds") + "Z")
    apk_path: Optional[str] = None
    # apk_sha256: Optional[str] = None
    version: Optional[str] = None          
    notes: Optional[str] = None

class AnalysisBlock(BaseModel):
    """Holds the full analysis block, including tool info, app metadata, and results."""
    tool: Optional[ToolInfo] = None
    app: Optional[AppMetadata] = None
    relevant_libs_map: Dict[Path, List[str]] = Field(default_factory=dict, alias="libs")
    analysisResults: AnalysisResults = Field(default_factory=AnalysisResults)

    @field_serializer("relevant_libs_map")
    def serialize_paths(self, libs: Dict[Path, List[str]], _info):
        # return just sanitized paths
        return [re.sub(r'/tmp/apk_so_[^/]*/', '', str(p)) for p in libs.keys()]

    @field_serializer("analysisResults")
    def serialize_results(self, results: AnalysisResults, _info):
        # Flatten the nested structure
        if hasattr(results, "analysisResults"):
            return results.analysisResults
        return results

    class Config:
        populate_by_name = True
        allow_population_by_field_name = True
    
class AnalysisEnvelope(BaseModel):
    """Top-level wrapper to nest results under 'analysis' and attach metadata."""
    analysis: AnalysisBlock


    def to_json(self, *, indent: int = 2, exclude_none: bool = True, ensure_ascii: bool = False,) -> str:
        """Serialize the whole envelope to JSON."""
        data = self.model_dump(mode="python", exclude_none=exclude_none, by_alias=True)
        return json.dumps(data, indent=indent, ensure_ascii=ensure_ascii)

    def to_json_file(self, path: Path, *, indent: int = 2, exclude_none: bool = True, ensure_ascii: bool = False, encoding: str = "utf-8",) -> None:
        """Serialize to JSON and write to `path`."""
        path.write_text(
            self.to_json(indent=indent, exclude_none=exclude_none, ensure_ascii=ensure_ascii),
            encoding=encoding,
        )

# ---------- Argument parsing ----------
def parse_args():
    default_outdir = Path(f"classification_{datetime.now(timezone.utc).astimezone().strftime("%Y_%m_%d_%H:%M")}")
    p = argparse.ArgumentParser(description="POIROT output dir-> vulnerability assessment via Jadx/Ghidra MCP")
    p.add_argument("target_APK", type=Path, help="Path to the POIROT output folder (containing the APPNAME/ subfolders)")

    p.add_argument("--apk-list", type=Path, default=None, help="Path to a .txt file containing the list of APKs/APPNAMEs to be included (one per line)." )
    p.add_argument("-m", "--model-name", type=str, default=os.getenv("LLM_MODEL_NAME", "gpt-5"), help="LLM model name (default: env LLM_MODEL_NAME or gemini-2.5-flash)")
    p.add_argument("-o", "--out-dir", type=Path, default=default_outdir, help="Base directory for reports. If not provided, a directory named 'classification_YYYY_MM_DD_HH:MM' will be created.")
    p.add_argument("--timeout", type=int, default=180, help="Timeout (seconds) for MCP servers")
    # p.add_argument("--threads", type=int, default=1, help="Number of worker threads (>=1). 1 = single execution in the current thread.")
    # p.add_argument("--headless", action="store_true", help="Do NOT open Jadx GUI (requires that Jadx MCP can operate headlessly)")
    p.add_argument("-d", "--debug", action="store_true", help="Enable verbose debug logs")
    p.add_argument("-v", "--verbose", action="store_true", help="Echo system/user prompts and model outputs")
    return p.parse_args()

# ---------- Orchestration ----------

async def run_assessment(apk: Path, appMetadata: AppMetadata, backtraces: Path, args) -> AnalysisEnvelope:
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
    backtraces : pathlib.Path
        Path to folder2backtraces.txt for a single JNI-driven crash.
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
    if not backtraces.is_file():
        print_message(RED, "ERROR", f"Crash file not found: {backtraces}")
        sys.exit(1)

    # Parse crash report
    crashes = Crashes(backtraces)
                
    # Prepare native libs via APK extraction
    print_message(BLUE, "INFO", f"Extracting .so files from APK: {apk}")
    with tempfile.TemporaryDirectory(prefix="apk_so_") as td:
        workdir = Path(td)
        so_paths = extract_so_files(apk, workdir)
        # if args.debug:
        #     for pth in so_paths:
        #         print_message(GREEN, "SO", f"found {pth}")
        relevant_libs_map = find_relevant_libs(so_paths, crashes=crashes, debug=args.debug)
        if not relevant_libs_map:
            print_message(YELLOW, "WARN", "No relevant libs identified; Returning empty assessment.")
            analysisResults = AnalysisResults()
            tool = ToolInfo(model_name=args.model_name, apk_path=str(apk), version=TOOL_VERSION)
            envelope = AnalysisEnvelope(
                analysis=AnalysisBlock(app=appMetadata, analysisResults=analysisResults, tool=tool, relevant_libs=[] )
            )
            return envelope
        
        if args.debug:
            for lib, methods in relevant_libs_map.items():
                print_message(CYAN, "DEBUG", f"Lib: {lib}, Methods: {methods}")                
                    
        print_message(BLUE, "INFO", f"Starting vulnerability assessment for {len(crashes)} crash entries...")
        
        try:
            analysisResults : AnalysisResults = await mcp_vuln_assessment(model_name=args.model_name, crashes=crashes, relevant_libs_map=relevant_libs_map, timeout=args.timeout, verbose=args.verbose, debug=args.debug)
        except Exception as e:
            handle_model_errors(e)
        
        tool = ToolInfo(model_name=args.model_name, apk_path=str(apk), version=TOOL_VERSION)
        envelope = AnalysisEnvelope(
            analysis=AnalysisBlock(app=appMetadata, analysisResults=analysisResults, tool=tool, relevant_libs_map=relevant_libs_map)
        )
    print_message(BLUE, "INFO", f"Assessment completed. Summary:")
    return envelope
    
    
def _normalize_name_for_filter(s: str) -> str:
    """Normalize a --apk-list line so it can be matched with APPNAME or the APK filename."""
    s = s.strip()
    if not s:
        return ""
    base = os.path.basename(s)
    # strip trailing ".apk" if present
    if base.lower().endswith(".apk"):
        base = base[:-4]
    if base.startswith("#"):
        return ""
    return base

def load_filter_set(apk_list_path: Optional[Path], *, debug: bool=False) -> Optional[set]:
    """Load a set of names from --apk-list (APPNAME or APK name without extension)."""
    if not apk_list_path:
        return None
    if not apk_list_path.is_file():
        print_message(YELLOW, "WARN", f"--apk-list not found: {apk_list_path}")
        return None
    names = set()
    for line in apk_list_path.read_text(encoding="utf-8").splitlines():
        name = _normalize_name_for_filter(line)
        if name:
            names.add(name)
    if debug:
        print_message(GREEN, "DEBUG", f"Filter loaded with {len(names)} entries from --apk-list")
    return names or None

def find_backtrace_apk_pairs(target_apk_dir: Path, *, apk_filter: Optional[set]=None, debug: bool=False):
    """
    Return a list of tuples: (path_to_folder2backtraces_txt, path_to_base_apk).

    Expected structure:
      target_APK/
        ├── APPNAME/
            ├── base.apk
            └── fuzzing_output/
                └── <case_dir>/
                    └── reproduced_crashes/
                        └── folder2backtraces.txt

    Rules:
    - Only consider <case_dir> names matching _CASE_DIR_RE.
    - Only include cases that contain 'reproduced_crashes/folder2backtraces.txt'.
    - If apk_filter is provided, keep only apps whose APPNAME or APK basename (without .apk) is in the filter.
    - If debug=True, print selected directories and summary counts.
    """
    results = []

    if not target_apk_dir.is_dir():
        print_message(RED, "ERROR", f"target_APK is not a valid directory: {target_apk_dir}")
        return results

    for app_dir in sorted(target_apk_dir.iterdir()):
        if not app_dir.is_dir():
            continue
        appname = app_dir.name

        base_apk = app_dir / "base.apk"
        if not base_apk.is_file():
            if debug:
                print_message(YELLOW, "WARN", f"base.apk not found for {appname} in {app_dir}")
            continue

        # Apply --apk-list filter (match APPNAME or APK stem)
        if apk_filter:
            base_stem = base_apk.stem
            if (appname not in apk_filter) and (base_stem not in apk_filter):
                continue

        fuzz_dir = app_dir / "fuzzing_output"
        if not fuzz_dir.is_dir():
            # if debug:
            #     print_message(YELLOW, "WARN", f"fuzzing_output not found for {appname}")
            continue

        for case_dir in sorted(fuzz_dir.iterdir()):
            if not case_dir.is_dir():
                continue
            if not _CASE_DIR_RE.match(case_dir.name):
                continue

            reproduced = case_dir / "reproduced_crashes"
            bt_file = reproduced / "folder2backtraces.txt"
            if bt_file.is_file():
                results.append((bt_file, base_apk))
                if debug:
                    print_message(GREEN, "SELECTED", f"{appname} : {case_dir.name}")

    print_message(BLUE, "INFO", f"Found {len(results)} (folder2backtraces.txt, base.apk) pairs")
    return results

    # --- Single job runner (used by workers or sequential mode) ---
def _run_single(pair, appMetadata : AppMetadata, out_root : Path, args, debug=False) -> None:
    """Run the assessment for a single (backtraces, apk) pair."""
    backtraces, apk = pair
    appname = apk.parent.name
    case_dir_name = backtraces.parent.parent.name  # .../reproduced_crashes/.. -> case dir

    # Final path: out_root/APPNAME/<case_dir>/report.json
    final_dir = out_root / appname / case_dir_name
    final_dir.mkdir(parents=True, exist_ok=True)
    final_json = final_dir / "report.json"

    if debug:
        print_message(BLUE, "INFO", f"Starting assessment: {appname} @ {case_dir_name}")
    result = asyncio.run(run_assessment(apk, appMetadata, backtraces, args))
    result.to_json_file(final_json)
    if debug:
        print_message(GREEN, "DONE", f"Wrote {final_json}")

def run(args):
    """Run the full assessment for all APKs in target_APK."""
    
    out_root = args.out_dir
    out_root.mkdir(parents=True, exist_ok=True)
    print_message(BLUE, "INFO", f"Output root: {out_root}")
        
    # --- Optional filter set ---
    apk_filter = load_filter_set(args.apk_list, debug=args.debug)

    # --- Discover pairs (backtraces, apk) ---
    pairs = find_backtrace_apk_pairs(args.target_APK, apk_filter=apk_filter, debug=args.debug)
    if not pairs:
        print_message(YELLOW, "WARN", "No pairs found. Exiting.")
        sys.exit(0)
        

    # --- Execution: single or multi-thread ---
    # n_threads = max(1, int(args.threads or 1))
    # if n_threads == 1:
    if args.debug:
        print_message(GREEN, "DEBUG", "Running single-thread (method: asyncio.run per job).")
        
    previous_appname = None
    previous_appMetadata = None
    for pair in pairs:
        apk = pair[1]
        appname = apk.parent.name
        
        if appname == previous_appname:
            if args.debug:
                print_message(GREEN, "DEBUG", f"Re-using previous appMetadata for {appname}")
            appMetadata = previous_appMetadata
        else:
            # Open Jadx GUI to make the project available to Jadx MCP
            if args.debug:
                print_message(BLUE, "INFO", f"Killing (if any) and re-opening Jadx GUI for {appname}")
            kill_jadx()  # kill previous instance (if any)
            start_jadx_gui(str(apk))
            # Extract metadata via Jadx MCP
            
            try:
                appMetadata = asyncio.run(get_jadx_metadata(model_name=args.model_name, verbose=args.verbose, debug=args.debug))      
            except Exception as e:
                handle_model_errors(e)
        
        _run_single(pair, appMetadata, out_root, args, debug=args.debug)
        previous_appname = appname
        previous_appMetadata = appMetadata
        
    """
    else:
        if args.debug:
            print_message(GREEN, "DEBUG", f"Running multi-thread with {n_threads} threads (method: asyncio.run per job).")
        print_message(RED, "NOT IMPLEMENTED", "Multi-threaded execution is not yet implemented.")
        sys.exit(1)
        # Fair split across threads
        chunks = [[] for _ in range(n_threads)]
        for i, pair in enumerate(pairs):
            chunks[i % n_threads].append(pair)

        if args.debug:
            for i, ch in enumerate(chunks, start=1):
                print_message(GREEN, "DEBUG", f"Thread {i} gets {len(ch)} items.")

        def _worker(idx, chunk):
            if args.debug:
                print_message(BLUE, "INFO", f"Thread {idx} started (method: asyncio.run per job).")
            for pair in chunk:
                _run_single(pair, out_root, args, debug=args.debug)

        with ThreadPoolExecutor(max_workers=n_threads) as ex:
            futures = [ex.submit(_worker, i+1, chunks[i]) for i in range(n_threads)]
            for fut in as_completed(futures):
                exc = fut.exception()
                if exc:
                    print_message(RED, "ERROR", f"Worker raised an exception: {exc}")
                    # Keep going; other workers may still complete.
                    
    """

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
    
    run(args)
    
    #cleanup_temp_dirs()
    shutil.rmtree('/pyghidra_mcp_projects', ignore_errors=True)


if __name__ == "__main__":
    main()
