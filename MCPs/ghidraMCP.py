"""
Module overview:
- Purpose: Provide high-level description of this module.
- Important classes/functions are documented inline.
"""

import os
import re
import sys
from typing import List
from pydantic import BaseModel
from pydantic_ai.mcp import MCPServerStdio

from MCPs.geminiCLI import GeminiCliMaxRetry, query_gemini_cli
from MCPs.jadxMCP import make_jadx_server
from MCPs.prompts.vulnDetection_prompts import DETECTION_SYSTEM_PROMPT
from MCPs.vulnDetection import AnalysisResult, AnalysisResults, VulnDetection
from ghidraMCP_helper_functions import *
from .get_agent import get_agent

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from CrashSummary import Crashes
from utils import *

# export GHIDRA_INSTALL_DIR="/snap/ghidra/current/ghidra_11.4_PUBLIC"
def make_ghidra_server(debug: bool = False, verbose: bool = False, timeout: int = 120) -> MCPServerStdio: # files: List[str], 
    """
    Build a Ghidra MCP server for the given list of binaries (.so, executables).
    It uses uvx pyghidra-mcp -t stdio "<file1>" "<file2>" ...
    """
    ghidra_mcp_dir = os.getenv("GHIDRA_MCP_DIR")
    ghidra_dir = os.getenv("GHIDRA_INSTALL_DIR")
        
    return MCPServerStdio(
        "python3",
        args=[
            f"{ghidra_mcp_dir}/bridge_mcp_ghidra.py",
            "--ghidra-server",
            "http://127.0.0.1:8080/",
        ],
        env={"GHIDRA_INSTALL_DIR": ghidra_dir},
        timeout=timeout,
    )
    
async def mcp_vuln_detection(model_name: str, crashes : Crashes, relevant_libs_map: Dict[Path, List[str]], timeout: int = 60, verbose: bool = False, debug: bool = False) -> AnalysisResults:
    """
    Run the assessment agent once, then feed it each CrashEntry (one by one).
    Returns a list of VulnDetection, in the same order as 'crashes'.
    """
    # Start MCP servers once
    
    if debug:
        print_message(CYAN, "DEBUG", f"Starting MCP servers with {len(relevant_libs_map.keys())} relevant libs: {list(relevant_libs_map.keys())}")
    ghidra_server = make_ghidra_server(timeout=timeout) #[str(p) for p in relevant_libs_map.keys()],  debug=debug, verbose=debug)
    jadx_server = make_jadx_server(timeout=timeout)

    results = AnalysisResults()

    # if verbose: print_message(BLUE, "SYSTEM_PROMPT", DETECTION_SYSTEM_PROMPT)

    sorted_libs = sorted(str(p) for p in relevant_libs_map.keys())
        
    openGhidraGUI(sorted_libs, timeout=45*(len(sorted_libs)+1), debug=debug)
    for lib in sorted_libs:
        openGhidraFile(sorted_libs, lib, debug=debug)
        
    if model_name != "gemini-cli":
        async with get_agent(DETECTION_SYSTEM_PROMPT, VulnDetection, [jadx_server, ghidra_server], model_name=model_name) as agent:
            for i, crash in enumerate(crashes, start=1):
                crash_str = str(crash)
                print_message(BLUE, "INFO", f"Assessing crash #{i}") 

                libs_map = "\n".join([f"- {re.sub(r'/tmp/apk_so_.*/', '', str(lib))}: {relevant_libs_map[lib]}" 
                                    for lib in relevant_libs_map.keys()])

                query = (
                    f"Assess the following crash and provide a vulnerability assessment in the specified format.\n"
                    f"{crash_str}\n"
                    f"This is a map where each key is a Path to a relevant .so library, "
                    f"and the value is the list of JNI methods it implements: \n{libs_map}"
                )

                if verbose:
                    print_message(CYAN, "QUERY", f"{query}")

                try:
                    resp = await agent.run(query)
                    vuln = resp.output
                    if debug:
                        print_message(GREEN, "LLM-USAGE", resp.usage())
                except Exception as e:
                    if debug:
                        print_message(RED, "ERROR", str(e))
                    continue

                results.append(AnalysisResult(crash=crash, assessment=vuln))

                if verbose:
                    print_message(PURPLE, "RESPONSE", vuln)
    else:  # Non-async case for gemini-cli
        for i, crash in enumerate(crashes, start=1):
            crash_str = str(crash)
            print_message(BLUE, "INFO", f"Assessing crash #{i}") 

            libs_map = "\n".join([f"- {re.sub(r'/tmp/apk_so_.*/', '', str(lib))}: {relevant_libs_map[lib]}" 
                                for lib in relevant_libs_map.keys()])

            query = (
                f"Assess the following crash and provide a vulnerability assessment in the specified format.\n"
                f"{crash_str}\n"
                f"This is a map where each key is a Path to a relevant .so library, "
                f"and the value is the list of JNI methods it implements: \n{libs_map}"
            )

            if verbose:
                print_message(CYAN, "QUERY", f"{query}")

            try:
                resp = query_gemini_cli(DETECTION_SYSTEM_PROMPT, query, VulnDetection, verbose=verbose, debug=debug, realTimeOutput=True)
                vuln = resp
            except GeminiCliMaxRetry:
                continue

            results.append(AnalysisResult(crash=crash, assessment=vuln))

            if verbose:
                print_message(PURPLE, "RESPONSE", vuln)

    closeGhidraGUI(debug=debug)

    return results

class GhidraFunctionList(BaseModel):
    # methods (list[str]): Methods.
    """
    Ghidra function list.
    
    This class encapsulates structured data and business rules.
    All attributes are validated and documented inline.
    """
    methods: list[str]