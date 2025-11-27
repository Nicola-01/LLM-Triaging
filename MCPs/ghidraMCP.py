"""
Module overview:
- Purpose: Manage the Ghidra MCP server and run vulnerability detection analysis.
- Important functions: make_ghidra_server, mcp_vuln_detection.
"""

import os
import re
import sys
import tempfile
from typing import List
from pydantic import BaseModel
from pydantic_ai.mcp import MCPServerStdio

from MCPs.geminiCLI import GeminiCliMaxRetry, query_gemini_cli
from MCPs.jadxMCP import make_jadx_server
from MCPs.prompts.Shimming_prompts import SHIMMING_VULNDECT_SYSTEM_PROMPT
from MCPs.prompts.VulnDetection_prompt import DETECTION_SYSTEM_PROMPT
from MCPs.prompts.VulnDetection_prompt_WITHOUT_CG import DETECTION_SYSTEM_PROMPT_WITOUT_CG
from MCPs.shimming_agent import oss_model
from MCPs.VulnResult import AnalysisResult, AnalysisResults, Statistics, VulnResult
from ghidra_helper_functions import *
from .get_agent import get_agent

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from MCPs.CrashSummary import Crashes
from utils import *

# Shered dir with the ghidra mcp bridge
SHARED_DIR = os.path.join(tempfile.gettempdir(), "mcp_ghidra_share")
os.makedirs(SHARED_DIR, exist_ok=True)
FILE_AVAILABLE = os.path.join(SHARED_DIR, "available.txt")
FILE_CURRENT = os.path.join(SHARED_DIR, "current_lib.txt")

# export GHIDRA_INSTALL_DIR="/snap/ghidra/current/ghidra_11.4_PUBLIC"
def make_ghidra_server(debug: bool = False, verbose: bool = False, timeout: int = 120) -> MCPServerStdio: 
    """
    Build a Ghidra MCP server for the given list of binaries (.so, executables).
    It uses uvx pyghidra-mcp -t stdio "<file1>" "<file2>" ...
    """
    ghidra_mcp_dir = os.getenv("GHIDRA_MCP_DIR")
    ghidra_dir = os.getenv("GHIDRA_INSTALL_DIR")
    
    if not ghidra_mcp_dir:
        raise ValueError("GHIDRA_MCP_DIR environment variable is not set.")
    if not ghidra_dir:
        raise ValueError("GHIDRA_INSTALL_DIR environment variable is not set.")
        
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

def startGhidraWith(libs: List[str], debug: bool = False):
    
    sorted_libs = sorted(libs, key=lambda s: s.lower())
            
    openGhidraGUI(sorted_libs, timeout=60*(len(sorted_libs)+2), debug=debug)

    with open(FILE_AVAILABLE, "w", encoding="utf-8") as f:
        libs = "\n".join(sorted_libs)
        libs = re.sub(r'APKs/[^/]+/lib/[^/]+/', '', libs)
        f.write(libs)
                
    openGhidraFile(sorted_libs, sorted_libs[0], debug=debug)
    with open(FILE_CURRENT, "w", encoding="utf-8") as f:
        f.write(sorted_libs[0])
        
    if debug:
        print_message(CYAN, "DEBUG", f"Starting MCP servers with {len(sorted_libs)} relevant libs: {sorted_libs}")
    
async def mcp_vuln_detection(model_name: str, crashes : Crashes, timeout: int = 60, verbose: bool = False, debug: bool = False) -> AnalysisResults:
    """
    Run the assessment agent once, then feed it each CrashEntry (one by one).
    Returns a list of VulnDetection, in the same order as 'crashes'.
    """
    # Start MCP servers once
    ghidra_server = make_ghidra_server(timeout=timeout)
    jadx_server = make_jadx_server(timeout=timeout)

    create_agent = True
    
    results = AnalysisResults()
    last_libs_open = None
    for i, crash in enumerate(crashes, start=1):
        
        if create_agent:
            if crash.JavaCallGraph is None or len(crash.JavaCallGraph) == 0: # The call graph is the same for all the crashes of the same methods
                print_message(YELLOW, "WARNING", "No Java Call Graph detected, triaging without CG")
                agent = get_agent(DETECTION_SYSTEM_PROMPT_WITOUT_CG, VulnResult, [jadx_server, ghidra_server], model_name=model_name)
            else:
                agent = get_agent(DETECTION_SYSTEM_PROMPT, VulnResult, [jadx_server, ghidra_server], model_name=model_name)
            create_agent = False
        
        libs = crash.LibMap.keys()
        libs = sorted(libs, key=lambda s: s.lower())
        
        if len(libs) == 0:
            print_message(YELLOW, "Warning", f"The method {crash.JNIBridgeMethod}, is not in the .so files")
           
        # # Early skip if the Java call graph is empty     
        # if not (crash.JavaCallGraph is None) and len(crash.JavaCallGraph) == 0:
        #     vuln = VulnResult(
        #         chain_of_thought = [],
        #         is_vulnerable = 0,
        #         confidence = 1.0,
        #         reasons = [f"The {crash.JNIBridgeMethod} method is not accessible from Java code."],
        #         cwe_ids = [],
        #         severity = None,
        #         affected_libraries = libs,
        #         evidence = [],
        #         recommendations = [],
        #         assumptions = [],
        #         limitations = []
        #     )
        #     results.append(AnalysisResult(crash=crash, assessment=vuln, statistics=Statistics()))
        #     continue
                
        if last_libs_open is None or set(last_libs_open) != set(libs):
            startGhidraWith(libs,debug=debug)
            last_libs_open = libs
        start = time.time()
        
        crash_str = str(crash)
        print_message(BLUE, "INFO", f"Assessing crash #{i}") 

        query = (
            f"Assess the following crash and provide a vulnerability assessment in the specified format.\n"
            f"{crash_str}"
        )

        if verbose:
            print_message(CYAN, "QUERY", f"{query}")

        if agent:
            async with agent:
                try:
                    resp = await agent.run(query)
                    vuln = resp.output
                except Exception as e:
                    if debug:
                        print_message(RED, "ERROR", str(e))
                    continue
                
            usage = resp.usage()
            statistics=Statistics(
                time=time.strftime('%H:%M:%S', time.gmtime(time.time() - start)),
                llm_requests=usage.requests,
                llm_tool_calls=usage.tool_calls,
                input_tokens=usage.input_tokens, 
                output_tokens=usage.output_tokens
            )
            
            results.append(AnalysisResult(crash=crash, assessment=vuln, statistics=statistics))
        elif model_name == "gemini-cli":
            try:
                vuln, stats = query_gemini_cli(DETECTION_SYSTEM_PROMPT, query, VulnResult, verbose=verbose, debug=debug)
            except GeminiCliMaxRetry:
                continue
            
            statistics=Statistics(
                time=time.strftime('%H:%M:%S', time.gmtime(time.time() - start)),
                llm_tool_calls=stats.get("tool_calls"),
                input_tokens=stats.get("input_tokens"), 
                output_tokens=stats.get("output_tokens")
            )
            results.append(AnalysisResult(crash=crash, assessment=vuln, statistics=statistics))
        else:
            print_message(RED,"oss",model_name)
            is_oss_model = True
            vuln: VulnResult = await oss_model(system_prompt=SHIMMING_VULNDECT_SYSTEM_PROMPT, prompt=query, 
                                        output_type=VulnResult, model_ulr=os.getenv('OLLAMA_BASE_URL'), model_name=model_name, debug=debug)
            statistics=Statistics(time=time.strftime('%H:%M:%S', time.gmtime(time.time() - start)))
            results.append(AnalysisResult(crash=crash, assessment=vuln, statistics=statistics))        

        if verbose:
            print_message(PURPLE, "RESPONSE", vuln)
        if debug:
            print_message(BLUE, "USAGE", statistics)
            
        
    closeGhidraGUI(debug=debug)

    return results

class GhidraFunctionList(BaseModel):
    """
    Ghidra function list.
    
    This class encapsulates structured data and business rules.
    All attributes are validated and documented inline.
    """
    methods: list[str]