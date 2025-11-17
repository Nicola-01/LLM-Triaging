"""
Module overview:
- Purpose: Provide high-level description of this module.
- Important classes/functions are documented inline.
"""


import os
from typing import Optional
from pydantic import BaseModel
from pydantic_ai.mcp import MCPServerStdio

from MCPs.AppMetadata import AppMetadata
from MCPs.geminiCLI import query_gemini_cli
from MCPs.shimming_agent import oss_model
from utils import *
from .prompts.jadx_prompts import *
from .get_agent import get_agent

# export JADX_MCP_DIR="/path/to/jadx-mcp-server"
def make_jadx_server(timeout: int = 60) -> MCPServerStdio:
    """
    Start the Jadx MCP server using uv, assuming the environment variable JADX_MCP_DIR is set.
    """
    jadx_dir = os.getenv("JADX_MCP_DIR")
    return MCPServerStdio(
        "uv",
        args=["--directory", jadx_dir, "run", "jadx_mcp_server.py"],
        timeout=timeout,
    )

async def get_jadx_metadata(model_name: Optional[str] = None, verbose: bool = False, debug: bool = False) -> AppMetadata:
    """Return app metadata from Jadx."""
    server: MCPServerStdio = make_jadx_server()
    
    if verbose: print_message(BLUE, "PROMPT", JADX_APP_METADATA)
    if model_name == "gemini-cli":       
        appMetadata = query_gemini_cli(JADX_APP_METADATA, "Extract app metadata from the currently open Jadx project.", AppMetadata, verbose=verbose, debug=debug)
    elif (model_name.startswith("gpt-") and not model_name.startswith("gpt-oss")) or (model_name.startswith("gemini-")):
        async with get_agent(JADX_APP_METADATA, AppMetadata, [server], model_name=model_name) as j_agent:
            j_meta = await j_agent.run("Extract app metadata from the currently open Jadx project.")
        appMetadata: AppMetadata = j_meta.output

        if debug:
            print_message(GREEN, "LLM-USAGE", j_meta.usage())
            
    else: #Open model -> need shimming agent
        appMetadata: AppMetadata = await oss_model(system_prompt=JADX_APP_METADATA, prompt="Extract app metadata from the currently open Jadx project.", 
                                             output_type=AppMetadata, onlyJadx=True, model_ulr=os.getenv('OLLAMA_BASE_URL'), model_name=model_name, debug=debug)
    
    if verbose: print_message(PURPLE, "RESPONSE", str(appMetadata))
    return appMetadata
        

class JNILibCandidates(BaseModel):
    # libraries (list[str]): Libraries.
    """
    This class encapsulates structured data and business rules.
    All attributes are validated and documented inline.
    """
    libraries: list[str]  # without lib prefix and .so suffix