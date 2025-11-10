"""
Module overview:
- Purpose: Provide high-level description of this module.
- Important classes/functions are documented inline.
"""

import json
import os
import re
import sys
from typing import Optional
from pydantic import BaseModel
from pydantic_ai.mcp import MCPServerStdio

from MCPs.geminiCLI import query_gemini_cli
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

class AppMetadata(BaseModel):
    """
    Metadata about an Android app extracted from Jadx.
    """
    # app_name (str): App name.
    # Fields
    # - **app_name** (str): App name.
    # - **package** (str): Package.
    # - **min_sdk** (Optional[int]): Min sdk.
    # - **target_sdk** (Optional[int]): Target sdk.
    # - **version_name** (Optional[str]): Version name.
    # - **version_code** (Optional[str]): Version code.
    """
    Str.
    
    Returns:
        Any: Description.
    """
    app_name: str
    package: str
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    
    def __str__(self) -> str:
        fields = [
            f"App Name     : {self.app_name}",
            f"Package      : {self.package}",
            f"Min SDK      : {self.min_sdk}" if self.min_sdk is not None else "Min SDK: N/A",
            f"Target SDK   : {self.target_sdk}" if self.target_sdk is not None else "Target SDK: N/A",
            f"Version Name : {self.version_name}" if self.version_name is not None else "Version Name: N/A",
            f"Version Code : {self.version_code}" if self.version_code is not None else "Version Code: N/A",
        ]
        return "AppMetadata : \n" + "\n".join(fields)
    
    def to_json(self, *, indent: int = 2, exclude_none: bool = True, ensure_ascii: bool = False, ) -> str:
        """
        Serialize this AppMetadata to a JSON string.
        - exclude_none=True drops unset optional fields
        - indent provides pretty-printing
        """
        data = self.model_dump(exclude_none=exclude_none)
        return json.dumps(data, indent=indent, ensure_ascii=ensure_ascii)

async def get_jadx_metadata(model_name: Optional[str] = None, verbose: bool = False, debug: bool = False) -> AppMetadata:
    """Return app metadata from Jadx."""
    server: MCPServerStdio = make_jadx_server()
    
    
    if model_name == "gemini-cli":
        gemini_output = query_gemini_cli(JADX_APP_METADATA, "Extract app metadata from the currently open Jadx project.", AppMetadata, verbose=verbose, debug=debug)
    
        if verbose: print_message(PURPLE, "RESPONSE", str(gemini_output))
        
        return gemini_output
    else:
        if verbose: print_message(BLUE, "PROMPT", JADX_APP_METADATA)
        async with get_agent(JADX_APP_METADATA, AppMetadata, [server], model_name=model_name) as j_agent:
            j_meta = await j_agent.run("Extract app metadata from the currently open Jadx project.")
        appMetadata: AppMetadata = j_meta.output
            
        if verbose: print_message(PURPLE, "RESPONSE", str(appMetadata))
        
        if debug:
            print_message(GREEN, "LLM-USAGE", j_meta.usage())
                
        return appMetadata

class JNILibCandidates(BaseModel):
    # libraries (list[str]): Libraries.
    """
    This class encapsulates structured data and business rules.
    All attributes are validated and documented inline.
    """
    libraries: list[str]  # without lib prefix and .so suffix