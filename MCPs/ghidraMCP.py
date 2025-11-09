"""
Module overview:
- Purpose: Provide high-level description of this module.
- Important classes/functions are documented inline.
"""

import os
import sys
from typing import List
from pydantic import BaseModel
from pydantic_ai.mcp import MCPServerStdio

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
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
    
    # if not files:
    #     print_message(RED, "ERROR", "make_ghidra_server() requires at least one file path.")
    #     sys.exit(1)

    # quoted = " ".join([f'"{f}"' for f in files])
    
    """
    os.environ["FILES"] = quoted
    print(os.environ["FILES"])
    
    redir = "" if verbose else "2>/dev/null"
    
    # Clean up old projects
    shutil.rmtree('/pyghidra_mcp_projects', ignore_errors=True)
    
    cmd = f'uvx --quiet pyghidra-mcp -t stdio {quoted} {redir}'
    
    if debug:
        print_message(CYAN, "DEBUG", f"Starting Ghidra MCP server with command: {cmd}")

    return MCPServerStdio(
        "bash",
        args=["-lc", cmd],
        env={"GHIDRA_INSTALL_DIR": ghidra_dir},
        timeout=timeout,
    )
    """

class GhidraFunctionList(BaseModel):
    # methods (list[str]): Methods.
    """
    Ghidra function list.
    
    This class encapsulates structured data and business rules.
    All attributes are validated and documented inline.
    """
    methods: list[str]