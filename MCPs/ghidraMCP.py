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

from utils import *
from .get_agent import get_agent
from .prompts.ghidra_prompts import GHIDRA_VULN_ASSESSMENT

# export GHIDRA_INSTALL_DIR="/snap/ghidra/current/ghidra_11.4_PUBLIC"
def make_ghidra_server(files: List[str], verbose: bool = False, timeout: int = 120) -> MCPServerStdio:
    """
    Build a Ghidra MCP server for the given list of binaries (.so, executables).
    It uses uvx pyghidra-mcp -t stdio "<file1>" "<file2>" ...
    """
    ghidra_dir = os.getenv("GHIDRA_INSTALL_DIR")

    if not files:
        print_message(RED, "ERROR", "make_ghidra_server() requires at least one file path.")
        sys.exit(1)

    quoted = " ".join([f'"{f}"' for f in files])
    redir = "" if verbose else "2>/dev/null"
    
    # Clean up old projects
    shutil.rmtree('/pyghidra_mcp_projects', ignore_errors=True)
    
    cmd = f'uvx --quiet pyghidra-mcp -t stdio {quoted} {redir}'

    return MCPServerStdio(
        "bash",
        args=["-lc", cmd],
        env={"GHIDRA_INSTALL_DIR": ghidra_dir},
        timeout=timeout,
    )

class GhidraFunctionList(BaseModel):
    # methods (list[str]): Methods.
    """
    Ghidra function list.
    
    This class encapsulates structured data and business rules.
    All attributes are validated and documented inline.
    """
    methods: list[str]