import os
import sys
from typing import List
from pydantic import BaseModel
from pydantic_ai.mcp import MCPServerStdio

from utils import *
from .get_agent import get_agent
from .prompts.ghidra_prompts import GHIDRA_FUNCTION_ANALYZER, GHIDRA_VULN_ASSESSMENT

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
    cmd = f'uvx --quiet pyghidra-mcp -t stdio {quoted} {redir}'

    return MCPServerStdio(
        "bash",
        args=["-lc", cmd],
        env={"GHIDRA_INSTALL_DIR": ghidra_dir},
        timeout=timeout,
    )

class GhidraFunctionList(BaseModel):
    methods: list[str]

# def get_ghidra_functions_agent(files: List[str]):
#     """Quick agent to list functions; useful for smoke tests."""
#     server = make_ghidra_server(files)
#     return get_agent(GHIDRA_FUNCTION_ANALYZER, GhidraFunctionList, [server])

