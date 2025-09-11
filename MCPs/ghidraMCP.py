import asyncio
import os
import sys
from pydantic import BaseModel
from pydantic_ai.mcp import MCPServerStdio

from utils import *
from .get_agent import get_agent
from .prompts.ghidra_prompts import *

# export GHIDRA_INSTALL_DIR="/snap/ghidra/current/ghidra_11.4_PUBLIC"
ghidra_dir = os.getenv("GHIDRA_INSTALL_DIR")
if not ghidra_dir:
    print_message(RED, "ERROR", "Environment variable 'GHIDRA_INSTALL_DIR' is not set.")
    sys.exit()

SILENT = True
GHIDRA_FILES = "/home/nicola/Desktop/Tesi/test/libmylib.so"

redir = "2>/dev/null" if SILENT else ""
cmd = f'uvx --quiet pyghidra-mcp -t stdio "{GHIDRA_FILES}" {redir}'

ghidra_server = MCPServerStdio(
    "bash",
    args=["-lc", cmd],
    env={"GHIDRA_INSTALL_DIR": ghidra_dir},
    timeout=60,
)


class AppInfo(BaseModel):
    methods: list[str]


# print("Ghidra tools:")
# toolList = asyncio.run(ghidra_server.list_tools())
# for tool in toolList:
#     print(f" - {tool.name}")

agent = get_agent(GHIDRA_FUNCTION_ANALYZER, AppInfo, [ghidra_server])


async def test_ghidra():
    async with agent:
        result = await agent.run(
            "What are the methods in libmylib.so using ghidra mcp?"
        )
        print_message(PURPLE, "RESPONSE", result.output)


# asyncio.run(test_ghidra())
