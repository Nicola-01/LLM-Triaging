import asyncio
import os
import sys
from pydantic import BaseModel
from pydantic_ai.mcp import MCPServerStdio
from get_agent import get_agent
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *

# export GHIDRA_INSTALL_DIR="/snap/ghidra/current/ghidra_11.4_PUBLIC"
ghidra_dir = os.getenv("GHIDRA_INSTALL_DIR")
if not ghidra_dir:
    print_message(RED, "ERROR", "Environment variable 'GHIDRA_INSTALL_DIR' is not set.")
    sys.exit()

SILENT = True
GHIDRA_FILES="/home/nicola/Desktop/Tesi/test/libmylib.so"

redir = "2>/dev/null" if SILENT else ""
cmd = f'uvx --quiet pyghidra-mcp -t stdio "{GHIDRA_FILES}" {redir}'

ghidra_server = MCPServerStdio(
    'bash',
    args=['-lc', cmd],
    env={"GHIDRA_INSTALL_DIR": ghidra_dir},
    timeout=60,
)

    
SYSTEM_PROMPT = """
You are an expert in reverse engineering using Ghidra.
Your task is to analyze the provided binary and extract relevant information about its functions and methods.
Respond exclusively by populating the output schema.
"""

class AppInfo(BaseModel):
    methods: list[str]
    

# print("Ghidra tools:")
# toolList = asyncio.run(ghidra_server.list_tools())
# for tool in toolList:
#     print(f" - {tool.name}")
    
agent = get_agent(SYSTEM_PROMPT, AppInfo, [ghidra_server])

async def test():
    async with agent:
        result = await agent.run("What are the methods in libmylib.so using ghidra mcp?")
    print(result.output)
    
asyncio.run(test())