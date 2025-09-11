import asyncio
import os
import sys
from pydantic import BaseModel
from pydantic_ai.mcp import MCPServerStdio

from utils import *
from .prompts.jadx_prompts import *
from .get_agent import get_agent

# export JADX_MCP_DIR="/home/nicola/Desktop/Tesi/jadx-ai-mcp/jadx-mcp-server-v3.1.0/jadx-mcp-server"
jadx_dir = os.getenv("JADX_MCP_DIR")
if not jadx_dir:
    print_message(RED, "ERROR", "Environment variable 'JADX_MCP_DIR' is not set.")
    sys.exit()

jadx_server = MCPServerStdio(
    "uv",
    args=["--directory", os.environ["JADX_MCP_DIR"], "run", "jadx_mcp_server.py"],
    timeout=30,
)


class AppInfo(BaseModel):
    app_name: str
    package: str


# print("Jadx tools:")
# toolList = asyncio.run(jadx_server.list_tools())
# for tool in toolList:
#     print(f" - {tool.name}")


agent = get_agent(JADX_EXTRACT_APP_NAME, AppInfo, [jadx_server])


async def test_jadx():
    async with agent:
        result = await agent.run(
            "Retrieve the app name and package from the current JADX project."
        )
        print_message(PURPLE, "RESPONSE", result.output)


# asyncio.run(test_jadx())
