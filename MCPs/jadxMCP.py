import asyncio
import os
import sys
from pydantic import BaseModel
from pydantic_ai.mcp import MCPServerStdio
from get_agent import get_agent
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *

# export JADX_MCP_DIR="/home/nicola/Desktop/Tesi/jadx-ai-mcp/jadx-mcp-server-v3.1.0/jadx-mcp-server"
jadx_dir = os.getenv("JADX_MCP_DIR")
if not jadx_dir:
    print_message(RED, "ERROR", "Environment variable 'JADX_MCP_DIR' is not set.")
    sys.exit()

jadx_server = MCPServerStdio(  
    'uv', 
    args=[
        '--directory', 
        os.environ["JADX_MCP_DIR"],
        'run', 
        'jadx_mcp_server.py'
    ], 
    timeout=30
)
    
SYSTEM_PROMPT = """
If you need to find the name of the app opened in JADX:
1) Call the MCP tool `get_android_manifest` to obtain the AndroidManifest.xml.
2) Extract the package from <manifest package="...">.
3) Find the app name:
   - If <application android:label="..."> is a literal string, use it.
   - If it is a reference like @string/xxx, call `get_strings()` and resolve the key.
4) If no valid label is found, return the package as a fallback for app_name.
Respond exclusively by populating the output schema.
"""

class AppInfo(BaseModel):
    app_name: str
    package: str


# print("Jadx tools:")
# toolList = asyncio.run(jadx_server.list_tools())
# for tool in toolList:
#     print(f" - {tool.name}")
   
   
agent = get_agent(SYSTEM_PROMPT, AppInfo, [jadx_server])

async def test():
    async with agent:
        result = await agent.run("Retrieve the app name and package from the current JADX project.")
    print(result.output)
    
asyncio.run(test())