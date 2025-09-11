import asyncio
from pydantic_ai import Agent
from pydantic import BaseModel
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.mcp import MCPServerStdio

jadx_server = MCPServerStdio(  
    'uv', 
    args=[
        '--directory', 
        '/home/nicola/Desktop/Tesi/jadx-ai-mcp/jadx-mcp-server-v3.1.0/jadx-mcp-server',
        'run', 
        'jadx_mcp_server.py'
    ], 
    timeout=30
)

GHIDRA_FILES="/home/nicola/Desktop/Tesi/test/libmylib.so"

ghidra_server = MCPServerStdio(  
    'uvx', 
    args=[
        'pyghidra-mcp', 
        '-t',
        'stdio', 
        GHIDRA_FILES
    ], 
    env={"GHIDRA_INSTALL_DIR": "/snap/ghidra/current/ghidra_11.4_PUBLIC"},
    timeout=60
)

# Read the API key from the file
with open("api.key", "r") as file:
    api_key = file.read().strip()

# Raise an error if the key is missing
if not api_key or api_key == "your-api-key":
    raise ValueError("API key is missing. Please add your API key to the 'api.key' file.")

# 3) Output schema
class AppInfo(BaseModel):
    app_name: str
    package: str
    
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

provider = GoogleProvider(api_key=api_key)
model = GoogleModel('gemini-1.5-flash', provider=provider)
agent = Agent(model, 
    system_prompt=SYSTEM_PROMPT,
    output_type=AppInfo,
    toolsets=[jadx_server]
    )


# print("Jadx tools:")
# toolList = asyncio.run(jadx_server.list_tools())
# for tool in toolList:
#     print(tool.name)
    
# print("Ghidra tools:")
# toolList = asyncio.run(ghidra_server.list_tools())
# for tool in toolList:
#     print(tool.name)
    

async def main():
    async with agent:
        result = await agent.run("Retrieve the app name and package from the current JADX project.")
    print(result.output)
    
asyncio.run(main())