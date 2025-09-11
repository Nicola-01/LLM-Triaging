import asyncio
from pydantic_ai import Agent
from pydantic import BaseModel
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.mcp import MCPServerStdio

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