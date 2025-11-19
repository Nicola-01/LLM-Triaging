import asyncio
from llama_index.tools.mcp import BasicMCPClient

JADX_MCP = "JADX_MCP"
GHIDRA_MCP = "GHIDRA_MCP"

mcp_clients = {}
mcp_clients[JADX_MCP] = BasicMCPClient("http://127.0.0.1:8651/sse")
mcp_clients[GHIDRA_MCP] = BasicMCPClient("http://127.0.0.1:8081/sse")

data = {
    "action": "search_string",
    "args": {
        "string_name": "wednesday",
        "contains" : False
        },
}

# print(f"action: {data["action"]}")
# print(f"args: {data["args"]}")

async def main():
    response = await mcp_clients[JADX_MCP].call_tool(data["action"], data["args"])
    print(response)

if __name__ == "__main__":
    asyncio.run(main())

# python3 $JADX_MCP_DIR/jadx_mcp_server.py --sse
# python3 $GHIDRA_MCP_DIR/bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/