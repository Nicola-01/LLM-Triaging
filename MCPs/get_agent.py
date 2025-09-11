from pydantic_ai import Agent
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.mcp import MCPServerStdio

# Read the API key from the file
with open("../api.key", "r") as file:
    api_key = file.read().strip()

# Raise an error if the key is missing
if not api_key or api_key == "your-api-key":
    raise ValueError("API key is missing. Please add your API key to the 'api.key' file.")


def get_agent( output_type, toolsets: list[MCPServerStdio]):
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
    
    model = GoogleModel('gemini-1.5-flash', provider=GoogleProvider(api_key=api_key))
    return Agent(
            model, 
            system_prompt=SYSTEM_PROMPT,
            toolsets=toolsets
        )