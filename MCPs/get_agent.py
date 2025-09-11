import os
import sys
from pydantic_ai import Agent
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.mcp import MCPServerStdio
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *

# export LLM_API_KEY="your-api-key"
api_key = os.getenv("LLM_API_KEY")
if not api_key:
    print_message(RED, "ERROR", "Environment variable 'LLM_API_KEY' is not set.")
    sys.exit()
    
llm_model_name = os.getenv("LLM_MODEL_NAME", "gemini-2.5-flash")

def get_agent(system_prompt: str, output_type, toolsets: list[MCPServerStdio]) -> Agent:  
    model = GoogleModel(llm_model_name, provider=GoogleProvider(api_key=api_key))
    return Agent(
            model, 
            system_prompt=system_prompt,
            output_type=output_type,
            toolsets=toolsets
        )