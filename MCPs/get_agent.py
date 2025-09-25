import os
import sys
from typing import Optional, List
from pydantic_ai import Agent
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.mcp import MCPServerStdio
from utils import *

def get_agent(system_prompt: str, output_type, toolsets: List[MCPServerStdio], model_name: Optional[str] = None) -> Agent:
    """
    Create a Pydantic-AI Agent with the given MCP toolsets.
    If model_name is None, falls back to env LLM_MODEL_NAME or 'gemini-2.5-flash'.
    """
    llm_model_name = model_name or os.getenv("LLM_MODEL_NAME", "gemini-2.5-flash")
    model = GoogleModel(llm_model_name, provider=GoogleProvider(api_key=os.getenv("LLM_API_KEY")))
    return Agent(
        model,
        system_prompt=system_prompt,
        output_type=output_type,
        toolsets=toolsets,
    )
