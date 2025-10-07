"""
Module overview:
- Purpose: Provide high-level description of this module.
- Important classes/functions are documented inline.
"""

from typing import Optional, List
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.ollama import OllamaProvider

def get_agent(system_prompt: str, output_type, toolsets: List[MCPServerStdio], model_name: Optional[str] = None) -> Agent:
    """
    Get agent.
    
    Args:
        system_prompt: Description.
        output_type: Description.
        toolsets: Description.
        model_name: Description.
    
    Returns:
        Any: Description.
    """
    
    model = OpenAIChatModel(
        model_name='qwen3:8b',
        provider=OllamaProvider(base_url='http://localhost:11434/v1'),  
    )
    
    return Agent(
        model,
        system_prompt=system_prompt,
        output_type=output_type,
        toolsets=toolsets,
    )