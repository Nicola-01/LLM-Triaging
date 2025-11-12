"""
Module overview:
- Purpose: Provide high-level description of this module.
- Important classes/functions are documented inline.
"""

import os
import sys
from typing import Optional, List
from pydantic_ai import Agent

from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.ollama import OllamaProvider

from pydantic_ai.mcp import MCPServerStdio
from utils import *

def get_agent(system_prompt: str, output_type, toolsets: List[MCPServerStdio], model_name: str, debug = True) -> Agent:
    """
    Create and configure a Pydantic-AI `Agent` instance using a specified LLM model and MCP toolsets.

    This function dynamically selects the appropriate model provider (OpenAI, Google, or local Ollama)
    based on the prefix of the provided `model_name`. It then initializes an `Agent` with the given
    system prompt, output schema, and list of toolsets (MCP servers).

    Args:
        system_prompt (str):
            The system-level instruction or role description guiding the agent's overall behaviour.
        output_type:
            The expected Pydantic model or schema that defines the agent's structured output format.
        toolsets (List[MCPServerStdio]):
            A list of active MCP server connections (tools or environments) available to the agent.
        model_name (Optional[str]):
            The model identifier used to select the language model backend. Recognised prefixes:
                - `"gpt-"` → OpenAI models (via `OpenAIProvider`)
                - `"gemini-"` → Google models (via `GoogleProvider`)
                - Any other name → Local Ollama model (via `OllamaProvider`)

    Returns:
        Agent:
            A fully initialized Pydantic-AI `Agent` configured with the chosen model, toolsets,
            and system prompt.

    Environment Variables:
        LLM_API_KEY:
            Required for OpenAI or Google providers to authenticate API access.

    Raises:
        ValueError: If `model_name` is `None` or an empty string.
        RuntimeError: If the model provider cannot be initialized.
    """
    
    if not model_name:
        raise ValueError("model_name must be provided and cannot be empty.")
    model = None

    if model_name.startswith("gpt-") and not model_name.startswith("gpt-oss"):
        model = OpenAIChatModel(model_name, provider=OpenAIProvider(api_key=os.getenv("LLM_API_KEY")))
    elif model_name.startswith("gemini-"):
        model = GoogleModel(model_name, provider=GoogleProvider(api_key=os.getenv("LLM_API_KEY")))
    else:   
        model = OpenAIChatModel(
            model_name=model_name,
            provider=OllamaProvider(base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")),
        )

    return Agent(
        model,
        system_prompt=system_prompt,
        output_type=output_type,
        retries=4,                 # retry per tool & output validation
        output_retries=4,          # esplicito (altrimenti = retries)
        toolsets=toolsets,
    )