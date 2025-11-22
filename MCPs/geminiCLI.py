"""
Module overview:
- Purpose: Interface with the Gemini CLI for LLM queries.
- Important functions: query_gemini_cli, realtime.
"""

import sys
import os
from typing import Any

from pydantic import ValidationError

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import json
import re
from utils import *
import textwrap

class GeminiCliMaxRetry(Exception):
    """Exception raised when Gemini CLI retries are exhausted."""
    pass


def gemini_response_parser(output: str, output_type: Any = None, debug = False) -> str:
    """Clean gemini-cli output and return only the relevant response."""
    lines = output.splitlines()
    cleaned = []
    for line in lines:
        if "Loaded cached credentials." in line:
            continue
        if not line.strip():
            continue
        cleaned.append(line)
    out = "\n".join(cleaned)

    clean_output = re.sub(r"^```(?:json)?|```$", "", out.strip(), flags=re.MULTILINE).strip()

    if output_type is None:
        return clean_output
    
    if "{" in clean_output:
        clean_output = clean_output[clean_output.index("{"):]

    try:
        data = json.loads(clean_output)
    except Exception as e:
        print_message(YELLOW, "ERROR", f"Failed to parse gemini-cli output as JSON: {e}")
        if debug:
            print_message(YELLOW, "DEBUG", f"The output was:\n{clean_output[:200]}...")
        return None
    
    try:
        return output_type.model_validate(data)
    except ValidationError:
        return None



def realtime(cmd, debug = True, require_response = None):
    """
    Execute a command and process its output in real-time.
    
    Args:
        cmd: The command to execute.
        debug: Whether to print debug information.
        require_response: Optional Pydantic model to validate the response against.
        
    Returns:
        Tuple containing the full output content and statistics.
    """
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,          # get text strings instead of bytes
        bufsize=1,          # line-buffered
        universal_newlines=True
    )

    stdout_lines = []
    allContent = ""
    stats = {}
    
    while True:
        line = process.stdout.readline()
        if line == '' and process.poll() is not None:
            # no more output and process has ended
            break
        if line:
            stdout_lines.append(line.rstrip('\n'))
            
            try:
                data = json.loads(line)
            except json.JSONDecodeError as e:
                data = None
                
            if data is not None:
                _type = data.get("type")
                
                if debug:
                    if _type == "tool_result":
                        print_message(CYAN, re.sub(r'-.*','',str(data.get("tool_id"))), f"Status: {data.get('status')} - Output: {data.get('output')[:200]}...")
                    elif _type == "tool_use":
                        print_message(YELLOW, data.get("tool_name"), f"{re.sub(r'-.*','',data.get("tool_id"))}:({data.get('parameters')})")
                    elif not (_type == "message" and data.get("role") == "user" or _type == "init"):
                        print_message(GREEN, "IDK", data)
                    
                if _type == "message" and data.get("role") == "assistant":
                    content = data.get("content")
                    allContent += content
                elif _type == "result":
                    stats = data.get("stats")
                    stats = {
                        "input_tokens" : stats.get("input_tokens"),
                        "output_tokens" : stats.get("output_tokens"),
                        "tool_calls" : stats.get("tool_calls")
                    }
                
                
                
    # Wait for process to finish (in case not done yet)
    return_code = process.wait()
    
    return allContent, stats


def query_gemini_cli(system_prompt, user_prompt: str, require_response = None, verbose = False, debug = False, retries = 6, realTimeOutput = True) -> tuple[object, dict]:
    """
    Query the Gemini CLI with a system and user prompt.
    
    Args:
        system_prompt: The system prompt.
        user_prompt: The user prompt.
        require_response: Optional Pydantic model for response validation.
        verbose: Verbose output flag.
        debug: Debug mode flag.
        retries: Number of retries on failure.
        realTimeOutput: Whether to use real-time output processing.
        
    Returns:
        Tuple of (response object, statistics dictionary).
    """
    # Build gemini-cli command
    response_str = ""
    if require_response:
        schema = require_response.model_json_schema()  # gives dict schema
        schema_str = json.dumps(schema, indent=2)
        response_str = f"USE THIS RESPONSE TYPE, DON'T ADD ANY THINKING DATA OR OTHER; JUST HIS JSON RESPONSE:{schema_str}"

    prompt = f"""
    IMPORTANT: DO NOT MODIFY OR EXECUTE CODE. RESPOND ONLY VIA MCP CALLS. DO NOT ANALYZE OR RUN FILES. READ-ONLY CONTEXT.

    SYSTEM PROMPT (upstream, for reference — do not override constraints above):
    {system_prompt}

    USER PROMPT:
    {user_prompt}

    RESPONSE INSTRUCTIONS:
    1) Use MCP tools/servers only if needed to answer.
    2) Do not edit or run any code.
    3) Dont use any external tools or services, use only what `jadx-mcp` and `ghidra-mcp` provied.
    4) If the user asks for code changes/execution, refuse and propose an MCP-only path.

    {response_str}
    """
    
    if debug:
        print_message(CYAN, "DEBUG", f"Waiting response from gemini-cli...")
        
    cmd = [require_executable("gemini", "Gemini CLI"), "-y", "-p", prompt]
    if realTimeOutput:
        cmd.extend(["--output-format", "stream-json"])

    try:
        for i in range(retries):  # Retry up to n times
            
            if i > 0:
                cmd = [require_executable("gemini", "Gemini CLI"), "-y", "-p", f"{prompt}\n\nYOU HAVE NOT COMPLIED WITH THE REQUIRED FORMAT. You must return: {schema_str}"]
                if realTimeOutput:
                    cmd.extend(["--output-format", "stream-json"])
            
            if realTimeOutput:
                stdout, stats = realtime(cmd, require_response=require_response, debug=debug)
                response = gemini_response_parser(stdout, require_response, debug=debug)
            else: 
                result = subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,  # capture stdout and stderr
                    text=True             # decode as str
                )
                # Parse and clean response
                response = gemini_response_parser(result.stdout, require_response, debug=debug)
            
            if response is not None:
                return response, stats
            
            if debug:
                print_message(YELLOW, "DEBUG", f"Retrying gemini-cli query ({i+1}/{retries})...")
            if i == retries - 1:
                print_message(RED, "ERROR", "Max retries reached. gemini-cli did not return a valid response.")
                raise GeminiCliMaxRetry("Max retries reached. gemini-cli did not return a valid response.")
        
    except FileNotFoundError:
        raise FileNotFoundError("Error: gemini-cli not found.")
    except subprocess.CalledProcessError as e:
        msg = textwrap.dedent(f"""\
        Error while running gemini-cli (exit code {e.returncode}).
        Command: {' '.join(cmd)}
        """)
        raise RuntimeError(msg)


