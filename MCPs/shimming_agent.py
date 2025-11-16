import asyncio
import json
import os
import subprocess
import sys
from typing import Any
from llama_index.tools.mcp import BasicMCPClient
from openai import OpenAI

from pydantic import ValidationError
import regex

from MCPs.prompts.shimming_prompt import GHIDRA_MCP_TOOLS, JADX_MCP_TOOLS, SHIMMING_VULNDECT_SYSTEM_PROMPT
from MCPs.vulnDetection import VulnDetection
from utils import *

sys.path.append(os.path.dirname(__file__))


JADX_MCP = "JADX_MCP"
GHIDRA_MCP = "GHIDRA_MCP"

def extract_first_json(s: str):
    finds = regex.search("{(?:[^{}]|(?R))*}", s)
 
    if not finds:
        # print_message(RED, "ERROR", f"string s: {s}")
        raise ValueError("No JSON object found in LLM reply")

    return finds.group()

def response_parser(output_type: Any, data: Any) -> bool:
    try:
        ret = output_type.model_validate(data)
        return ret
    except ValidationError:
        return None

async def mcpRequest(mcp_clients:list, data, MAX_ERRORS = 5, error_calls = None):
    
    if data["action"] in JADX_MCP_TOOLS:
        response = await mcp_clients[JADX_MCP].call_tool(data["action"], data["args"])
        pass
    elif data["action"] in GHIDRA_MCP_TOOLS:
        response = await mcp_clients[GHIDRA_MCP].call_tool(data["action"], data["args"])
        pass
    else:
        return f"The tool doesn't exists, use a valid one from JADX MCP AND GHIDRA MCP"
    
    response = response.content
    
    print_message(GREEN, "SHIMMING_TOOL", response)
    
    tool_call = [data["action"], data["args"]]
    if error_calls and not response:
        if tool_call not in error_calls:
            response = "Response is empty, call is malformed."
            error_calls.append(tool_call)
        else:
            response = "Tool call failed more than once with an empty response, try a different tool."
    else:
        error_calls = []
    if len(error_calls) > MAX_ERRORS:
        prompt = 'Answer with a writeup that explains how the binary works and how the challenge could be solved. Use the following format: {"action" : "final", "result": <writeup>}'
    else:
        prompt = f"Tool Response: {response}"
        
    return prompt


async def oss_model(system_prompt:str, prompt:str, output_type:object, onlyJadx:bool, model_ulr:str, model_name:str, debug:bool = False) -> object:
    mcp_clients = []
    mcp_clients.append(JADX_MCP,BasicMCPClient("TODO")) # TODO
    if not onlyJadx:
        mcp_clients.append(GHIDRA_MCP,BasicMCPClient("http://127.0.0.1:8081/sse"))

    jadx_mcp_process = subprocess.Popen(
        "uv run $JADX_MCP_DIR/jadx_mcp_server.py --http --port 9999",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )

    ghidra_mcp_process = subprocess.Popen(
        "python3 $GHIDRA_MCP_DIR/bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )

    result = "None"
    tool_called = False
    
    client = OpenAI(base_url=model_ulr, api_key='ollama', )
    
    messages = [ {"role": "system", "content": system_prompt} ] # SHIMMING_VULNDECT_SYSTEM_PROMPT

    completion = client.chat.completions.create(
        model=model_name,
        messages=messages,
        temperature=0,
    )
    
    error_calls = []
    MAX_ERRORS = 5
    while True:
        if not prompt.startswith("Tool Response: "):
            print_message(PURPLE, "SHIMMING_PROMPT", prompt)
        new_message = {"role": "user", "content": prompt}
        messages.append(new_message)
        
        completion = client.chat.completions.create(
            model=model_name,
            messages=messages,
            temperature=0,
        )
        try:
            reply = completion.choices[0].message.content
        except ValueError:
            continue
        
        try:
            data = json.loads(reply)
        except Exception:
            try:
                reply = extract_first_json(reply)
            except ValueError:
                prompt = 'Invalid JSON. Follow schema strictly and reply only with a JSON. If you have enough information, write your writeup using the following schema: {"action": "final", "result": <writeup>}. Otherwise, call a tool with {"action": <tool_function>, "args": <args_if_needed>}.'
                continue
            
        messages.append({"role": "assistant", "content": reply})
            
        # print(f"[?] {reply}")
        print_message(CYAN, "SHIMMING_REPLY_CLEANED", reply)
        
        try:
            data = json.loads(reply)
        except:
            print_message(YELLOW, "WARNING", "INVALID JSON")
            prompt = 'Invalid JSON. Follow schema strictly and reply only with a JSON. If you have enough information, write your writeup using the following schema: {"action": "final", "result": <writeup>}. Otherwise, call a tool with {"action": <tool_function>, "args": <args_if_needed>}.'
            continue
        
        response = response_parser(output_type, data)
        if response:
            ghidra_mcp_process.kill()
            jadx_mcp_process.kill()
            return response
        
        if not ("action" in data and ("args" in data or "result" in data)):
            print_message(YELLOW, "WARNING", "Not action in data and no args/results in data")
            prompt = ('Invalid JSON. Follow schema strictly and reply only with a JSON. If you have enough information, write your writeup using the following schema: {"action": "final", "result": <writeup>}.' 
            + 'There the <writeup> is this JSON schmea:\n'
            + json.dumps(VulnDetection.model_json_schema(), indent=2)
            + '\n----\nOtherwise, call a tool with {"action": <tool_function>, "args": <args_if_needed>}.')
            continue
        
        prompt = await mcpRequest(mcp_clients, data, error_calls = error_calls)

        if data["action"] == "final":
            if not tool_called:
                prompt = 'You must call at least one tool before finalizing. Reply only with a JSON with the following schema: {"action": <tool_function>, "args": <args_if_needed>}'
                continue
            
            response = response_parser(output_type, data["result"])
            if response:
                jadx_mcp_process.kill()
                ghidra_mcp_process.kill()
                return response
            
            print_message(YELLOW, "WARNING", "Not action in data and no args/results in data")
            prompt = 'Invalid JSON. Follow schema strictly and reply only with a JSON. If you have enough information, write your writeup using the following schema: {"action": "final", "result": <writeup>}.' 
            + 'There the <writeup> is this JSON schmea:\n'
            + json.dumps(VulnDetection.model_json_schema(), indent=2)
            + '\n----\nOtherwise, call a tool with {"action": <tool_function>, "args": <args_if_needed>}.'
            continue

        tool_called = True

    return result

# python3 /home/nicola/Desktop/Tesi/GhidraMCP/GhidraMCP-release-1-4/bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/

# prompt = """
# CrashEntry:
#   Process Termination : abort
#   Stack Trace         : 
#         scudo::die
#         scudo::ScopedErrorReport::~ScopedErrorReport
#         scudo::reportInvalidChunkState
#         scudo::Allocator<scudo::AndroidConfig, &scudo_malloc_postinit>::deallocate
#         mp4_write_one_h264
#         Java_com_tplink_skylight_common_jni_MP4Encoder_packVideo
#   JNI Bridge Method   : Java_com_tplink_skylight_common_jni_MP4Encoder_packVideo
#   Fuzz Harness Entry  : fuzz_one_input
#   Program Entry       : main
# This is a map where each key is a Path to a relevant .so library, and the value is the list of JNI methods it implements: 
# - APKs/com.tplink.skylight/lib/arm64-v8a/libTPMp4Encoder.so: ['Java_com_tplink_skylight_common_jni_MP4Encoder_packVideo', 'mp4_write_one_h264', 'mp4_write_one_jpeg']

# """

# response = asyncio.run(oss_model(prompt, output_type=VulnDetection, mcp_url="http://127.0.0.1:8081/sse", 
#                       model_name="gpt-oss:120b", model_ulr="http://localhost:11435/v1"))

# print_message(PURPLE,"OUTPUT",response)