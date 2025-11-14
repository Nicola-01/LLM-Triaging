import asyncio
import json
import re
from llama_index.tools.mcp import BasicMCPClient
from openai import OpenAI

from MCPs.prompts.shimming_prompt import SYSTEM_PROMPT

def RawJSONDecoder(index):
    class _RawJSONDecoder(json.JSONDecoder):
        end = None

        def decode(self, s, *_):
            data, self.__class__.end = self.raw_decode(s, index)
            return data
    return _RawJSONDecoder

def extract_json(s, index=0):
    while (index := s.find('{', index)) != -1:
        try:
            yield json.loads(s, cls=(decoder := RawJSONDecoder(index)))
            index = decoder.end
        except json.JSONDecodeError:
            index += 1

async def oss_model(prompt, mcp_url, model_ulr, model):
    mcp_client = BasicMCPClient(mcp_url)

    result = "None"
    tool_called = False
    
    agent = OpenAI(base_url = model_ulr, api_key='ollama', )
    
    messages = [
        {
            "role": "system",
            "content": SYSTEM_PROMPT,
        }
    ]

    completion = agent.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0,  ## però potrebbe essere un problema temperature 0 per la classificazione?
    )
    
    error_calls = []
    MAX_ERRORS = 5
    while True:
        print(f"[+] {prompt}")
        new_message = {"role": "user", "content": prompt}
        messages.append(new_message)
        
        completion = agent.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0,
        )
        try:
            reply = completion.choices[0].message.content
        except ValueError:
            continue
        
        reply = re.sub(r'^[^{]+','',reply)
        reply = re.sub(r'[^}]*$','',reply)

        reply = str(reply)
        print(f"[?] {reply}")

        messages.append({"role": "assistant", "content": reply})

        try:
            data = json.loads(reply)
        except Exception as e:
            reply = extract_json(reply)
            print(reply)
        try:
            data = json.loads(reply)
        except:
            prompt = 'Invalid JSON. Follow schema strictly and reply only with a JSON. If you have enough information, write your writeup using the following schema: {"action": "final", "result": <writeup>}. Otherwise, call a tool with {"action": <tool_function>, "args": <args_if_needed>}.'
            continue

        if ("action" not in data and "args" not in data) or (
            "action" not in data and "result" not in data
        ):
            prompt = 'Invalid JSON. Follow schema strictly and reply only with a JSON. If you have enough information, write your writeup using the following schema: {"action": "final", "result": <writeup>}. Otherwise, call a tool with {"action": <tool_function>, "args": <args_if_needed>}.'
            continue
        
        prompt = mcpRequest()

        if data["action"] == "final":
            if not tool_called:
                prompt = 'You must call at least one tool before finalizing. Reply only with a JSON with the following schema: {"action": <tool_function>, "args": <args_if_needed>}'
                continue
            return data["result"]

        # response = await mcp_client.call_tool(data["action"], data["args"])
        # response = response.structuredContent
        # tool_call = [data["action"], data["args"]]
        # if not response:
        #     if tool_call not in error_calls:
        #         response = "Response is empty, call is malformed."
        #         error_calls.append(tool_call)
        #     else:
        #         response = "Tool call failed more than once with an empty response, try a different tool."
        # else:
        #     error_calls = []
        # if len(error_calls) > MAX_ERRORS:
        #     prompt = 'Answer with a writeup that explains how the binary works and how the challenge could be solved. Use the following format: {"action" : "final", "result": <writeup>}'
        # else:
        #     prompt = f"Tool Reponse: {response}"
        prompt = mcpRequest(mcp_client, data, error_calls = error_calls)
        
        tool_called = True

    return result

#asyncio.run(oss_model("hello"))
# python3 /home/nicola/Desktop/Tesi/GhidraMCP/GhidraMCP-release-1-4/bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
# asyncio.run(oss_model("Find the function `NI_PublicKeyDecode`, using `search_functions_by_name`"))

async def mcpRequest(mcp_client, data, MAX_ERRORS = 5, error_calls = None):
    print(">>> SENT:", data)

    response = await mcp_client.call_tool(data["action"], data["args"])
    response = response.content
    print(f"\nRESPONSE {response}")
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

async def myTest():
    # mcp_client = BasicMCPClient("http://127.0.0.1:8080")
    mcp_client = BasicMCPClient("http://127.0.0.1:8082/sse")
    
    # print(await mcp_client.list_tools())

    
    
    methodName = "Java_com_tplink_skylight_common_jni_MP4Encoder_packVideo"
    

    print("===\n\n search_functions_by_name")
    data = {
        "action": "search_functions_by_name",
        "args": {
            "query": methodName
        }
    }
    await mcpRequest(mcp_client, data)
    
    print("\n===\n\n decompile_function")
    data = {
        "action": "decompile_function",
        "args": {
            "name": methodName
        }
    }
    await mcpRequest(mcp_client, data)
    
    
    
    
    print("\n===\n\n get_function_by_address")
    data = {
        "action": "get_function_by_address",
        "args": {
            "address": "0x00140204"
        }
    }
    await mcpRequest(mcp_client, data)
    
    print("\n===\n\n list_methods")
    data = {
        "action": "list_methods",
        "args": {}
    }
    await mcpRequest(mcp_client, data)
    
    
    print("\n===\n\n decompile_function_by_address")
    data = {
        "action": "decompile_function_by_address",
        "args": {
            "address": "0x00140204"
        }
    }
    await mcpRequest(mcp_client, data)
    print("\n===")
    
    
    
    return
    

    
    print("\n===\n\n get_function_by_address")
    data = {
        "action": "get_function_by_address",
        "args": {
            "address": "0x0014020400"
        }
    }
    await mcpRequest(mcp_client, data)
    
    print("\n===\n\n decompile_function")
    data = {
        "action": "decompile_function",
        "args": {
            "name": methodName
        }
    }
    await mcpRequest(mcp_client, data)
    

# Run the test function using asyncio
asyncio.run(myTest())

# ./ghidra-cli -n -i APKs/com.tplink.skylight/lib/arm64-v8a/libTPMp4Encoder.so

# clear && python3 /home/nicola/Desktop/Tesi/GhidraMCP/GhidraMCP-release-1-4/bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
