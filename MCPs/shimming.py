import asyncio
import json
import re
from llama_index.tools.mcp import BasicMCPClient  # pip install llama-index-tools-mcp
from openai import OpenAI
from together import Together # pip install together 

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

async def oss_model(prompt, url="http://127.0.0.1:8080", model="llama3.1:70b"):
    mcp_client = BasicMCPClient(
        url
    )  # MCP VIENE ESEGUITO SU UN ENDPOINT HTTP, METTI QUI URL

    SYSTEM_PROMPT = """
You are a tool-using assistant that can use tools to reverse engineer a binary using Ghidra to understand how it works. 
You can ONLY communicate in JSON.

Available functionalities:

  - decompile_function
    Decompile a specific function by name and return the decompiled C code.
      Parameters:
      {
        "type": "object",
        "properties": {
          "name": {
            "title": "Name",
            "type": "string"
          }
        },
        "required": [
          "name"
        ],
        "title": "decompile_functionArguments"
      }
  - decompile_function_by_address
    Decompile a function at the given address.
      Parameters:
      {
        "type": "object",
        "properties": {
          "address": {
            "title": "Address",
            "type": "string"
          }
        },
        "required": [
          "address"
        ],
        "title": "decompile_function_by_addressArguments"
      }
  - disassemble_function
    Get assembly code (address: instruction; comment) for a function.
      Parameters:
      {
        "type": "object",
        "properties": {
          "address": {
            "title": "Address",
            "type": "string"
          }
        },
        "required": [
          "address"
        ],
        "title": "disassemble_functionArguments"
      }
  - get_current_address
    Get the address currently selected by the user.
      Parameters:
      {
        "type": "object",
        "properties": {},
        "title": "get_current_addressArguments"
      }
  - get_current_function
    Get the function currently selected by the user.
      Parameters:
      {
        "type": "object",
        "properties": {},
        "title": "get_current_functionArguments"
      }
  - get_function_by_address
    Get a function by its address.
      Parameters:
      {
        "type": "object",
        "properties": {
          "address": {
            "title": "Address",
            "type": "string"
          }
        },
        "required": [
          "address"
        ],
        "title": "get_function_by_addressArguments"
      }
  - get_function_xrefs
    Get all references to the specified function by name.

    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
      Parameters:
      {
        "type": "object",
        "properties": {
          "name": {
            "title": "Name",
            "type": "string"
          },
          "offset": {
            "default": 0,
            "title": "Offset",
            "type": "integer"
          },
          "limit": {
            "default": 100,
            "title": "Limit",
            "type": "integer"
          }
        },
        "required": [
          "name"
        ],
        "title": "get_function_xrefsArguments"
      }
  - get_xrefs_from
    Get all references from the specified address (xref from).

    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
      Parameters:
      {
        "type": "object",
        "properties": {
          "address": {
            "title": "Address",
            "type": "string"
          },
          "offset": {
            "default": 0,
            "title": "Offset",
            "type": "integer"
          },
          "limit": {
            "default": 100,
            "title": "Limit",
            "type": "integer"
          }
        },
        "required": [
          "address"
        ],
        "title": "get_xrefs_fromArguments"
      }
  - get_xrefs_to
    Get all references to the specified address (xref to).

    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
      Parameters:
      {
        "type": "object",
        "properties": {
          "address": {
            "title": "Address",
            "type": "string"
          },
          "offset": {
            "default": 0,
            "title": "Offset",
            "type": "integer"
          },
          "limit": {
            "default": 100,
            "title": "Limit",
            "type": "integer"
          }
        },
        "required": [
          "address"
        ],
        "title": "get_xrefs_toArguments"
      }
  - list_classes
    List all namespace/class names in the program with pagination.
      Parameters:
      {
        "type": "object",
        "properties": {
          "offset": {
            "default": 0,
            "title": "Offset",
            "type": "integer"
          },
          "limit": {
            "default": 100,
            "title": "Limit",
            "type": "integer"
          }
        },
        "title": "list_classesArguments"
      }
  - list_data_items
    List defined data labels and their values with pagination.
      Parameters:
      {
        "type": "object",
        "properties": {
          "offset": {
            "default": 0,
            "title": "Offset",
            "type": "integer"
          },
          "limit": {
            "default": 100,
            "title": "Limit",
            "type": "integer"
          }
        },
        "title": "list_data_itemsArguments"
      }
  - list_exports
    List exported functions/symbols with pagination.
      Parameters:
      {
        "type": "object",
        "properties": {
          "offset": {
            "default": 0,
            "title": "Offset",
            "type": "integer"
          },
          "limit": {
            "default": 100,
            "title": "Limit",
            "type": "integer"
          }
        },
        "title": "list_exportsArguments"
      }
  - list_functions
    List all functions in the database.
      Parameters:
      {
        "type": "object",
        "properties": {},
        "title": "list_functionsArguments"
      }
  - list_imports
    List imported symbols in the program with pagination.
      Parameters:
      {
        "type": "object",
        "properties": {
          "offset": {
            "default": 0,
            "title": "Offset",
            "type": "integer"
          },
          "limit": {
            "default": 100,
            "title": "Limit",
            "type": "integer"
          }
        },
        "title": "list_importsArguments"
      }
  - list_methods
    List all function names in the program with pagination.
      Parameters:
      {
        "type": "object",
        "properties": {
          "offset": {
            "default": 0,
            "title": "Offset",
            "type": "integer"
          },
          "limit": {
            "default": 100,
            "title": "Limit",
            "type": "integer"
          }
        },
        "title": "list_methodsArguments"
      }
  - list_namespaces
    List all non-global namespaces in the program with pagination.
      Parameters:
      {
        "type": "object",
        "properties": {
          "offset": {
            "default": 0,
            "title": "Offset",
            "type": "integer"
          },
          "limit": {
            "default": 100,
            "title": "Limit",
            "type": "integer"
          }
        },
        "title": "list_namespacesArguments"
      }
  - list_segments
    List all memory segments in the program with pagination.
      Parameters:
      {
        "type": "object",
        "properties": {
          "offset": {
            "default": 0,
            "title": "Offset",
            "type": "integer"
          },
          "limit": {
            "default": 100,
            "title": "Limit",
            "type": "integer"
          }
        },
        "title": "list_segmentsArguments"
      }
  - list_strings
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
      Parameters:
      {
        "type": "object",
        "properties": {
          "offset": {
            "default": 0,
            "title": "Offset",
            "type": "integer"
          },
          "limit": {
            "default": 2000,
            "title": "Limit",
            "type": "integer"
          },
          "filter": {
            "default": null,
            "title": "Filter",
            "type": "string"
          }
        },
        "title": "list_stringsArguments"
      }
  - rename_data
    Rename a data label at the specified address.
      Parameters:
      {
        "type": "object",
        "properties": {
          "address": {
            "title": "Address",
            "type": "string"
          },
          "new_name": {
            "title": "New Name",
            "type": "string"
          }
        },
        "required": [
          "address",
          "new_name"
        ],
        "title": "rename_dataArguments"
      }
  - rename_function
    Rename a function by its current name to a new user-defined name.
      Parameters:
      {
        "type": "object",
        "properties": {
          "old_name": {
            "title": "Old Name",
            "type": "string"
          },
          "new_name": {
            "title": "New Name",
            "type": "string"
          }
        },
        "required": [
          "old_name",
          "new_name"
        ],
        "title": "rename_functionArguments"
      }
  - rename_function_by_address
    Rename a function by its address.
      Parameters:
      {
        "type": "object",
        "properties": {
          "function_address": {
            "title": "Function Address",
            "type": "string"
          },
          "new_name": {
            "title": "New Name",
            "type": "string"
          }
        },
        "required": [
          "function_address",
          "new_name"
        ],
        "title": "rename_function_by_addressArguments"
      }
  - rename_variable
    Rename a local variable within a function.
      Parameters:
      {
        "type": "object",
        "properties": {
          "function_name": {
            "title": "Function Name",
            "type": "string"
          },
          "old_name": {
            "title": "Old Name",
            "type": "string"
          },
          "new_name": {
            "title": "New Name",
            "type": "string"
          }
        },
        "required": [
          "function_name",
          "old_name",
          "new_name"
        ],
        "title": "rename_variableArguments"
      }
  - search_functions_by_name
    Search for functions whose name contains the given substring.
      Parameters:
      {
        "type": "object",
        "properties": {
          "query": {
            "title": "Query",
            "type": "string"
          },
          "offset": {
            "default": 0,
            "title": "Offset",
            "type": "integer"
          },
          "limit": {
            "default": 100,
            "title": "Limit",
            "type": "integer"
          }
        },
        "required": [
          "query"
        ],
        "title": "search_functions_by_nameArguments"
      }
  - set_decompiler_comment
    Set a comment for a given address in the function pseudocode.
      Parameters:
      {
        "type": "object",
        "properties": {
          "address": {
            "title": "Address",
            "type": "string"
          },
          "comment": {
            "title": "Comment",
            "type": "string"
          }
        },
        "required": [
          "address",
          "comment"
        ],
        "title": "set_decompiler_commentArguments"
      }
  - set_disassembly_comment
    Set a comment for a given address in the function disassembly.
      Parameters:
      {
        "type": "object",
        "properties": {
          "address": {
            "title": "Address",
            "type": "string"
          },
          "comment": {
            "title": "Comment",
            "type": "string"
          }
        },
        "required": [
          "address",
          "comment"
        ],
        "title": "set_disassembly_commentArguments"
      }
  - set_function_prototype
    Set a function's prototype.
      Parameters:
      {
        "type": "object",
        "properties": {
          "function_address": {
            "title": "Function Address",
            "type": "string"
          },
          "prototype": {
            "title": "Prototype",
            "type": "string"
          }
        },
        "required": [
          "function_address",
          "prototype"
        ],
        "title": "set_function_prototypeArguments"
      }
  - set_local_variable_type
    Set a local variable's type.
      Parameters:
      {
        "type": "object",
        "properties": {
          "function_address": {
            "title": "Function Address",
            "type": "string"
          },
          "variable_name": {
            "title": "Variable Name",
            "type": "string"
          },
          "new_type": {
            "title": "New Type",
            "type": "string"
          }
        },
        "required": [
          "function_address",
          "variable_name",
          "new_type"
        ],
        "title": "set_local_variable_typeArguments"
      }


For each step, reply ONLY with a JSON with the proposed schema.
{
  "action": <tool_name>,
  "args": { ... },
}

For example:
{
  "action": "get_function_by_name",
  "args": {"name": "main"},
}


Return only valid JSON.
Do not add explanations, prefixes, or markdown code fences.

---

**Only After receiving the tool result**, you will be asked again.
Only when explicitly instructed with "final" may you return your writeup:
{
  "action": "final",
  "result": <writeup>,
}

Rules:
- NEVER output text outside of JSON.
- NEVER skip directly to "final" without using a tool.
- If you are unsure of arguments, fill with placeholders.
- Your job is to call a tool on every turn until told otherwise.
    """
    
    
    # llm = Ollama(model=model, base_url=OSS_MODEL_URL, request_timeout=500.0)
    """ 

    agent = ReActAgent(
        name="ida-pro-mcp",
        llm=llm,
        tools=tools,
        system_prompt=SYSTEM_PROMPT,
    )
    ctx = Context(agent)
    chat_history = [ChatMessage(role="system", content=SYSTEM_PROMPT)]
    """
    result = "None"
    tool_called = False
    
    # client = Together(api_key="miao")  # C
    
    client = OpenAI(
        base_url = 'http://localhost:11435/v1',
        api_key='ollama', 
    )
    
    messages = [
        {
            "role": "system",
            "content": SYSTEM_PROMPT,
        }
    ]

    completion = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0,
    )
    error_calls = []
    MAX_ERRORS = 5
    while True:
        print(f"[+] {prompt}")
        new_message = {"role": "user", "content": prompt}
        messages.append(new_message)
        completion = client.chat.completions.create(
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
