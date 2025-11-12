import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import json
import re
from utils import *
import textwrap

def gemini_response_parser(output: str, output_type = None, debug = False) -> str:
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
            print_message(YELLOW, "DEBUG", f"The output was:\n{clean_output}")
        return None
    return output_type.model_validate(data)



def realtime(cmd, debug = True, require_response = None):
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
                # print(f"Failed to parse JSON: {e}")
                # print_message(YELLOW, "DEBUG", f"Line content: {line.rstrip()}")
                data = None
                
            if data is not None:
                _type      = data.get("type")
                
                if _type == "tool_result":
                    print_message(CYAN, data.get("tool_id"), f"Status: {data.get('status')} - Output: {data.get('output')!r}")
                elif _type == "tool_use":
                    print_message(YELLOW, data.get("tool_name"), f"{data.get('tool_id')}({data.get('parameters')})")
                elif _type == "message" and data.get("role") == "assistant":
                    content = data.get("content")
                    allContent += content
                else:
                    print_message(GREEN, "IDK", data)
                            
            
            # # print in real time
            # if debug:
            #     print_message(CYAN, "DEBUG", line.rstrip('\n'))
            # else:
            #     print(line.rstrip('\n'))
                
                
                
    # Wait for process to finish (in case not done yet)
    return_code = process.wait()
    
    print_message(PURPLE, "CONTENT", allContent)
    
    return allContent
    
    print_message(YELLOW, "INFO", "gemini-cli process finished.")
    sys.exit(0)

    if return_code != 0:
        print_message(RED, "ERROR", f"gemini-cli exited with code {return_code}")
        sys.exit(1)

    # Now you have full output in stdout_lines; if you parse it:
    full_output = "\n".join(stdout_lines)
    response = gemini_response_parser(full_output, require_response, debug=debug)


def query_gemini_cli(system_prompt, user_prompt: str, require_response = None, verbose = False, debug = False, retries = 4, realTimeOutput = False):
    # Build gemini-cli command
    response_str = ""
    if require_response:
        schema = require_response.model_json_schema()  # gives dict schema
        schema_str = json.dumps(schema, indent=2)
        response_str = f"USE THIS RESPONSE TYPE, DON'T ADD ANY THINKING DATA OR OTHER; JUST HIS JSON RESPONSE:{schema_str}"

    # prompt = f"IMPORTANT: YOU DON'T HAVE TO MODIFY THE CODE, ONLY RESPONDS TO THE PROMPT BY USING THE MCPs, DON'T ANALYSE THE CODE.\nSYSTEM PROMPT: {system_prompt}\nUSER PROMPT: {user_prompt}{response_str}"

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


    cmd = [require_executable("gemini", "Gemini CLI"), "-y", "-p", prompt]
    
    if verbose: print_message(BLUE, "PROMPT", prompt)
    
    if debug:
        print_message(CYAN, "DEBUG", f"Waiting response from gemini-cli...")
        
    if realTimeOutput:
        cmd.extend(["--output-format", "stream-json"])

    try:
        for i in range(retries):  # Retry up to n times
            
            if realTimeOutput:
                stdout = realtime(cmd, require_response=require_response)
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
                return response
            
            if debug:
                print_message(YELLOW, "DEBUG", f"Retrying gemini-cli query ({i+1}/{retries})...")
            if i == retries - 1:
                print_message(RED, "ERROR", "Max retries reached. gemini-cli did not return a valid response.")
                sys.exit(1)
        
    except FileNotFoundError:
        sys.exit("Error: gemini-cli not found.")
    except subprocess.CalledProcessError as e:
        msg = textwrap.dedent(f"""\
        Error while running gemini-cli (exit code {e.returncode}).
        Command: {' '.join(cmd)}
        """)
        sys.exit(msg)


