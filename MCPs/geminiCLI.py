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
    else:
        try:
            data = json.loads(clean_output)
        except Exception as e:
            print_message(YELLOW, "ERROR", f"Failed to parse gemini-cli output as JSON: {e}")
            if debug:
                print_message(YELLOW, "DEBUG", f"The output was:\n{clean_output}")
            return None
        return output_type.model_validate(data)


def query_gemini_cli(system_prompt, user_prompt: str, require_response = None, debug = False, retries = 4):
    # Build gemini-cli command
    response_str = ""
    if require_response:
        schema = require_response.model_json_schema()  # gives dict schema
        schema_str = json.dumps(schema, indent=2)
        response_str = f"USE THIS RESPONSE TYPE:{schema_str}"

    prompt = f"SYSTEM PROMPT: {system_prompt}\nUSER PROMPT: {user_prompt}{response_str}"

    cmd = [require_executable("gemini", "Gemini CLI"), "-y", "-p", prompt]


    # print_message(CYAN, "INFO", "Querying gemini-cli with the provided prompt...")
    try:
        for i in range(retries):  # Retry up to n times
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
            
    except FileNotFoundError:
        sys.exit("Error: gemini-cli not found.")
    except subprocess.CalledProcessError as e:
        msg = textwrap.dedent(f"""\
        Error while running gemini-cli (exit code {e.returncode}).
        Command: {' '.join(cmd)}
        """)
        sys.exit(msg)


