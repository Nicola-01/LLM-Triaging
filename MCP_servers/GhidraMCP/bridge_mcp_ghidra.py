# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import os
from pathlib import Path
import re
import sys
import tempfile
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

if 'DISPLAY' not in os.environ:
    os.environ['DISPLAY'] = ':0'

# if 'XAUTHORITY' not in os.environ:
#     import pwd
    
#     uid = os.getuid()
#     user_entry = pwd.getpwuid(uid)
#     real_home = user_entry.pw_dir
    
#     # Costruisce il percorso
#     xauth_path = os.path.join(real_home, '.Xauthority')
    
#     if os.path.exists(xauth_path):
#         os.environ['XAUTHORITY'] = xauth_path
#     else:
#         print(f"[WARN] .Xauthority non trovato in {real_home}", file=sys.stderr)
            
    
from ghidra_helper_functions import closeGhidraFile, closeGhidraGUI, openGhidraFile, openGhidraGUI
from MCPs.CrashSummary import find_relevant_libs, get_libs_method_map


DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)


SHARED_DIR = os.path.join(tempfile.gettempdir(), "mcp_ghidra_share")
os.makedirs(SHARED_DIR, exist_ok=True)
FILE_AVAILABLE = os.path.join(SHARED_DIR, "available.txt")
FILE_CURRENT = os.path.join(SHARED_DIR, "current_lib.txt")
APK_CURRENT = os.path.join(SHARED_DIR, "current_apk.txt")

def _read_lines(filepath):
    """Helper for reading clean lines from a txt file."""
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return sorted([line.strip() for line in f if line.strip()], key=lambda s: s.lower())

@mcp.tool()
def list_available_libs() -> list:
    """
    Retrieves a list of all libs currently imported into the Ghidra Project.
    
    Use this tool to discover valid libs names before attempting to open or analyze a specific binary.
    If the user asks about a specific library that is not in this list, you may need to use `analyze_new_binary` (if available) or ask the user to import it.

    Returns:
        A list of filenames (e.g., ["libssl.so", "lib2.so"]) available in the project root.
    """
    files = _read_lines(FILE_AVAILABLE)
    if not files:
        return "No libs found in GHIDRA_FILES environment variable."
        # raise Exception("No libs found in GHIDRA_FILES environment variable.")
    return files

@mcp.tool()
def get_current_lib_name() -> str:
    """
    Identifies the lib currently active and visible in the Ghidra CodeBrowser.

    Use this to establish context before performing analysis actions to ensure you are working on the correct file.
    
    Returns:
        str: The name of the currently open lib (e.g., "auth_module.dll").
    """
    ret = _read_lines(FILE_CURRENT)
    if ret[0] == None:
        return "There are not open files, open one with `open_lib`"
        # raise Exception("There are not open files, open one with `open_lib`")
    else:
        return ret[0]

@mcp.tool()
def open_lib(lib_name: str):
    """
    Switches the active view in Ghidra CodeBrowser to the specified lib.

    You should call `list_available_libs` first to verify the lib exists.
    This does not start analysis, it only brings the binary into focus in the UI.
    
    Args:
        lib_name (str): The exact name of the lib to open (must match an entry from `list_available_libs`).      
    """
    files = _read_lines(FILE_AVAILABLE)
    if lib_name not in files:
        return f"The lib {lib_name} doesn't exists in current Ghidra session, use one of this {files}"
        # raise Exception(f"The lib {lib_name} doesn't exists in current Ghidra session, use one of this {files}")
    
    if lib_name == get_current_lib_name():
        return f"The lib {lib_name} is currently open"
        # raise Exception(f"The lib {lib_name} is currently open")
    
    for f in files:
        closeGhidraFile(f, debug=True)
    openGhidraFile(files, lib_name)
    with open(FILE_CURRENT, "w", encoding="utf-8") as f:
        f.write(lib_name)
        
    return safe_get("string", {"outcome": f"The lib {lib_name} has been opened successfully."})
    
def open_external_method(method_name: str):
    """
    Searches for the given method in the APK's native libraries and imports the libs.

    Args:
        method_name (str): Exact JNI method name to locate.

    Raises:
        Exception: If the method cannot be found or is already available.
    """
    
    apk_path = Path(_read_lines(APK_CURRENT)[0])
    
    lib_method_map = get_libs_method_map(apk_path)
    new_lib_map = find_relevant_libs(lib_method_map, method_name).keys()
    new_lib = new_lib_map.keys()
    
    files = _read_lines(FILE_AVAILABLE)
    
    prev_size = len(files)
    
    if len(new_lib) == 0:
        return "The method could not be found."
        # raise Exception("The method could not be found.")
    
    for n in new_lib:
        files.append(n)
    
    new_size = len(set(files))
    if new_size == prev_size:
        for lib, method in new_lib_map.items():  # for name, age in dictionary.iteritems():  (for Python 2.x)
            if method == method_name:
                return f"The method {method_name} is already available at {lib}"
                # raise Exception(f"The method is already available at {lib}")
        return "The method is not available."
        # raise Exception("The method is not available.")
    
    closeGhidraGUI()
    
    sorted_libs = sorted(files, key=lambda s: s.lower())
    
    openGhidraGUI(sorted_libs, timeout=60*(len(sorted_libs)+2))

    with open(FILE_AVAILABLE, "w", encoding="utf-8") as f:
        libs = "\n".join(sorted_libs)
        libs = re.sub(r'APKs/[^/]+/lib/[^/]+/', '', libs)
        f.write(libs)
                
    openGhidraFile(sorted_libs, sorted_libs[0])
    with open(FILE_CURRENT, "w", encoding="utf-8") as f:
        f.write(sorted_libs[0])
        
    return f"The method {method_name} has been found and the relevant libs have been imported: {', '.join(new_lib).strip()}."

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

