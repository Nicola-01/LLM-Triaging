import argparse
import os
from pathlib import Path
import subprocess
import re
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils import *

# Regular expressions to extract src and dst
EDGE_RE = re.compile(r'"src":\s*"([^"]+)",\s*"dst":\s*"([^"]+)"')
DST_RE  = re.compile(r'"dst":\s*"([^"]+)"')
SRC_RE  = re.compile(r'"src":\s*"([^"]+)"')

def rg(pattern, file):
    """Executes ripgrep and returns the found lines as a list of strings."""   
    
    safe = escape(pattern)
    # print(f"rg '{safe}' {file}")
    result = subprocess.run(
        ["rg", safe, file],
        stdout=subprocess.PIPE,
        text=True
    )
    if result.stdout:
        return result.stdout.strip().split("\n")
    return []


def escape(s):
    """Escapes special characters for ripgrep."""
    specials = r".^$*+?{}[]|()\/"
    out = ""
    for ch in s:
        if ch in specials:
            out += "\\" + ch
        else:
            out += ch
    return out


def extract_src(line):
    """Extracts the source (caller) from a JSON line."""
    m = SRC_RE.search(line)
    return m.group(1) if m else None


def extract_dst(line):
    """Extracts the destination (callee) from a JSON line."""
    m = DST_RE.search(line)
    return m.group(1) if m else None


def get_callouts(src, file):
    """
    Uses rg to get all lines where src is the caller.
    Returns a list of dsts. (NOT USED in the backward DFS)
    """
    pattern = f'"src": "{src}"'
    lines = rg(pattern, file)

    dsts = []
    for line in lines:
        d = extract_dst(line)
        if d:
            dsts.append(d)
    return dsts


def get_callers(dst, file):
    """
    Uses rg to get all lines where dst is the callee.
    Returns a list of srcs (the callers).
    """
    # We search for lines where 'dst' is in the "dst" field
    pattern = f'"dst": "{dst}"'
    lines = rg(pattern, file)

    srcs = []
    for line in lines:
        d = extract_dst(line)
        # We ensure that the extracted DST exactly matches the given one.
        if d == dst:
             s = extract_src(line)
             if s:
                 srcs.append(s)
    
    # Remove duplicates (if a caller appears multiple times in the JSON)
    return list(set(srcs))


def find_start_dst(dst, file):
    """
    Finds the first line that contains the target method.
    Returns its src (the direct caller) and the full dst.
    """
    # rg searches for the DST string in the file. 
    # This can be a substring, e.g., 'jniParse' in '<class: jniParse(...)>'
    hits = rg(dst, file) 
    
    if not hits:
        return None, None
    
    for h in hits:
        h_dst = extract_dst(h)
        # Find the first hit that contains the target in the DST field
        if dst in h_dst:
            # Extract the SRC and return both SRC and the full DST
            return extract_src(h), h_dst 
    return None, None


def dfs_paths(start, file, max_depth, initial_target_dst):
    """
    Traverses the callgraph upwards starting from `start` (the direct caller of the target),
    finding all paths within `max_depth`.
    Returns: list[list[str]] (all possible paths in the order Root -> Target).
    """
    
    all_paths = []

    def dfs(node, depth, current_path):
        
        # Add the current node to the path (the most recent node goes to the head)
        # The list is built backwards: [DirectCaller, Caller1, Caller2, ...]
        new_path = [node] + current_path 

        # Termination condition 1: Maximum depth reached
        if depth >= max_depth:
            # Add the complete and reversed path
            # [Root, ..., DirectCaller] + [Target]
            all_paths.append(new_path[::-1] + [initial_target_dst])
            return

        # Find all nodes that call the current node (upward traversal)
        callers = get_callers(node, file)

        if not callers:
            # Termination condition 2: Root node (not called by anyone)
            # Add the complete and reversed path
            # [Root, ..., DirectCaller] + [Target]
            all_paths.append(new_path[::-1] + [initial_target_dst])
            return

        # Continue the depth-first search for each caller
        for caller in callers:
            # Continue the recursion
            dfs(caller, depth + 1, new_path)

    # Start the DFS from the target's direct caller (start_src)
    dfs(start, 1, [])
    
    return all_paths

def generateCallGraph(app_path, timeout:int = 60*5, overwrite: bool = False, debug: bool = False) -> bool:
    """Generate a call graph `callgraph.json`
    
    Args:
        app_path (Path): Path to the APK/directory.
        timeout (int): Time to generate the call graph.
        overwrite (bool): Overwrite call graph regeneration.
        debug (bool): Print debug path info.
        
    Returns:
        bool: `True` if the callgraph was generate, `False` otherwise.
    """
    
    app_path = Path(app_path)
    directory = "callGraph"
    if not os.path.exists(directory):
        os.makedirs(directory)
            
    app_name = app_path.name
    package_name = app_name
    if not app_name.endswith(".apk"):
        app_name = "base.apk"
        app_path = app_path / app_name
    else:
        package_name = app_path.parent.name
        
    output_dir = f"{directory}/{package_name}"
    
    # print(f"app path: {app_path}\noutput: {output_dir}")
    callgraph_file = f"{output_dir}/callgraph.json"
    
    try:
        if not os.path.exists(callgraph_file) or overwrite:
            # Note: $HOME/Android/Sdk/platforms is used as the Android platform path
            print_message(BLUE, "INFO", f"Extracting flow graph from {package_name}")
            subprocess.run(
                f"java -jar flowdroid_gen/flowdroid-cg/target/flowdroid-cg-1.0-SNAPSHOT.jar $HOME/Android/Sdk/platforms {app_path} {output_dir}",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                timeout=timeout 
            )
            return True
    except subprocess.TimeoutExpired:
        print_message(YELLOW, "WARNING", f"FlowDroid call timed out after {timeout} seconds. The call graph was not generated.")
        return False
    

def getFlowGraph(app_path: Path, JNIBridgeMethod: str, max_depth = 5, max_paths = 25, debug: bool = False) -> List[str]:
    """
    Finds call paths backward from the start_method in the call graph.

    Args:
        app_path (Path): Path to the APK/directory.
        JNIBridgeMethod (str): Target method (e.g., 'jniParse').
        max_depth (int): Max backward search depth.
        max_paths (int): Max number of path to return.
        debug (bool): Print debug path info.

    Returns:
        List[List[str]]: Found call paths ([Root → ... → Target]) or None.
    """
    app_path = Path(app_path)
    
    app_name = app_path.name
    package_name = app_name
    if not app_name.endswith(".apk"):
        app_name = "base.apk"
        app_path = app_path / app_name
    else:
        package_name = app_path.parent.name
            
    # print(f"app path: {app_path}\noutput: {output_dir}")
    callgraph_file = f"callGraph/{package_name}/callgraph.json"
    
    if not os.path.exists(callgraph_file):
        print_message(YELLOW,"WARNING", f"The file {callgraph_file} doesent exists")
        return None
       
    bridgeMethod = JNIBridgeMethod.split("_") 
    start_method = None 
    for i in range(1,len(bridgeMethod)):
        test_method = "_".join(bridgeMethod[-i:])
        ret = rg(test_method, callgraph_file)
        if debug:
            print_message(CYAN, "DEBUG", f"Search for {test_method} in {callgraph_file}")
        if (len(ret) > 0):
            start_method = test_method
        else:
            break
        
    curedJNIBridgeMethod = JNIBridgeMethod.replace("_", ";")
    if (curedJNIBridgeMethod.count(";1")):
        curedJNIBridgeMethod = curedJNIBridgeMethod.replace(";1","_")
        if debug:
            print_message(CYAN, "DEBUG", f"Replaced _, unsing {curedJNIBridgeMethod}")
        bridgeMethod = curedJNIBridgeMethod.split(";") 
        for i in range(1,len(bridgeMethod)):
            test_method = "_".join(bridgeMethod[-(i):])
            ret = rg(test_method, callgraph_file)
            if (len(ret) == 0):
                break
            if (max_i >= i):
                max_i = i
                start_method = test_method
        
    if not start_method:
        print_message(YELLOW, "WARNING", f"The method {JNIBridgeMethod} is not present in {callgraph_file}")
        return None
        
    start_src, target_dst = find_start_dst(start_method, callgraph_file)

    if not start_src:
        print_message(YELLOW, "WARNING", "Target not found or not called by any method. Check the target name and the content of callgraph.json.")
        return None
        
    callGraph = None
    # new_callGraph = getFlowGraph(apk, JNIBridgeMethod, max_depth, debug=True)
    paths = []
    ret: list[str] = []
    depth = 1
    while True:
        new_paths = dfs_paths(start_src, callgraph_file, depth, target_dst) 
        if not new_paths or len(new_paths) == 0:
            if debug:
                print_message(YELLOW, "DEBUG", "Call Graph is null")
            break
        if len(new_paths) < max_paths:
            paths = new_paths
        else:
            break
        depth += 1
        if depth > max_depth:
            break

    if len(paths) == 0:
        print_message(YELLOW, "WARNING", "No paths found.")
        return None
    elif debug:
        print_message(GREEN, "INFO", f"Found {len(paths)} paths:")
        for p in paths:
            ret.append(" -> ".join(p))
            # print_message(CYAN, "DEBUG", " -> ".join(p))
    return ret