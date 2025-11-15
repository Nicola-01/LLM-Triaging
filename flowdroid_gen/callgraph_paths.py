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

def getFlowGraf(app_path: Path, start_method: str, depth = 3, force: bool = False, debug: bool = False) -> list:
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
    
    
    if not os.path.exists(callgraph_file) or force:
        subprocess.run(
            f"flowdroid_gen/flowdroid-cg/target/flowdroid-cg-1.0-SNAPSHOT.jar $HOME/Android/Sdk/platforms {app_path} {output_dir}",
            shell=True
        )
        
    
    start_src, target_dst = find_start_dst(start_method, callgraph_file)

    if not start_src:
        print_message(YELLOW, "WARNING", "Target not found or not called by any method. Check the target name and the content of callgraph.json.")
        return None
    
    paths = dfs_paths(start_src, callgraph_file, depth, target_dst) 
    
    if not paths:
        print_message(YELLOW, "WARNING", "No paths found within the specified depth.")
        return None
    elif debug:
        print_message(GREEN, "INFO", f"Found {len(paths)} paths:")
        for p in paths:
            print_message(CYAN, "DEBUG", " -> ".join(p))
    return paths
        
"""


    
    
# getFlowGraf("/home/nicola/Desktop/LLM-Triaging/APKs/br.com.pedidos10", "jniParse", debug = True)
# getFlowGraf("/home/nicola/Desktop/LLM-Triaging/APKs/br.com.pedidos10/base.apk")


def main():
    # parser = argparse.ArgumentParser(
    #     description="Find call paths in a JSON callgraph using internal search."
    # )
    # parser.add_argument("file", help="callgraph.json")
    # parser.add_argument("target", help="method to reach (e.g. jniParse() or Java_za_co...)") 
    # parser.add_argument("--depth", type=int, default=5, help="Maximum depth for traversing up the callgraph.")
    # args = parser.parse_args()
    
    # target = args.target
    # file = args.file
    # depth = args.depth
    
    target = "<za.co.twyst.tbxml.TBXML: jniParse([B)J>"
    target = "jniParse"
    file = "/home/nicola/Downloads/flowdroid_gen/flowdroid-cg/tmp/base/callgraph.json"
    depth = 5

    print(f"[+] Searching for direct caller (start_src) of target '{target}'...")
    
    # Find the direct caller (start_src) and the full name of the target (target_dst)
    start_src, target_dst = find_start_dst(target, file)

    if not start_src:
        print("[-] Target not found or not called by any method. Check the target name and the content of callgraph.json.")
        return
    
    print(f"[+] Full Target DST = {target_dst}")
    print(f"[+] Start SRC (Direct Caller) = {start_src}")
    
    print(f"\n[+] DFS with depth={depth} using internal search...")
    # Pass the full target_dst to DFS to include it in the final path
    paths = dfs_paths(start_src, file, depth, target_dst) 

    print(f"\n[+] Found {len(paths)} paths:")
    if paths:
        # The paths are already in the correct order: [Root → ... → Target]
        for p in paths:
            print(" -> ".join(p) )
    else:
        print("[-] No paths found within the specified depth.")


# if __name__ == "__main__":
#     main()

"""